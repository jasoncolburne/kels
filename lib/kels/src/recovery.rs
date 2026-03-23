//! Background recovery archival task.
//!
//! After a `rec` event resolves divergence, adversary events are archived
//! asynchronously by this background task. Each cycle processes one recovery
//! record, performing a single state transition or archiving one page of
//! adversary events.
//!
//! The task is generic over the pool type so both the kels service and
//! kels-registry can reuse it.

use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use tracing::{debug, error, info, warn};
use verifiable_storage::{Chained, Delete, Order, Query, QueryExecutor, TransactionExecutor};

use crate::{EventSignature, KelsError, KeyEvent, RecoveryRecord, RecoveryState};

/// Table name configuration for the recovery task.
#[derive(Clone)]
pub struct RecoveryConfig {
    pub events_table: &'static str,
    pub signatures_table: &'static str,
    pub recovery_table: &'static str,
    pub archived_events_table: &'static str,
    pub archived_signatures_table: &'static str,
}

/// Run the recovery archival loop without cache invalidation. Call via `tokio::spawn`.
///
/// Polls every `interval` for non-terminal recovery records and processes
/// one operation per record per cycle.
pub async fn recovery_archival_loop<P: QueryExecutor + Clone + 'static>(
    pool: P,
    config: RecoveryConfig,
    interval: Duration,
) {
    loop {
        tokio::time::sleep(interval).await;

        if let Err(e) = process_all_recoveries(&pool, &config, &|_: &str| async {}).await {
            error!("Recovery archival error: {}", e);
        }
    }
}

/// Run the recovery archival loop with cache invalidation. Call via `tokio::spawn`.
///
/// Same as `recovery_archival_loop` but invalidates the KEL cache during
/// the cleanup phase after adversary archival completes.
#[cfg(feature = "redis")]
pub async fn recovery_archival_loop_with_cache<P: QueryExecutor + Clone + 'static>(
    pool: P,
    config: RecoveryConfig,
    cache: crate::ServerKelCache,
    interval: Duration,
) {
    loop {
        tokio::time::sleep(interval).await;

        let invalidate = |prefix: &str| {
            let cache = cache.clone();
            let prefix = prefix.to_string();
            async move {
                if let Err(e) = cache.invalidate(&prefix).await {
                    warn!(
                        kel_prefix = %prefix,
                        "Recovery cache invalidation failed: {}",
                        e
                    );
                }
            }
        };

        if let Err(e) = process_all_recoveries(&pool, &config, &invalidate).await {
            error!("Recovery archival error: {}", e);
        }
    }
}

/// Process all non-terminal recovery records, one operation each.
async fn process_all_recoveries<P, F, Fut>(
    pool: &P,
    config: &RecoveryConfig,
    on_cleanup: &F,
) -> Result<(), KelsError>
where
    P: QueryExecutor,
    F: Fn(&str) -> Fut + Send + Sync,
    Fut: std::future::Future<Output = ()> + Send,
{
    let records = query_active_recoveries(pool, config).await?;

    for record in records {
        if let Err(e) = process_one_recovery(pool, config, on_cleanup, &record).await {
            warn!(
                kel_prefix = %record.kel_prefix,
                state = %record.state,
                "Recovery processing error: {}",
                e
            );
        }
    }

    Ok(())
}

/// Query all non-terminal recovery records (latest version per kel_prefix).
async fn query_active_recoveries<P: QueryExecutor>(
    pool: &P,
    config: &RecoveryConfig,
) -> Result<Vec<RecoveryRecord>, KelsError> {
    let query = Query::<RecoveryRecord>::for_table(config.recovery_table)
        .ne("state", "recovered")
        .order_by("kel_prefix", Order::Asc)
        .order_by("version", Order::Desc);
    let all_records: Vec<RecoveryRecord> = pool.fetch(query).await?;

    // Deduplicate: keep only the latest version per kel_prefix
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for record in all_records {
        if seen.insert(record.kel_prefix.clone()) {
            result.push(record);
        }
    }

    Ok(result)
}

/// Process a single recovery record: one state transition or one page of archival.
async fn process_one_recovery<P, F, Fut>(
    pool: &P,
    config: &RecoveryConfig,
    on_cleanup: &F,
    record: &RecoveryRecord,
) -> Result<(), KelsError>
where
    P: QueryExecutor,
    F: Fn(&str) -> Fut + Send + Sync,
    Fut: std::future::Future<Output = ()> + Send,
{
    match record.state {
        RecoveryState::Pending => transition_to_archiving(pool, config, record).await,
        RecoveryState::Archiving => archive_one_page(pool, config, record).await,
        RecoveryState::Cleanup => {
            on_cleanup(&record.kel_prefix).await;
            transition_to_recovered(pool, config, record).await
        }
        RecoveryState::Recovered => Ok(()), // terminal — should not reach here
    }
}

/// Pending → Archiving: discover the adversary tip and begin archival.
async fn transition_to_archiving<P: QueryExecutor>(
    pool: &P,
    config: &RecoveryConfig,
    record: &RecoveryRecord,
) -> Result<(), KelsError> {
    let mut tx = pool.begin_transaction().await?;
    tx.acquire_advisory_lock(&record.kel_prefix).await?;

    // Re-read the record under lock to avoid races
    let current = read_latest_recovery(&mut tx, config, &record.kel_prefix).await?;
    if current.state != RecoveryState::Pending {
        tx.rollback().await?;
        return Ok(());
    }

    // Find the adversary tip. If there are no adversary events (proactive
    // recovery on a non-divergent KEL), skip directly to cleanup.
    let mut next = current;
    match find_adversary_tip(&mut tx, config, &next).await {
        Ok(adversary_tip_said) => {
            next.state = RecoveryState::Archiving;
            next.adversary_tip_said = Some(adversary_tip_said);
            debug!(kel_prefix = %next.kel_prefix, "Recovery: pending → archiving");
        }
        Err(_) => {
            next.state = RecoveryState::Cleanup;
            debug!(
                kel_prefix = %next.kel_prefix,
                "Recovery: pending → cleanup (no adversary events)"
            );
        }
    }
    next.increment()
        .map_err(|e| KelsError::StorageError(e.to_string()))?;
    tx.insert_with_table(&next, config.recovery_table).await?;
    tx.commit().await?;

    Ok(())
}

/// Archive one page of adversary events (backward from tail).
///
/// Batch-fetches events by serial range and walks the adversary chain via
/// `previous` pointers in memory. At `diverged_at` serial there may be both
/// an adversary event and the owner's rec/rot — the chain walk deterministically
/// selects only the adversary event since the owner's event is never reachable
/// via the adversary's `previous` chain.
async fn archive_one_page<P: QueryExecutor>(
    pool: &P,
    config: &RecoveryConfig,
    record: &RecoveryRecord,
) -> Result<(), KelsError> {
    let mut tx = pool.begin_transaction().await?;
    tx.acquire_advisory_lock(&record.kel_prefix).await?;

    // Re-read under lock
    let current = read_latest_recovery(&mut tx, config, &record.kel_prefix).await?;
    if current.state != RecoveryState::Archiving {
        tx.rollback().await?;
        return Ok(());
    }

    let Some(tip_said) = &current.adversary_tip_said else {
        // No tip — shouldn't happen in archiving state, transition to cleanup
        let mut next = current;
        next.state = RecoveryState::Cleanup;
        next.increment()
            .map_err(|e| KelsError::StorageError(e.to_string()))?;
        tx.insert_with_table(&next, config.recovery_table).await?;
        tx.commit().await?;
        return Ok(());
    };

    // Fetch the tip event to determine its serial for the batch window
    let tip_query = Query::<KeyEvent>::for_table(config.events_table)
        .eq("prefix", &current.kel_prefix)
        .eq("said", tip_said)
        .limit(1);
    let tip_events: Vec<KeyEvent> = tx.fetch(tip_query).await?;
    let Some(tip_event) = tip_events.into_iter().next() else {
        // Tip already archived or missing — transition to cleanup
        let mut next = current;
        next.state = RecoveryState::Cleanup;
        next.adversary_tip_said = None;
        next.increment()
            .map_err(|e| KelsError::StorageError(e.to_string()))?;
        tx.insert_with_table(&next, config.recovery_table).await?;
        tx.commit().await?;
        return Ok(());
    };

    let page_size = crate::page_size() as u64;

    // Compute the serial window: one page backward from tip, clamped to diverged_at.
    let low_serial = tip_event
        .serial
        .saturating_sub(page_size - 1)
        .max(current.diverged_at);

    // Batch fetch all events in the serial window. At diverged_at there may be
    // 2 events (adversary + owner's rec/rot), so fetch extra room.
    let batch_query = Query::<KeyEvent>::for_table(config.events_table)
        .eq("prefix", &current.kel_prefix)
        .gte("serial", low_serial)
        .lte("serial", tip_event.serial)
        .limit((page_size + 1) * 2);
    let batch: Vec<KeyEvent> = tx.fetch(batch_query).await?;

    // Index by SAID for O(1) chain walking
    let by_said: HashMap<&str, &KeyEvent> = batch.iter().map(|e| (e.said.as_str(), e)).collect();

    // Walk backward from tip through `previous` pointers to identify the
    // adversary chain. This naturally excludes the owner's rec/rot at
    // diverged_at since those are on a different `previous` chain.
    let mut events_to_archive: Vec<KeyEvent> = Vec::new();
    let mut walk_said: &str = tip_said;

    loop {
        let Some(event) = by_said.get(walk_said) else {
            break; // Not in this batch — below serial window or already archived
        };

        if event.serial < current.diverged_at {
            break; // Reached shared chain — stop
        }

        events_to_archive.push((*event).clone());

        match &event.previous {
            Some(prev) => walk_said = prev,
            None => break,
        }
    }

    if events_to_archive.is_empty() {
        // Nothing left to archive — transition to cleanup
        let mut next = current;
        next.state = RecoveryState::Cleanup;
        next.increment()
            .map_err(|e| KelsError::StorageError(e.to_string()))?;
        tx.insert_with_table(&next, config.recovery_table).await?;
        tx.commit().await?;
        debug!(
            kel_prefix = %next.kel_prefix,
            "Recovery: archiving → cleanup (no events remaining)"
        );
        return Ok(());
    }

    // Archive: move events + signatures to archive tables
    let event_saids: Vec<String> = events_to_archive.iter().map(|e| e.said.clone()).collect();

    // Fetch signatures for these events
    let sig_query = Query::<EventSignature>::for_table(config.signatures_table)
        .r#in("event_said", event_saids.clone());
    let signatures: Vec<EventSignature> = tx.fetch(sig_query).await?;

    // INSERT INTO archive tables
    for event in &events_to_archive {
        tx.insert_with_table(event, config.archived_events_table)
            .await?;
    }
    for sig in &signatures {
        tx.insert_with_table(sig, config.archived_signatures_table)
            .await?;
    }

    // DELETE from live tables
    let sig_saids: Vec<String> = signatures.iter().map(|s| s.said.clone()).collect();
    if !sig_saids.is_empty() {
        let sig_delete =
            Delete::<EventSignature>::for_table(config.signatures_table).r#in("said", sig_saids);
        tx.delete(sig_delete).await?;
    }
    let event_delete = Delete::<KeyEvent>::for_table(config.events_table).r#in("said", event_saids);
    tx.delete(event_delete).await?;

    // The oldest archived event (last in our backward walk) determines the new tip.
    // Its `previous` is the next event to process on the next cycle.
    let oldest = &events_to_archive[events_to_archive.len() - 1];
    let new_tip = oldest.previous.clone();
    let reached_root = oldest.serial == current.diverged_at || new_tip.is_none();

    // Update recovery record
    let mut next = current.clone();
    next.cursor_serial = oldest.serial;

    if reached_root {
        // This branch is fully archived. Check if there are remaining adversary
        // events at diverged_at. Identify owner events by tracing the rec_previous
        // chain — any event at diverged_at NOT on the owner's chain is adversary.
        if current.owner_first_serial <= current.diverged_at {
            let diverged_query = Query::<KeyEvent>::for_table(config.events_table)
                .eq("prefix", &current.kel_prefix)
                .eq("serial", current.diverged_at)
                .limit(4);
            let remaining: Vec<KeyEvent> = tx.fetch(diverged_query).await?;

            // Build the set of owner event SAIDs at diverged_at by walking
            // backward from rec_previous, plus the rec and rot-after-rec.
            let mut owner_saids: HashSet<String> = HashSet::new();
            let mut walk = Some(current.rec_previous.clone());
            for _ in 0..crate::page_size() {
                let Some(said) = walk.take() else { break };
                let q = Query::<KeyEvent>::for_table(config.events_table)
                    .eq("prefix", &current.kel_prefix)
                    .eq("said", &said)
                    .limit(1);
                let events: Vec<KeyEvent> = tx.fetch(q).await?;
                let Some(event) = events.into_iter().next() else {
                    break;
                };
                if event.serial < current.diverged_at {
                    break;
                }
                owner_saids.insert(event.said.clone());
                walk = event.previous;
            }

            // Include the rec (and rot-after-rec) as owner events — they must
            // never be archived. The rec_previous walk above only traces events
            // BEFORE rec; the rec itself must be added explicitly.
            let rec_query = Query::<KeyEvent>::for_table(config.events_table)
                .eq("prefix", &current.kel_prefix)
                .eq("serial", current.recovery_serial)
                .limit(3);
            let rec_events: Vec<KeyEvent> = tx.fetch(rec_query).await?;
            for e in &rec_events {
                if e.is_recover() {
                    owner_saids.insert(e.said.clone());
                }
            }
            let rot_query = Query::<KeyEvent>::for_table(config.events_table)
                .eq("prefix", &current.kel_prefix)
                .eq("serial", current.recovery_serial + 1)
                .limit(2);
            let rot_events: Vec<KeyEvent> = tx.fetch(rot_query).await?;
            for e in &rot_events {
                if e.is_rotation()
                    && e.previous
                        .as_deref()
                        .is_some_and(|p| rec_events.iter().any(|r| r.is_recover() && r.said == p))
                {
                    owner_saids.insert(e.said.clone());
                }
            }

            let other_adversary = remaining
                .into_iter()
                .find(|e| !owner_saids.contains(&e.said));

            if let Some(other) = other_adversary {
                next.adversary_tip_said = Some(other.said);
            } else {
                next.state = RecoveryState::Cleanup;
                next.adversary_tip_said = None;
            }
        } else {
            next.state = RecoveryState::Cleanup;
            next.adversary_tip_said = None;
        }
    } else {
        next.adversary_tip_said = new_tip;
    }

    next.increment()
        .map_err(|e| KelsError::StorageError(e.to_string()))?;
    tx.insert_with_table(&next, config.recovery_table).await?;
    tx.commit().await?;

    debug!(
        kel_prefix = %next.kel_prefix,
        archived = events_to_archive.len(),
        state = %next.state,
        "Recovery: archived page"
    );
    Ok(())
}

/// Cleanup → Recovered: terminal transition.
async fn transition_to_recovered<P: QueryExecutor>(
    pool: &P,
    config: &RecoveryConfig,
    record: &RecoveryRecord,
) -> Result<(), KelsError> {
    let mut tx = pool.begin_transaction().await?;
    tx.acquire_advisory_lock(&record.kel_prefix).await?;

    let current = read_latest_recovery(&mut tx, config, &record.kel_prefix).await?;
    if current.state != RecoveryState::Cleanup {
        tx.rollback().await?;
        return Ok(());
    }

    let mut next = current;
    next.state = RecoveryState::Recovered;
    next.increment()
        .map_err(|e| KelsError::StorageError(e.to_string()))?;
    tx.insert_with_table(&next, config.recovery_table).await?;
    tx.commit().await?;

    info!(
        kel_prefix = %next.kel_prefix,
        "Recovery complete"
    );
    Ok(())
}

// ==================== Helpers ====================

/// Read the latest recovery record for a kel_prefix within a transaction.
async fn read_latest_recovery<T: TransactionExecutor>(
    tx: &mut T,
    config: &RecoveryConfig,
    kel_prefix: &str,
) -> Result<RecoveryRecord, KelsError> {
    let query = Query::<RecoveryRecord>::for_table(config.recovery_table)
        .eq("kel_prefix", kel_prefix)
        .order_by("version", Order::Desc)
        .limit(1);
    let records: Vec<RecoveryRecord> = tx.fetch(query).await?;
    records.into_iter().next().ok_or_else(|| {
        KelsError::StorageError(format!(
            "Recovery record not found for kel_prefix: {}",
            kel_prefix
        ))
    })
}

/// Find the adversary chain tip (leaf event) for a recovery record.
///
/// Two cases based on `owner_first_serial`:
/// - `<= diverged_at`: all events from diverged_at are adversary. Find the
///   highest-serial event that isn't the owner's rec/rot.
/// - `> diverged_at`: use `rec_previous` to identify the adversary at diverged_at,
///   then walk forward to find the tip.
async fn find_adversary_tip<T: TransactionExecutor>(
    tx: &mut T,
    config: &RecoveryConfig,
    record: &RecoveryRecord,
) -> Result<String, KelsError> {
    if record.owner_first_serial <= record.diverged_at {
        // All events from diverged_at onward (except owner's rec+rot) are adversary.
        // Find the highest-serial adversary event.
        find_adversary_tip_all_adversary(tx, config, record).await
    } else {
        // Owner has events at diverged_at. Identify the adversary event and walk forward.
        find_adversary_tip_with_owner_events(tx, config, record).await
    }
}

/// Case: owner_first_serial <= diverged_at. Find the highest-serial adversary
/// event by identifying owner events via the rec_previous chain.
async fn find_adversary_tip_all_adversary<T: TransactionExecutor>(
    tx: &mut T,
    config: &RecoveryConfig,
    record: &RecoveryRecord,
) -> Result<String, KelsError> {
    // Build the set of owner event SAIDs by walking backward from rec_previous.
    // This traces the owner's chain from just before the rec back to (and including)
    // events at diverged_at.
    let mut owner_saids: HashSet<String> = HashSet::new();
    let mut walk = Some(record.rec_previous.clone());
    for _ in 0..crate::page_size() {
        let Some(said) = walk.take() else { break };
        let q = Query::<KeyEvent>::for_table(config.events_table)
            .eq("prefix", &record.kel_prefix)
            .eq("said", &said)
            .limit(1);
        let events: Vec<KeyEvent> = tx.fetch(q).await?;
        let Some(event) = events.into_iter().next() else {
            break;
        };
        if event.serial < record.diverged_at {
            break;
        }
        owner_saids.insert(event.said.clone());
        walk = event.previous;
    }

    // Also include the rec and rot-after-rec as owner events.
    // At recovery_serial there may be up to 3 events: 2 divergent + rec.
    let rec_query = Query::<KeyEvent>::for_table(config.events_table)
        .eq("prefix", &record.kel_prefix)
        .eq("serial", record.recovery_serial)
        .limit(3);
    let rec_events: Vec<KeyEvent> = tx.fetch(rec_query).await?;
    for e in &rec_events {
        if e.is_recover() {
            owner_saids.insert(e.said.clone());
        }
    }
    let rot_query = Query::<KeyEvent>::for_table(config.events_table)
        .eq("prefix", &record.kel_prefix)
        .eq("serial", record.recovery_serial + 1)
        .limit(2);
    let rot_events: Vec<KeyEvent> = tx.fetch(rot_query).await?;
    for e in &rot_events {
        if e.is_rotation()
            && e.previous
                .as_deref()
                .is_some_and(|p| rec_events.iter().any(|r| r.is_recover() && r.said == p))
        {
            owner_saids.insert(e.said.clone());
        }
    }

    // The adversary tip is the highest-serial event NOT in the owner set.
    // Owner events are bounded, so fetch a small window from the top.
    let query = Query::<KeyEvent>::for_table(config.events_table)
        .eq("prefix", &record.kel_prefix)
        .gte("serial", record.diverged_at)
        .order_by("serial", Order::Desc)
        .order_by("said", Order::Asc)
        .limit((owner_saids.len() as u64 + 1).max(3));
    let events: Vec<KeyEvent> = tx.fetch(query).await?;

    for event in &events {
        if !owner_saids.contains(&event.said) {
            return Ok(event.said.clone());
        }
    }

    Err(KelsError::StorageError(
        "No adversary events found during tip discovery".to_string(),
    ))
}

/// Case: owner has events at diverged_at. Identify adversary at divergence
/// and walk forward to find the tip.
///
/// Uses the same logic as merge.rs `find_adversary_event`:
/// 1. Direct match: if `rec_previous` matches one divergent event's SAID,
///    the other is the adversary.
/// 2. N case: if the owner extended beyond diverged_at, the divergent event
///    WITH a child at the next serial is the owner's; the one WITHOUT is
///    the adversary's (adversary branch is always exactly 1 event at
///    the divergence serial in this case).
async fn find_adversary_tip_with_owner_events<T: TransactionExecutor>(
    tx: &mut T,
    config: &RecoveryConfig,
    record: &RecoveryRecord,
) -> Result<String, KelsError> {
    // Fetch events at diverged_at AND diverged_at+1 to check child relationships
    let query = Query::<KeyEvent>::for_table(config.events_table)
        .eq("prefix", &record.kel_prefix)
        .gte("serial", record.diverged_at)
        .lte("serial", record.diverged_at + 1)
        .limit(4); // 2 at diverged_at + up to 2 at diverged_at+1
    let events: Vec<KeyEvent> = tx.fetch(query).await?;

    let divergent: Vec<&KeyEvent> = events
        .iter()
        .filter(|e| e.serial == record.diverged_at)
        .collect();

    if divergent.len() != 2 {
        return Err(KelsError::StorageError(format!(
            "Expected 2 events at divergence serial {}, found {}",
            record.diverged_at,
            divergent.len()
        )));
    }

    // Direct match: rec_previous points to one of the divergent events
    if record.rec_previous == divergent[0].said {
        return walk_chain_to_tip(tx, config, &divergent[1].said, &record.kel_prefix).await;
    }
    if record.rec_previous == divergent[1].said {
        return walk_chain_to_tip(tx, config, &divergent[0].said, &record.kel_prefix).await;
    }

    // N case: rec extends a longer chain. The divergent event WITH a child
    // at the next serial is the owner's; the one WITHOUT is the adversary's.
    let d0_has_child = events.iter().any(|e| {
        e.serial == record.diverged_at + 1 && e.previous.as_deref() == Some(&divergent[0].said)
    });
    let d1_has_child = events.iter().any(|e| {
        e.serial == record.diverged_at + 1 && e.previous.as_deref() == Some(&divergent[1].said)
    });

    match (d0_has_child, d1_has_child) {
        // d0 has child (owner's), d1 is adversary (no chain)
        (true, false) => Ok(divergent[1].said.clone()),
        // d1 has child (owner's), d0 is adversary (no chain)
        (false, true) => Ok(divergent[0].said.clone()),
        _ => Err(KelsError::StorageError(
            "Cannot identify adversary event at divergence point".to_string(),
        )),
    }
}

/// Walk forward from a starting event to find the chain tip (leaf node).
async fn walk_chain_to_tip<T: TransactionExecutor>(
    tx: &mut T,
    config: &RecoveryConfig,
    start_said: &str,
    prefix: &str,
) -> Result<String, KelsError> {
    let max_steps = crate::max_pages() * crate::page_size();
    let mut current_said = start_said.to_string();

    for _ in 0..max_steps {
        // Find any event whose `previous` is current_said
        let query = Query::<KeyEvent>::for_table(config.events_table)
            .eq("prefix", prefix)
            .eq("previous", &current_said)
            .limit(2); // expect 0 or 1, 2 would indicate corruption
        let children: Vec<KeyEvent> = tx.fetch(query).await?;

        // Filter to children on the adversary branch (not the owner's rec)
        let adversary_children: Vec<&KeyEvent> =
            children.iter().filter(|e| !e.is_recover()).collect();

        match adversary_children.len() {
            0 => return Ok(current_said), // leaf found — this is the tip
            1 => current_said = adversary_children[0].said.clone(),
            _ => {
                return Err(KelsError::StorageError(
                    "Adversary chain has unexpected branch".to_string(),
                ));
            }
        }
    }

    Err(KelsError::StorageError(
        "Forward chain walk exceeded iteration limit".to_string(),
    ))
}
