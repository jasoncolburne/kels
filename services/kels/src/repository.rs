//! PostgreSQL Repository for KELS

use std::collections::{HashMap, HashSet};

use verifiable_storage::{ColumnQuery, StorageError, Value};
use verifiable_storage_postgres::{Filter, Order, PgPool, Query, QueryExecutor, Stored};

use kels_core::{
    KelRecoveryEvent, KeyEvent, PrefixListResponse, PrefixState, RecoveryRecord, SignedKeyEvent,
};
use kels_derive::SignedEvents;

#[derive(Stored, SignedEvents)]
#[stored(item_type = KeyEvent, table = "kels_key_events", version_field = "serial")]
#[signed_events(
    signatures_table = "kels_key_event_signatures",
    recovery_table = "kels_recovery",
    archived_events_table = "kels_archived_events",
    archived_signatures_table = "kels_archived_event_signatures",
    recovery_events_table = "kels_recovery_events"
)]
pub struct KeyEventRepository {
    pub pool: PgPool,
}

#[derive(Stored)]
#[stored(item_type = RecoveryRecord, table = "kels_recovery", chained = false)]
pub struct RecoveryRecordRepository {
    pub pool: PgPool,
}

#[derive(Stored)]
#[stored(migrations = "migrations")]
pub struct KelsRepository {
    pub key_events: KeyEventRepository,
    pub recovery_records: RecoveryRecordRepository,
}

impl KeyEventRepository {
    /// Paginated query of archived adversary events for a prefix.
    pub async fn get_archived_events(
        &self,
        prefix: &str,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<SignedKeyEvent>, bool), kels_core::KelsError> {
        use verifiable_storage::TransactionExecutor;

        let mut tx = self.pool.begin_transaction().await?;
        let result = kels_core::load_signed_history(
            &mut tx,
            "kels_archived_events",
            "kels_archived_event_signatures",
            prefix,
            limit,
            offset,
        )
        .await?;
        tx.commit().await?;
        Ok(result)
    }

    /// Paginated query of archived events linked to a specific recovery SAID.
    pub async fn get_recovery_archived_events(
        &self,
        recovery_said: &str,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<SignedKeyEvent>, bool), kels_core::KelsError> {
        use verifiable_storage::TransactionExecutor;

        let clamped_limit = limit.min(kels_core::page_size() as u64);

        let mut tx = self.pool.begin_transaction().await?;

        // Fetch recovery_event join records for this recovery_said, paginated.
        let join_query = Query::<KelRecoveryEvent>::new()
            .eq("recovery_said", recovery_said)
            .order_by("event_said", Order::Asc)
            .limit(clamped_limit + 1)
            .offset(offset);
        let mut join_records: Vec<KelRecoveryEvent> = tx.fetch(join_query).await?;

        let has_more = join_records.len() > clamped_limit as usize;
        if has_more {
            join_records.pop();
        }

        if join_records.is_empty() {
            tx.commit().await?;
            return Ok((vec![], false));
        }

        let event_saids: Vec<String> = join_records
            .iter()
            .map(|r| r.event_said.to_string())
            .collect();

        // Fetch the archived events by their SAIDs.
        let events_query = Query::<KeyEvent>::for_table("kels_archived_events")
            .r#in("said", event_saids.clone())
            .order_by("serial", Order::Asc)
            .order_by("said", Order::Asc);
        let events: Vec<KeyEvent> = tx.fetch(events_query).await?;

        // Fetch signatures for those events.
        let sig_query =
            Query::<kels_core::EventSignature>::for_table("kels_archived_event_signatures")
                .r#in("event_said", event_saids);
        let signatures: Vec<kels_core::EventSignature> = tx.fetch(sig_query).await?;

        let mut sig_map: HashMap<String, Vec<kels_core::EventSignature>> = HashMap::new();
        for sig in signatures {
            sig_map
                .entry(sig.event_said.to_string())
                .or_default()
                .push(sig);
        }

        tx.commit().await?;

        let mut result = Vec::with_capacity(events.len());
        for event in events {
            let said_str = event.said.to_string();
            let sigs = sig_map.get(&said_str).ok_or_else(|| {
                kels_core::KelsError::StorageError(format!(
                    "No signatures found for event {}",
                    event.said
                ))
            })?;
            let sig_pairs: Vec<(String, cesr::Signature)> = sigs
                .iter()
                .map(|s| (s.label.clone(), s.signature.clone()))
                .collect();
            result.push(SignedKeyEvent::from_signatures(event, sig_pairs));
        }
        Ok((result, has_more))
    }

    /// Check if an event with the given SAID exists (efficient SELECT EXISTS query).
    pub async fn event_exists_by_said(&self, said: &str) -> Result<bool, StorageError> {
        let query = Query::<KeyEvent>::for_table(Self::TABLE_NAME).eq("said", said);
        self.pool.exists(query).await
    }

    /// List unique prefixes with their effective SAIDs for bootstrap sync and anti-entropy.
    /// Returns prefixes in sorted order with cursor-based pagination.
    ///
    /// For non-divergent KELs, the SAID is the tip event's SAID.
    /// For divergent KELs (frozen due to conflicting events), the SAID is a Blake3 hash
    /// of all sorted tip SAIDs — ensuring deterministic comparison between nodes that
    /// have the same divergent branches. See [`kels_core::compute_effective_said`] for details.
    pub async fn list_prefixes(
        &self,
        since: Option<&cesr::Digest>,
        limit: usize,
    ) -> Result<PrefixListResponse, StorageError> {
        // DISTINCT ON (prefix) with secondary sort by serial DESC ensures we
        // deterministically get the highest-serial event per prefix.
        let mut query = Query::<KeyEvent>::for_table(Self::TABLE_NAME)
            .distinct_on("prefix")
            .order_by("prefix", Order::Asc)
            .order_by("serial", Order::Desc)
            .limit(limit as u64 + 1);

        if let Some(cursor) = since {
            query = query.gt("prefix", cursor.as_ref());
        }

        let events: Vec<KeyEvent> = self.pool.fetch(query).await?;

        let mut prefix_states: Vec<PrefixState> = events
            .into_iter()
            .map(|e| PrefixState {
                prefix: e.prefix,
                said: e.said,
            })
            .collect();

        // Check if there are more results beyond the limit
        let next_cursor = if prefix_states.len() > limit {
            prefix_states.pop();
            prefix_states.last().map(|s| s.prefix)
        } else if let Some(cursor) = since {
            // Wrap around: fill remaining slots from prefixes <= cursor
            // (the beginning of the prefix space). No duplicates because
            // the first query fetched prefix > cursor.
            let remaining = limit - prefix_states.len();
            if remaining > 0 {
                let wrap_query = Query::<KeyEvent>::for_table(Self::TABLE_NAME)
                    .distinct_on("prefix")
                    .order_by("prefix", Order::Asc)
                    .order_by("serial", Order::Desc)
                    .lte("prefix", cursor.as_ref())
                    .limit(remaining as u64);
                let wrap_events: Vec<KeyEvent> = self.pool.fetch(wrap_query).await?;
                prefix_states.extend(wrap_events.into_iter().map(|e| PrefixState {
                    prefix: e.prefix,
                    said: e.said,
                }));
            }
            None
        } else {
            None
        };

        // Batch divergence check: find all prefixes in this page that have
        // duplicate serials, in a single query.
        let page_prefixes: Vec<String> =
            prefix_states.iter().map(|s| s.prefix.to_string()).collect();
        let divergent_query = ColumnQuery::new(Self::TABLE_NAME, "prefix")
            .distinct()
            .r#in("prefix", page_prefixes)
            .group_by("prefix")
            .group_by("serial")
            .having_count_gt(1);
        let divergent_prefixes: HashSet<String> = self
            .pool
            .fetch_column(divergent_query)
            .await?
            .into_iter()
            .collect();

        // For divergent prefixes, replace the single tip SAID with a deterministic
        // composite hash of all sorted tip SAIDs.
        for state in &mut prefix_states {
            if divergent_prefixes.contains(state.prefix.as_ref())
                && let Some((effective, _)) = self
                    .compute_prefix_effective_said(state.prefix.as_ref())
                    .await?
            {
                state.said = effective;
            }
        }

        Ok(PrefixListResponse {
            prefixes: prefix_states,
            next_cursor,
        })
    }

    /// Quick check: does any serial number appear more than once for this prefix?
    ///
    /// Uses `GROUP BY serial ORDER BY COUNT(*) DESC LIMIT 1` — returns true if
    /// the highest count exceeds 1.
    pub async fn is_divergent(&self, prefix: &str) -> Result<bool, StorageError> {
        let query = ColumnQuery::new(Self::TABLE_NAME, "*")
            .filter(Filter::Eq(
                "prefix".to_string(),
                Value::String(prefix.to_string()),
            ))
            .group_by("serial")
            .limit(1);
        let counts: Vec<i64> = self.pool.fetch_grouped_count(query).await?;
        Ok(counts.first().is_some_and(|&c| c > 1))
    }

    /// Find the lowest serial where divergence occurs (duplicate serial values).
    /// Returns `None` if no divergence exists.
    pub async fn find_divergence_serial(&self, prefix: &str) -> Result<Option<u64>, StorageError> {
        let query = ColumnQuery::new(Self::TABLE_NAME, "serial")
            .filter(Filter::Eq(
                "prefix".to_string(),
                Value::String(prefix.to_string()),
            ))
            .order(Order::Asc);
        let serials: Vec<i64> = self.pool.fetch_column(query).await?;

        let mut seen = HashSet::new();
        for serial in &serials {
            if !seen.insert(*serial as u64) {
                return Ok(Some(*serial as u64));
            }
        }
        Ok(None)
    }
}

impl RecoveryRecordRepository {
    pub async fn get_by_kel_prefix(
        &self,
        kel_prefix: &str,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<RecoveryRecord>, bool), StorageError> {
        let clamped_limit = limit.min(kels_core::page_size() as u64);
        let query = Query::<RecoveryRecord>::new()
            .eq("kel_prefix", kel_prefix)
            .order_by("created_at", Order::Asc)
            .limit(clamped_limit + 1)
            .offset(offset);
        let mut records: Vec<RecoveryRecord> = self.pool.fetch(query).await?;

        let has_more = records.len() > clamped_limit as usize;
        if has_more {
            records.pop();
        }

        Ok((records, has_more))
    }
}
