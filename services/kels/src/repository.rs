//! PostgreSQL Repository for KELS

use async_trait::async_trait;
use kels::{
    EventSignature, KelsAuditRecord, KeyEvent, PrefixListResponse, PrefixState, SignedKeyEvent,
};
use libkels_derive::SignedEvents;
use std::collections::{HashMap, HashSet};
use verifiable_storage::{
    ColumnQuery, ScalarSubquery, SelfAddressed, StorageError, TransactionExecutor, Value,
};
use verifiable_storage_postgres::{Delete, Filter, Order, PgPool, Query, QueryExecutor, Stored};

#[derive(Stored, SignedEvents)]
#[stored(item_type = KeyEvent, table = "kels_key_events", version_field = "serial")]
#[signed_events(signatures_table = "kels_key_event_signatures")]
pub struct KeyEventRepository {
    pub pool: PgPool,
}

#[derive(Stored)]
#[stored(item_type = KelsAuditRecord, table = "kels_audit_records", chained = false)]
pub struct AuditRecordRepository {
    pub pool: PgPool,
}

#[derive(Stored)]
#[stored(migrations = "migrations")]
pub struct KelsRepository {
    pub key_events: KeyEventRepository,
    pub audit_records: AuditRecordRepository,
}

impl KeyEventRepository {
    /// Check if an event with the given SAID exists (efficient SELECT EXISTS query).
    pub async fn event_exists_by_said(&self, said: &str) -> Result<bool, StorageError> {
        let query = Query::<KeyEvent>::for_table(Self::TABLE_NAME).eq("said", said);
        self.pool.exists(query).await
    }

    /// Get signed history since a given SAID (exclusive — the since event itself is not returned).
    ///
    /// Uses a scalar subquery to find the serial of the since event, then fetches
    /// events with `serial >= that serial`, filtering out the since event itself.
    /// Returns `(events, has_more)` using the limit+1 pop pattern.
    /// Events are ordered by `serial ASC, said ASC` for deterministic pagination.
    pub async fn get_signed_history_since(
        &self,
        prefix: &str,
        since_said: &str,
        limit: u64,
    ) -> Result<(Vec<SignedKeyEvent>, bool), StorageError> {
        let subquery = ScalarSubquery::new(
            Self::TABLE_NAME,
            "serial",
            vec![Filter::Eq(
                "said".to_string(),
                Value::String(since_said.to_string()),
            )],
        );

        // Fetch limit + 2: one extra for the since event we'll filter out, one extra for has_more detection
        // Clamp to prevent i64 overflow when cast for PostgreSQL LIMIT
        let clamped_limit = limit.min(i64::MAX as u64 - 2);
        let query = Query::<KeyEvent>::for_table(Self::TABLE_NAME)
            .eq("prefix", prefix)
            .gte_scalar_subquery("serial", subquery)
            .order_by("serial", Order::Asc)
            .order_by("said", Order::Asc)
            .limit(clamped_limit + 2);
        let mut events: Vec<KeyEvent> = self.pool.fetch(query).await?;

        // Filter out the since event itself (we want events *after* it,
        // but we need >= its serial to include divergent events at the same serial)
        events.retain(|e| e.said != since_said);

        let has_more = events.len() > clamped_limit as usize;
        if has_more {
            events.truncate(limit as usize);
        }

        if events.is_empty() {
            return Ok((vec![], false));
        }

        let saids: Vec<String> = events.iter().map(|e| e.said.clone()).collect();
        let signatures = self.get_signatures_by_saids(&saids).await?;

        let mut signed_events = Vec::with_capacity(events.len());
        for event in events {
            let sigs = signatures.get(&event.said).ok_or_else(|| {
                StorageError::StorageError(format!("No signatures found for event {}", event.said))
            })?;
            let sig_pairs: Vec<(String, String)> = sigs
                .iter()
                .map(|s| (s.public_key.clone(), s.signature.clone()))
                .collect();
            signed_events.push(SignedKeyEvent::from_signatures(event, sig_pairs));
        }

        Ok((signed_events, has_more))
    }

    /// List unique prefixes with their effective SAIDs for bootstrap sync and anti-entropy.
    /// Returns prefixes in sorted order with cursor-based pagination.
    ///
    /// For non-divergent KELs, the SAID is the tip event's SAID.
    /// For divergent KELs (frozen due to conflicting events), the SAID is a Blake3 hash
    /// of all sorted tip SAIDs — ensuring deterministic comparison between nodes that
    /// have the same divergent branches. See [`kels::compute_effective_said`] for details.
    pub async fn list_prefixes(
        &self,
        since: Option<&str>,
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
            query = query.filter(Filter::Gt(
                "prefix".to_string(),
                Value::String(cursor.to_string()),
            ));
        }

        let events: Vec<KeyEvent> = self.pool.fetch(query).await?;

        let mut prefix_states: Vec<PrefixState> = events
            .into_iter()
            .map(|e| PrefixState {
                prefix: e.prefix,
                said: e.said,
            })
            .collect();

        // Check if there are more results
        let next_cursor = if prefix_states.len() > limit {
            prefix_states.pop();
            prefix_states.last().map(|s| s.prefix.clone())
        } else {
            None
        };

        // For divergent prefixes, replace the single tip SAID with a deterministic
        // composite hash of all sorted tip SAIDs.
        for state in &mut prefix_states {
            if self.is_divergent(&state.prefix).await?
                && let Some(effective) = self.compute_prefix_effective_said(&state.prefix).await?
            {
                state.said = effective;
            }
        }

        Ok(PrefixListResponse {
            prefixes: prefix_states,
            next_cursor,
        })
    }

    /// Compute the effective SAID for a prefix by finding all tip events.
    ///
    /// Fetches all events for the prefix, identifies tips (events not referenced
    /// as `previous` by any other event), and delegates to [`kels::compute_effective_tail_said`].
    pub async fn compute_prefix_effective_said(
        &self,
        prefix: &str,
    ) -> Result<Option<String>, StorageError> {
        let query = Query::<KeyEvent>::for_table(Self::TABLE_NAME)
            .eq("prefix", prefix)
            .order_by("said", Order::Asc);
        let events: Vec<KeyEvent> = self.pool.fetch(query).await?;

        let pairs: Vec<(&str, Option<&str>)> = events
            .iter()
            .map(|e| (e.said.as_str(), e.previous.as_deref()))
            .collect();

        Ok(kels::compute_effective_tail_said(&pairs))
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

    /// Begin transaction with advisory lock on prefix. Serializes all operations on this prefix.
    pub async fn begin_locked_transaction(
        &self,
        prefix: &str,
    ) -> Result<KelTransaction, StorageError> {
        let mut tx = self.pool.begin_transaction().await?;
        tx.acquire_advisory_lock(prefix).await?;
        Ok(KelTransaction {
            tx,
            prefix: prefix.to_string(),
        })
    }
}

/// Transaction with advisory lock. Lock held until commit/rollback/drop.
pub struct KelTransaction {
    tx: <PgPool as QueryExecutor>::Transaction,
    prefix: String,
}

impl KelTransaction {
    const EVENTS_TABLE: &'static str = KeyEventRepository::TABLE_NAME;
    const SIGNATURES_TABLE: &'static str = KeyEventRepository::SIGNATURES_TABLE_NAME;
    const AUDIT_TABLE: &'static str = AuditRecordRepository::TABLE_NAME;

    /// Get a paginated page of signed events for this prefix starting from `since_serial`.
    ///
    /// Returns `(events, has_more)` using the limit+1 pop pattern.
    /// Events are ordered by `serial ASC, said ASC` for deterministic pagination.
    pub async fn get_signed_history_since(
        &mut self,
        since_serial: u64,
        limit: u64,
    ) -> Result<(Vec<SignedKeyEvent>, bool), StorageError> {
        // Clamp to prevent i64 overflow when cast for PostgreSQL LIMIT
        let clamped_limit = limit.min(i64::MAX as u64 - 1);
        let query = Query::<KeyEvent>::for_table(Self::EVENTS_TABLE)
            .eq("prefix", &self.prefix)
            .gte("serial", since_serial)
            .order_by("serial", Order::Asc)
            .order_by("said", Order::Asc)
            .limit(clamped_limit + 1);
        let mut events: Vec<KeyEvent> = self.tx.fetch(query).await?;

        let has_more = events.len() > clamped_limit as usize;
        if has_more {
            events.pop();
        }

        if events.is_empty() {
            return Ok((vec![], false));
        }

        let saids: Vec<String> = events.iter().map(|e| e.said.clone()).collect();
        let query =
            Query::<EventSignature>::for_table(Self::SIGNATURES_TABLE).r#in("event_said", saids);
        let signatures: Vec<EventSignature> = self.tx.fetch(query).await?;
        let mut sig_map: HashMap<String, Vec<EventSignature>> = HashMap::new();
        for sig in signatures {
            sig_map.entry(sig.event_said.clone()).or_default().push(sig);
        }
        let mut result = Vec::with_capacity(events.len());
        for event in events {
            let sigs = sig_map.get(&event.said).ok_or_else(|| {
                StorageError::StorageError(format!("No signatures found for event {}", event.said))
            })?;
            let sig_pairs: Vec<(String, String)> = sigs
                .iter()
                .map(|s| (s.public_key.clone(), s.signature.clone()))
                .collect();
            result.push(SignedKeyEvent::from_signatures(event, sig_pairs));
        }

        Ok((result, has_more))
    }

    /// Check which of the given SAIDs already exist in the database.
    /// Returns the subset that exist. Bounded by the input size.
    pub async fn existing_saids(
        &mut self,
        saids: &[String],
    ) -> Result<HashSet<String>, StorageError> {
        if saids.is_empty() {
            return Ok(HashSet::new());
        }
        let query = Query::<KeyEvent>::for_table(Self::EVENTS_TABLE)
            .eq("prefix", &self.prefix)
            .r#in("said", saids.to_vec());
        let events: Vec<KeyEvent> = self.tx.fetch(query).await?;
        Ok(events.into_iter().map(|e| e.said).collect())
    }

    pub async fn delete_events_by_said(&mut self, saids: Vec<String>) -> Result<u64, StorageError> {
        if saids.is_empty() {
            return Ok(0);
        }
        let delete = Delete::<KeyEvent>::for_table(Self::EVENTS_TABLE).r#in("said", saids);
        self.tx.delete(delete).await
    }

    pub async fn insert_signed_event(
        &mut self,
        signed_event: &SignedKeyEvent,
    ) -> Result<(), StorageError> {
        self.tx
            .insert_with_table(&signed_event.event, Self::EVENTS_TABLE)
            .await?;
        for sig in signed_event.event_signatures() {
            let mut event_sig: EventSignature = sig;
            event_sig.derive_said()?;
            self.tx
                .insert_with_table(&event_sig, Self::SIGNATURES_TABLE)
                .await?;
        }

        Ok(())
    }

    pub async fn insert_audit_record(
        &mut self,
        record: &KelsAuditRecord,
    ) -> Result<(), StorageError> {
        self.tx.insert_with_table(record, Self::AUDIT_TABLE).await?;
        Ok(())
    }

    /// Load a page of signed events by offset (for PageLoader impl).
    pub async fn load(
        &mut self,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<SignedKeyEvent>, bool), StorageError> {
        let clamped_limit = limit.min(i64::MAX as u64 - 1);
        let query = Query::<KeyEvent>::for_table(Self::EVENTS_TABLE)
            .eq("prefix", &self.prefix)
            .order_by("serial", Order::Asc)
            .order_by("said", Order::Asc)
            .limit(clamped_limit + 1)
            .offset(offset);
        let mut events: Vec<KeyEvent> = self.tx.fetch(query).await?;

        let has_more = events.len() > clamped_limit as usize;
        if has_more {
            events.pop();
        }

        if events.is_empty() {
            return Ok((vec![], false));
        }

        let saids: Vec<String> = events.iter().map(|e| e.said.clone()).collect();
        let query =
            Query::<EventSignature>::for_table(Self::SIGNATURES_TABLE).r#in("event_said", saids);
        let signatures: Vec<EventSignature> = self.tx.fetch(query).await?;
        let mut sig_map: HashMap<String, Vec<EventSignature>> = HashMap::new();
        for sig in signatures {
            sig_map.entry(sig.event_said.clone()).or_default().push(sig);
        }
        let mut result = Vec::with_capacity(events.len());
        for event in events {
            let sigs = sig_map.get(&event.said).ok_or_else(|| {
                StorageError::StorageError(format!("No signatures found for event {}", event.said))
            })?;
            let sig_pairs: Vec<(String, String)> = sigs
                .iter()
                .map(|s| (s.public_key.clone(), s.signature.clone()))
                .collect();
            result.push(SignedKeyEvent::from_signatures(event, sig_pairs));
        }

        Ok((result, has_more))
    }

    pub async fn commit(self) -> Result<(), StorageError> {
        self.tx.commit().await
    }
    pub async fn rollback(self) -> Result<(), StorageError> {
        self.tx.rollback().await
    }
}

#[async_trait]
impl kels::PageLoader for KelTransaction {
    async fn load_page(
        &mut self,
        _prefix: &str,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<SignedKeyEvent>, bool), kels::KelsError> {
        self.load(limit, offset)
            .await
            .map_err(|e| kels::KelsError::StorageError(e.to_string()))
    }
}

impl AuditRecordRepository {
    pub async fn get_by_kel_prefix(
        &self,
        kel_prefix: &str,
    ) -> Result<Vec<KelsAuditRecord>, StorageError> {
        let query = Query::<KelsAuditRecord>::new()
            .eq("kel_prefix", kel_prefix)
            .order_by("recorded_at", Order::Asc);
        self.pool.fetch(query).await
    }
}
