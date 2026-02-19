//! PostgreSQL Repository for KELS

use kels::{
    EventSignature, KelsAuditRecord, KeyEvent, PrefixListResponse, PrefixState, SignedKeyEvent,
};
use libkels_derive::SignedEvents;
use std::collections::{HashMap, HashSet};
use verifiable_storage::{ColumnQuery, SelfAddressed, StorageError, TransactionExecutor, Value};
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

    /// Get signed history since a given serial (inclusive).
    pub async fn get_signed_history_since(
        &self,
        prefix: &str,
        since_serial: u64,
    ) -> Result<Vec<SignedKeyEvent>, StorageError> {
        use verifiable_storage::ChainedRepository;

        let events =
            <Self as ChainedRepository<KeyEvent>>::get_history_since(self, prefix, since_serial)
                .await?;
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

        Ok(signed_events)
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
        // Use DISTINCT ON to get one event per prefix for the page
        let mut query = Query::<KeyEvent>::for_table(Self::TABLE_NAME)
            .distinct_on("prefix")
            .order_by("prefix", Order::Asc)
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

        // For divergent prefixes, replace the arbitrary SAID from DISTINCT ON with
        // a deterministic hash of sorted tip SAIDs.
        for state in &mut prefix_states {
            if self.find_divergence_serial(&state.prefix).await?.is_some()
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

    pub async fn load_signed_events(&mut self) -> Result<Vec<SignedKeyEvent>, StorageError> {
        let query = Query::<KeyEvent>::for_table(Self::EVENTS_TABLE)
            .eq("prefix", &self.prefix)
            .order_by("serial", Order::Asc);
        let events: Vec<KeyEvent> = self.tx.fetch(query).await?;

        if events.is_empty() {
            return Ok(vec![]);
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
            let sigs = sig_map.remove(&event.said).unwrap_or_default();
            let signed_event = SignedKeyEvent::from_signatures(
                event,
                sigs.into_iter()
                    .map(|s| (s.public_key, s.signature))
                    .collect(),
            );
            result.push(signed_event);
        }

        Ok(result)
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

    pub async fn commit(self) -> Result<(), StorageError> {
        self.tx.commit().await
    }
    pub async fn rollback(self) -> Result<(), StorageError> {
        self.tx.rollback().await
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
