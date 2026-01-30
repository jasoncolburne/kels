//! PostgreSQL Repository for KELS

use kels::{
    EventSignature, KelsAuditRecord, KeyEvent, PrefixListResponse, PrefixState, SignedKeyEvent,
};
use libkels_derive::SignedEvents;
use std::collections::HashMap;
use verifiable_storage::{SelfAddressed, StorageError, TransactionExecutor, Value};
use verifiable_storage_postgres::{Delete, Filter, Order, PgPool, Query, QueryExecutor, Stored};

#[derive(Stored, SignedEvents)]
#[stored(item_type = KeyEvent, table = "kels_key_events")]
#[signed_events(signatures_table = "kels_key_event_signatures")]
pub struct KeyEventRepository {
    pub pool: PgPool,
}

#[derive(Stored)]
#[stored(item_type = KelsAuditRecord, table = "kels_audit_records", versioned = false)]
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
    /// List unique prefixes with their latest SAIDs for bootstrap sync.
    /// Returns prefixes in sorted order with cursor-based pagination.
    /// Each entry includes the SAID of the latest event for that prefix.
    pub async fn list_prefixes(
        &self,
        since: Option<&str>,
        limit: usize,
    ) -> Result<PrefixListResponse, StorageError> {
        // Use DISTINCT ON to get latest event per prefix
        // Order by prefix ASC (for pagination), then version DESC (to get latest)
        let mut query = Query::<KeyEvent>::new()
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

        // Extract prefix and said from each event
        let mut prefix_states: Vec<PrefixState> = events
            .into_iter()
            .map(|e| PrefixState {
                prefix: e.prefix,
                said: e.said,
            })
            .collect();

        // Check if there are more results
        let next_cursor = if prefix_states.len() > limit {
            prefix_states.pop(); // Remove the extra item
            prefix_states.last().map(|s| s.prefix.clone())
        } else {
            None
        };

        Ok(PrefixListResponse {
            prefixes: prefix_states,
            next_cursor,
        })
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
    pub async fn load_signed_events(&mut self) -> Result<Vec<SignedKeyEvent>, StorageError> {
        let query = Query::<KeyEvent>::new().eq("prefix", &self.prefix);
        let events: Vec<KeyEvent> = self.tx.fetch(query).await?;

        if events.is_empty() {
            return Ok(vec![]);
        }

        let saids: Vec<String> = events.iter().map(|e| e.said.clone()).collect();
        let query = Query::<EventSignature>::for_table("kels_key_event_signatures")
            .r#in("event_said", saids);
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
        let delete = Delete::<KeyEvent>::new().r#in("said", saids);
        self.tx.delete(delete).await
    }

    pub async fn insert_signed_event(
        &mut self,
        signed_event: &SignedKeyEvent,
    ) -> Result<(), StorageError> {
        self.tx.insert(&signed_event.event).await?;
        for sig in signed_event.event_signatures() {
            let mut event_sig: EventSignature = sig;
            event_sig.derive_said()?;
            self.tx.insert(&event_sig).await?;
        }

        Ok(())
    }

    pub async fn insert_audit_record(
        &mut self,
        record: &KelsAuditRecord,
    ) -> Result<(), StorageError> {
        self.tx.insert(record).await?;
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
