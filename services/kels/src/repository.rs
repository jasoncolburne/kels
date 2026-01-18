//! PostgreSQL Repository for KELS
//!
//! Implements CRUD operations for Key Event Logs with separate signature storage.

use kels::{EventSignature, KelsAuditRecord, KeyEvent, SignedKeyEvent};
use libkels_derive::SignedEvents;
use std::collections::HashMap;
use verifiable_storage::{
    SelfAddressed, StorageDatetime, StorageError, TransactionExecutor, Value,
};
use verifiable_storage_postgres::{Delete, Order, PgPool, Query, QueryExecutor, Stored};

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
    /// Get multiple KELs by prefix in batch (2 DB calls total).
    ///
    /// Supports incremental updates via `since_map`: for each prefix with a since value,
    /// only events with version > since are returned. Signatures are only fetched for
    /// the filtered events.
    ///
    /// Returns a map of prefix -> Vec<SignedKeyEvent>, ordered by version.
    /// Prefixes not found (or fully cached) will have empty vectors.
    pub async fn get_signed_histories_since(
        &self,
        prefixes: &[&str],
        since_map: &HashMap<&str, u64>,
    ) -> Result<HashMap<String, Vec<SignedKeyEvent>>, StorageError> {
        if prefixes.is_empty() {
            return Ok(HashMap::new());
        }

        // Convert to owned strings for the query
        let prefixes_owned: Vec<String> = prefixes.iter().map(|s| s.to_string()).collect();

        // Single query for all events across all prefixes using Query abstraction
        let query = Query::<KeyEvent>::new()
            .r#in("prefix", prefixes_owned)
            .order_by("prefix", Order::Asc)
            .order_by("version", Order::Asc);
        let all_events = self.pool.fetch(query).await?;

        // Filter: keep only events newer than client's cached version
        let events: Vec<KeyEvent> = all_events
            .into_iter()
            .filter(|e| {
                since_map
                    .get(e.prefix.as_str())
                    .map(|since| e.version > *since)
                    .unwrap_or(true) // No since = fetch all
            })
            .collect();

        if events.is_empty() {
            return Ok(prefixes.iter().map(|p| (p.to_string(), vec![])).collect());
        }

        // Only fetch signatures for filtered events
        let saids: Vec<String> = events.iter().map(|e| e.said.clone()).collect();
        let signatures = self.get_signatures_by_saids(&saids).await?;

        // Build result from filtered events only
        let mut result: HashMap<String, Vec<SignedKeyEvent>> =
            prefixes.iter().map(|p| (p.to_string(), vec![])).collect();

        for event in events {
            let sigs = signatures.get(&event.said).ok_or_else(|| {
                StorageError::StorageError(format!("No signatures found for event {}", event.said))
            })?;
            let signed_event = SignedKeyEvent::from_signatures(
                event.clone(),
                sigs.iter()
                    .map(|s| (s.public_key.clone(), s.signature.clone()))
                    .collect(),
            );

            result
                .entry(event.prefix.clone())
                .or_default()
                .push(signed_event);
        }

        Ok(result)
    }

    /// Delete events from a prefix starting at a given version.
    ///
    /// Note: Signatures are NOT deleted - they remain in the signatures table
    /// for audit purposes and can be queried by event SAID.
    pub async fn delete_events_from_version(
        &self,
        prefix: &str,
        from_version: u64,
    ) -> Result<(), StorageError> {
        // Delete from key_events only (signatures remain for audit)
        let delete = Delete::<KeyEvent>::new()
            .eq("prefix", prefix)
            .gte("version", from_version);
        self.pool.delete(delete).await?;

        Ok(())
    }

    /// Get signed events for a prefix created after a given timestamp.
    ///
    /// Used for timestamp-based incremental sync. Returns events where
    /// `created_at > since_timestamp`, ensuring divergent events at earlier
    /// versions are returned if they were created recently.
    pub async fn get_signed_history_since(
        &self,
        prefix: &str,
        since_timestamp: &StorageDatetime,
    ) -> Result<Vec<SignedKeyEvent>, StorageError> {
        // Query events created after the timestamp
        let query = Query::<KeyEvent>::new()
            .eq("prefix", prefix)
            .filter(verifiable_storage::Filter::Gt(
                "created_at".to_string(),
                Value::Datetime(since_timestamp.clone()),
            ))
            .order_by("version", Order::Asc);

        let events: Vec<KeyEvent> = self.pool.fetch(query).await?;

        if events.is_empty() {
            return Ok(vec![]);
        }

        // Fetch signatures for filtered events
        let saids: Vec<String> = events.iter().map(|e| e.said.clone()).collect();
        let signatures = self.get_signatures_by_saids(&saids).await?;

        // Build signed events
        let mut result = Vec::with_capacity(events.len());
        for event in events {
            let sigs = signatures.get(&event.said).ok_or_else(|| {
                StorageError::StorageError(format!("No signatures found for event {}", event.said))
            })?;
            let signed_event = SignedKeyEvent::from_signatures(
                event.clone(),
                sigs.iter()
                    .map(|s| (s.public_key.clone(), s.signature.clone()))
                    .collect(),
            );
            result.push(signed_event);
        }

        Ok(result)
    }

    /// Begin a transaction with advisory lock on the prefix.
    ///
    /// The advisory lock serializes all operations on this prefix across all
    /// concurrent connections. The lock is automatically released when the
    /// transaction commits or rolls back.
    ///
    /// # Error handling
    /// If the returned `KelTransaction` is dropped without calling `commit()`,
    /// the transaction is automatically rolled back and the lock is released.
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

/// A transaction handle for KEL operations with advisory lock.
///
/// Provides transactional versions of load, delete, and insert operations.
/// The advisory lock is held until `commit()` or `rollback()` is called,
/// or the transaction is dropped (which triggers automatic rollback).
pub struct KelTransaction {
    tx: <PgPool as QueryExecutor>::Transaction,
    prefix: String,
}

impl KelTransaction {
    /// Load all signed events for this KEL within the transaction.
    pub async fn load_signed_events(&mut self) -> Result<Vec<SignedKeyEvent>, StorageError> {
        // Fetch all events for this prefix
        let query = Query::<KeyEvent>::new()
            .eq("prefix", &self.prefix)
            .order_by("version", Order::Asc);
        let events: Vec<KeyEvent> = self.tx.fetch(query).await?;

        if events.is_empty() {
            return Ok(vec![]);
        }

        // Fetch signatures for all events
        let saids: Vec<String> = events.iter().map(|e| e.said.clone()).collect();
        let query = Query::<EventSignature>::for_table("kels_key_event_signatures")
            .r#in("event_said", saids);
        let signatures: Vec<EventSignature> = self.tx.fetch(query).await?;

        // Group signatures by event SAID
        let mut sig_map: HashMap<String, Vec<EventSignature>> = HashMap::new();
        for sig in signatures {
            sig_map.entry(sig.event_said.clone()).or_default().push(sig);
        }

        // Build signed events
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

    /// Delete events from this KEL starting at a given version.
    pub async fn delete_from_version(&mut self, from_version: u64) -> Result<u64, StorageError> {
        let delete = Delete::<KeyEvent>::new()
            .eq("prefix", &self.prefix)
            .gte("version", from_version);
        self.tx.delete(delete).await
    }

    /// Delete specific events by their SAIDs.
    pub async fn delete_events_by_said(&mut self, saids: Vec<String>) -> Result<u64, StorageError> {
        if saids.is_empty() {
            return Ok(0);
        }
        let delete = Delete::<KeyEvent>::new().r#in("said", saids);
        self.tx.delete(delete).await
    }

    /// Insert a signed event within the transaction.
    pub async fn insert_signed_event(
        &mut self,
        signed_event: &SignedKeyEvent,
    ) -> Result<(), StorageError> {
        // Insert the key event
        self.tx.insert(&signed_event.event).await?;

        // Insert all signatures
        for sig in signed_event.event_signatures() {
            let mut event_sig: EventSignature = sig;
            event_sig.derive_said()?;
            self.tx.insert(&event_sig).await?;
        }

        Ok(())
    }

    /// Insert an audit record within the transaction.
    pub async fn insert_audit_record(
        &mut self,
        record: &KelsAuditRecord,
    ) -> Result<(), StorageError> {
        self.tx.insert(record).await?;
        Ok(())
    }

    /// Commit the transaction, releasing the advisory lock.
    pub async fn commit(self) -> Result<(), StorageError> {
        self.tx.commit().await
    }

    /// Rollback the transaction, releasing the advisory lock.
    pub async fn rollback(self) -> Result<(), StorageError> {
        self.tx.rollback().await
    }
}

impl AuditRecordRepository {
    /// Get all audit records for a KEL prefix.
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
