//! PostgreSQL Repository for KELS
//!
//! Implements CRUD operations for Key Event Logs with separate signature storage.

use kels::{KelsAuditEvent, KelsAuditRecord, KeyEvent, SignedKeyEvent};
use libkels_derive::SignedEvents;
use std::collections::HashMap;
use verifiable_storage::StorageError;
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
}

impl AuditRecordRepository {
    /// Check if a KEL prefix is contested (has a Contest audit record).
    pub async fn is_contested(&self, kel_prefix: &str) -> Result<bool, StorageError> {
        let contest_event = format!("{:?}", KelsAuditEvent::Contest);
        let query = Query::<KelsAuditRecord>::new()
            .eq("kel_prefix", kel_prefix)
            .eq("event", contest_event)
            .limit(1);
        let result = self.pool.fetch_optional(query).await?;
        Ok(result.is_some())
    }

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
