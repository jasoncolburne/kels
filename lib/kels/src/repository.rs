//! SignedEventRepository trait - database-backed KEL storage

use std::collections::HashMap;

use async_trait::async_trait;
use verifiable_storage::{Order, Query, TransactionExecutor};

use crate::{
    EventKind, EventSignature, KeyEvent, MAX_EVENTS_PER_KEL_QUERY, SignedKeyEvent,
    error::KelsError, merge::MergeOutcome,
};

/// Combine raw events with a pre-fetched signature map into `SignedKeyEvent`s.
pub(crate) fn zip_events_with_signatures(
    events: Vec<KeyEvent>,
    sig_map: &HashMap<String, Vec<EventSignature>>,
) -> Result<Vec<SignedKeyEvent>, KelsError> {
    let mut result = Vec::with_capacity(events.len());
    for event in events {
        let sigs = sig_map.get(&event.said).ok_or_else(|| {
            KelsError::StorageError(format!("No signatures found for event {}", event.said))
        })?;
        let sig_pairs: Vec<(String, String)> = sigs
            .iter()
            .map(|s| (s.public_key.clone(), s.signature.clone()))
            .collect();
        result.push(SignedKeyEvent::from_signatures(event, sig_pairs));
    }
    Ok(result)
}

/// Load a page of signed events from the database, ordered deterministically.
///
/// Queries events by prefix with the standard `serial ASC, kind priority ASC, said ASC`
/// ordering, fetches their signatures, and assembles into `SignedKeyEvent`s.
/// Returns `(events, has_more)` using the limit+1 pop pattern.
pub async fn load_signed_history(
    tx: &mut impl TransactionExecutor,
    events_table: &str,
    signatures_table: &str,
    prefix: &str,
    limit: u64,
    offset: u64,
) -> Result<(Vec<SignedKeyEvent>, bool), KelsError> {
    let clamped_limit = limit.min(MAX_EVENTS_PER_KEL_QUERY as u64);
    let query = Query::<KeyEvent>::for_table(events_table)
        .eq("prefix", prefix)
        .order_by("serial", Order::Asc)
        .order_by_case("kind", &EventKind::sort_priority_mapping(), Order::Asc)
        .order_by("said", Order::Asc)
        .limit(clamped_limit + 1)
        .offset(offset);
    let mut events: Vec<KeyEvent> = tx.fetch(query).await?;

    let has_more = events.len() > clamped_limit as usize;
    if has_more {
        events.pop();
    }

    if events.is_empty() {
        return Ok((vec![], false));
    }

    let saids: Vec<String> = events.iter().map(|e| e.said.clone()).collect();
    let sig_query = Query::<EventSignature>::for_table(signatures_table).r#in("event_said", saids);
    let signatures: Vec<EventSignature> = tx.fetch(sig_query).await?;
    let mut sig_map: HashMap<String, Vec<EventSignature>> = HashMap::new();
    for sig in signatures {
        sig_map.entry(sig.event_said.clone()).or_default().push(sig);
    }

    let result = zip_events_with_signatures(events, &sig_map)?;
    Ok((result, has_more))
}

/// Implemented by repositories generated with `#[derive(SignedEvents)]`.
/// Wrap with `RepositoryKelStore` to use as `KelStore`.
#[async_trait]
pub trait SignedEventRepository: Send + Sync {
    /// Get a paginated page of signed events for a prefix.
    /// Returns `(events, has_more)`.
    async fn get_signed_history(
        &self,
        prefix: &str,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<crate::SignedKeyEvent>, bool), KelsError>;

    async fn get_signature_by_said(
        &self,
        said: &str,
    ) -> Result<Option<crate::EventSignature>, KelsError>;
    async fn create_with_signatures(
        &self,
        event: crate::KeyEvent,
        signatures: Vec<crate::EventSignature>,
    ) -> Result<crate::KeyEvent, KelsError>;

    /// Create multiple events with signatures in a single transaction.
    /// This ensures atomicity when saving multiple events (e.g., recovery + rotation).
    async fn create_batch_with_signatures(
        &self,
        events: Vec<(crate::KeyEvent, Vec<crate::EventSignature>)>,
    ) -> Result<(), KelsError>;

    /// Save signed events with full merge (verification, divergence detection, recovery).
    /// Uses an advisory lock on the prefix to serialize operations.
    async fn save_with_merge(
        &self,
        prefix: &str,
        events: &[crate::SignedKeyEvent],
    ) -> Result<MergeOutcome, KelsError>;
}
