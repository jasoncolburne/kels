//! PostgreSQL Repository for KELS

use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use verifiable_storage::{
    ChainedRepository, ColumnQuery, CorrelatedSubquery, ScalarSubquery, StorageError, Value,
};
use verifiable_storage_postgres::{Filter, Order, PgPool, Query, QueryExecutor, Stored};

use kels::{
    EventKind, EventSignature, KelServer, KelsAuditRecord, KelsError, KeyEvent, PrefixListResponse,
    PrefixState, SignedKeyEvent,
};
use libkels_derive::SignedEvents;

/// Combine raw events with a pre-fetched signature map into `SignedKeyEvent`s.
fn zip_events_with_signatures(
    events: Vec<KeyEvent>,
    sig_map: &HashMap<String, Vec<EventSignature>>,
) -> Result<Vec<SignedKeyEvent>, StorageError> {
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
    Ok(result)
}

#[derive(Stored, SignedEvents)]
#[stored(item_type = KeyEvent, table = "kels_key_events", version_field = "serial")]
#[signed_events(
    signatures_table = "kels_key_event_signatures",
    audit_table = "kels_audit_records"
)]
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
    /// Events are ordered by `serial ASC, kind sort_priority ASC, said ASC` for deterministic pagination.
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
            .order_by_case("kind", &EventKind::sort_priority_mapping(), Order::Asc)
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
        let sig_map = self.get_signatures_by_saids(&saids).await?;
        let signed_events = zip_events_with_signatures(events, &sig_map)?;
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

    /// Compute the effective SAID for a prefix by finding tip events (events with no successor).
    ///
    /// Uses a NOT EXISTS subquery to find tips directly in SQL rather than loading
    /// all events into memory. Returns the tip SAID for non-divergent KELs, or a
    /// deterministic hash of sorted tip SAIDs for divergent KELs.
    pub async fn compute_prefix_effective_said(
        &self,
        prefix: &str,
    ) -> Result<Option<String>, StorageError> {
        let query = ColumnQuery::new(Self::TABLE_NAME, "said")
            .filter(Filter::Eq(
                "prefix".to_string(),
                Value::String(prefix.to_string()),
            ))
            .filter(Filter::NotExists(CorrelatedSubquery::new(
                Self::TABLE_NAME,
                "_cs",
                Self::TABLE_NAME,
                vec![("previous".to_string(), "said".to_string())],
                vec![Filter::Eq(
                    "_cs.prefix".to_string(),
                    Value::String(prefix.to_string()),
                )],
            )))
            .order(Order::Asc);

        let tip_saids: Vec<String> = self.pool.fetch_column(query).await?;

        match tip_saids.len() {
            0 => Ok(None),
            1 => Ok(Some(tip_saids.into_iter().next().unwrap_or_default())),
            _ => {
                let refs: Vec<&str> = tip_saids.iter().map(|s| s.as_str()).collect();
                Ok(Some(kels::hash_tip_saids(&refs)))
            }
        }
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

#[async_trait]
impl KelServer for KeyEventRepository {
    async fn load_page(
        &self,
        prefix: &str,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<SignedKeyEvent>, bool), KelsError> {
        self.get_signed_history(prefix, limit, offset)
            .await
            .map_err(KelsError::from)
    }

    async fn load_page_since(
        &self,
        prefix: &str,
        since_said: &str,
        limit: u64,
    ) -> Result<(Vec<SignedKeyEvent>, bool), KelsError> {
        self.get_signed_history_since(prefix, since_said, limit)
            .await
            .map_err(KelsError::from)
    }

    async fn effective_said(&self, prefix: &str) -> Result<Option<String>, KelsError> {
        self.compute_prefix_effective_said(prefix)
            .await
            .map_err(KelsError::from)
    }

    async fn event_prefix_by_said(&self, said: &str) -> Result<Option<String>, KelsError> {
        let event: Option<KeyEvent> = self.get_by_said(said).await.map_err(KelsError::from)?;
        Ok(event.map(|e| e.prefix))
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
