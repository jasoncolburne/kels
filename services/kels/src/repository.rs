//! PostgreSQL Repository for KELS

use std::collections::HashSet;

use verifiable_storage::{ColumnQuery, StorageError, Value};
use verifiable_storage_postgres::{Filter, Order, PgPool, Query, QueryExecutor, Stored};

use kels::{KeyEvent, PrefixListResponse, PrefixState, RecoveryRecord, SignedKeyEvent};
use libkels_derive::SignedEvents;

#[derive(Stored, SignedEvents)]
#[stored(item_type = KeyEvent, table = "kels_key_events", version_field = "serial")]
#[signed_events(
    signatures_table = "kels_key_event_signatures",
    recovery_table = "kels_recovery"
)]
pub struct KeyEventRepository {
    pub pool: PgPool,
}

#[derive(Stored)]
#[stored(item_type = RecoveryRecord, table = "kels_recovery")]
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
    ) -> Result<(Vec<SignedKeyEvent>, bool), kels::KelsError> {
        use verifiable_storage::TransactionExecutor;

        let mut tx = self.pool.begin_transaction().await?;
        let result = kels::load_signed_history(
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
                && let Some((effective, _)) =
                    self.compute_prefix_effective_said(&state.prefix).await?
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
    ) -> Result<Vec<RecoveryRecord>, StorageError> {
        let query = Query::<RecoveryRecord>::new()
            .eq("kel_prefix", kel_prefix)
            .order_by("version", Order::Asc);
        self.pool.fetch(query).await
    }
}
