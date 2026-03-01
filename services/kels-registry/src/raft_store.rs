//! PostgreSQL-backed storage for Raft consensus state and member KELs
//!
//! Uses verifiable-storage patterns with SelfAddressed entities.

use async_trait::async_trait;
use verifiable_storage::{ChainedRepository, ColumnQuery, CorrelatedSubquery, StorageError, Value};
use verifiable_storage_postgres::{
    Filter, Order, PgPool, Query, QueryExecutor, ScalarSubquery, Stored,
};

use kels::{
    EventKind, KelServer, KelsError, KeyEvent, RaftLogAuditRecord, RaftLogEntry, RaftState,
    RaftVote, SignedKeyEvent,
};
use libkels_derive::SignedEvents;

/// PostgreSQL-backed Raft vote repository
#[derive(Clone, Stored)]
#[stored(item_type = RaftVote, table = "raft_vote")]
pub struct RaftVoteRepository {
    pub pool: PgPool,
}

/// PostgreSQL-backed Raft log entry repository
#[derive(Clone, Stored)]
#[stored(item_type = RaftLogEntry, table = "raft_log")]
pub struct RaftLogRepository {
    pub pool: PgPool,
}

/// PostgreSQL-backed Raft state repository
#[derive(Clone, Stored)]
#[stored(item_type = RaftState, table = "raft_state")]
pub struct RaftStateRepository {
    pub pool: PgPool,
}

/// PostgreSQL-backed Raft log audit repository
#[derive(Clone, Stored)]
#[stored(item_type = RaftLogAuditRecord, table = "raft_log_audit", chained = false)]
pub struct RaftLogAuditRepository {
    pub pool: PgPool,
}

/// PostgreSQL-backed member KEL repository (federation member key events)
#[derive(Clone, Stored, SignedEvents)]
#[stored(item_type = KeyEvent, table = "member_key_events", version_field = "serial")]
#[signed_events(signatures_table = "member_key_event_signatures")]
pub struct MemberKelRepository {
    pub pool: PgPool,
}

impl MemberKelRepository {
    /// Fetch signed events after a given SAID (delta fetch).
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

        let clamped_limit = limit.min(i64::MAX as u64 - 2);
        let query = Query::<KeyEvent>::for_table(Self::TABLE_NAME)
            .eq("prefix", prefix)
            .gte_scalar_subquery("serial", subquery)
            .order_by("serial", Order::Asc)
            .order_by_case("kind", &EventKind::sort_priority_mapping(), Order::Asc)
            .order_by("said", Order::Asc)
            .limit(clamped_limit + 2);
        let mut events: Vec<KeyEvent> = self.pool.fetch(query).await?;

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

    /// Compute the effective SAID for a prefix by finding tip events.
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
}

#[async_trait]
impl KelServer for MemberKelRepository {
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
