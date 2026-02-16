//! Raft log storage for federation consensus.
//!
//! PostgreSQL-backed storage using verifiable-storage for content-addressed,
//! auditable Raft state persistence. Truncate and purge operations move entries
//! to an audit table rather than deleting them.

use std::{fmt::Debug, io, ops::RangeBounds, sync::Arc};
use tokio::sync::Mutex;
use tracing::debug;

use kels::{RaftLogAuditRecord, RaftLogEntry, RaftState, RaftVote};
use openraft::{
    Entry, LogId, LogState, OptionalSend, Vote,
    storage::IOFlushed,
    type_config::alias::{CommittedLeaderIdOf, LogIdOf},
};
use verifiable_storage::{
    Chained, Delete, Filter, Order, Query, QueryExecutor, TransactionExecutor,
};

use super::types::{FederationRequest, TypeConfig};
use crate::raft_store::{RaftLogRepository, RaftStateRepository, RaftVoteRepository};

/// PostgreSQL-backed Raft log storage using verifiable-storage.
#[derive(Clone)]
pub struct LogStore {
    votes: Arc<RaftVoteRepository>,
    logs: Arc<RaftLogRepository>,
    state: Arc<RaftStateRepository>,
    node_id: u64,
    /// Cache of current vote/state to avoid repeated queries
    current_vote: Arc<Mutex<Option<RaftVote>>>,
    current_state: Arc<Mutex<Option<RaftState>>>,
}

impl Debug for LogStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogStore")
            .field("node_id", &self.node_id)
            .finish()
    }
}

impl LogStore {
    /// Create new log storage with repositories.
    pub fn new(
        votes: Arc<RaftVoteRepository>,
        logs: Arc<RaftLogRepository>,
        state: Arc<RaftStateRepository>,
        node_id: u64,
    ) -> Self {
        Self {
            votes,
            logs,
            state,
            node_id,
            current_vote: Arc::new(Mutex::new(None)),
            current_state: Arc::new(Mutex::new(None)),
        }
    }

    /// Create a LogId from term, node_id, and index.
    fn make_log_id(term: u64, node_id: u64, index: u64) -> LogIdOf<TypeConfig> {
        LogId::new(CommittedLeaderIdOf::<TypeConfig> { term, node_id }, index)
    }

    /// Get the current vote record for this node (from cache or DB).
    async fn get_vote(&self) -> Result<Option<RaftVote>, io::Error> {
        let cached = self.current_vote.lock().await;
        if let Some(vote) = cached.as_ref() {
            return Ok(Some(vote.clone()));
        }
        drop(cached);

        // Query for latest vote by node_id
        let query = Query::<RaftVote>::new()
            .eq("node_id", self.node_id)
            .order_by("version", Order::Desc)
            .limit(1);

        let votes: Vec<RaftVote> = self
            .votes
            .pool
            .fetch(query)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        let vote = votes.into_iter().next();
        if let Some(ref v) = vote {
            *self.current_vote.lock().await = Some(v.clone());
        }
        Ok(vote)
    }

    /// Get the current state record for this node (from cache or DB).
    async fn get_state(&self) -> Result<Option<RaftState>, io::Error> {
        let cached = self.current_state.lock().await;
        if let Some(state) = cached.as_ref() {
            return Ok(Some(state.clone()));
        }
        drop(cached);

        // Query for latest state by node_id
        let query = Query::<RaftState>::new()
            .eq("node_id", self.node_id)
            .order_by("version", Order::Desc)
            .limit(1);

        let states: Vec<RaftState> = self
            .state
            .pool
            .fetch(query)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        let state = states.into_iter().next();
        if let Some(ref s) = state {
            *self.current_state.lock().await = Some(s.clone());
        }
        Ok(state)
    }

    /// Try to get log entries in a range.
    pub async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug>(
        &self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, io::Error> {
        let (start, end) = range_to_bounds(&range);

        // Query log entries by node_id and log_index range
        let query = Query::<RaftLogEntry>::new()
            .eq("node_id", self.node_id)
            .gte("log_index", start as i64)
            .lt("log_index", end as i64)
            .order_by("log_index", Order::Asc);

        let entries: Vec<RaftLogEntry> = self
            .logs
            .pool
            .fetch(query)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        let result: Vec<Entry<TypeConfig>> =
            entries.iter().filter_map(log_entry_to_raft_entry).collect();

        Ok(result)
    }

    /// Read the current vote.
    pub async fn read_vote(&self) -> Result<Option<Vote<TypeConfig>>, io::Error> {
        let vote = match self.get_vote().await? {
            Some(v) => v,
            None => return Ok(None),
        };

        if vote.term == 0 && vote.voted_for.is_none() {
            return Ok(None);
        }

        let raft_vote = if vote.committed {
            Vote::new_committed(vote.term, vote.voted_for.unwrap_or(0))
        } else {
            Vote::new(vote.term, vote.voted_for.unwrap_or(0))
        };

        debug!(
            "Read vote: term={}, voted_for={:?}, committed={}",
            vote.term, vote.voted_for, vote.committed
        );
        Ok(Some(raft_vote))
    }

    /// Get the current log state.
    pub async fn get_log_state(&self) -> Result<LogState<TypeConfig>, io::Error> {
        let last_purged_log_id = if let Some(state) = self.get_state().await? {
            match (
                state.last_purged_index,
                state.last_purged_term,
                state.last_purged_node_id,
            ) {
                (Some(idx), Some(term), Some(node_id)) => {
                    Some(Self::make_log_id(term, node_id, idx))
                }
                _ => None,
            }
        } else {
            None
        };

        // Get last log entry
        let query = Query::<RaftLogEntry>::new()
            .eq("node_id", self.node_id)
            .order_by("log_index", Order::Desc)
            .limit(1);

        let entries: Vec<RaftLogEntry> = self
            .logs
            .pool
            .fetch(query)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        let last_log_id = entries
            .into_iter()
            .next()
            .map(|e| Self::make_log_id(e.term, e.leader_node_id, e.log_index));

        Ok(LogState {
            last_purged_log_id,
            last_log_id,
        })
    }

    /// Save a vote using transaction with advisory lock.
    pub async fn save_vote(&self, vote: &Vote<TypeConfig>) -> Result<(), io::Error> {
        debug!(
            "Saving vote: term={}, node_id={}, committed={}",
            vote.leader_id.term, vote.leader_id.node_id, vote.committed
        );

        let lock_key = format!("raft_vote_{}", self.node_id);

        // Begin transaction and acquire advisory lock
        let mut tx = self
            .votes
            .pool
            .begin_transaction()
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        tx.acquire_advisory_lock(&lock_key)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        // Query for latest vote within transaction
        let query = Query::<RaftVote>::new()
            .eq("node_id", self.node_id)
            .order_by("version", Order::Desc)
            .limit(1);

        let votes: Vec<RaftVote> = tx
            .fetch(query)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        let new_vote = if let Some(mut current) = votes.into_iter().next() {
            // Update existing and increment
            current.term = vote.leader_id.term;
            current.voted_for = Some(vote.leader_id.node_id);
            current.committed = vote.committed;
            current
                .increment()
                .map_err(|e| io::Error::other(e.to_string()))?;
            current
        } else {
            // Create initial vote record
            RaftVote::create(
                self.node_id,
                vote.leader_id.term,
                Some(vote.leader_id.node_id),
                vote.committed,
            )
            .map_err(|e| io::Error::other(e.to_string()))?
        };

        tx.insert(&new_vote)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        // Update cache
        *self.current_vote.lock().await = Some(new_vote);

        Ok(())
    }

    /// Save the committed log ID using transaction with advisory lock.
    pub async fn save_committed(
        &self,
        committed: Option<LogIdOf<TypeConfig>>,
    ) -> Result<(), io::Error> {
        let lock_key = format!("raft_state_{}", self.node_id);

        // Begin transaction and acquire advisory lock
        let mut tx = self
            .state
            .pool
            .begin_transaction()
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        tx.acquire_advisory_lock(&lock_key)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        // Query for latest state within transaction
        let query = Query::<RaftState>::new()
            .eq("node_id", self.node_id)
            .order_by("version", Order::Desc)
            .limit(1);

        let states: Vec<RaftState> = tx
            .fetch(query)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        let new_state = if let Some(mut current) = states.into_iter().next() {
            // Update existing and increment
            current.committed_index = committed.map(|c| c.index);
            current.committed_term = committed.map(|c| c.leader_id.term);
            current.committed_node_id = committed.map(|c| c.leader_id.node_id);
            current
                .increment()
                .map_err(|e| io::Error::other(e.to_string()))?;
            current
        } else {
            // Create initial state record
            RaftState::create(
                self.node_id,
                None,
                None,
                None,
                committed.map(|c| c.index),
                committed.map(|c| c.leader_id.term),
                committed.map(|c| c.leader_id.node_id),
            )
            .map_err(|e| io::Error::other(e.to_string()))?
        };

        tx.insert(&new_state)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        // Update cache
        *self.current_state.lock().await = Some(new_state);

        Ok(())
    }

    /// Read the committed log ID.
    pub async fn read_committed(&self) -> Result<Option<LogIdOf<TypeConfig>>, io::Error> {
        let state = match self.get_state().await? {
            Some(s) => s,
            None => return Ok(None),
        };

        Ok(
            match (
                state.committed_index,
                state.committed_term,
                state.committed_node_id,
            ) {
                (Some(idx), Some(term), Some(node_id)) => {
                    Some(Self::make_log_id(term, node_id, idx))
                }
                _ => None,
            },
        )
    }

    /// Append entries to the log using transaction with advisory lock.
    pub async fn append<I>(
        &self,
        entries: I,
        callback: IOFlushed<TypeConfig>,
    ) -> Result<(), io::Error>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + OptionalSend,
    {
        let entries: Vec<_> = entries.into_iter().collect();

        if entries.is_empty() {
            callback.io_completed(Ok(()));
            return Ok(());
        }

        let lock_key = format!("raft_log_{}", self.node_id);

        // Begin transaction and acquire advisory lock
        let mut tx = self
            .logs
            .pool
            .begin_transaction()
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        tx.acquire_advisory_lock(&lock_key)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        // Query for latest log entry within transaction
        let query = Query::<RaftLogEntry>::new()
            .eq("node_id", self.node_id)
            .order_by("version", Order::Desc)
            .limit(1);

        let existing: Vec<RaftLogEntry> = tx
            .fetch(query)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        let mut latest = existing.into_iter().next();

        for entry in entries {
            let log_entry = if let Some(mut prev) = latest.take() {
                // Chain from previous entry
                update_log_entry_fields(&mut prev, self.node_id, &entry);
                prev.increment()
                    .map_err(|e| io::Error::other(e.to_string()))?;
                prev
            } else {
                // First entry - create new
                raft_entry_to_log_entry(self.node_id, &entry).map_err(io::Error::other)?
            };

            tx.insert(&log_entry)
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;

            // Use this entry as the base for the next one
            latest = Some(log_entry);
        }

        tx.commit()
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        callback.io_completed(Ok(()));
        Ok(())
    }

    /// Truncate the log after a given log ID.
    /// Moves truncated entries to audit table.
    pub async fn truncate_after(
        &self,
        after: Option<LogIdOf<TypeConfig>>,
    ) -> Result<(), io::Error> {
        let start_index = after.map(|l| l.index + 1).unwrap_or(0);
        let lock_key = format!("raft_log_{}", self.node_id);

        // Begin transaction and acquire advisory lock
        let mut tx = self
            .logs
            .pool
            .begin_transaction()
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        tx.acquire_advisory_lock(&lock_key)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        // Query entries to be truncated within transaction
        let query = Query::<RaftLogEntry>::new()
            .eq("node_id", self.node_id)
            .gte("log_index", start_index as i64);

        let entries: Vec<RaftLogEntry> = tx
            .fetch(query)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        if entries.is_empty() {
            tx.commit()
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
            return Ok(());
        }

        // Create audit record
        let audit_record = RaftLogAuditRecord::for_truncate(self.node_id, &entries)
            .map_err(|e| io::Error::other(e.to_string()))?;
        tx.insert(&audit_record)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        // Delete entries
        let saids: Vec<String> = entries.iter().map(|e| e.said.clone()).collect();
        let delete = Delete::<RaftLogEntry>::new().r#in("said", saids);
        tx.delete(delete)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        Ok(())
    }

    /// Purge log entries up to and including the given log ID.
    /// Moves purged entries to audit table.
    pub async fn purge(&self, log_id: LogIdOf<TypeConfig>) -> Result<(), io::Error> {
        // Query entries to be purged
        let query = Query::<RaftLogEntry>::new()
            .eq("node_id", self.node_id)
            .filter(Filter::Lte(
                "log_index".to_string(),
                (log_id.index as i64).into(),
            ));

        let entries: Vec<RaftLogEntry> = self
            .logs
            .pool
            .fetch(query)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        if !entries.is_empty() {
            // Create audit record and delete in transaction
            let mut tx = self
                .logs
                .pool
                .begin_transaction()
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;

            // Create audit record
            let audit_record = RaftLogAuditRecord::for_purge(self.node_id, &entries)
                .map_err(|e| io::Error::other(e.to_string()))?;
            tx.insert(&audit_record)
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;

            // Delete entries
            let saids: Vec<String> = entries.iter().map(|e| e.said.clone()).collect();
            let delete = Delete::<RaftLogEntry>::new().r#in("said", saids);
            tx.delete(delete)
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;

            tx.commit()
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
        }

        // Update state with last_purged using transaction with advisory lock
        let lock_key = format!("raft_state_{}", self.node_id);

        let mut tx = self
            .state
            .pool
            .begin_transaction()
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        tx.acquire_advisory_lock(&lock_key)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        // Query for latest state within transaction
        let query = Query::<RaftState>::new()
            .eq("node_id", self.node_id)
            .order_by("version", Order::Desc)
            .limit(1);

        let states: Vec<RaftState> = tx
            .fetch(query)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        let new_state = if let Some(mut current) = states.into_iter().next() {
            current.last_purged_index = Some(log_id.index);
            current.last_purged_term = Some(log_id.leader_id.term);
            current.last_purged_node_id = Some(log_id.leader_id.node_id);
            current
                .increment()
                .map_err(|e| io::Error::other(e.to_string()))?;
            current
        } else {
            RaftState::create(
                self.node_id,
                Some(log_id.index),
                Some(log_id.leader_id.term),
                Some(log_id.leader_id.node_id),
                None,
                None,
                None,
            )
            .map_err(|e| io::Error::other(e.to_string()))?
        };

        tx.insert(&new_state)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        // Update cache
        *self.current_state.lock().await = Some(new_state);

        Ok(())
    }
}

/// Convert a RangeBounds to (start, end) tuple
fn range_to_bounds<RB: RangeBounds<u64>>(range: &RB) -> (u64, u64) {
    use std::ops::Bound;

    let start = match range.start_bound() {
        Bound::Included(&n) => n,
        Bound::Excluded(&n) => n + 1,
        Bound::Unbounded => 0,
    };

    let end = match range.end_bound() {
        Bound::Included(&n) => n + 1,
        Bound::Excluded(&n) => n,
        Bound::Unbounded => u64::MAX,
    };

    (start, end)
}

/// Update an existing RaftLogEntry with new Raft entry data (for chaining).
fn update_log_entry_fields(log_entry: &mut RaftLogEntry, node_id: u64, entry: &Entry<TypeConfig>) {
    let (payload_type, payload_data) = match &entry.payload {
        openraft::EntryPayload::Blank => ("blank".to_string(), None),
        openraft::EntryPayload::Normal(req) => {
            let data = serde_json::to_string(req).ok();
            ("normal".to_string(), data)
        }
        openraft::EntryPayload::Membership(m) => {
            let data = serde_json::to_string(m).ok();
            ("membership".to_string(), data)
        }
    };

    log_entry.node_id = node_id;
    log_entry.log_index = entry.log_id.index;
    log_entry.term = entry.log_id.leader_id.term;
    log_entry.leader_node_id = entry.log_id.leader_id.node_id;
    log_entry.payload_type = payload_type;
    log_entry.payload_data = payload_data;
}

/// Convert RaftLogEntry to Raft Entry
fn log_entry_to_raft_entry(entry: &RaftLogEntry) -> Option<Entry<TypeConfig>> {
    let payload = match entry.payload_type.as_str() {
        "blank" => openraft::EntryPayload::Blank,
        "normal" => {
            let req: FederationRequest = serde_json::from_str(entry.payload_data.as_ref()?).ok()?;
            openraft::EntryPayload::Normal(req)
        }
        "membership" => {
            let membership: openraft::Membership<TypeConfig> =
                serde_json::from_str(entry.payload_data.as_ref()?).ok()?;
            openraft::EntryPayload::Membership(membership)
        }
        _ => return None,
    };

    Some(Entry {
        log_id: LogStore::make_log_id(entry.term, entry.leader_node_id, entry.log_index),
        payload,
    })
}

/// Convert Raft Entry to RaftLogEntry
fn raft_entry_to_log_entry(
    node_id: u64,
    entry: &Entry<TypeConfig>,
) -> Result<RaftLogEntry, String> {
    let (payload_type, payload_data) = match &entry.payload {
        openraft::EntryPayload::Blank => ("blank".to_string(), None),
        openraft::EntryPayload::Normal(req) => {
            let data = serde_json::to_string(req).map_err(|e| e.to_string())?;
            ("normal".to_string(), Some(data))
        }
        openraft::EntryPayload::Membership(m) => {
            let data = serde_json::to_string(m).map_err(|e| e.to_string())?;
            ("membership".to_string(), Some(data))
        }
    };

    // Get the term and leader node_id from the log_id
    let term = entry.log_id.leader_id.term;
    let leader_node_id = entry.log_id.leader_id.node_id;

    RaftLogEntry::create(
        node_id,
        entry.log_id.index,
        term,
        leader_node_id,
        payload_type,
        payload_data,
    )
    .map_err(|e| e.to_string())
}

// Implement the OpenRaft log storage traits
mod impl_log_store {
    use super::*;
    use openraft::storage::{RaftLogReader, RaftLogStorage};

    impl RaftLogReader<TypeConfig> for LogStore {
        async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + OptionalSend>(
            &mut self,
            range: RB,
        ) -> Result<Vec<Entry<TypeConfig>>, io::Error> {
            LogStore::try_get_log_entries(self, range).await
        }

        async fn read_vote(&mut self) -> Result<Option<Vote<TypeConfig>>, io::Error> {
            LogStore::read_vote(self).await
        }
    }

    impl RaftLogStorage<TypeConfig> for LogStore {
        type LogReader = Self;

        async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, io::Error> {
            LogStore::get_log_state(self).await
        }

        async fn get_log_reader(&mut self) -> Self::LogReader {
            self.clone()
        }

        async fn save_vote(&mut self, vote: &Vote<TypeConfig>) -> Result<(), io::Error> {
            LogStore::save_vote(self, vote).await
        }

        async fn save_committed(
            &mut self,
            committed: Option<LogIdOf<TypeConfig>>,
        ) -> Result<(), io::Error> {
            LogStore::save_committed(self, committed).await
        }

        async fn read_committed(&mut self) -> Result<Option<LogIdOf<TypeConfig>>, io::Error> {
            LogStore::read_committed(self).await
        }

        async fn append<I>(
            &mut self,
            entries: I,
            callback: IOFlushed<TypeConfig>,
        ) -> Result<(), io::Error>
        where
            I: IntoIterator<Item = Entry<TypeConfig>> + OptionalSend,
        {
            LogStore::append(self, entries, callback).await
        }

        async fn truncate_after(
            &mut self,
            after: Option<LogIdOf<TypeConfig>>,
        ) -> Result<(), io::Error> {
            LogStore::truncate_after(self, after).await
        }

        async fn purge(&mut self, log_id: LogIdOf<TypeConfig>) -> Result<(), io::Error> {
            LogStore::purge(self, log_id).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kels::{Peer, PeerScope, RaftLogEntry};
    use openraft::EntryPayload;

    #[test]
    fn test_range_to_bounds_included_excluded() {
        // Test included start, excluded end
        let (start, end) = range_to_bounds(&(5..10));
        assert_eq!(start, 5);
        assert_eq!(end, 10);
    }

    #[test]
    fn test_range_to_bounds_included_included() {
        // Test included start, included end
        let (start, end) = range_to_bounds(&(5..=10));
        assert_eq!(start, 5);
        assert_eq!(end, 11);
    }

    #[test]
    fn test_range_to_bounds_unbounded_start() {
        // Test unbounded start
        let (start, end) = range_to_bounds(&(..10));
        assert_eq!(start, 0);
        assert_eq!(end, 10);
    }

    #[test]
    fn test_range_to_bounds_unbounded_end() {
        // Test unbounded end
        let (start, end) = range_to_bounds(&(5..));
        assert_eq!(start, 5);
        assert_eq!(end, u64::MAX);
    }

    #[test]
    fn test_range_to_bounds_fully_unbounded() {
        // Test fully unbounded
        let (start, end) = range_to_bounds(&(..));
        assert_eq!(start, 0);
        assert_eq!(end, u64::MAX);
    }

    #[test]
    fn test_raft_entry_to_log_entry_blank() {
        let entry = Entry {
            log_id: LogStore::make_log_id(1, 0, 5),
            payload: EntryPayload::Blank,
        };

        let log_entry = raft_entry_to_log_entry(42, &entry).unwrap();
        assert_eq!(log_entry.node_id, 42);
        assert_eq!(log_entry.log_index, 5);
        assert_eq!(log_entry.term, 1);
        assert_eq!(log_entry.leader_node_id, 0);
        assert_eq!(log_entry.payload_type, "blank");
        assert!(log_entry.payload_data.is_none());
    }

    #[test]
    fn test_raft_entry_to_log_entry_normal() {
        let peer = Peer::create(
            "12D3KooWTest".to_string(),
            "node-test".to_string(),
            "EAuthorizingKel_____________________________".to_string(),
            true,
            PeerScope::Core,
            "http://node-test:8080".to_string(),
            "/ip4/127.0.0.1/tcp/4001".to_string(),
        )
        .unwrap();
        let request = FederationRequest::AddPeer(peer);

        let entry = Entry {
            log_id: LogStore::make_log_id(2, 1, 10),
            payload: EntryPayload::Normal(request),
        };

        let log_entry = raft_entry_to_log_entry(99, &entry).unwrap();
        assert_eq!(log_entry.node_id, 99);
        assert_eq!(log_entry.log_index, 10);
        assert_eq!(log_entry.term, 2);
        assert_eq!(log_entry.leader_node_id, 1);
        assert_eq!(log_entry.payload_type, "normal");
        assert!(log_entry.payload_data.is_some());
    }

    #[test]
    fn test_log_entry_to_raft_entry_blank() {
        let log_entry = RaftLogEntry::create(1, 5, 10, 0, "blank".to_string(), None).unwrap();

        let raft_entry = log_entry_to_raft_entry(&log_entry).unwrap();
        assert_eq!(raft_entry.log_id.index, 5);
        assert_eq!(raft_entry.log_id.leader_id.term, 10);
        assert_eq!(raft_entry.log_id.leader_id.node_id, 0);
        assert!(matches!(raft_entry.payload, EntryPayload::Blank));
    }

    #[test]
    fn test_log_entry_to_raft_entry_normal() {
        let peer = Peer::create(
            "12D3KooWTest".to_string(),
            "node-test".to_string(),
            "EAuthorizingKel_____________________________".to_string(),
            true,
            PeerScope::Core,
            "http://node-test:8080".to_string(),
            "/ip4/127.0.0.1/tcp/4001".to_string(),
        )
        .unwrap();
        let request = FederationRequest::AddPeer(peer);
        let payload_json = serde_json::to_string(&request).unwrap();

        let log_entry =
            RaftLogEntry::create(1, 7, 3, 2, "normal".to_string(), Some(payload_json)).unwrap();

        let raft_entry = log_entry_to_raft_entry(&log_entry).unwrap();
        assert_eq!(raft_entry.log_id.index, 7);
        assert_eq!(raft_entry.log_id.leader_id.term, 3);
        assert_eq!(raft_entry.log_id.leader_id.node_id, 2);

        assert!(
            matches!(
                raft_entry.payload,
                EntryPayload::Normal(FederationRequest::AddPeer(ref p)) if p.peer_id == "12D3KooWTest"
            ),
            "Expected Normal payload with AddPeer and matching peer_id"
        );
    }

    #[test]
    fn test_log_entry_to_raft_entry_unknown_type() {
        let log_entry = RaftLogEntry::create(1, 5, 10, 0, "unknown".to_string(), None).unwrap();

        let result = log_entry_to_raft_entry(&log_entry);
        assert!(result.is_none());
    }

    #[test]
    fn test_log_entry_to_raft_entry_normal_missing_data() {
        let log_entry = RaftLogEntry::create(1, 5, 10, 0, "normal".to_string(), None).unwrap();

        let result = log_entry_to_raft_entry(&log_entry);
        assert!(result.is_none());
    }

    #[test]
    fn test_update_log_entry_fields() {
        let mut log_entry = RaftLogEntry::create(1, 0, 0, 0, "blank".to_string(), None).unwrap();

        let peer = Peer::create(
            "12D3KooWTest".to_string(),
            "node-test".to_string(),
            "EAuthorizingKel_____________________________".to_string(),
            true,
            PeerScope::Core,
            "http://node-test:8080".to_string(),
            "/ip4/127.0.0.1/tcp/4001".to_string(),
        )
        .unwrap();
        let request = FederationRequest::AddPeer(peer);

        let entry = Entry {
            log_id: LogStore::make_log_id(5, 3, 100),
            payload: EntryPayload::Normal(request),
        };

        update_log_entry_fields(&mut log_entry, 42, &entry);

        assert_eq!(log_entry.node_id, 42);
        assert_eq!(log_entry.log_index, 100);
        assert_eq!(log_entry.term, 5);
        assert_eq!(log_entry.leader_node_id, 3);
        assert_eq!(log_entry.payload_type, "normal");
        assert!(log_entry.payload_data.is_some());
    }

    #[test]
    fn test_make_log_id() {
        let log_id = LogStore::make_log_id(10, 5, 100);
        assert_eq!(log_id.leader_id.term, 10);
        assert_eq!(log_id.leader_id.node_id, 5);
        assert_eq!(log_id.index, 100);
    }

    #[test]
    fn test_roundtrip_blank_entry() {
        let original = Entry {
            log_id: LogStore::make_log_id(1, 0, 5),
            payload: EntryPayload::Blank,
        };

        let log_entry = raft_entry_to_log_entry(1, &original).unwrap();
        let recovered = log_entry_to_raft_entry(&log_entry).unwrap();

        assert_eq!(original.log_id.index, recovered.log_id.index);
        assert_eq!(
            original.log_id.leader_id.term,
            recovered.log_id.leader_id.term
        );
        assert!(matches!(recovered.payload, EntryPayload::Blank));
    }

    #[test]
    fn test_roundtrip_normal_entry() {
        let peer = Peer::create(
            "12D3KooWRoundtrip".to_string(),
            "node-roundtrip".to_string(),
            "EAuthorizingKel_____________________________".to_string(),
            true,
            PeerScope::Regional,
            "http://node-roundtrip:8080".to_string(),
            "/ip4/127.0.0.1/tcp/4001".to_string(),
        )
        .unwrap();
        let request = FederationRequest::RemovePeer(peer.peer_id.clone());

        let original = Entry {
            log_id: LogStore::make_log_id(7, 2, 42),
            payload: EntryPayload::Normal(request),
        };

        let log_entry = raft_entry_to_log_entry(1, &original).unwrap();
        let recovered = log_entry_to_raft_entry(&log_entry).unwrap();

        assert_eq!(original.log_id.index, recovered.log_id.index);
        assert_eq!(
            original.log_id.leader_id.term,
            recovered.log_id.leader_id.term
        );
        assert_eq!(
            original.log_id.leader_id.node_id,
            recovered.log_id.leader_id.node_id
        );

        assert!(
            matches!(
                recovered.payload,
                EntryPayload::Normal(FederationRequest::RemovePeer(ref peer_id)) if peer_id == "12D3KooWRoundtrip"
            ),
            "Expected Normal payload with RemovePeer and matching peer_id"
        );
    }
}
