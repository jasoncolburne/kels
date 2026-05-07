//! PostgreSQL Repository for KELS SADStore

use std::collections::HashSet;

use cesr::Matter;
use kels_core::{IdentityEvent, IdentityEventKind, SadEvent, SadEventRepair, SelRepairEvent};
use kels_policy::Policy;
use verifiable_storage::{
    ChainedRepository, ColumnQuery, QueryExecutor, ScalarSubquery, StorageError,
    TransactionExecutor, UnchainedRepository, Value,
};
use verifiable_storage_postgres::{Filter, PgPool, Stored};

/// How to identify the IEL chain when fetching events.
///
/// Per #167's said-form fetch comment: the existing query rewrites to use a
/// scalar subquery when the caller has only an IEL event SAID (no prefix).
/// Single change at the query layer; pagination, ordering, and response
/// shape are unchanged.
#[derive(Debug, Clone, Copy)]
pub enum IelChainSelector<'a> {
    /// Direct lookup by IEL prefix.
    Prefix(&'a str),
    /// Lookup by the SAID of any event on the IEL — server resolves the
    /// prefix via subquery: `prefix IN (SELECT prefix FROM iel_events WHERE said = ?)`.
    EventSaid(&'a str),
}

impl<'a> IelChainSelector<'a> {
    /// The WHERE-clause filter that pins the chain. Used by both the
    /// transactional and pool fetch paths.
    fn prefix_filter(&self, table: &str) -> Filter {
        match self {
            Self::Prefix(p) => Filter::Eq("prefix".into(), Value::String((*p).into())),
            Self::EventSaid(s) => Filter::InSubquery(
                "prefix".into(),
                ScalarSubquery::new(
                    table,
                    "prefix",
                    vec![Filter::Eq("said".into(), Value::String((*s).into()))],
                ),
            ),
        }
    }

    /// Render the selector for inclusion in error messages.
    fn label(&self) -> String {
        match self {
            Self::Prefix(p) => format!("prefix {}", p),
            Self::EventSaid(s) => format!("event said {}", s),
        }
    }
}

/// Result of a `save_batch` operation on an event chain.
#[derive(Debug)]
pub enum SaveBatchResult {
    /// Events were accepted, chain remains non-divergent.
    Accepted { new_count: u32 },
    /// A version collision was detected — the forking event was inserted and
    /// the chain is now divergent (frozen). Remaining batch events were discarded.
    DivergenceCreated {
        new_count: u32,
        diverged_at_version: u64,
    },
}

#[derive(Stored)]
#[stored(item_type = SadEvent, table = "sad_events", chained = true)]
pub struct SadEventRepository {
    pub pool: PgPool,
}

impl SadEventRepository {
    /// Store a batch of events within a caller-managed transaction.
    ///
    /// Caller must hold an advisory lock on the SEL prefix.
    ///
    /// If the chain is already divergent, returns an error. If an event in the
    /// batch collides at the same version as an existing event (creating
    /// divergence), inserts only up to and including the forking event, then
    /// discards the rest. The chain freezes immediately.
    pub async fn save_batch<Tx: TransactionExecutor>(
        &self,
        tx: &mut Tx,
        events: &[SadEvent],
        last_governance_version: Option<u64>,
    ) -> Result<SaveBatchResult, StorageError> {
        if events.is_empty() {
            return Ok(SaveBatchResult::Accepted { new_count: 0 });
        }

        let prefix = events[0].prefix;

        // Quick divergence check — reject appends to frozen chains
        let divergence_query = ColumnQuery::new(Self::TABLE_NAME, "*")
            .filter(Filter::Eq(
                "prefix".to_string(),
                Value::String(prefix.to_string()),
            ))
            .group_by("version")
            .limit(1);
        let counts: Vec<i64> = tx.fetch_grouped_count(divergence_query).await?;
        if counts.first().is_some_and(|&c| c > 1) {
            return Err(StorageError::StorageError(
                "Chain is divergent — repair required".to_string(),
            ));
        }

        // Collect existing SAIDs for dedup
        let existing_saids: HashSet<cesr::Digest256> = {
            let saids: Vec<String> = events.iter().map(|e| e.said.to_string()).collect();
            let query = verifiable_storage_postgres::Query::<SadEvent>::for_table(Self::TABLE_NAME)
                .r#in("said", saids);
            tx.fetch(query)
                .await?
                .into_iter()
                .map(|e: SadEvent| e.said)
                .collect()
        };

        // Collect occupied versions in one query: fetch only the version column
        // for existing events at the batch's versions.
        let mut occupied_versions: HashSet<u64> = {
            let batch_versions: Vec<i64> = events
                .iter()
                .map(|e| e.version as i64)
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            let query = ColumnQuery::new(Self::TABLE_NAME, "version")
                .eq("prefix", &prefix)
                .r#in("version", batch_versions);
            tx.fetch_column_i64(query)
                .await?
                .into_iter()
                .map(|v| v as u64)
                .collect()
        };

        let mut count = 0u32;
        for event in events {
            if existing_saids.contains(&event.said) {
                continue;
            }

            // Version collision creates divergence — insert this forking event then freeze
            if occupied_versions.contains(&event.version) {
                // Reject fork at or before the last evaluation — sealed by governance_policy
                if let Some(gp_version) = last_governance_version
                    && event.version <= gp_version
                {
                    return Err(StorageError::StorageError(format!(
                        "Cannot fork at version {} — sealed by evaluation at version {}",
                        event.version, gp_version,
                    )));
                }
                self.insert_in(tx, event.clone()).await?;
                count += 1;
                return Ok(SaveBatchResult::DivergenceCreated {
                    new_count: count,
                    diverged_at_version: event.version,
                });
            }

            self.insert_in(tx, event.clone()).await?;
            occupied_versions.insert(event.version);
            count += 1;
        }

        Ok(SaveBatchResult::Accepted { new_count: count })
    }

    /// Insert a single event under a caller-managed transaction without the
    /// divergent-chain check. Used by the #147 contest / decommission
    /// paths where `Cnt` / `Dec` are the only events allowed to land on a
    /// (sealed-)divergent chain. Caller must hold an advisory lock on the
    /// prefix and must have verified the event is structurally valid +
    /// IEL-resolved-governance-authorized (the verifier surfaces SOFT-pass
    /// vs HARD-pass; terminal flags are content-based on the chain).
    /// Mirrors `IdentityEventRepository::insert_event`.
    pub async fn insert_event<Tx: TransactionExecutor>(
        &self,
        tx: &mut Tx,
        event: &SadEvent,
    ) -> Result<(), StorageError> {
        self.insert_in(tx, event.clone()).await?;
        Ok(())
    }

    /// Truncate events at and after the first replacement's version and insert replacements.
    ///
    /// Used to repair divergent chains. Archives displaced events, creates a repair
    /// audit event, then inserts the replacements.
    /// Caller must hold an advisory lock on the SEL prefix.
    pub async fn truncate_and_replace<Tx: TransactionExecutor>(
        &self,
        tx: &mut Tx,
        events: &[SadEvent],
    ) -> Result<u64, StorageError> {
        if events.is_empty() {
            return Err(StorageError::StorageError("Empty batch".to_string()));
        }

        let prefix = events[0].prefix;

        // Note: per-event authorization is tracked by the verifier's branch state
        // across versions; no consistency check at the repo layer — callers must
        // verify via SelVerifier (the handler does this with PolicyChecker after
        // truncate_and_replace).

        // Skip leading events that already exist locally
        let (new_events, from_version) = {
            let saids: Vec<String> = events.iter().map(|e| e.said.to_string()).collect();
            let existing_query =
                verifiable_storage_postgres::Query::<SadEvent>::for_table(Self::TABLE_NAME)
                    .r#in("said", saids);
            let existing: HashSet<cesr::Digest256> = tx
                .fetch(existing_query)
                .await?
                .into_iter()
                .map(|e: SadEvent| e.said)
                .collect();
            let deduped: Vec<_> = events
                .iter()
                .skip_while(|e| existing.contains(&e.said))
                .collect();
            if deduped.is_empty() {
                let last_version = events.last().map(|e| e.version).unwrap_or(0);
                (deduped, last_version + 1)
            } else {
                let version = deduped[0].version;
                (deduped, version)
            }
        };

        // Archive events page-at-a-time before deleting
        let page_size = kels_core::page_size();
        let mut repair_said: Option<cesr::Digest256> = None;
        let mut version_cursor = from_version;

        loop {
            let page_query =
                verifiable_storage_postgres::Query::<SadEvent>::for_table(Self::TABLE_NAME)
                    .eq("prefix", &prefix)
                    .gte("version", version_cursor)
                    .order_by("version", verifiable_storage::Order::Asc)
                    .order_by_case(
                        "kind",
                        &kels_core::SadEventKind::sort_priority_mapping(),
                        verifiable_storage::Order::Asc,
                    )
                    .limit(page_size as u64);
            let page: Vec<SadEvent> = tx.fetch(page_query).await?;

            if page.is_empty() {
                break;
            }

            let repair_said_ref = match &repair_said {
                Some(said) => said,
                None => {
                    let repair = SadEventRepair::create(prefix, from_version)?;
                    tx.insert(&repair).await?;
                    repair_said = Some(repair.said);
                    repair_said.as_ref().ok_or_else(|| {
                        StorageError::StorageError("repair SAID missing".to_string())
                    })?
                }
            };

            // Skip events already in archives (stale gossip can re-insert fork
            // events after a prior repair archived them)
            let already_archived: HashSet<cesr::Digest256> = {
                let page_saids: Vec<String> = page.iter().map(|e| e.said.to_string()).collect();
                let archive_query = verifiable_storage_postgres::Query::<SadEvent>::for_table(
                    Self::ARCHIVED_EVENTS_TABLE,
                )
                .r#in("said", page_saids);
                tx.fetch(archive_query)
                    .await?
                    .into_iter()
                    .map(|e: SadEvent| e.said)
                    .collect()
            };

            for event in &page {
                if already_archived.contains(&event.said) {
                    continue;
                }
                tx.insert_with_table(event, Self::ARCHIVED_EVENTS_TABLE)
                    .await?;
                let repair_record = SelRepairEvent::create(*repair_said_ref, event.said)?;
                tx.insert(&repair_record).await?;
            }

            let page_len = page.len();
            if let Some(last) = page.last() {
                version_cursor = last.version + 1;
            }
            if page_len < page_size {
                break;
            }
        }

        // Delete events at and after from_version
        let delete_events = verifiable_storage::Delete::<SadEvent>::for_table(Self::TABLE_NAME)
            .eq("prefix", &prefix)
            .gte("version", from_version);
        tx.delete(delete_events).await?;

        // Insert replacements
        for event in new_events {
            self.insert_in(tx, event.clone()).await?;
        }

        Ok(from_version)
    }

    /// Quick check: does any version appear more than once for this prefix?
    pub async fn is_divergent(&self, prefix: &cesr::Digest256) -> Result<bool, StorageError> {
        let query = ColumnQuery::new(Self::TABLE_NAME, "*")
            .filter(Filter::Eq(
                "prefix".to_string(),
                Value::String(prefix.to_string()),
            ))
            .group_by("version")
            .limit(1);
        let counts: Vec<i64> = self.pool.fetch_grouped_count(query).await?;
        Ok(counts.first().is_some_and(|&c| c > 1))
    }

    /// Lowest version at which more than one event exists for this prefix, or
    /// `None` if every version is single-rowed.
    ///
    /// `is_divergent` answers "is the chain divergent at all?" but the dedup
    /// short-circuit in `submit_sad_events` needs the actual version so it can
    /// populate `SubmitSadEventsResponse.diverged_at` symmetrically with the
    /// normal-path response. Without this, a client retrying after a phase-3
    /// failure (Round 4 M1's terminology) gets `diverged_at: None` even when
    /// the chain is currently divergent server-side.
    ///
    /// `ColumnQuery` / `fetch_grouped_count` can't express MIN(grouped_column)
    /// HAVING COUNT(*) > 1 — the API returns counts only, not group keys —
    /// so this drops to a hand-written SQL query via the underlying sqlx pool.
    pub async fn first_divergent_version(
        &self,
        prefix: &cesr::Digest256,
    ) -> Result<Option<u64>, StorageError> {
        let row: Option<i64> = sqlx::query_scalar(
            "SELECT MIN(version) FROM (\
                SELECT version FROM sad_events \
                WHERE prefix = $1 \
                GROUP BY version HAVING COUNT(*) > 1\
             ) AS divergent_versions",
        )
        .bind(prefix.to_string())
        .fetch_optional(self.pool.inner())
        .await
        .map_err(|e| StorageError::StorageError(e.to_string()))?
        .flatten();
        Ok(row.map(|v| v as u64))
    }

    /// Get the tail of a chain — the last `limit` events ordered by
    /// `(version DESC, said DESC)`, then reversed before returning so the
    /// caller sees `(version ASC, said ASC)` (matches `get_stored`'s shape).
    ///
    /// Used by `SadEventBuilder::repair`'s adversary-extension walk-back: the
    /// boundary is at most `MAX_NON_EVALUATION_EVENTS = 63` hops from the tip,
    /// so a single `MINIMUM_PAGE_SIZE`-bounded fetch covers everything the
    /// walk could possibly need — independent of the chain's total length.
    /// The handler caps `limit` at `MINIMUM_PAGE_SIZE` before reaching this
    /// method; the repository signature accepts an arbitrary `u64` only
    /// because it doesn't know about that constant.
    pub async fn get_stored_tail(
        &self,
        prefix: &str,
        limit: u64,
    ) -> Result<Vec<SadEvent>, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;
        let query = verifiable_storage_postgres::Query::<SadEvent>::for_table(Self::TABLE_NAME)
            .eq("prefix", prefix)
            .order_by("version", verifiable_storage_postgres::Order::Desc)
            .order_by_case(
                "kind",
                &kels_core::SadEventKind::sort_priority_mapping(),
                verifiable_storage_postgres::Order::Desc,
            )
            .order_by("said", verifiable_storage_postgres::Order::Desc)
            .limit(limit);
        let mut events: Vec<SadEvent> = self.pool.fetch(query).await?;
        events.reverse();
        Ok(events)
    }

    /// Get the version of the most recent governance evaluation for a chain.
    /// Returns None if no governance evaluation has been recorded.
    pub async fn last_governance_version<Tx: TransactionExecutor>(
        &self,
        tx: &mut Tx,
        prefix: &cesr::Digest256,
    ) -> Result<Option<u64>, StorageError> {
        let query = verifiable_storage_postgres::Query::<SadEvent>::for_table(Self::TABLE_NAME)
            .eq("prefix", prefix)
            .r#in(
                "kind",
                vec![
                    kels_core::SadEventKind::Sea.as_str().to_string(),
                    kels_core::SadEventKind::Rpr.as_str().to_string(),
                ],
            )
            .order_by("version", verifiable_storage::Order::Desc)
            .limit(1);
        let events: Vec<SadEvent> = tx.fetch(query).await?;
        Ok(events.first().map(|e| e.version))
    }

    /// Check if an event with the given SAID exists.
    pub async fn exists(&self, said: &cesr::Digest256) -> Result<bool, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let query = verifiable_storage_postgres::Query::<SadEvent>::for_table(Self::TABLE_NAME)
            .eq("said", said.as_ref())
            .limit(1);
        Ok(!self.pool.fetch(query).await?.is_empty())
    }

    /// True iff the chain has any `Cnt` event. Mirrors
    /// `IdentityEventRepository::is_contested`.
    pub async fn is_contested(&self, prefix: &cesr::Digest256) -> Result<bool, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let query = verifiable_storage_postgres::Query::<SadEvent>::for_table(Self::TABLE_NAME)
            .eq("prefix", prefix)
            .eq("kind", kels_core::SadEventKind::Cnt.as_str())
            .limit(1);
        Ok(!self.pool.fetch(query).await?.is_empty())
    }

    /// True iff the chain has any `Dec` event. Mirrors
    /// `IdentityEventRepository::is_decommissioned`.
    pub async fn is_decommissioned(&self, prefix: &cesr::Digest256) -> Result<bool, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let query = verifiable_storage_postgres::Query::<SadEvent>::for_table(Self::TABLE_NAME)
            .eq("prefix", prefix)
            .eq("kind", kels_core::SadEventKind::Dec.as_str())
            .limit(1);
        Ok(!self.pool.fetch(query).await?.is_empty())
    }

    /// Get the chain as bare `SadEvent`s.
    ///
    /// Ordering: `version ASC, kind sort_priority ASC, said ASC` — deterministic
    /// across nodes (mirrors KEL's `serial ASC, kind sort_priority ASC, said ASC`).
    /// Delegates to `get_stored_in` via an implicit transaction.
    pub async fn get_stored(
        &self,
        prefix: &str,
        since_said: Option<&str>,
        limit: Option<u64>,
    ) -> Result<Vec<SadEvent>, StorageError> {
        let mut tx = self.pool.begin_transaction().await?;
        let result = self
            .get_stored_in(&mut tx, prefix, since_said, limit)
            .await?;
        tx.commit().await?;
        Ok(result)
    }

    /// Get SAD events within an existing transaction.
    ///
    /// Same ordering as `get_stored`: `version ASC, kind sort_priority ASC, said ASC`.
    /// State-determining events (Rpr) sort after normal events at the same version,
    /// so cross-node convergence under gossip-induced reordering is canonical.
    pub async fn get_stored_in<Tx: TransactionExecutor>(
        &self,
        tx: &mut Tx,
        prefix: &str,
        since_said: Option<&str>,
        limit: Option<u64>,
    ) -> Result<Vec<SadEvent>, StorageError> {
        let since_position: Option<(u64, kels_core::SadEventKind, cesr::Digest256)> =
            if let Some(said) = since_said {
                let cursor_query =
                    verifiable_storage_postgres::Query::<SadEvent>::for_table(Self::TABLE_NAME)
                        .eq("said", said)
                        .limit(1);
                tx.fetch(cursor_query)
                    .await?
                    .into_iter()
                    .next()
                    .map(|r| (r.version, r.kind, r.said))
            } else {
                None
            };

        let mut query = verifiable_storage_postgres::Query::<SadEvent>::for_table(Self::TABLE_NAME)
            .eq("prefix", prefix)
            .order_by("version", verifiable_storage_postgres::Order::Asc)
            .order_by_case(
                "kind",
                &kels_core::SadEventKind::sort_priority_mapping(),
                verifiable_storage_postgres::Order::Asc,
            )
            .order_by("said", verifiable_storage_postgres::Order::Asc);

        if let Some((version, _, _)) = &since_position {
            query = query.gte("version", *version);
        }

        if let Some(limit) = limit {
            let fetch_limit = if since_position.is_some() {
                limit + 2
            } else {
                limit
            };
            query = query.limit(fetch_limit);
        }

        let mut events: Vec<SadEvent> = tx.fetch(query).await?;

        if let Some((version, kind, said)) = &since_position {
            let skipped = events.len();
            // Strictly-greater on (version, kind sort_priority, said) — the canonical
            // tuple ordering. Same SAID implies same content (and thus same kind),
            // so the kind comparison only affects events at the same version.
            let since_priority = kind.sort_priority();
            events.retain(|e| {
                let e_priority = e.kind.sort_priority();
                e.version > *version
                    || (e.version == *version && e_priority > since_priority)
                    || (e.version == *version && e_priority == since_priority && e.said > *said)
            });
            let skipped = skipped - events.len();

            if skipped > 2 {
                return Err(StorageError::StorageError(format!(
                    "Chain integrity violation: {} events skipped at version {} for prefix {} — possible DB tampering",
                    skipped, version, prefix
                )));
            }

            if let Some(limit) = limit {
                events.truncate(limit as usize);
            }
        }

        Ok(events)
    }

    /// Get the effective SAID for a SEL prefix.
    ///
    /// Terminal-state precedence (mirrors
    /// `IdentityEventRepository::effective_said`):
    /// 1. Decommissioned → the latest `Dec` event's SAID.
    /// 2. Contested → `hash_effective_said("contested:{prefix}")`.
    /// 3. Divergent (non-terminal) → `hash_effective_said("divergent:{prefix}")`.
    /// 4. Linear → tip event SAID.
    /// 5. Empty → `None`.
    ///
    /// The bool in the return tuple is `true` for synthetic SAIDs
    /// (contested/divergent) so callers can distinguish a real chain tip
    /// from a state marker.
    pub async fn effective_said(
        &self,
        prefix: &cesr::Digest256,
    ) -> Result<Option<(cesr::Digest256, bool)>, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        // 1. Decommissioned takes precedence: the Dec event itself is the
        //    effective SAID. (A Dec lands on either a linear chain or a
        //    sealed-divergent chain per Gap 4 routing; in either case the
        //    Dec SAID is the deterministic effective value.)
        let dec_query = verifiable_storage_postgres::Query::<SadEvent>::for_table(Self::TABLE_NAME)
            .eq("prefix", prefix)
            .eq("kind", kels_core::SadEventKind::Dec.as_str())
            .order_by("version", verifiable_storage::Order::Desc)
            .limit(1);
        let dec: Vec<SadEvent> = self.pool.fetch(dec_query).await?;
        if let Some(dec_event) = dec.first() {
            return Ok(Some((dec_event.said, false)));
        }

        // 2. Contested → synthetic "contested:{prefix}" hash.
        if self.is_contested(prefix).await? {
            let said = kels_core::hash_effective_said(&format!("contested:{}", prefix));
            return Ok(Some((said, true)));
        }

        // 3. Divergent → synthetic "divergent:{prefix}" hash.
        if self.is_divergent(prefix).await? {
            let said = kels_core::hash_effective_said(&format!("divergent:{}", prefix));
            return Ok(Some((said, true)));
        }

        // 4. Linear → tip event SAID. 5. Empty → None.
        let latest = self.get_latest(prefix).await?;
        Ok(latest.map(|e| (e.said, false)))
    }

    const ARCHIVED_EVENTS_TABLE: &'static str = "sad_event_archives";

    /// Get repairs for a SEL prefix, paginated.
    pub async fn get_repairs(
        &self,
        prefix: &str,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<kels_core::SadEventRepair>, bool), StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let query = verifiable_storage_postgres::Query::<kels_core::SadEventRepair>::new()
            .eq("event_prefix", prefix)
            .order_by("repaired_at", verifiable_storage_postgres::Order::Asc)
            .offset(offset)
            .limit(limit + 1);
        let mut repairs: Vec<kels_core::SadEventRepair> = self.pool.fetch(query).await?;

        let has_more = repairs.len() as u64 > limit;
        repairs.truncate(limit as usize);
        Ok((repairs, has_more))
    }

    /// Get archived events for a specific repair, paginated.
    pub async fn get_repair_events(
        &self,
        repair_said: &str,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<SadEvent>, bool), StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let link_query = verifiable_storage_postgres::Query::<SelRepairEvent>::new()
            .eq("repair_said", repair_said)
            .offset(offset)
            .limit(limit + 1);
        let mut links: Vec<SelRepairEvent> = self.pool.fetch(link_query).await?;

        let has_more = links.len() as u64 > limit;
        links.truncate(limit as usize);

        if links.is_empty() {
            return Ok((Vec::new(), false));
        }

        let event_saids: Vec<String> = links.iter().map(|l| l.event_said.to_string()).collect();

        let events_query =
            verifiable_storage_postgres::Query::<SadEvent>::for_table(Self::ARCHIVED_EVENTS_TABLE)
                .r#in("said", event_saids);
        let events: Vec<SadEvent> = self.pool.fetch(events_query).await?;

        Ok((events, has_more))
    }

    /// List SEL prefixes with their effective SAIDs, paginated.
    pub async fn list_prefixes(
        &self,
        cursor: Option<&cesr::Digest256>,
        limit: usize,
    ) -> Result<kels_core::PrefixListResponse, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let mut query = verifiable_storage_postgres::Query::<SadEvent>::for_table(Self::TABLE_NAME)
            .distinct_on("prefix")
            .order_by("prefix", verifiable_storage_postgres::Order::Asc)
            .order_by("version", verifiable_storage_postgres::Order::Desc)
            .limit(limit as u64 + 1);

        if let Some(cursor) = cursor {
            query = query.gt("prefix", cursor.as_ref());
        }

        let events: Vec<SadEvent> = self.pool.fetch(query).await?;

        let mut prefix_states: Vec<kels_core::PrefixState> = events
            .into_iter()
            .map(|e| kels_core::PrefixState {
                prefix: e.prefix,
                said: e.said,
            })
            .collect();

        let next_cursor = if prefix_states.len() > limit {
            prefix_states.pop();
            prefix_states.last().map(|s| s.prefix)
        } else if let Some(cursor) = cursor {
            let remaining = limit - prefix_states.len();
            if remaining > 0 {
                let wrap_query =
                    verifiable_storage_postgres::Query::<SadEvent>::for_table(Self::TABLE_NAME)
                        .distinct_on("prefix")
                        .order_by("prefix", verifiable_storage_postgres::Order::Asc)
                        .order_by("version", verifiable_storage_postgres::Order::Desc)
                        .lte("prefix", cursor.as_ref())
                        .limit(remaining as u64);
                let wrap_events: Vec<SadEvent> = self.pool.fetch(wrap_query).await?;
                prefix_states.extend(wrap_events.into_iter().map(|e| kels_core::PrefixState {
                    prefix: e.prefix,
                    said: e.said,
                }));
            }
            None
        } else {
            None
        };

        // Terminal-state-aware effective-SAID resolution. Apply
        // precedence per prefix in three batch passes (matches the
        // `effective_said` order):
        //   1. Decommissioned: replace SAID with the prefix's `Dec` SAID.
        //   2. Contested (and not already decommissioned): synthetic
        //      `contested:{prefix}` hash.
        //   3. Divergent (and neither of the above): synthetic
        //      `divergent:{prefix}` hash.
        // The default (linear) tip SAID is already populated from the
        // distinct_on query above.
        let page_prefixes: Vec<String> =
            prefix_states.iter().map(|s| s.prefix.to_string()).collect();

        // Pass 1 — Dec SAIDs per prefix (latest Dec wins, mirroring
        // single-prefix `effective_said`).
        let dec_query = verifiable_storage_postgres::Query::<SadEvent>::for_table(Self::TABLE_NAME)
            .r#in("prefix", page_prefixes.clone())
            .eq("kind", kels_core::SadEventKind::Dec.as_str())
            .order_by("version", verifiable_storage::Order::Desc);
        let dec_events: Vec<SadEvent> = self.pool.fetch(dec_query).await?;
        let mut dec_by_prefix: std::collections::HashMap<cesr::Digest256, cesr::Digest256> =
            std::collections::HashMap::new();
        for ev in dec_events {
            dec_by_prefix.entry(ev.prefix).or_insert(ev.said);
        }

        // Pass 2 — set of prefixes that have at least one Cnt event.
        let cnt_query = verifiable_storage_postgres::Query::<SadEvent>::for_table(Self::TABLE_NAME)
            .r#in("prefix", page_prefixes.clone())
            .eq("kind", kels_core::SadEventKind::Cnt.as_str());
        let cnt_events: Vec<SadEvent> = self.pool.fetch(cnt_query).await?;
        let contested_prefixes: HashSet<cesr::Digest256> =
            cnt_events.into_iter().map(|e| e.prefix).collect();

        // Pass 3 — divergent prefixes (existing batch).
        let divergent_query = ColumnQuery::new(Self::TABLE_NAME, "prefix")
            .distinct()
            .r#in("prefix", page_prefixes)
            .group_by("prefix")
            .group_by("version")
            .having_count_gt(1);
        let divergent_prefixes: HashSet<String> = self
            .pool
            .fetch_column(divergent_query)
            .await?
            .into_iter()
            .collect();

        for state in &mut prefix_states {
            if let Some(dec_said) = dec_by_prefix.get(&state.prefix) {
                state.said = *dec_said;
            } else if contested_prefixes.contains(&state.prefix) {
                state.said = kels_core::hash_effective_said(&format!("contested:{}", state.prefix));
            } else if divergent_prefixes.contains(state.prefix.as_ref()) {
                state.said = kels_core::hash_effective_said(&format!("divergent:{}", state.prefix));
            }
        }

        Ok(kels_core::PrefixListResponse {
            prefixes: prefix_states,
            next_cursor,
        })
    }
}

/// Tracks SAD object SAIDs stored in object store.
#[derive(Stored)]
#[stored(item_type = kels_core::SadObjectEntry, table = "sad_objects", chained = false)]
pub struct SadObjectIndex {
    pub pool: PgPool,
}

impl SadObjectIndex {
    /// Store a SAD object in object store and track it in the index.
    ///
    /// **Ordering: object store first, then PG insert (auto-commit).** Object
    /// store PUT is idempotent under content-addressing (same SAID = same
    /// content), so a crash between PUT and INSERT leaves a transient
    /// object-store-only orphan that the retry's INSERT step heals. The prior
    /// shape (PG INSERT inside an open transaction wrapped around the PUT) was
    /// non-atomic against PUT-ack-then-COMMIT-fail, producing sticky
    /// PG-orphans under object-store concurrency pressure (#157). PG is now
    /// the source of truth for "we have this object"; the HEAD-check sites
    /// in `handlers.rs` consult PG, not the object store.
    ///
    /// #167: the pre-reshape `custody` SAID parameter is replaced
    /// by denormalized lifecycle fields sourced from the parent SAD's inline
    /// `custody.read` and `availability.{nodes,ttl,once}`. All four
    /// participate in the entry's SAID computation, so the index row is
    /// reverifiable from the parent SAD's bytes.
    #[allow(clippy::too_many_arguments)]
    pub async fn store(
        &self,
        sad_said: &cesr::Digest256,
        custody_read: Option<cesr::Digest256>,
        availability_nodes: Option<cesr::Digest256>,
        availability_ttl: Option<u64>,
        availability_once: Option<bool>,
        object_store: &crate::object_store::ObjectStore,
        data: &[u8],
    ) -> Result<(), StorageError> {
        let entry = kels_core::SadObjectEntry::create(
            *sad_said,
            custody_read,
            availability_nodes,
            availability_ttl,
            availability_once,
        )?;

        // Object store first: idempotent under content-addressing. PUT failure
        // returns Err with no PG row created — caller retries with consistent
        // missing state on both sides.
        object_store
            .put(sad_said, data)
            .await
            .map_err(|e| StorageError::StorageError(e.to_string()))?;

        // PG INSERT (auto-commit). DuplicateRecord on the entry SAID or the
        // `sad_said` UNIQUE index is idempotent success — the index already
        // tracks this SAID and the prior PUT confirmed object-store bytes
        // match by content-addressing.
        match self.insert(entry).await {
            Ok(_) => Ok(()),
            Err(StorageError::DuplicateRecord(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Fetch a SAD object index entry by its object store SAID.
    pub async fn get_by_sad_said(
        &self,
        sad_said: &cesr::Digest256,
    ) -> Result<Option<kels_core::SadObjectEntry>, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let query = verifiable_storage_postgres::Query::<kels_core::SadObjectEntry>::for_table(
            Self::TABLE_NAME,
        )
        .eq("sad_said", sad_said.as_ref())
        .limit(1);
        self.pool.fetch_optional(query).await
    }

    /// Atomically delete a SAD object index entry by its object store SAID.
    /// Returns the number of rows deleted (1 = consumed, 0 = not found/already consumed).
    /// Used for `once` semantics.
    pub async fn delete_by_sad_said(
        &self,
        sad_said: &cesr::Digest256,
    ) -> Result<u64, StorageError> {
        let delete =
            verifiable_storage::Delete::<kels_core::SadObjectEntry>::for_table(Self::TABLE_NAME)
                .eq("sad_said", sad_said.as_ref());
        self.pool.delete(delete).await
    }

    /// Check if a SAD object is tracked.
    pub async fn is_tracked(&self, sad_said: &str) -> Result<bool, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let query = verifiable_storage_postgres::Query::<kels_core::SadObjectEntry>::for_table(
            Self::TABLE_NAME,
        )
        .eq("sad_said", sad_said)
        .limit(1);
        Ok(self.pool.fetch_optional(query).await?.is_some())
    }

    /// List SAD object SAIDs, paginated with wrap-around.
    pub async fn list(
        &self,
        cursor: Option<&cesr::Digest256>,
        limit: usize,
    ) -> Result<kels_core::SadObjectListResponse, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let mut query = verifiable_storage_postgres::Query::<kels_core::SadObjectEntry>::for_table(
            Self::TABLE_NAME,
        )
        .order_by("sad_said", verifiable_storage_postgres::Order::Asc)
        .limit(limit as u64 + 1);

        if let Some(cursor) = cursor {
            query = query.gt("sad_said", cursor.as_ref());
        }

        let entries: Vec<kels_core::SadObjectEntry> = self.pool.fetch(query).await?;

        let mut saids: Vec<cesr::Digest256> = entries.into_iter().map(|e| e.sad_said).collect();

        let next_cursor = if saids.len() > limit {
            saids.pop();
            saids.last().cloned()
        } else if let Some(cursor) = cursor {
            let remaining = limit - saids.len();
            if remaining > 0 {
                let wrap_query =
                    verifiable_storage_postgres::Query::<kels_core::SadObjectEntry>::for_table(
                        Self::TABLE_NAME,
                    )
                    .order_by("sad_said", verifiable_storage_postgres::Order::Asc)
                    .lte("sad_said", cursor.as_ref())
                    .limit(remaining as u64);
                let wrap_entries: Vec<kels_core::SadObjectEntry> =
                    self.pool.fetch(wrap_query).await?;
                saids.extend(wrap_entries.into_iter().map(|e| e.sad_said));
            }
            None
        } else {
            None
        };

        Ok(kels_core::SadObjectListResponse { saids, next_cursor })
    }

    /// Fetch up to `limit` index entries whose `availability_ttl` is set,
    /// for the TTL reaper. Returns `(sad_said, ttl, created_at)` triples
    /// so the caller can compute expiry without a second round-trip.
    pub async fn fetch_ttl_set(
        &self,
        limit: u64,
    ) -> Result<Vec<(cesr::Digest256, u64, verifiable_storage::StorageDatetime)>, StorageError>
    {
        type TtlRow = (String, i64, chrono::DateTime<chrono::Utc>);
        let rows: Vec<TtlRow> = sqlx::query_as(
            "SELECT sad_said, availability_ttl, created_at FROM sad_objects \
             WHERE availability_ttl IS NOT NULL \
             LIMIT $1",
        )
        .bind(limit as i64)
        .fetch_all(self.pool.inner())
        .await
        .map_err(|e| StorageError::StorageError(e.to_string()))?;

        rows.into_iter()
            .map(|(s, t, created)| {
                let said = cesr::Digest256::from_qb64(&s)
                    .map_err(|e| StorageError::StorageError(e.to_string()))?;
                Ok((said, t as u64, created.into()))
            })
            .collect()
    }
}

/// Cached policy SADs for evaluation without object store round-trips.
#[derive(Stored)]
#[stored(item_type = Policy, table = "policies", chained = false)]
pub struct PolicyRepository {
    pub pool: PgPool,
}

impl PolicyRepository {
    /// Store a policy SAD in the cache (idempotent).
    pub async fn store(&self, policy: &Policy) -> Result<(), StorageError> {
        match self.insert(policy.clone()).await {
            Ok(_) => Ok(()),
            Err(StorageError::DuplicateRecord(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Fetch a cached policy by SAID.
    pub async fn get_by_said(
        &self,
        said: &cesr::Digest256,
    ) -> Result<Option<Policy>, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let query = verifiable_storage_postgres::Query::<Policy>::for_table(Self::TABLE_NAME)
            .eq("said", said.as_ref())
            .limit(1);
        self.pool.fetch_optional(query).await
    }
}

// ============================================================
// Identity Event Log (IEL) repository
// ============================================================
//
// Mirrors `SadEventRepository` for the IEL primitive. IEL has no `Rpr`,
// no archive table, and no `truncate_and_replace`. Divergence is preserved
// in-place; only `Cnt` resolves it. See `docs/design/iel/event-log.md`.

#[derive(Stored)]
#[stored(item_type = IdentityEvent, table = "iel_events", chained = true)]
pub struct IdentityEventRepository {
    pub pool: PgPool,
}

impl IdentityEventRepository {
    /// Insert a batch of events under a caller-managed transaction.
    ///
    /// Caller must hold an advisory lock on the IEL prefix.
    ///
    /// Behavior mirrors `SadEventRepository::save_batch`:
    /// - Rejects appends to a divergent chain. The contest path bypasses this
    ///   method (it inserts `Cnt` directly via `insert_in`) — see Gap 5.
    /// - On version collision, inserts the single forking event and returns
    ///   `DivergenceCreated`; remaining events are discarded.
    /// - Rejects forks at or before the evaluation seal (governance-sealed).
    pub async fn save_batch<Tx: TransactionExecutor>(
        &self,
        tx: &mut Tx,
        events: &[IdentityEvent],
        last_governance_version: Option<u64>,
    ) -> Result<SaveBatchResult, StorageError> {
        if events.is_empty() {
            return Ok(SaveBatchResult::Accepted { new_count: 0 });
        }

        let prefix = events[0].prefix;

        // Reject appends to frozen chains (divergent).
        let divergence_query = ColumnQuery::new(Self::TABLE_NAME, "*")
            .filter(Filter::Eq(
                "prefix".to_string(),
                Value::String(prefix.to_string()),
            ))
            .group_by("version")
            .limit(1);
        let counts: Vec<i64> = tx.fetch_grouped_count(divergence_query).await?;
        if counts.first().is_some_and(|&c| c > 1) {
            return Err(StorageError::StorageError(
                "Chain is divergent — only Cnt resolves an IEL".to_string(),
            ));
        }

        // Dedup: SAIDs already in the chain.
        let existing_saids: HashSet<cesr::Digest256> = {
            let saids: Vec<String> = events.iter().map(|e| e.said.to_string()).collect();
            let query =
                verifiable_storage_postgres::Query::<IdentityEvent>::for_table(Self::TABLE_NAME)
                    .r#in("said", saids);
            tx.fetch(query)
                .await?
                .into_iter()
                .map(|e: IdentityEvent| e.said)
                .collect()
        };

        // Occupied versions for overlap detection.
        let mut occupied_versions: HashSet<u64> = {
            let batch_versions: Vec<i64> = events
                .iter()
                .map(|e| e.version as i64)
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            let query = ColumnQuery::new(Self::TABLE_NAME, "version")
                .eq("prefix", &prefix)
                .r#in("version", batch_versions);
            tx.fetch_column_i64(query)
                .await?
                .into_iter()
                .map(|v| v as u64)
                .collect()
        };

        let mut count = 0u32;
        for event in events {
            if existing_saids.contains(&event.said) {
                continue;
            }

            if occupied_versions.contains(&event.version) {
                if let Some(gp_version) = last_governance_version
                    && event.version <= gp_version
                {
                    return Err(StorageError::StorageError(format!(
                        "Cannot fork at version {} — sealed by governance evaluation at version {}",
                        event.version, gp_version,
                    )));
                }
                self.insert_in(tx, event.clone()).await?;
                count += 1;
                return Ok(SaveBatchResult::DivergenceCreated {
                    new_count: count,
                    diverged_at_version: event.version,
                });
            }

            self.insert_in(tx, event.clone()).await?;
            occupied_versions.insert(event.version);
            count += 1;
        }

        Ok(SaveBatchResult::Accepted { new_count: count })
    }

    /// Insert a single event under a caller-managed transaction without the
    /// divergent-chain check. Used by the contest path where `Cnt` is the
    /// only allowed event on a divergent chain. Caller must hold an advisory
    /// lock on the prefix and must have verified the event is structurally
    /// valid + governance-authorized.
    pub async fn insert_event<Tx: TransactionExecutor>(
        &self,
        tx: &mut Tx,
        event: &IdentityEvent,
    ) -> Result<(), StorageError> {
        self.insert_in(tx, event.clone()).await?;
        Ok(())
    }

    /// Lowest version at which more than one event exists for this prefix, or
    /// `None` if every version is single-rowed. Same shape as
    /// `SadEventRepository::first_divergent_version`.
    pub async fn first_divergent_version(
        &self,
        prefix: &cesr::Digest256,
    ) -> Result<Option<u64>, StorageError> {
        let row: Option<i64> = sqlx::query_scalar(
            "SELECT MIN(version) FROM (\
                SELECT version FROM iel_events \
                WHERE prefix = $1 \
                GROUP BY version HAVING COUNT(*) > 1\
             ) AS divergent_versions",
        )
        .bind(prefix.to_string())
        .fetch_optional(self.pool.inner())
        .await
        .map_err(|e| StorageError::StorageError(e.to_string()))?
        .flatten();
        Ok(row.map(|v| v as u64))
    }

    /// Version of the most recent `Evl` event on the chain (the evaluation
    /// seal). `Cnt` and `Dec` are terminal and do NOT advance the seal.
    pub async fn last_governance_version<Tx: TransactionExecutor>(
        &self,
        tx: &mut Tx,
        prefix: &cesr::Digest256,
    ) -> Result<Option<u64>, StorageError> {
        let query =
            verifiable_storage_postgres::Query::<IdentityEvent>::for_table(Self::TABLE_NAME)
                .eq("prefix", prefix)
                .eq("kind", IdentityEventKind::Evl.as_str())
                .order_by("version", verifiable_storage::Order::Desc)
                .limit(1);
        let events: Vec<IdentityEvent> = tx.fetch(query).await?;
        Ok(events.first().map(|e| e.version))
    }

    /// True iff the chain has any `Cnt` event.
    pub async fn is_contested(&self, prefix: &cesr::Digest256) -> Result<bool, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let query =
            verifiable_storage_postgres::Query::<IdentityEvent>::for_table(Self::TABLE_NAME)
                .eq("prefix", prefix)
                .eq("kind", IdentityEventKind::Cnt.as_str())
                .limit(1);
        Ok(!self.pool.fetch(query).await?.is_empty())
    }

    /// True iff the chain has any `Dec` event.
    pub async fn is_decommissioned(&self, prefix: &cesr::Digest256) -> Result<bool, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let query =
            verifiable_storage_postgres::Query::<IdentityEvent>::for_table(Self::TABLE_NAME)
                .eq("prefix", prefix)
                .eq("kind", IdentityEventKind::Dec.as_str())
                .limit(1);
        Ok(!self.pool.fetch(query).await?.is_empty())
    }

    /// True iff any version on this prefix has more than one event.
    pub async fn is_divergent(&self, prefix: &cesr::Digest256) -> Result<bool, StorageError> {
        let query = ColumnQuery::new(Self::TABLE_NAME, "*")
            .filter(Filter::Eq(
                "prefix".to_string(),
                Value::String(prefix.to_string()),
            ))
            .group_by("version")
            .limit(1);
        let counts: Vec<i64> = self.pool.fetch_grouped_count(query).await?;
        Ok(counts.first().is_some_and(|&c| c > 1))
    }

    /// True iff an event with the given SAID exists.
    pub async fn event_exists(&self, said: &cesr::Digest256) -> Result<bool, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let query =
            verifiable_storage_postgres::Query::<IdentityEvent>::for_table(Self::TABLE_NAME)
                .eq("said", said.as_ref())
                .limit(1);
        Ok(!self.pool.fetch(query).await?.is_empty())
    }

    /// Get IEL events for a prefix, ordered
    /// `(version ASC, kind sort_priority ASC, said ASC)` with optional
    /// exclusive `since_said` cursor and limit. Same shape as
    /// `SadEventRepository::get_stored_in`.
    /// Non-transactional companion to [`Self::fetch_iel_page`] using
    /// `&self.pool` directly. Used by in-process readers that don't hold
    /// a transaction (e.g. `RepositoryIelResolver` walking the IEL to
    /// answer `is_satisfied` from inside the SE submit handler — the SE
    /// submit's tx isolates SE state, but IEL state is read-only here so
    /// pool reads are appropriate).
    ///
    /// Same semantics as the transactional variant: ordered
    /// `(version ASC, kind sort_priority ASC, said ASC)`; `since_said`
    /// is exclusive; post-filters to strict-greater-than on the canonical
    /// tuple (so duplicates at the cursor's version are dropped).
    pub async fn fetch_iel_page_pool(
        &self,
        selector: IelChainSelector<'_>,
        since_said: Option<&str>,
        limit: Option<u64>,
    ) -> Result<Vec<IdentityEvent>, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let since_position: Option<(u64, IdentityEventKind, cesr::Digest256)> = if let Some(said) =
            since_said
        {
            let cursor_query =
                verifiable_storage_postgres::Query::<IdentityEvent>::for_table(Self::TABLE_NAME)
                    .eq("said", said)
                    .limit(1);
            self.pool
                .fetch(cursor_query)
                .await?
                .into_iter()
                .next()
                .map(|r| (r.version, r.kind, r.said))
        } else {
            None
        };

        let mut query =
            verifiable_storage_postgres::Query::<IdentityEvent>::for_table(Self::TABLE_NAME)
                .filter(selector.prefix_filter(Self::TABLE_NAME))
                .order_by("version", verifiable_storage_postgres::Order::Asc)
                .order_by_case(
                    "kind",
                    &IdentityEventKind::sort_priority_mapping(),
                    verifiable_storage_postgres::Order::Asc,
                )
                .order_by("said", verifiable_storage_postgres::Order::Asc);

        if let Some((version, _, _)) = &since_position {
            query = query.gte("version", *version);
        }

        if let Some(limit) = limit {
            let fetch_limit = if since_position.is_some() {
                limit + 2
            } else {
                limit
            };
            query = query.limit(fetch_limit);
        }

        let mut events: Vec<IdentityEvent> = self.pool.fetch(query).await?;

        if let Some((version, kind, said)) = &since_position {
            let skipped = events.len();
            let since_priority = kind.sort_priority();
            events.retain(|e| {
                let e_priority = e.kind.sort_priority();
                e.version > *version
                    || (e.version == *version && e_priority > since_priority)
                    || (e.version == *version && e_priority == since_priority && e.said > *said)
            });
            let skipped = skipped - events.len();
            if skipped > 2 {
                return Err(StorageError::StorageError(format!(
                    "IEL chain integrity violation: {} events skipped at version {} for {} — possible DB tampering",
                    skipped,
                    version,
                    selector.label()
                )));
            }

            if let Some(limit) = limit {
                events.truncate(limit as usize);
            }
        }

        Ok(events)
    }

    pub async fn fetch_iel_page<Tx: TransactionExecutor>(
        &self,
        tx: &mut Tx,
        selector: IelChainSelector<'_>,
        since_said: Option<&str>,
        limit: Option<u64>,
    ) -> Result<Vec<IdentityEvent>, StorageError> {
        let since_position: Option<(u64, IdentityEventKind, cesr::Digest256)> = if let Some(said) =
            since_said
        {
            let cursor_query =
                verifiable_storage_postgres::Query::<IdentityEvent>::for_table(Self::TABLE_NAME)
                    .eq("said", said)
                    .limit(1);
            tx.fetch(cursor_query)
                .await?
                .into_iter()
                .next()
                .map(|r| (r.version, r.kind, r.said))
        } else {
            None
        };

        let mut query =
            verifiable_storage_postgres::Query::<IdentityEvent>::for_table(Self::TABLE_NAME)
                .filter(selector.prefix_filter(Self::TABLE_NAME))
                .order_by("version", verifiable_storage_postgres::Order::Asc)
                .order_by_case(
                    "kind",
                    &IdentityEventKind::sort_priority_mapping(),
                    verifiable_storage_postgres::Order::Asc,
                )
                .order_by("said", verifiable_storage_postgres::Order::Asc);

        if let Some((version, _, _)) = &since_position {
            query = query.gte("version", *version);
        }

        if let Some(limit) = limit {
            let fetch_limit = if since_position.is_some() {
                limit + 2
            } else {
                limit
            };
            query = query.limit(fetch_limit);
        }

        let mut events: Vec<IdentityEvent> = tx.fetch(query).await?;

        if let Some((version, kind, said)) = &since_position {
            let skipped = events.len();
            let since_priority = kind.sort_priority();
            events.retain(|e| {
                let e_priority = e.kind.sort_priority();
                e.version > *version
                    || (e.version == *version && e_priority > since_priority)
                    || (e.version == *version && e_priority == since_priority && e.said > *said)
            });
            let skipped = skipped - events.len();
            if skipped > 2 {
                return Err(StorageError::StorageError(format!(
                    "IEL chain integrity violation: {} events skipped at version {} for {} — possible DB tampering",
                    skipped,
                    version,
                    selector.label()
                )));
            }

            if let Some(limit) = limit {
                events.truncate(limit as usize);
            }
        }

        Ok(events)
    }

    /// Get the effective SAID for an IEL prefix.
    ///
    /// - Decommissioned → the `Dec` event's SAID (mirrors KEL `dec` shape).
    /// - Contested → `hash_effective_said("contested:{prefix}")`.
    /// - Divergent (non-terminal) → `hash_effective_said("divergent:{prefix}")`.
    /// - Linear → tip event SAID.
    /// - Empty → `None`.
    pub async fn effective_said(
        &self,
        prefix: &cesr::Digest256,
    ) -> Result<Option<(cesr::Digest256, bool)>, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        // Decommissioned takes precedence: the Dec event itself is the
        // effective SAID. (A Dec lands on a non-divergent chain by routing
        // rule, so we don't need to gate on divergence here.)
        let dec_query =
            verifiable_storage_postgres::Query::<IdentityEvent>::for_table(Self::TABLE_NAME)
                .eq("prefix", prefix)
                .eq("kind", IdentityEventKind::Dec.as_str())
                .order_by("version", verifiable_storage::Order::Desc)
                .limit(1);
        let dec: Vec<IdentityEvent> = self.pool.fetch(dec_query).await?;
        if let Some(dec_event) = dec.first() {
            return Ok(Some((dec_event.said, false)));
        }

        if self.is_contested(prefix).await? {
            let said = kels_core::hash_effective_said(&format!("contested:{}", prefix));
            return Ok(Some((said, true)));
        }

        if self.is_divergent(prefix).await? {
            let said = kels_core::hash_effective_said(&format!("divergent:{}", prefix));
            return Ok(Some((said, true)));
        }

        let latest = self.get_latest(prefix).await?;
        Ok(latest.map(|e| (e.said, false)))
    }

    /// List IEL prefixes with their effective SAIDs, paginated.
    ///
    /// Mirrors `SadEventRepository::list_prefixes`: `distinct_on(prefix)`
    /// over the chain table to grab one row per prefix at the highest
    /// version, then a three-pass terminal-state-aware effective-SAID
    /// resolution (Dec → contested → divergent → linear tip). Used by
    /// gossip bootstrap and anti-entropy IEL phases (#172).
    pub async fn list_prefixes(
        &self,
        cursor: Option<&cesr::Digest256>,
        limit: usize,
    ) -> Result<kels_core::PrefixListResponse, StorageError> {
        use verifiable_storage_postgres::QueryExecutor;

        let mut query =
            verifiable_storage_postgres::Query::<IdentityEvent>::for_table(Self::TABLE_NAME)
                .distinct_on("prefix")
                .order_by("prefix", verifiable_storage_postgres::Order::Asc)
                .order_by("version", verifiable_storage_postgres::Order::Desc)
                .limit(limit as u64 + 1);

        if let Some(cursor) = cursor {
            query = query.gt("prefix", cursor.as_ref());
        }

        let events: Vec<IdentityEvent> = self.pool.fetch(query).await?;

        let mut prefix_states: Vec<kels_core::PrefixState> = events
            .into_iter()
            .map(|e| kels_core::PrefixState {
                prefix: e.prefix,
                said: e.said,
            })
            .collect();

        let next_cursor = if prefix_states.len() > limit {
            prefix_states.pop();
            prefix_states.last().map(|s| s.prefix)
        } else if let Some(cursor) = cursor {
            let remaining = limit - prefix_states.len();
            if remaining > 0 {
                let wrap_query = verifiable_storage_postgres::Query::<IdentityEvent>::for_table(
                    Self::TABLE_NAME,
                )
                .distinct_on("prefix")
                .order_by("prefix", verifiable_storage_postgres::Order::Asc)
                .order_by("version", verifiable_storage_postgres::Order::Desc)
                .lte("prefix", cursor.as_ref())
                .limit(remaining as u64);
                let wrap_events: Vec<IdentityEvent> = self.pool.fetch(wrap_query).await?;
                prefix_states.extend(wrap_events.into_iter().map(|e| kels_core::PrefixState {
                    prefix: e.prefix,
                    said: e.said,
                }));
            }
            None
        } else {
            None
        };

        // Terminal-state-aware effective-SAID resolution. Apply
        // precedence per prefix in three batch passes (matches the
        // `effective_said` order):
        //   1. Decommissioned: replace SAID with the prefix's `Dec` SAID.
        //   2. Contested (and not already decommissioned): synthetic
        //      `contested:{prefix}` hash.
        //   3. Divergent (and neither of the above): synthetic
        //      `divergent:{prefix}` hash.
        // The default (linear) tip SAID is already populated from the
        // distinct_on query above.
        let page_prefixes: Vec<String> =
            prefix_states.iter().map(|s| s.prefix.to_string()).collect();

        // Pass 1 — Dec SAIDs per prefix (latest Dec wins).
        let dec_query =
            verifiable_storage_postgres::Query::<IdentityEvent>::for_table(Self::TABLE_NAME)
                .r#in("prefix", page_prefixes.clone())
                .eq("kind", IdentityEventKind::Dec.as_str())
                .order_by("version", verifiable_storage::Order::Desc);
        let dec_events: Vec<IdentityEvent> = self.pool.fetch(dec_query).await?;
        let mut dec_by_prefix: std::collections::HashMap<cesr::Digest256, cesr::Digest256> =
            std::collections::HashMap::new();
        for ev in dec_events {
            dec_by_prefix.entry(ev.prefix).or_insert(ev.said);
        }

        // Pass 2 — set of prefixes with at least one Cnt event.
        let cnt_query =
            verifiable_storage_postgres::Query::<IdentityEvent>::for_table(Self::TABLE_NAME)
                .r#in("prefix", page_prefixes.clone())
                .eq("kind", IdentityEventKind::Cnt.as_str());
        let cnt_events: Vec<IdentityEvent> = self.pool.fetch(cnt_query).await?;
        let contested_prefixes: HashSet<cesr::Digest256> =
            cnt_events.into_iter().map(|e| e.prefix).collect();

        // Pass 3 — divergent prefixes (any version with >1 row).
        let divergent_query = ColumnQuery::new(Self::TABLE_NAME, "prefix")
            .distinct()
            .r#in("prefix", page_prefixes)
            .group_by("prefix")
            .group_by("version")
            .having_count_gt(1);
        let divergent_prefixes: HashSet<String> = self
            .pool
            .fetch_column(divergent_query)
            .await?
            .into_iter()
            .collect();

        for state in &mut prefix_states {
            if let Some(dec_said) = dec_by_prefix.get(&state.prefix) {
                state.said = *dec_said;
            } else if contested_prefixes.contains(&state.prefix) {
                state.said = kels_core::hash_effective_said(&format!("contested:{}", state.prefix));
            } else if divergent_prefixes.contains(state.prefix.as_ref()) {
                state.said = kels_core::hash_effective_said(&format!("divergent:{}", state.prefix));
            }
        }

        Ok(kels_core::PrefixListResponse {
            prefixes: prefix_states,
            next_cursor,
        })
    }
}

#[derive(Stored)]
#[stored(migrations = "migrations")]
pub struct SadStoreRepository {
    pub sad_events: SadEventRepository,
    pub sad_objects: SadObjectIndex,
    pub policies: PolicyRepository,
    pub iel_events: IdentityEventRepository,
}
