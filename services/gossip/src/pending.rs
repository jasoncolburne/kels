//! #156: Redis-backed pending map for the deferred-deps protocol.
//!
//! When sadstore returns a typed 422 deferred-deps response on an inbound
//! gossip POST, gossip parks the message here and replays via the existing
//! pubsub subscribers (kel/iel/sad updates) when the awaited deps commit.
//!
//! ## Wire shape
//!
//! Primary record (source of truth):
//! ```text
//! pending:msg:{record.said}    → JSON of ParkRecord                                (SET)
//! ```
//!
//! Secondary indexes:
//! ```text
//! pending:said:{S}             → set of {record.said} waiting on SAD object SAID S (SADD)
//! pending:chain:{prefix}       → list of [record.said, eff_said_at_park]           (RPUSH)
//! ```
//!
//! - `pending:said:{S}` indexes parks waiting on a SAD object commit
//!   (`SadObject` deps).
//! - `pending:chain:{prefix}` indexes every park whose deps reference a
//!   chain (`KelAnchor`, `IelEvent`, `TransientChain`). Per-event commits
//!   and chain-state transitions both drive drain through this index via
//!   synthetic-SAID comparison.
//!
//! ## Park sequence (write-order invariant)
//!
//! Secondaries before primary so a mid-park crash leaves an orphaned
//! primary (TTLs out cleanly) rather than orphaned secondaries (which
//! would trigger spurious primary lookups during drain).
//!
//! ## Cleanup order
//!
//! `GET primary → enumerate record.deps → SREM/LREM each secondary →
//! DEL primary`. Secondaries-before-primary so a mid-cleanup crash leaves
//! an orphaned primary that TTLs out cleanly.

use std::collections::BTreeSet;
use std::sync::Arc;

use kels_core::KelsError;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;
use verifiable_storage::SelfAddressed;

/// What the parked gossip message is — replayable subject.
///
/// Replay routes by variant:
/// - `IelChain` / `SelChain` → `forward_*_events(prefix, remote_source(record.origin), local_sink, ..)`.
/// - `SadObject` → `remote_client(record.origin).get_sad_object(said)` then `local_client.post_sad_object(&obj)`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ParkSubject {
    IelChain {
        prefix: cesr::Digest256,
        remote_eff_said: cesr::Digest256,
    },
    SelChain {
        prefix: cesr::Digest256,
        remote_eff_said: cesr::Digest256,
    },
    SadObject {
        said: cesr::Digest256,
    },
}

/// A specific deferrable dep the parked message is waiting on.
///
/// `BTreeSet<DepRef>` is the canonical container; deterministic ordering
/// (variant declaration order: `KelAnchor < IelEvent < SadObject <
/// TransientChain`) is load-bearing for `ParkRecord.said` determinism.
/// **Do not reorder these variants** — every existing parked record's
/// SAID would shift, breaking drain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DepRef {
    KelAnchor {
        kel_prefix: cesr::Digest256,
        anchor_said: cesr::Digest256,
    },
    IelEvent {
        iel_prefix: cesr::Digest256,
        event_said: cesr::Digest256,
    },
    SadObject {
        said: cesr::Digest256,
    },
    TransientChain {
        prefix: cesr::Digest256,
        eff_said_at_park: cesr::Digest256,
    },
}

impl DepRef {
    /// The chain prefix this dep references, for `pending:chain:{prefix}`
    /// enrolment. Returns `None` for `SadObject` (which goes in
    /// `pending:said:{S}` instead).
    pub fn chain_prefix(&self) -> Option<cesr::Digest256> {
        match self {
            Self::KelAnchor { kel_prefix, .. } => Some(*kel_prefix),
            Self::IelEvent { iel_prefix, .. } => Some(*iel_prefix),
            Self::TransientChain { prefix, .. } => Some(*prefix),
            Self::SadObject { .. } => None,
        }
    }

    /// The SAD object SAID this dep references, for `pending:said:{S}`
    /// enrolment. Returns `None` for chain-referencing variants.
    pub fn sad_object_said(&self) -> Option<cesr::Digest256> {
        match self {
            Self::SadObject { said } => Some(*said),
            _ => None,
        }
    }
}

/// SelfAddressed park record. The `said` field is computed from the rest
/// of the struct via `ParkRecord::create()`.
///
/// Idempotent park: two inbound gossip messages for the same
/// `(subject, origin, deps)` produce the same `said` and collapse to a
/// single park. A different `remote_eff_said` (chain advanced upstream
/// while we waited) produces a different `said` and parks distinctly,
/// which is correct.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ParkRecord {
    #[said]
    pub said: cesr::Digest256,
    pub subject: ParkSubject,
    /// Peer KEL prefix; replay re-fetches from this peer's sadstore.
    pub origin: cesr::Digest256,
    /// Canonical-ordered set of awaited deps. Drives both indexes and
    /// the primary's content-derived SAID.
    pub deps: BTreeSet<DepRef>,
}

/// #156: pending-map errors that aren't `KelsError`-shaped.
#[derive(Debug, Error)]
pub enum PendingError {
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("Serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("ParkRecord SAID verification failed (tampered or partial-write garbage)")]
    SaidVerificationFailed,
    #[error("Operational error: {0}")]
    Operational(String),
}

impl From<KelsError> for PendingError {
    fn from(e: KelsError) -> Self {
        Self::Operational(e.to_string())
    }
}

/// Default TTL for pending entries. Spec §Synthetic dispatch line 194
/// pins 5 minutes; configurable via `KELS_PENDING_TTL_SECS`.
fn default_ttl_secs() -> u64 {
    kels_core::env_usize("KELS_PENDING_TTL_SECS", 300) as u64
}

/// Redis-backed pending map for #156's deferred-deps protocol.
///
/// All operations are idempotent at the Redis level; concurrent drains
/// for the same parked record race-resolve via `GET pending:msg:{said}`
/// returning empty after the first cleanup completes.
#[derive(Clone)]
pub struct PendingMap {
    redis: Arc<redis::aio::ConnectionManager>,
    ttl_secs: u64,
}

impl PendingMap {
    pub fn new(redis: Arc<redis::aio::ConnectionManager>) -> Self {
        Self {
            redis,
            ttl_secs: default_ttl_secs(),
        }
    }

    /// Build the key for `pending:msg:{said}`.
    fn primary_key(said: &cesr::Digest256) -> String {
        format!("pending:msg:{}", said)
    }

    /// Build the key for `pending:said:{S}`.
    fn sad_secondary_key(sad_said: &cesr::Digest256) -> String {
        format!("pending:said:{}", sad_said)
    }

    /// Build the key for `pending:chain:{prefix}`.
    fn chain_secondary_key(prefix: &cesr::Digest256) -> String {
        format!("pending:chain:{}", prefix)
    }

    /// Encode a `pending:chain:*` list element. Wire shape: `"{record.said}|{eff_said_at_park}"`.
    fn encode_chain_entry(
        record_said: &cesr::Digest256,
        eff_said_at_park: &cesr::Digest256,
    ) -> String {
        format!("{}|{}", record_said, eff_said_at_park)
    }

    /// Decode a `pending:chain:*` list element. Returns `(record.said,
    /// eff_said_at_park)` or an error if the element is malformed.
    fn decode_chain_entry(s: &str) -> Result<(cesr::Digest256, cesr::Digest256), PendingError> {
        use cesr::Matter;
        let (record_said_s, eff_said_s) = s
            .split_once('|')
            .ok_or_else(|| PendingError::Operational(format!("malformed chain entry: {}", s)))?;
        let record_said = cesr::Digest256::from_qb64(record_said_s).map_err(|e| {
            PendingError::Operational(format!("bad record_said in chain entry: {}", e))
        })?;
        let eff_said = cesr::Digest256::from_qb64(eff_said_s).map_err(|e| {
            PendingError::Operational(format!("bad eff_said in chain entry: {}", e))
        })?;
        Ok((record_said, eff_said))
    }

    /// Park a record. Writes secondaries first (SADD for `SadObject`
    /// deps, RPUSH for chain prefixes), then the primary `pending:msg`.
    /// Each key gets `EXPIRE` set to `self.ttl_secs`.
    ///
    /// `chain_eff_said_for(prefix)` provides the `eff_said_at_park` for
    /// each chain prefix referenced by the record's deps. Caller derives
    /// these from the 422 response's `chain_eff_said` fields (one per
    /// chain-referencing dep) — we accept a closure rather than a HashMap
    /// to keep the call site flexible.
    pub async fn park(
        &self,
        record: &ParkRecord,
        chain_eff_said_for: impl Fn(&cesr::Digest256) -> Option<cesr::Digest256>,
    ) -> Result<(), PendingError> {
        use redis::AsyncCommands;
        let json = serde_json::to_string(record)?;
        let primary = Self::primary_key(&record.said);
        let mut conn = (*self.redis).clone();

        // Step 3: SAID-secondary enrolment for SadObject deps.
        for dep in &record.deps {
            if let Some(sad_said) = dep.sad_object_said() {
                let key = Self::sad_secondary_key(&sad_said);
                let _: () = conn.sadd(&key, record.said.to_string()).await?;
                let _: () = conn.expire(&key, self.ttl_secs as i64).await?;
            }
        }

        // Step 4: chain-secondary enrolment. Distinct chains get one
        // RPUSH each (multiple deps to the same chain produce a single
        // entry per park).
        let mut chain_prefixes: BTreeSet<cesr::Digest256> = BTreeSet::new();
        for dep in &record.deps {
            if let Some(prefix) = dep.chain_prefix() {
                chain_prefixes.insert(prefix);
            }
        }
        for prefix in &chain_prefixes {
            let key = Self::chain_secondary_key(prefix);
            let eff_said_at_park = chain_eff_said_for(prefix).ok_or_else(|| {
                PendingError::Operational(format!(
                    "chain_eff_said_for({}) returned None — caller invariant breach",
                    prefix
                ))
            })?;
            let entry = Self::encode_chain_entry(&record.said, &eff_said_at_park);
            let _: () = conn.rpush(&key, entry).await?;
            let _: () = conn.expire(&key, self.ttl_secs as i64).await?;
        }

        // Step 5: primary.
        let _: () = conn.set_ex(&primary, json, self.ttl_secs).await?;
        Ok(())
    }

    /// Read a parked record by SAID. Verifies the record's SAID against
    /// its content; returns `Ok(None)` if the key is missing (cleanup or
    /// orphan), `Err(SaidVerificationFailed)` on tamper/partial-write.
    pub async fn read_record(
        &self,
        record_said: &cesr::Digest256,
    ) -> Result<Option<ParkRecord>, PendingError> {
        use redis::AsyncCommands;
        let key = Self::primary_key(record_said);
        let mut conn = (*self.redis).clone();
        let value: Option<String> = conn.get(&key).await?;
        let Some(json) = value else {
            return Ok(None);
        };
        let record: ParkRecord = serde_json::from_str(&json)?;
        if record.verify_said().is_err() || &record.said != record_said {
            warn!(
                "pending:msg:{} failed SAID verification — drop and log",
                record_said
            );
            return Err(PendingError::SaidVerificationFailed);
        }
        Ok(Some(record))
    }

    /// Cleanup a parked record. Reads the primary (to enumerate deps),
    /// prunes each secondary, then deletes the primary. Idempotent —
    /// concurrent cleanups race-resolve at the GET step (returns empty
    /// for a record already cleaned).
    pub async fn cleanup_record(&self, record_said: &cesr::Digest256) -> Result<(), PendingError> {
        use redis::AsyncCommands;
        let mut conn = (*self.redis).clone();
        let key = Self::primary_key(record_said);
        let value: Option<String> = conn.get(&key).await?;
        let Some(json) = value else {
            return Ok(());
        };
        let record: ParkRecord = match serde_json::from_str(&json) {
            Ok(r) => r,
            Err(e) => {
                // Garbage primary; drop without touching secondaries —
                // they'll TTL out independently.
                warn!(
                    "pending:msg:{} JSON parse failed — drop and log: {}",
                    record_said, e
                );
                let _: () = conn.del(&key).await?;
                return Ok(());
            }
        };

        // Prune SAD-object secondaries.
        for dep in &record.deps {
            if let Some(sad_said) = dep.sad_object_said() {
                let sec = Self::sad_secondary_key(&sad_said);
                let _: () = conn.srem(&sec, record.said.to_string()).await?;
            }
        }

        // Prune chain secondaries. Re-derive `eff_said_at_park` from the
        // dep's `TransientChain.eff_said_at_park` field where present;
        // for KelAnchor/IelEvent deps, the chain entry's eff_said is the
        // chain's effective SAID at park time which we don't carry on the
        // record itself — LREM by exact value would require fetching the
        // chain entry first. Instead, scan the list and remove any entry
        // whose `record.said` matches.
        let mut chain_prefixes: BTreeSet<cesr::Digest256> = BTreeSet::new();
        for dep in &record.deps {
            if let Some(prefix) = dep.chain_prefix() {
                chain_prefixes.insert(prefix);
            }
        }
        for prefix in &chain_prefixes {
            let sec = Self::chain_secondary_key(prefix);
            let entries: Vec<String> = conn.lrange(&sec, 0, -1).await?;
            for entry in entries {
                if let Ok((entry_said, _)) = Self::decode_chain_entry(&entry)
                    && entry_said == record.said
                {
                    let _: () = conn.lrem(&sec, 0, entry).await?;
                }
            }
        }

        // Delete primary last.
        let _: () = conn.del(&key).await?;
        Ok(())
    }

    /// Lookup parks waiting on a specific SAD object SAID. Drained on
    /// `sad_updates(S)` arrival.
    pub async fn parks_by_sad(
        &self,
        sad_said: &cesr::Digest256,
    ) -> Result<Vec<cesr::Digest256>, PendingError> {
        use redis::AsyncCommands;
        let key = Self::sad_secondary_key(sad_said);
        let mut conn = (*self.redis).clone();
        let saids: Vec<String> = conn.smembers(&key).await?;
        use cesr::Matter;
        let mut out = Vec::with_capacity(saids.len());
        for s in saids {
            match cesr::Digest256::from_qb64(&s) {
                Ok(d) => out.push(d),
                Err(e) => warn!("pending:said:{}: bad record_said {}: {}", sad_said, s, e),
            }
        }
        Ok(out)
    }

    /// #156 drain: refresh a parked record with new deps after a 422-on-replay.
    ///
    /// The replay returned a new typed-422 with refreshed dep set (some old
    /// deps may now be satisfied; new deps may have surfaced from the
    /// re-walked verifier). The new record carries a different SAID
    /// because the deps changed. Cleanup the old record (prunes
    /// secondaries + DELs primary), then park the new one (re-enrolls
    /// secondaries + SETs primary with refreshed TTL).
    ///
    /// Returns the new `ParkRecord` so the caller can keep replaying
    /// against the same identity for further drain attempts.
    pub async fn refresh(
        &self,
        old_record: &ParkRecord,
        new_deps: BTreeSet<DepRef>,
        chain_eff_said_for: impl Fn(&cesr::Digest256) -> Option<cesr::Digest256>,
    ) -> Result<ParkRecord, PendingError> {
        let new_record =
            ParkRecord::create(old_record.subject.clone(), old_record.origin, new_deps)
                .map_err(|e| PendingError::Operational(e.to_string()))?;
        // Same-SAID short-circuit: deps unchanged from the original park.
        // Skipping the cleanup+park keeps the original record's TTL intact
        // — without this, busy chains whose advances never satisfy a parked
        // record's deps would re-enter refresh on every advance and renew
        // the TTL indefinitely, blowing past the 5-minute eviction bound.
        if new_record.said == old_record.said {
            return Ok(new_record);
        }
        self.cleanup_record(&old_record.said).await?;
        self.park(&new_record, chain_eff_said_for).await?;
        Ok(new_record)
    }

    /// Lookup parks enrolled on a chain prefix. Drained on
    /// `kel_updates(K, _)` / `iel_updates(P, _)` arrival.
    /// Returns `(record.said, eff_said_at_park)` pairs.
    pub async fn parks_by_chain(
        &self,
        prefix: &cesr::Digest256,
    ) -> Result<Vec<(cesr::Digest256, cesr::Digest256)>, PendingError> {
        use redis::AsyncCommands;
        let key = Self::chain_secondary_key(prefix);
        let mut conn = (*self.redis).clone();
        let entries: Vec<String> = conn.lrange(&key, 0, -1).await?;
        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            match Self::decode_chain_entry(&entry) {
                Ok(pair) => out.push(pair),
                Err(e) => warn!("pending:chain:{}: bad entry {}: {}", prefix, entry, e),
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(label: &[u8]) -> cesr::Digest256 {
        cesr::Digest256::blake3_256(label)
    }

    fn sample_record(origin_label: &[u8]) -> ParkRecord {
        let mut deps: BTreeSet<DepRef> = BTreeSet::new();
        deps.insert(DepRef::KelAnchor {
            kel_prefix: d(b"kel-prefix"),
            anchor_said: d(b"anchor-said"),
        });
        deps.insert(DepRef::IelEvent {
            iel_prefix: d(b"iel-prefix"),
            event_said: d(b"iel-event-said"),
        });
        deps.insert(DepRef::SadObject { said: d(b"sad-1") });
        ParkRecord::create(
            ParkSubject::SadObject {
                said: d(b"target-sad"),
            },
            d(origin_label),
            deps,
        )
        .expect("create park record")
    }

    /// Same `(subject, origin, deps)` produces the same SAID — collapse
    /// to a single park, idempotently.
    #[test]
    fn park_record_said_is_deterministic() {
        let a = sample_record(b"origin-A");
        let b = sample_record(b"origin-A");
        assert_eq!(a.said, b.said);
    }

    /// Different `origin` produces a different SAID.
    #[test]
    fn park_record_said_differs_on_origin() {
        let a = sample_record(b"origin-A");
        let b = sample_record(b"origin-B");
        assert_ne!(a.said, b.said);
    }

    /// JSON round-trip preserves the SAID — caller's `verify_said` after
    /// `serde_json::from_str` matches the on-the-wire SAID.
    #[test]
    fn park_record_json_round_trip_preserves_said() {
        let record = sample_record(b"origin-rt");
        let json = serde_json::to_string(&record).expect("serialize");
        let recovered: ParkRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered.said, record.said);
        assert!(recovered.verify_said().is_ok());
    }

    /// `BTreeSet<DepRef>` enumeration order is canonical regardless of
    /// insertion order — two records constructed with the same logical
    /// dep set produce identical SAIDs even if deps are inserted in
    /// different orders.
    #[test]
    fn park_record_said_independent_of_dep_insertion_order() {
        let mut deps_a: BTreeSet<DepRef> = BTreeSet::new();
        deps_a.insert(DepRef::SadObject { said: d(b"s") });
        deps_a.insert(DepRef::IelEvent {
            iel_prefix: d(b"i"),
            event_said: d(b"e"),
        });
        deps_a.insert(DepRef::KelAnchor {
            kel_prefix: d(b"k"),
            anchor_said: d(b"a"),
        });

        let mut deps_b: BTreeSet<DepRef> = BTreeSet::new();
        deps_b.insert(DepRef::KelAnchor {
            kel_prefix: d(b"k"),
            anchor_said: d(b"a"),
        });
        deps_b.insert(DepRef::IelEvent {
            iel_prefix: d(b"i"),
            event_said: d(b"e"),
        });
        deps_b.insert(DepRef::SadObject { said: d(b"s") });

        let subject = ParkSubject::IelChain {
            prefix: d(b"p"),
            remote_eff_said: d(b"r"),
        };
        let origin = d(b"origin");

        let a = ParkRecord::create(subject.clone(), origin, deps_a).unwrap();
        let b = ParkRecord::create(subject, origin, deps_b).unwrap();
        assert_eq!(a.said, b.said);
    }

    /// `DepRef` `chain_prefix` / `sad_object_said` accessors return the
    /// right index target per variant.
    #[test]
    fn dep_ref_index_targets() {
        let kp = d(b"k-target");
        let ap = d(b"a-target");
        let ip = d(b"i-target");
        let ep = d(b"e-target");
        let sp = d(b"s-target");
        let tp = d(b"t-target");
        let tef = d(b"t-eff");

        let kel = DepRef::KelAnchor {
            kel_prefix: kp,
            anchor_said: ap,
        };
        assert_eq!(kel.chain_prefix(), Some(kp));
        assert_eq!(kel.sad_object_said(), None);

        let iel = DepRef::IelEvent {
            iel_prefix: ip,
            event_said: ep,
        };
        assert_eq!(iel.chain_prefix(), Some(ip));
        assert_eq!(iel.sad_object_said(), None);

        let sad = DepRef::SadObject { said: sp };
        assert_eq!(sad.chain_prefix(), None);
        assert_eq!(sad.sad_object_said(), Some(sp));

        let trans = DepRef::TransientChain {
            prefix: tp,
            eff_said_at_park: tef,
        };
        assert_eq!(trans.chain_prefix(), Some(tp));
        assert_eq!(trans.sad_object_said(), None);
    }

    /// Chain-entry encoding round-trips.
    #[test]
    fn chain_entry_round_trip() {
        let record_said = d(b"record");
        let eff = d(b"eff-at-park");
        let encoded = PendingMap::encode_chain_entry(&record_said, &eff);
        let (decoded_said, decoded_eff) = PendingMap::decode_chain_entry(&encoded).unwrap();
        assert_eq!(decoded_said, record_said);
        assert_eq!(decoded_eff, eff);
    }
}
