//! SAD (Self-Addressing Data) event types for the replicated SADStore.
//!
//! Two layers:
//! - **SAD objects** — content-addressed JSON blobs stored/retrieved by SAID (MinIO).
//! - **SAD events** — versioned event chains with deterministic prefix discovery
//!   and policy-based ownership. Each non-inception event references content in
//!   the SAD object store via `content`.
//!
//! The SEL prefix is derived from v0's `(write_policy SAID, topic)`. Prefix
//! derivation is fully deterministic: given the inception write_policy SAID
//! and topic, anyone can compute the SEL prefix offline. Write_policy can
//! evolve across versions.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use verifiable_storage::{Chained, SelfAddressed};

use crate::error::KelsError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SadEventKind {
    #[serde(rename = "kels/sad/v1/events/icp")]
    Icp, // Inception (v0)
    #[serde(rename = "kels/sad/v1/events/upd")]
    Upd, // Update
    #[serde(rename = "kels/sad/v1/events/est")]
    Est, // Establish (governance_policy declaration, no evaluation)
    #[serde(rename = "kels/sad/v1/events/evl")]
    Evl, // Evaluate (evaluated against governance_policy)
    #[serde(rename = "kels/sad/v1/events/rpr")]
    Rpr, // Repair (resolves divergence, evaluates governance_policy)
}

impl SadEventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Icp => "kels/sad/v1/events/icp",
            Self::Upd => "kels/sad/v1/events/upd",
            Self::Est => "kels/sad/v1/events/est",
            Self::Evl => "kels/sad/v1/events/evl",
            Self::Rpr => "kels/sad/v1/events/rpr",
        }
    }

    /// Short event kind name (e.g. "icp", "upd") as used by CLI tools and responses.
    pub fn short_name(&self) -> &'static str {
        match self {
            Self::Icp => "icp",
            Self::Upd => "upd",
            Self::Est => "est",
            Self::Evl => "evl",
            Self::Rpr => "rpr",
        }
    }

    /// Parse a short event kind name (e.g. "icp", "upd") as used by CLI tools.
    pub fn from_short_name(s: &str) -> Result<Self, KelsError> {
        match s {
            "icp" => Ok(Self::Icp),
            "upd" => Ok(Self::Upd),
            "est" => Ok(Self::Est),
            "evl" => Ok(Self::Evl),
            "rpr" => Ok(Self::Rpr),
            _ => Err(KelsError::VerificationFailed(format!(
                "Unknown event kind: {}",
                s
            ))),
        }
    }

    /// True for kinds that evaluate governance_policy (Evl, Rpr).
    /// These reset events_since_evaluation and update last_governance_version.
    pub fn evaluates_governance(&self) -> bool {
        matches!(self, Self::Evl | Self::Rpr)
    }

    /// True for repair events (Rpr only).
    pub fn is_repair(&self) -> bool {
        matches!(self, Self::Rpr)
    }

    /// True for inception events (Icp only).
    pub fn is_inception(&self) -> bool {
        matches!(self, Self::Icp)
    }

    /// Sort priority within the same version (lower = earlier in sorted order).
    /// State-determining events (Rpr) sort after normal events so that — under
    /// gossip-induced reordering or divergent generations — the canonical
    /// ordering converges on the most authoritative event. Mirrors KEL's
    /// `KeyEventKind::sort_priority` shape (`lib/kels/src/types/kel/event.rs:86-97`).
    pub fn sort_priority(&self) -> u8 {
        match self {
            Self::Icp => 0,
            Self::Est => 1,
            Self::Upd => 2,
            Self::Evl => 3,
            Self::Rpr => 4,
        }
    }

    const ALL: [Self; 5] = [Self::Icp, Self::Est, Self::Upd, Self::Evl, Self::Rpr];

    /// Returns the sort priority mapping for use with `order_by_case` in DB queries.
    /// Mirrors KEL's `KeyEventKind::sort_priority_mapping`.
    pub fn sort_priority_mapping() -> Vec<(&'static str, i64)> {
        Self::ALL
            .iter()
            .map(|k| (k.as_str(), k.sort_priority() as i64))
            .collect()
    }
}

impl fmt::Display for SadEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for SadEventKind {
    type Err = KelsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "kels/sad/v1/events/icp" => Ok(Self::Icp),
            "kels/sad/v1/events/upd" => Ok(Self::Upd),
            "kels/sad/v1/events/est" => Ok(Self::Est),
            "kels/sad/v1/events/evl" => Ok(Self::Evl),
            "kels/sad/v1/events/rpr" => Ok(Self::Rpr),
            _ => Err(KelsError::VerificationFailed(format!(
                "Unknown event kind: {}",
                s
            ))),
        }
    }
}

/// A chained, self-addressed event in the SADStore.
///
/// The v0 (inception) event has `content: None` — this makes the prefix
/// fully deterministic from `write_policy` + `topic` alone. Content is added in v1+.
///
/// No `created_at` field — intentionally omitted so inception events are fully
/// deterministic for prefix computation.
///
/// Authorization is via the anchoring model: `write_policy` is consumer-side,
/// endorsing parties anchor the event's SAID in their KELs.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "sad_events")]
#[serde(rename_all = "camelCase")]
pub struct SadEvent {
    #[said]
    pub said: cesr::Digest256,
    #[prefix]
    pub prefix: cesr::Digest256,
    #[previous]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub previous: Option<cesr::Digest256>,
    #[version]
    pub version: u64,
    /// The topic of this event chain (e.g., `"kels/sad/v1/keys/mlkem"`).
    pub topic: String,
    /// The event kind.
    pub kind: SadEventKind,
    /// SAID of the content object in the SAD store (None for v0 inception).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub content: Option<cesr::Digest256>,
    /// SAID of the custody SAD (optional, controls readPolicy/nodes for the chain).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub custody: Option<cesr::Digest256>,
    /// SAID of the write policy (denormalized from custody for chain keying).
    /// Required on `Icp` (prefix derivation) and optional on `Evl` (policy evolution).
    /// Forbidden on `Est`, `Upd`, `Rpr`. Absence on `Evl` means "pure evaluation,
    /// no policy change" — verifier inherits the tracked policy from branch state.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub write_policy: Option<cesr::Digest256>,
    /// SAID of the governance policy — a higher-threshold policy that bounds
    /// divergence. An attacker who satisfies write_policy but can't satisfy
    /// governance_policy has their fork bounded to ≤63 events.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub governance_policy: Option<cesr::Digest256>,
}

/// Compute the SAD Event Log prefix for a given write policy SAID and topic.
///
/// Anyone can call this offline — no server needed. The prefix is derived from
/// the v0 inception event content (with said+prefix as placeholders), which
/// contains only deterministic fields.
///
/// Routes through `SadEvent::icp` so prefix derivation and v0 staging share
/// exactly the same structural-validation gate — a future tightening of Icp's
/// rules surfaces uniformly across both paths. The cost is one extra Blake3
/// hash (the SAID derivation, whose result we discard) plus `validate_structure`.
/// If profiling later shows this on a hot path (e.g., bulk identity-chain
/// lookup), factor a private prefix-only helper that `SadEvent::icp` also calls.
pub fn compute_sad_event_prefix(
    write_policy: cesr::Digest256,
    topic: impl Into<String>,
) -> Result<cesr::Digest256, KelsError> {
    Ok(SadEvent::icp(topic, write_policy, None)?.prefix)
}

impl SadEvent {
    /// Build a v0 `Icp` (inception) event.
    ///
    /// `governance_policy` is `Option` because declaring it on v0 makes the
    /// chain prefix depend on it — chains that need prefix recomputation
    /// from `(topic, write_policy)` alone (exchange keys, identity chains,
    /// any lookup-driven flow) pass `None` here and declare governance via
    /// a v1 `Est` instead. See `SadEventBuilder::incept` vs
    /// `incept_deterministic` for the two flows.
    ///
    /// Runs `validate_structure` before returning, matching the staging
    /// contract in `SadEventBuilder` and the prefix-derivation invariant in
    /// `compute_sad_event_prefix`. A future tightening of Icp's structural
    /// rules surfaces here rather than at server-side verification.
    pub fn icp(
        topic: impl Into<String>,
        write_policy: cesr::Digest256,
        governance_policy: Option<cesr::Digest256>,
    ) -> Result<Self, KelsError> {
        let event = Self::create(
            topic.into(),
            SadEventKind::Icp,
            None,
            None,
            Some(write_policy),
            governance_policy,
        )?;
        event
            .validate_structure()
            .map_err(KelsError::InvalidKeyEvent)?;
        Ok(event)
    }

    /// Build a v1 `Est` (governance establishment) event from a v0 `Icp` tip.
    ///
    /// `governance_policy` is required (Est's purpose is to declare it).
    /// `content` is optional. The new event inherits the chain prefix and
    /// links to the previous event via `increment()`. Runs `validate_structure`
    /// before returning.
    pub fn est(
        previous: &Self,
        content: Option<cesr::Digest256>,
        governance_policy: cesr::Digest256,
    ) -> Result<Self, KelsError> {
        let mut event = previous.clone();
        event.content = content;
        event.kind = SadEventKind::Est;
        event.write_policy = None;
        event.governance_policy = Some(governance_policy);
        event.increment()?;
        event
            .validate_structure()
            .map_err(KelsError::InvalidKeyEvent)?;
        Ok(event)
    }

    /// Build a v+1 `Upd` event from a chain tip. `content` is required.
    pub fn upd(previous: &Self, content: cesr::Digest256) -> Result<Self, KelsError> {
        let mut event = previous.clone();
        event.content = Some(content);
        event.kind = SadEventKind::Upd;
        event.write_policy = None;
        event.governance_policy = None;
        event.increment()?;
        event
            .validate_structure()
            .map_err(KelsError::InvalidKeyEvent)?;
        Ok(event)
    }

    /// Build a v+1 `Evl` (governance evaluation) event from a chain tip.
    ///
    /// All three fields are optional — all-`None` is a legal pure
    /// evaluation that resets the events-since-evaluation counter without
    /// changing tracked state. `Some(write_policy)` is policy evolution.
    /// `Some(governance_policy)` is governance evolution (Evl is the only
    /// kind that allows it post-establishment).
    pub fn evl(
        previous: &Self,
        content: Option<cesr::Digest256>,
        write_policy: Option<cesr::Digest256>,
        governance_policy: Option<cesr::Digest256>,
    ) -> Result<Self, KelsError> {
        let mut event = previous.clone();
        event.content = content;
        event.kind = SadEventKind::Evl;
        event.write_policy = write_policy;
        event.governance_policy = governance_policy;
        event.increment()?;
        event
            .validate_structure()
            .map_err(KelsError::InvalidKeyEvent)?;
        Ok(event)
    }

    /// Build a v+1 `Rpr` (repair) event from a chain tip. `content` is
    /// optional. Rpr forbids both `write_policy` and `governance_policy`
    /// (validated by `validate_structure`).
    pub fn rpr(previous: &Self, content: Option<cesr::Digest256>) -> Result<Self, KelsError> {
        let mut event = previous.clone();
        event.content = content;
        event.kind = SadEventKind::Rpr;
        event.write_policy = None;
        event.governance_policy = None;
        event.increment()?;
        event
            .validate_structure()
            .map_err(KelsError::InvalidKeyEvent)?;
        Ok(event)
    }

    /// Validates that the event has the correct fields for its kind.
    /// Returns Ok(()) if valid, Err with description if invalid.
    pub fn validate_structure(&self) -> Result<(), String> {
        let require = |name: &str, present: bool| -> Result<(), String> {
            if present {
                Ok(())
            } else {
                Err(format!("{} event requires {}", self.kind, name))
            }
        };
        let forbid = |name: &str, present: bool| -> Result<(), String> {
            if present {
                Err(format!("{} event must not have {}", self.kind, name))
            } else {
                Ok(())
            }
        };

        match self.kind {
            SadEventKind::Icp => {
                if self.version != 0 {
                    return Err(format!(
                        "Icp event must have version 0, got {}",
                        self.version
                    ));
                }
                require("writePolicy", self.write_policy.is_some())?;
                forbid("previous", self.previous.is_some())?;
                forbid("content", self.content.is_some())?;
                // governance_policy is optional (non-discoverable chains may declare at v0)
            }
            SadEventKind::Est => {
                if self.version != 1 {
                    return Err(format!(
                        "Est event must have version 1, got {}",
                        self.version
                    ));
                }
                require("previous", self.previous.is_some())?;
                require("governancePolicy", self.governance_policy.is_some())?;
                forbid("writePolicy", self.write_policy.is_some())?;
            }
            SadEventKind::Upd => {
                if self.version < 1 {
                    return Err(format!(
                        "Upd event must have version >= 1, got {}",
                        self.version
                    ));
                }
                require("previous", self.previous.is_some())?;
                forbid("governancePolicy", self.governance_policy.is_some())?;
                forbid("writePolicy", self.write_policy.is_some())?;
            }
            SadEventKind::Evl => {
                if self.version < 1 {
                    return Err(format!(
                        "Evl event must have version >= 1, got {}",
                        self.version
                    ));
                }
                require("previous", self.previous.is_some())?;
                // write_policy optional — present = policy evolution, absent = pure evaluation
                // governance_policy optional — allows policy evolution
            }
            SadEventKind::Rpr => {
                if self.version < 1 {
                    return Err(format!(
                        "Rpr event must have version >= 1, got {}",
                        self.version
                    ));
                }
                require("previous", self.previous.is_some())?;
                forbid("governancePolicy", self.governance_policy.is_some())?;
                forbid("writePolicy", self.write_policy.is_some())?;
            }
        }

        Ok(())
    }
}

/// A verified SEL branch endpoint: tip event plus the per-branch state that
/// drives policy authorization on extension.
///
/// For non-divergent chains there is exactly one `SadBranchTip`; for divergent
/// chains there is one per branch. Mirrors `kel::BranchTip` (`lib/kels/src/types/kel/verification.rs`)
/// — the shape that lets `SelVerifier::resume` rehydrate full per-branch state
/// rather than collapsing to a tie-break winner.
///
/// Unlike KEL's split between runtime `BranchState` and serialized `BranchTip`,
/// SEL's per-branch state has no derivable-at-resume crypto — `tracked_write_policy`
/// is set by `Icp` and advanced by authorized `Evl`s, `events_since_evaluation`
/// is a counter, etc. So one type serves both the verifier's runtime HashMap
/// and the verification token.
#[derive(Debug, Clone)]
pub struct SadBranchTip {
    /// The chain head — latest event on this branch.
    pub tip: SadEvent,
    /// The effective write_policy for this branch. Seeded from v0 (`Icp` always
    /// has `write_policy`) and updated when an `Evl` carries a new `write_policy`
    /// *and* the evolution was authorized by the previous policy.
    pub tracked_write_policy: cesr::Digest256,
    /// The governance_policy SAID tracked on this branch. `None` until first
    /// declared (via `Icp` at v0 or `Est` at v1).
    pub governance_policy: Option<cesr::Digest256>,
    /// Number of non-evaluation events on this branch since the last
    /// authorized governance evaluation (or since chain start if none).
    pub events_since_evaluation: usize,
    /// Version of the most recent governance evaluation (`Evl` or `Rpr`) on
    /// this branch that passed both the governance check and the soft
    /// write_policy check. `None` until the first authorized evaluation.
    pub last_governance_version: Option<u64>,
}

/// Proof-of-verification token for a SAD Event Log.
///
/// Cannot be constructed outside this crate — only via `SelVerifier`.
/// Having a `SelVerification` proves the chain was fully verified
/// (structural integrity and policy authorization checked).
///
/// Carries per-branch state in `branches` so `SelVerifier::resume` can
/// rehydrate divergent chains symmetrically with `KeyEventVerifier::resume`.
/// Most accessors (`current_event`, `write_policy`, `governance_policy`,
/// `events_since_evaluation`, `last_governance_version`) return values from
/// the **tie-break winner** (higher version, then lexicographically greater
/// SAID), which is the right answer for non-divergent chains and a
/// deterministic-but-branch-scoped answer on divergent ones. Consumers needing
/// chain-wide invariants on divergent state should iterate `branches()`.
#[derive(Debug, Clone)]
pub struct SelVerification {
    /// All verified branch endpoints, sorted by tip SAID. Length 1 for
    /// non-divergent chains. Never empty (the verifier rejects empty chains
    /// at `finish` time).
    branches: Vec<SadBranchTip>,
    policy_satisfied: bool,
    establishment_version: Option<u64>,
    diverged_at_version: Option<u64>,
}

impl SelVerification {
    /// Create a new verification token. Crate-internal only.
    pub(crate) fn new(
        branches: Vec<SadBranchTip>,
        policy_satisfied: bool,
        establishment_version: Option<u64>,
        diverged_at_version: Option<u64>,
    ) -> Self {
        Self {
            branches,
            policy_satisfied,
            establishment_version,
            diverged_at_version,
        }
    }

    /// The tie-break winner across all verified branches: higher version wins,
    /// then higher kind sort_priority (state-determining sorts later — order is
    /// `Rpr > Evl > Upd > Est > Icp`), then lexicographically greater SAID.
    /// Reproducible across callers, and converges across nodes regardless of
    /// arrival order because kind priority is canonical. Mirrors KEL's
    /// branch-tip selection.
    ///
    /// Invariant: `branches` is non-empty (constructor's only caller is
    /// `SelVerifier::finish`, which rejects empty chains before calling here).
    fn winning_branch(&self) -> &SadBranchTip {
        #[allow(clippy::expect_used)]
        // SelVerification invariant: at least one branch — enforced by SelVerifier::finish.
        self.branches
            .iter()
            .max_by(|a, b| {
                a.tip
                    .version
                    .cmp(&b.tip.version)
                    .then_with(|| a.tip.kind.sort_priority().cmp(&b.tip.kind.sort_priority()))
                    .then_with(|| a.tip.said.as_ref().cmp(b.tip.said.as_ref()))
            })
            .expect("SelVerification invariant: branches is non-empty")
    }

    /// All verified branch endpoints. Sorted by tip SAID for deterministic
    /// ordering. Length 1 on non-divergent chains; >1 on divergent.
    ///
    /// Used by `SadEventBuilder` to identify the owner's branch tip for
    /// in-builder repair, and by `SelVerifier::resume` to rehydrate per-branch
    /// state without collapsing to a tie-break winner.
    pub fn branches(&self) -> &[SadBranchTip] {
        &self.branches
    }

    /// The latest verified event on the tie-break winner's branch.
    pub fn current_event(&self) -> &SadEvent {
        &self.winning_branch().tip
    }

    /// The SAID of the content object referenced by the winning branch's tip.
    pub fn current_content(&self) -> Option<&cesr::Digest256> {
        self.winning_branch().tip.content.as_ref()
    }

    /// The SEL prefix. All branches share the same prefix (the verifier
    /// enforces this); returning the winner's is unambiguous.
    pub fn prefix(&self) -> &cesr::Digest256 {
        &self.winning_branch().tip.prefix
    }

    /// The tracked (effective) write policy SAID on the tie-break winner's branch.
    ///
    /// Seeded by v0 (Icp) and updated whenever an Evl event carries a new
    /// write_policy *and* the evolution was authorized by the previous policy.
    /// Never `None` — v0 always establishes it. Evolutions that fail the soft
    /// write_policy check do not advance this value (the soft failure is also
    /// recorded in `policy_satisfied()`).
    ///
    /// For divergent chains, this reflects only the tie-break winner's branch
    /// state (higher version wins; equal versions break on lexicographically
    /// greater SAID). Divergent branches may legitimately carry different
    /// tracked policies, so callers that depend on chain-wide invariants
    /// should iterate `branches()` directly.
    pub fn write_policy(&self) -> &cesr::Digest256 {
        &self.winning_branch().tracked_write_policy
    }

    /// The event topic. All branches share the same topic.
    pub fn topic(&self) -> &str {
        &self.winning_branch().tip.topic
    }

    /// The tracked governance_policy SAID on the tie-break winner's branch, if established.
    ///
    /// `None` until an `Icp` with governance_policy or an `Est` at v1 establishes it.
    /// For divergent chains where branches legitimately carry different governance
    /// policies, this reflects only the tie-break winner — gate on `policy_satisfied()`
    /// before relying on a chain-wide interpretation.
    pub fn governance_policy(&self) -> Option<&cesr::Digest256> {
        self.winning_branch().governance_policy.as_ref()
    }

    /// Number of non-evaluation events on the winning branch since the last
    /// governance evaluation (Evl or Rpr), or since chain start if none.
    ///
    /// Used by builder-side enforcement of `MAX_NON_EVALUATION_EVENTS` before
    /// staging an `Upd`.
    pub fn events_since_evaluation(&self) -> usize {
        self.winning_branch().events_since_evaluation
    }

    /// Whether all write_policy checks were satisfied during verification.
    pub fn policy_satisfied(&self) -> bool {
        self.policy_satisfied
    }

    /// The version of the most recent governance evaluation on the tie-break
    /// winner's branch, if any. Versions at or before this are sealed by
    /// governance_policy on that branch.
    ///
    /// Branch-scoped (winner's value), unlike `establishment_version` which is
    /// chain-wide. Consumers needing the chain-wide weakest-seal must iterate
    /// `branches()` and reduce. In practice the SADStore handler's
    /// `save_batch` only consults this on linear chains (the divergence check
    /// rejects appends to multi-branch chains), so winner's value coincides
    /// with the chain-wide value.
    pub fn last_governance_version(&self) -> Option<u64> {
        self.winning_branch().last_governance_version
    }

    /// The version at which governance_policy was established (v0 if Icp declared it, v1 if Est).
    /// Repair cannot truncate at or before this version.
    ///
    /// This value is **chain-wide**, representing the earliest establishment point across
    /// all branches. It acts as the repair seal — no truncation at or before this version
    /// regardless of which branch is being repaired.
    ///
    /// In divergent scenarios where some Est events soft-failed the write_policy check,
    /// this value may not match the tie-break winner's branch state: the winning branch
    /// may have `governance_policy = None` while `establishment_version` is `Some` (because
    /// another branch's Est did establish governance_policy at that version). Consumers
    /// reading this as branch-scoped must gate on `policy_satisfied()` first.
    pub fn establishment_version(&self) -> Option<u64> {
        self.establishment_version
    }

    /// The lowest version at which divergence was first observed, or `None` on
    /// linear chains. Mirrors `KelVerification::diverged_at_serial()`.
    ///
    /// `Some(_)` indicates the chain has multiple live tips. Branch-scoped
    /// accessors (`write_policy`, `governance_policy`, `events_since_evaluation`,
    /// `last_governance_version`) reflect only the tie-break winner; iterate
    /// `branches()` for the full picture. `SelVerifier::resume` accepts
    /// divergent tokens and rehydrates full per-branch state.
    pub fn diverged_at_version(&self) -> Option<u64> {
        self.diverged_at_version
    }

    /// Stamp a server-reported divergence version onto a token whose local
    /// verification didn't observe the fork.
    ///
    /// `or_else` semantics: if the token already carries `Some(_)` (the local
    /// verifier saw the divergence itself), leave it untouched. Only stamps
    /// when the local detection produced `None`. Crate-private so external
    /// callers can't fabricate a divergence claim.
    pub(crate) fn set_diverged_at_version(&mut self, version: u64) {
        if self.diverged_at_version.is_none() {
            self.diverged_at_version = Some(version);
        }
    }
}

/// A page of stored SAD events returned by the SAD Event Log API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SadEventPage {
    pub events: Vec<SadEvent>,
    pub has_more: bool,
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use verifiable_storage::{Chained, SelfAddressed};

    use super::*;

    fn test_digest(label: &[u8]) -> cesr::Digest256 {
        cesr::Digest256::blake3_256(label)
    }

    #[test]
    fn test_compute_sad_event_prefix_deterministic() {
        let wp = test_digest(b"write-policy");
        let prefix1 = compute_sad_event_prefix(wp, "kels/sad/v1/keys/mlkem").unwrap();
        let prefix2 = compute_sad_event_prefix(wp, "kels/sad/v1/keys/mlkem").unwrap();
        assert_eq!(prefix1, prefix2);
    }

    #[test]
    fn test_compute_sad_event_prefix_different_inputs() {
        let prefix1 =
            compute_sad_event_prefix(test_digest(b"wp1"), "kels/sad/v1/keys/mlkem").unwrap();
        let prefix2 =
            compute_sad_event_prefix(test_digest(b"wp2"), "kels/sad/v1/keys/mlkem").unwrap();
        assert_ne!(prefix1, prefix2);

        let prefix3 = compute_sad_event_prefix(test_digest(b"wp1"), "kels/v1/other-kind").unwrap();
        assert_ne!(prefix1, prefix3);
    }

    #[test]
    fn test_sad_event_inception_no_content() {
        let event =
            SadEvent::icp("kels/sad/v1/keys/mlkem", test_digest(b"write-policy"), None).unwrap();
        assert_eq!(event.version, 0);
        assert!(event.previous.is_none());
        assert!(event.content.is_none());
        assert_eq!(event.kind, SadEventKind::Icp);
    }

    #[test]
    fn test_sad_event_chain_increment() {
        let mut event =
            SadEvent::icp("kels/sad/v1/keys/mlkem", test_digest(b"write-policy"), None).unwrap();

        let v0_said = event.said;
        let prefix = event.prefix;

        event.content = Some(test_digest(b"content_abc"));
        event.kind = SadEventKind::Upd;
        event.increment().unwrap();

        assert_eq!(event.version, 1);
        assert_eq!(event.previous, Some(v0_said));
        assert_eq!(event.prefix, prefix);
        assert_eq!(event.content, Some(test_digest(b"content_abc")));
    }

    #[test]
    fn test_sad_event_verify_said() {
        let event =
            SadEvent::icp("kels/sad/v1/keys/mlkem", test_digest(b"write-policy"), None).unwrap();
        assert!(event.verify_said().is_ok());

        // Tamper with content
        let mut tampered = event;
        tampered.topic = "kels/v1/tampered".to_string();
        assert!(tampered.verify_said().is_err());
    }

    #[test]
    fn test_sad_event_kind_sort_priority() {
        // State-determining kinds (Rpr) sort after normal kinds. Mirrors KEL's
        // priority ordering — the convention is "lower priority sorts earlier."
        assert_eq!(SadEventKind::Icp.sort_priority(), 0);
        assert_eq!(SadEventKind::Est.sort_priority(), 1);
        assert_eq!(SadEventKind::Upd.sort_priority(), 2);
        assert_eq!(SadEventKind::Evl.sort_priority(), 3);
        assert_eq!(SadEventKind::Rpr.sort_priority(), 4);

        // sort_priority_mapping returns canonical (kind_string, i64) pairs for
        // use with `order_by_case` in DB queries — round-trip via `as_str`.
        let mapping = SadEventKind::sort_priority_mapping();
        assert_eq!(mapping.len(), 5);
        assert!(mapping.contains(&("kels/sad/v1/events/icp", 0)));
        assert!(mapping.contains(&("kels/sad/v1/events/est", 1)));
        assert!(mapping.contains(&("kels/sad/v1/events/upd", 2)));
        assert!(mapping.contains(&("kels/sad/v1/events/evl", 3)));
        assert!(mapping.contains(&("kels/sad/v1/events/rpr", 4)));
    }

    #[test]
    fn test_sad_event_verify_prefix() {
        let event =
            SadEvent::icp("kels/sad/v1/keys/mlkem", test_digest(b"write-policy"), None).unwrap();
        assert!(event.verify_prefix().is_ok());

        // Tamper with write_policy
        let mut tampered = event;
        tampered.write_policy = Some(test_digest(b"tampered"));
        tampered.derive_said().unwrap();
        assert!(tampered.verify_prefix().is_err());
    }
}
