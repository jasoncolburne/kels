//! SAD (Self-Addressing Data) event types for the replicated SADStore.
//!
//! Two layers:
//! - **SAD objects** — content-addressed JSON blobs stored/retrieved by SAID (object store).
//! - **SAD events** — versioned event chains with deterministic prefix discovery
//!   bound to an Identity Event Log (IEL). Each non-inception event references
//!   content in the SAD object store via `content`.
//!
//! Round-12 shape: SE chains are **identity-rooted**. The chain prefix is
//! derived from `(identity, topic)`; every v1+ event binds to a specific IEL
//! event by SAID via `identity_event` to resolve its authorization policy
//! (auth_policy for `Upd`; governance_policy for `Sea` / `Rpr` / `Cnt` / `Dec`).
//! SE no longer carries `write_policy` / `governance_policy` fields — those
//! live on IEL.

use std::{collections::BTreeSet, fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use verifiable_storage::{Chained, SelfAddressed};

use crate::error::KelsError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SadEventKind {
    #[serde(rename = "kels/sad/v1/events/icp")]
    Icp, // Inception (v0) — binds the chain to an IEL identity.
    #[serde(rename = "kels/sad/v1/events/upd")]
    Upd, // Update — content advancement; auth-policy authorized.
    #[serde(rename = "kels/sad/v1/events/sea")]
    Sea, // Seal — degenerate governance evaluation; advances last_governance_version.
    #[serde(rename = "kels/sad/v1/events/rpr")]
    Rpr, // Repair — resolves divergence on unsealed chains.
    #[serde(rename = "kels/sad/v1/events/cnt")]
    Cnt, // Contest — terminal authority conflict / sealed-divergence resolution.
    #[serde(rename = "kels/sad/v1/events/dec")]
    Dec, // Decommission — terminal owner-initiated end.
}

impl SadEventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Icp => "kels/sad/v1/events/icp",
            Self::Upd => "kels/sad/v1/events/upd",
            Self::Sea => "kels/sad/v1/events/sea",
            Self::Rpr => "kels/sad/v1/events/rpr",
            Self::Cnt => "kels/sad/v1/events/cnt",
            Self::Dec => "kels/sad/v1/events/dec",
        }
    }

    /// Short event kind name (e.g. "icp", "upd") as used by CLI tools and responses.
    pub fn short_name(&self) -> &'static str {
        match self {
            Self::Icp => "icp",
            Self::Upd => "upd",
            Self::Sea => "sea",
            Self::Rpr => "rpr",
            Self::Cnt => "cnt",
            Self::Dec => "dec",
        }
    }

    /// Parse a short event kind name (e.g. "icp", "upd") as used by CLI tools.
    pub fn from_short_name(s: &str) -> Result<Self, KelsError> {
        match s {
            "icp" => Ok(Self::Icp),
            "upd" => Ok(Self::Upd),
            "sea" => Ok(Self::Sea),
            "rpr" => Ok(Self::Rpr),
            "cnt" => Ok(Self::Cnt),
            "dec" => Ok(Self::Dec),
            _ => Err(KelsError::VerificationFailed(format!(
                "Unknown event kind: {}",
                s
            ))),
        }
    }

    /// True for kinds that evaluate the IEL-resolved governance_policy
    /// (`Sea` / `Rpr` / `Cnt` / `Dec`). `Upd` evaluates auth_policy and is
    /// excluded.
    pub fn evaluates_governance(&self) -> bool {
        matches!(self, Self::Sea | Self::Rpr | Self::Cnt | Self::Dec)
    }

    /// True for repair events (`Rpr` only).
    pub fn is_repair(&self) -> bool {
        matches!(self, Self::Rpr)
    }

    /// True for inception events (`Icp` only).
    pub fn is_inception(&self) -> bool {
        matches!(self, Self::Icp)
    }

    /// True for `Cnt` only.
    pub fn is_contest(&self) -> bool {
        matches!(self, Self::Cnt)
    }

    /// True for `Dec` only.
    pub fn is_decommission(&self) -> bool {
        matches!(self, Self::Dec)
    }

    /// True for terminal kinds (`Cnt` / `Dec`).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Cnt | Self::Dec)
    }

    /// Sort priority within the same version (lower = earlier). Mirrors
    /// IEL's `Icp=0, Evl=1, Cnt=2, Dec=3` shape with terminal kinds last.
    /// Differs from KEL (which sorts Cnt last only).
    pub fn sort_priority(&self) -> u8 {
        match self {
            Self::Icp => 0,
            Self::Upd => 1,
            Self::Sea => 2,
            Self::Rpr => 3,
            Self::Cnt => 4,
            Self::Dec => 5,
        }
    }

    const ALL: [Self; 6] = [
        Self::Icp,
        Self::Upd,
        Self::Sea,
        Self::Rpr,
        Self::Cnt,
        Self::Dec,
    ];

    /// Returns the sort priority mapping for use with `order_by_case` in DB queries.
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
            "kels/sad/v1/events/sea" => Ok(Self::Sea),
            "kels/sad/v1/events/rpr" => Ok(Self::Rpr),
            "kels/sad/v1/events/cnt" => Ok(Self::Cnt),
            "kels/sad/v1/events/dec" => Ok(Self::Dec),
            _ => Err(KelsError::VerificationFailed(format!(
                "Unknown event kind: {}",
                s
            ))),
        }
    }
}

/// A chained, self-addressed event in the SADStore.
///
/// Round 12 shape: identity-rooted. The v0 `Icp` carries `identity` (the IEL
/// prefix the chain is bound to) and no `content`; v1+ events carry
/// `identity_event` (the SAID of the IEL event whose policy authorizes them).
/// SE has no first-class policy fields — authorization is resolved by walking
/// to the bound IEL event via `IelResolver`.
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
    /// SAID of the content object in the SAD store. `None` on `Icp`; required
    /// on `Upd`; preserved (carry-forward) on `Sea` / `Rpr` / `Cnt` / `Dec`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub content: Option<cesr::Digest256>,
    /// SAID of the custody SAD (optional; controls readPolicy / nodes for the
    /// chain). Independent of the round-12 IEL binding.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub custody: Option<cesr::Digest256>,
    /// IEL prefix the chain is bound to. `Some` on `Icp` (where it participates
    /// in prefix derivation alongside `topic`); `None` on every other kind.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub identity: Option<cesr::Digest256>,
    /// SAID of the IEL event whose policy authorizes this SE event. `None` on
    /// `Icp` (permissionless inception); `Some` on every v1+ kind.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub identity_event: Option<cesr::Digest256>,
}

/// Compute the SAD Event Log prefix for a given identity prefix and topic.
///
/// Anyone can call this offline — no server needed. The prefix is derived from
/// the v0 inception event content (with said+prefix as placeholders), which
/// contains only `(identity, topic)` as discriminators. Round-12 SE inception
/// is permissionless: prefix derivation grants no authority by itself, since
/// the chain cannot advance past `Icp` without satisfying the IEL-resolved
/// `auth_policy`.
///
/// Routes through `SadEvent::icp` so prefix derivation and v0 staging share
/// exactly the same structural-validation gate.
pub fn compute_sad_event_prefix(
    identity: cesr::Digest256,
    topic: impl Into<String>,
) -> Result<cesr::Digest256, KelsError> {
    Ok(SadEvent::icp(identity, topic)?.prefix)
}

impl SadEvent {
    /// Build a v0 `Icp` (inception) event bound to an IEL identity.
    ///
    /// `content`, `custody`, and `identity_event` are all `None` on `Icp`. The
    /// chain prefix is derived from `(identity, topic)`. Inception is
    /// permissionless — no authorization check fires until the v1 `Upd` lands
    /// (per the inception batch rule enforced by the submit handler).
    pub fn icp(identity: cesr::Digest256, topic: impl Into<String>) -> Result<Self, KelsError> {
        let event = Self::create(
            topic.into(),
            SadEventKind::Icp,
            None,
            None,
            Some(identity),
            None,
        )?;
        event
            .validate_structure()
            .map_err(KelsError::InvalidKeyEvent)?;
        Ok(event)
    }

    /// Build a v+1 `Upd` event from a chain tip. `content` is required;
    /// `identity_event` binds the event to the IEL event whose `auth_policy`
    /// authorizes this advance.
    pub fn upd(
        previous: &Self,
        identity_event: cesr::Digest256,
        content: cesr::Digest256,
    ) -> Result<Self, KelsError> {
        let mut event = previous.clone();
        event.content = Some(content);
        event.kind = SadEventKind::Upd;
        event.identity = None;
        event.identity_event = Some(identity_event);
        event.increment()?;
        event
            .validate_structure()
            .map_err(KelsError::InvalidKeyEvent)?;
        Ok(event)
    }

    /// Build a v+1 `Sea` (degenerate seal marker) from a chain tip. Carries
    /// `previous.content` forward unchanged. `identity_event` binds the event
    /// to the IEL event whose `governance_policy` authorizes this seal.
    pub fn sea(previous: &Self, identity_event: cesr::Digest256) -> Result<Self, KelsError> {
        let mut event = previous.clone();
        event.kind = SadEventKind::Sea;
        // content carries forward from `previous` unchanged.
        event.identity = None;
        event.identity_event = Some(identity_event);
        event.increment()?;
        event
            .validate_structure()
            .map_err(KelsError::InvalidKeyEvent)?;
        Ok(event)
    }

    /// Build a v+1 `Rpr` (repair) event from a chain tip. Carries
    /// `previous.content` forward. `identity_event` binds to the
    /// governance-authorizing IEL event.
    pub fn rpr(previous: &Self, identity_event: cesr::Digest256) -> Result<Self, KelsError> {
        let mut event = previous.clone();
        event.kind = SadEventKind::Rpr;
        event.identity = None;
        event.identity_event = Some(identity_event);
        event.increment()?;
        event
            .validate_structure()
            .map_err(KelsError::InvalidKeyEvent)?;
        Ok(event)
    }

    /// Build a v+1 `Cnt` (contest) event from a chain tip. Carries
    /// `previous.content` forward. Terminal: chain becomes contested.
    pub fn cnt(previous: &Self, identity_event: cesr::Digest256) -> Result<Self, KelsError> {
        let mut event = previous.clone();
        event.kind = SadEventKind::Cnt;
        event.identity = None;
        event.identity_event = Some(identity_event);
        event.increment()?;
        event
            .validate_structure()
            .map_err(KelsError::InvalidKeyEvent)?;
        Ok(event)
    }

    /// Build a v+1 `Dec` (decommission) event from a chain tip. Carries
    /// `previous.content` forward. Terminal: chain becomes decommissioned.
    pub fn dec(previous: &Self, identity_event: cesr::Digest256) -> Result<Self, KelsError> {
        let mut event = previous.clone();
        event.kind = SadEventKind::Dec;
        event.identity = None;
        event.identity_event = Some(identity_event);
        event.increment()?;
        event
            .validate_structure()
            .map_err(KelsError::InvalidKeyEvent)?;
        Ok(event)
    }

    /// Validates that the event has the correct fields for its kind. Per-event
    /// only — cross-event invariants like content preservation and IEL binding
    /// resolution live in the verifier (`SelVerifier`) and the submit handler.
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
                forbid("previous", self.previous.is_some())?;
                require("identity", self.identity.is_some())?;
                forbid("identityEvent", self.identity_event.is_some())?;
                forbid("content", self.content.is_some())?;
            }
            SadEventKind::Upd => {
                if self.version < 1 {
                    return Err(format!(
                        "Upd event must have version >= 1, got {}",
                        self.version
                    ));
                }
                require("previous", self.previous.is_some())?;
                forbid("identity", self.identity.is_some())?;
                require("identityEvent", self.identity_event.is_some())?;
                require("content", self.content.is_some())?;
            }
            SadEventKind::Sea | SadEventKind::Rpr | SadEventKind::Cnt | SadEventKind::Dec => {
                if self.version < 1 {
                    return Err(format!(
                        "{} event must have version >= 1, got {}",
                        self.kind, self.version
                    ));
                }
                require("previous", self.previous.is_some())?;
                forbid("identity", self.identity.is_some())?;
                require("identityEvent", self.identity_event.is_some())?;
                // `content` is preserved — the verifier enforces
                // `event.content == previous.content` cross-event;
                // `validate_structure` is per-event and admits any value here.
            }
        }

        Ok(())
    }
}

/// A verified SE branch endpoint: tip event plus the per-branch state the
/// verifier needs to authorize extension and to ratchet the IEL binding.
///
/// Round-12 shape: the chain is identity-rooted, so every branch carries
/// the bound IEL prefix (`identity`, set at Icp) and the highest IEL event
/// the branch has ratcheted to (`last_identity_event`). Authorization
/// policies are not tracked per branch — they live on the IEL and are
/// resolved on demand via `IelResolver`.
#[derive(Debug, Clone)]
pub struct SadBranchTip {
    /// The chain head — latest event on this branch.
    pub tip: SadEvent,
    /// IEL prefix the chain is bound to. Set at Icp from `event.identity`
    /// and never changes thereafter. Carried per-branch (not chain-wide)
    /// because each `SadBranchTip` is also the verifier's runtime
    /// state — every branch needs the identity to feed the resolver.
    /// Always equal across branches on a divergent chain (Icp is shared).
    pub identity: cesr::Digest256,
    /// Highest IEL event SAID this branch has ratcheted to, in IEL chain
    /// order. `None` until the first v1+ event lands hard-passing all of
    /// fetch / divergence / policy-pick / anchor (per Gap 2's "Update
    /// precondition" — soft-passed Cnt/Dec do NOT advance the ratchet).
    pub last_identity_event: Option<cesr::Digest256>,
    /// Number of non-evaluation events on this branch since the last
    /// authorized governance evaluation (or since chain start if none).
    /// Tracked for the round-12 builder's evaluation-required gates.
    pub events_since_evaluation: usize,
    /// Version of the most recent governance evaluation (`Sea` / `Rpr`)
    /// on this branch. `None` until the first authorized evaluation.
    /// Terminal kinds (`Cnt` / `Dec`) do NOT advance the seal.
    pub last_governance_version: Option<u64>,
}

/// Proof-of-verification token for a SAD Event Log.
///
/// Cannot be constructed outside this crate — only via `SelVerifier`.
///
/// Round-12 shape: per-branch tips plus chain-wide aggregates. The terminal
/// flags (`is_contested` / `is_decommissioned`) are content-based — set
/// unconditionally on any landed `Cnt` / `Dec` regardless of whether the
/// terminating event passed its governance anchor check; auth status is
/// conveyed separately via `policy_satisfied`. Mirrors
/// `IelVerification` (`lib/kels/src/types/iel/verification.rs`).
#[derive(Debug, Clone)]
pub struct SelVerification {
    branches: Vec<SadBranchTip>,
    policy_satisfied: bool,
    is_contested: bool,
    is_decommissioned: bool,
    last_governance_version: Option<u64>,
    diverged_at_version: Option<u64>,
    /// Caller-provided up-front: SE event SAIDs the consumer cares about.
    /// Mirrors `KelVerification::queried_saids` and the IEL parallel.
    queried_saids: BTreeSet<cesr::Digest256>,
    /// Verifier-populated subset of `queried_saids`: SAIDs whose corresponding
    /// SE event passed its auth check AND lives at `version <
    /// first_divergent_version` (or chain non-divergent). Cnt is structurally
    /// at-or-after the divergence cut and never appears here; Dec on a clean
    /// chain CAN.
    satisfied_saids: BTreeSet<cesr::Digest256>,
}

impl SelVerification {
    /// Create a new verification token. Crate-internal only.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        branches: Vec<SadBranchTip>,
        policy_satisfied: bool,
        is_contested: bool,
        is_decommissioned: bool,
        last_governance_version: Option<u64>,
        diverged_at_version: Option<u64>,
        queried_saids: BTreeSet<cesr::Digest256>,
        satisfied_saids: BTreeSet<cesr::Digest256>,
    ) -> Self {
        Self {
            branches,
            policy_satisfied,
            is_contested,
            is_decommissioned,
            last_governance_version,
            diverged_at_version,
            queried_saids,
            satisfied_saids,
        }
    }

    /// The tie-break winner across all verified branches: higher version wins,
    /// then higher kind sort_priority, then lexicographically greater SAID.
    /// Invariant: `branches` is non-empty (constructor's only caller is
    /// `SelVerifier::finish`, which rejects empty chains).
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

    /// The event topic. All branches share the same topic.
    pub fn topic(&self) -> &str {
        &self.winning_branch().tip.topic
    }

    /// Number of non-evaluation events on the winning branch since the last
    /// governance evaluation, or since chain start if none.
    pub fn events_since_evaluation(&self) -> usize {
        self.winning_branch().events_since_evaluation
    }

    /// Whether all per-event policy checks passed during verification.
    pub fn policy_satisfied(&self) -> bool {
        self.policy_satisfied
    }

    /// Version of the most recent governance evaluation across the chain
    /// (the maximum of per-branch `last_governance_version`). `None` until
    /// the first authorized `Sea` / `Rpr` lands. Terminal kinds (`Cnt` /
    /// `Dec`) do NOT advance the seal.
    pub fn last_governance_version(&self) -> Option<u64> {
        self.last_governance_version
    }

    /// True when at least one `Cnt` event has landed on the chain.
    /// Content-based (set unconditionally on landed `Cnt` regardless of
    /// whether its governance anchor check passed) — mirrors the round-11
    /// IEL terminal-flag rule.
    pub fn is_contested(&self) -> bool {
        self.is_contested
    }

    /// True when at least one `Dec` event has landed on the chain. Same
    /// content-based semantics as `is_contested`.
    pub fn is_decommissioned(&self) -> bool {
        self.is_decommissioned
    }

    /// Chain-wide IEL ratchet view: the per-branch `last_identity_event`
    /// when the chain is linear, `None` on divergent chains. Computed on
    /// demand from per-branch state.
    ///
    /// On divergent chains the accessor returns `None` because deriving
    /// a canonical chain-wide value requires comparing per-branch
    /// positions via `IelChainPosition::try_cmp`, which needs a resolver
    /// — the synchronous accessor has none. (Per-branch values themselves
    /// compare cleanly: the verifier's Update precondition keeps the
    /// ratchet pinned to non-divergent IEL positions; the limit is the
    /// accessor's API, not the data.) Callers needing the full picture
    /// iterate `branches()` and consult the resolver.
    pub fn last_identity_event(&self) -> Option<&cesr::Digest256> {
        if self.branches.len() != 1 {
            return None;
        }
        self.branches
            .first()
            .and_then(|b| b.last_identity_event.as_ref())
    }

    /// The lowest version at which divergence was first observed, or `None`
    /// on linear chains.
    pub fn diverged_at_version(&self) -> Option<u64> {
        self.diverged_at_version
    }

    /// True when the verifier observed a fork. Mirrors
    /// `IelVerification::is_divergent` for consumer ergonomics; equivalent
    /// to `branches().len() > 1`.
    pub fn is_divergent(&self) -> bool {
        self.branches.len() > 1
    }

    /// Whether the named SE event passed its auth check AND lives at
    /// `version < first_divergent_version` (or chain is non-divergent).
    /// Mirrors `KelVerification::is_said_anchored` and the IEL parallel.
    /// Returns `false` for SAIDs not in `queried_saids` — callers must
    /// register interest before walking.
    pub fn is_said_satisfied(&self, said: &cesr::Digest256) -> bool {
        self.satisfied_saids.contains(said)
    }

    /// The full set of satisfied SAIDs (subset of `queried_saids`).
    pub fn satisfied_saids(&self) -> &BTreeSet<cesr::Digest256> {
        &self.satisfied_saids
    }

    /// The set of SAIDs the caller registered interest in.
    pub fn queried_saids(&self) -> &BTreeSet<cesr::Digest256> {
        &self.queried_saids
    }

    /// Stamp a server-reported divergence version onto a token whose local
    /// verification didn't observe the fork. Crate-private.
    ///
    /// Currently unused — Gap 4's submit-handler rewrite will re-introduce
    /// the call site that stamps server-reported divergence onto local
    /// tokens (the round-10 builder code that called this was stubbed in
    /// Gap 1).
    #[allow(dead_code)]
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
    use super::*;

    fn test_digest(label: &[u8]) -> cesr::Digest256 {
        cesr::Digest256::blake3_256(label)
    }

    const TEST_TOPIC: &str = "kels/sad/v1/keys/mlkem";

    fn test_identity() -> cesr::Digest256 {
        test_digest(b"identity-prefix")
    }

    fn test_iel_event() -> cesr::Digest256 {
        test_digest(b"iel-event-said")
    }

    // ==================== Prefix derivation ====================

    #[test]
    fn test_compute_sad_event_prefix_deterministic() {
        let id = test_identity();
        let prefix1 = compute_sad_event_prefix(id, TEST_TOPIC).unwrap();
        let prefix2 = compute_sad_event_prefix(id, TEST_TOPIC).unwrap();
        assert_eq!(prefix1, prefix2);
    }

    #[test]
    fn test_compute_sad_event_prefix_uses_identity_and_topic() {
        let id1 = test_digest(b"id1");
        let id2 = test_digest(b"id2");
        let p_id1 = compute_sad_event_prefix(id1, TEST_TOPIC).unwrap();
        let p_id2 = compute_sad_event_prefix(id2, TEST_TOPIC).unwrap();
        assert_ne!(p_id1, p_id2);

        let p_other_topic = compute_sad_event_prefix(id1, "kels/sad/v1/other").unwrap();
        assert_ne!(p_id1, p_other_topic);
    }

    #[test]
    fn test_icp_constructor_round_trip() {
        let id = test_identity();
        let event = SadEvent::icp(id, TEST_TOPIC).unwrap();
        assert_eq!(event.version, 0);
        assert!(event.previous.is_none());
        assert!(event.content.is_none());
        assert!(event.identity_event.is_none());
        assert_eq!(event.identity, Some(id));
        assert_eq!(event.kind, SadEventKind::Icp);
        assert!(event.verify_said().is_ok());
        assert!(event.verify_prefix().is_ok());
    }

    #[test]
    fn test_upd_constructor_carries_identity_event_and_content() {
        let id = test_identity();
        let v0 = SadEvent::icp(id, TEST_TOPIC).unwrap();
        let iel_evt = test_iel_event();
        let content = test_digest(b"some-content");

        let v1 = SadEvent::upd(&v0, iel_evt, content).unwrap();
        assert_eq!(v1.version, 1);
        assert_eq!(v1.previous, Some(v0.said));
        assert_eq!(v1.kind, SadEventKind::Upd);
        assert_eq!(v1.content, Some(content));
        assert_eq!(v1.identity_event, Some(iel_evt));
        assert!(v1.identity.is_none());
        assert_eq!(v1.prefix, v0.prefix);
    }

    #[test]
    fn test_sea_preserves_previous_content() {
        let id = test_identity();
        let v0 = SadEvent::icp(id, TEST_TOPIC).unwrap();
        let iel_evt_a = test_digest(b"iel-a");
        let v1 = SadEvent::upd(&v0, iel_evt_a, test_digest(b"content-v1")).unwrap();

        let iel_evt_b = test_digest(b"iel-b");
        let v2 = SadEvent::sea(&v1, iel_evt_b).unwrap();
        assert_eq!(v2.kind, SadEventKind::Sea);
        assert_eq!(v2.content, v1.content);
        assert_eq!(v2.identity_event, Some(iel_evt_b));
    }

    #[test]
    fn test_terminal_constructors_round_trip() {
        let id = test_identity();
        let v0 = SadEvent::icp(id, TEST_TOPIC).unwrap();
        let iel_evt = test_iel_event();
        let v1 = SadEvent::upd(&v0, iel_evt, test_digest(b"c")).unwrap();

        let cnt = SadEvent::cnt(&v1, iel_evt).unwrap();
        assert_eq!(cnt.kind, SadEventKind::Cnt);
        assert_eq!(cnt.content, v1.content);
        assert!(cnt.kind.is_terminal());
        assert!(cnt.kind.is_contest());

        let dec = SadEvent::dec(&v1, iel_evt).unwrap();
        assert_eq!(dec.kind, SadEventKind::Dec);
        assert_eq!(dec.content, v1.content);
        assert!(dec.kind.is_terminal());
        assert!(dec.kind.is_decommission());
    }

    // ==================== validate_structure: Icp ====================

    #[test]
    fn test_validate_structure_icp_valid() {
        let event = SadEvent::icp(test_identity(), TEST_TOPIC).unwrap();
        assert!(event.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_icp_wrong_version() {
        let mut event = SadEvent::icp(test_identity(), TEST_TOPIC).unwrap();
        event.version = 1;
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("version 0"));
    }

    #[test]
    fn test_validate_structure_icp_forbids_previous() {
        let mut event = SadEvent::icp(test_identity(), TEST_TOPIC).unwrap();
        event.previous = Some(test_digest(b"prev"));
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("must not have previous"));
    }

    #[test]
    fn test_validate_structure_icp_requires_identity() {
        let mut event = SadEvent::icp(test_identity(), TEST_TOPIC).unwrap();
        event.identity = None;
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("requires identity"));
    }

    #[test]
    fn test_validate_structure_icp_forbids_identity_event() {
        let mut event = SadEvent::icp(test_identity(), TEST_TOPIC).unwrap();
        event.identity_event = Some(test_iel_event());
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("must not have identityEvent"));
    }

    #[test]
    fn test_validate_structure_icp_forbids_content() {
        let mut event = SadEvent::icp(test_identity(), TEST_TOPIC).unwrap();
        event.content = Some(test_digest(b"content"));
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("must not have content"));
    }

    // ==================== validate_structure: Upd ====================

    #[test]
    fn test_validate_structure_upd_valid() {
        let v0 = SadEvent::icp(test_identity(), TEST_TOPIC).unwrap();
        let v1 = SadEvent::upd(&v0, test_iel_event(), test_digest(b"content")).unwrap();
        assert!(v1.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_upd_requires_content() {
        let v0 = SadEvent::icp(test_identity(), TEST_TOPIC).unwrap();
        let mut v1 = SadEvent::upd(&v0, test_iel_event(), test_digest(b"content")).unwrap();
        v1.content = None;
        let err = v1.validate_structure().unwrap_err();
        assert!(err.contains("requires content"));
    }

    #[test]
    fn test_validate_structure_upd_requires_identity_event() {
        let v0 = SadEvent::icp(test_identity(), TEST_TOPIC).unwrap();
        let mut v1 = SadEvent::upd(&v0, test_iel_event(), test_digest(b"content")).unwrap();
        v1.identity_event = None;
        let err = v1.validate_structure().unwrap_err();
        assert!(err.contains("requires identityEvent"));
    }

    #[test]
    fn test_validate_structure_upd_forbids_identity() {
        let v0 = SadEvent::icp(test_identity(), TEST_TOPIC).unwrap();
        let mut v1 = SadEvent::upd(&v0, test_iel_event(), test_digest(b"content")).unwrap();
        v1.identity = Some(test_identity());
        let err = v1.validate_structure().unwrap_err();
        assert!(err.contains("must not have identity"));
    }

    // ==================== validate_structure: Sea / Rpr / Cnt / Dec ====================

    #[test]
    fn test_validate_structure_sea_valid() {
        let v0 = SadEvent::icp(test_identity(), TEST_TOPIC).unwrap();
        let v1 = SadEvent::upd(&v0, test_iel_event(), test_digest(b"content")).unwrap();
        let v2 = SadEvent::sea(&v1, test_iel_event()).unwrap();
        assert!(v2.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_terminal_kinds_require_identity_event() {
        let v0 = SadEvent::icp(test_identity(), TEST_TOPIC).unwrap();
        let v1 = SadEvent::upd(&v0, test_iel_event(), test_digest(b"content")).unwrap();

        for kind in [
            SadEventKind::Sea,
            SadEventKind::Rpr,
            SadEventKind::Cnt,
            SadEventKind::Dec,
        ] {
            let mut event = v1.clone();
            event.kind = kind;
            event.identity_event = None;
            event.increment().unwrap();
            let err = event.validate_structure().unwrap_err();
            assert!(
                err.contains("requires identityEvent"),
                "{kind} did not require identityEvent: {err}"
            );
        }
    }

    #[test]
    fn test_validate_structure_terminal_kinds_forbid_identity() {
        let v0 = SadEvent::icp(test_identity(), TEST_TOPIC).unwrap();
        let v1 = SadEvent::upd(&v0, test_iel_event(), test_digest(b"content")).unwrap();

        for kind in [
            SadEventKind::Sea,
            SadEventKind::Rpr,
            SadEventKind::Cnt,
            SadEventKind::Dec,
        ] {
            let mut event = v1.clone();
            event.kind = kind;
            event.identity = Some(test_identity());
            event.increment().unwrap();
            let err = event.validate_structure().unwrap_err();
            assert!(
                err.contains("must not have identity"),
                "{kind} did not forbid identity: {err}"
            );
        }
    }

    // ==================== Kind enum ====================

    #[test]
    fn test_sad_event_kind_sort_priority() {
        assert_eq!(SadEventKind::Icp.sort_priority(), 0);
        assert_eq!(SadEventKind::Upd.sort_priority(), 1);
        assert_eq!(SadEventKind::Sea.sort_priority(), 2);
        assert_eq!(SadEventKind::Rpr.sort_priority(), 3);
        assert_eq!(SadEventKind::Cnt.sort_priority(), 4);
        assert_eq!(SadEventKind::Dec.sort_priority(), 5);

        let mapping = SadEventKind::sort_priority_mapping();
        assert_eq!(mapping.len(), 6);
        assert!(mapping.contains(&("kels/sad/v1/events/icp", 0)));
        assert!(mapping.contains(&("kels/sad/v1/events/dec", 5)));
    }

    #[test]
    fn test_sad_event_kind_predicates() {
        assert!(SadEventKind::Icp.is_inception());
        assert!(SadEventKind::Rpr.is_repair());
        assert!(SadEventKind::Cnt.is_contest());
        assert!(SadEventKind::Dec.is_decommission());
        assert!(SadEventKind::Cnt.is_terminal());
        assert!(SadEventKind::Dec.is_terminal());
        assert!(!SadEventKind::Sea.is_terminal());

        for kind in [
            SadEventKind::Sea,
            SadEventKind::Rpr,
            SadEventKind::Cnt,
            SadEventKind::Dec,
        ] {
            assert!(
                kind.evaluates_governance(),
                "{kind} should evaluate governance"
            );
        }
        assert!(!SadEventKind::Upd.evaluates_governance());
        assert!(!SadEventKind::Icp.evaluates_governance());
    }

    #[test]
    fn test_sad_event_kind_short_name_round_trip() {
        for kind in [
            SadEventKind::Icp,
            SadEventKind::Upd,
            SadEventKind::Sea,
            SadEventKind::Rpr,
            SadEventKind::Cnt,
            SadEventKind::Dec,
        ] {
            let parsed = SadEventKind::from_short_name(kind.short_name()).unwrap();
            assert_eq!(parsed, kind);
        }
    }

    #[test]
    fn test_sad_event_kind_topic_round_trip() {
        for kind in [
            SadEventKind::Icp,
            SadEventKind::Upd,
            SadEventKind::Sea,
            SadEventKind::Rpr,
            SadEventKind::Cnt,
            SadEventKind::Dec,
        ] {
            let parsed: SadEventKind = kind.as_str().parse().unwrap();
            assert_eq!(parsed, kind);
        }
    }

    // ==================== SAID / prefix integrity ====================

    #[test]
    fn test_sad_event_verify_said_detects_tamper() {
        let event = SadEvent::icp(test_identity(), TEST_TOPIC).unwrap();
        let mut tampered = event;
        tampered.topic = "kels/v1/tampered".to_string();
        assert!(tampered.verify_said().is_err());
    }

    #[test]
    fn test_sad_event_verify_prefix_detects_identity_tamper() {
        let event = SadEvent::icp(test_identity(), TEST_TOPIC).unwrap();
        let mut tampered = event;
        tampered.identity = Some(test_digest(b"different-identity"));
        tampered.derive_said().unwrap();
        assert!(tampered.verify_prefix().is_err());
    }
}
