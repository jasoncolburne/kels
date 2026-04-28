//! Identity Event Log (IEL) event types.
//!
//! See `docs/design/iel/events.md` for per-kind field rules and chain shapes.
//!
//! IEL events carry the chain's tracked `auth_policy` and `governance_policy`
//! state on every event; both fields are non-`Option` `Digest256`. `Icp`
//! declares them; `Evl` may carry them forward unchanged or evolve them;
//! `Cnt` / `Dec` carry them forward (the verifier rejects any change at
//! these terminal kinds, treating it as the structural equivalent of the
//! design's "forbidden" rule).
//!
//! There is no `content` field on IEL — the chain's "data" is its tracked
//! policy state, mutated only by `Evl`.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use verifiable_storage::{Chained, SelfAddressed};

use crate::error::KelsError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IdentityEventKind {
    #[serde(rename = "kels/iel/v1/events/icp")]
    Icp, // Inception (v0)
    #[serde(rename = "kels/iel/v1/events/evl")]
    Evl, // Evolve — governance evaluation; may carry policy evolution.
    #[serde(rename = "kels/iel/v1/events/cnt")]
    Cnt, // Contest — terminal authority conflict / divergence resolution.
    #[serde(rename = "kels/iel/v1/events/dec")]
    Dec, // Decommission — terminal owner-initiated end.
}

impl IdentityEventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Icp => "kels/iel/v1/events/icp",
            Self::Evl => "kels/iel/v1/events/evl",
            Self::Cnt => "kels/iel/v1/events/cnt",
            Self::Dec => "kels/iel/v1/events/dec",
        }
    }

    /// Short event kind name (e.g. `"icp"`, `"evl"`) as used by CLI tools.
    pub fn short_name(&self) -> &'static str {
        match self {
            Self::Icp => "icp",
            Self::Evl => "evl",
            Self::Cnt => "cnt",
            Self::Dec => "dec",
        }
    }

    /// Parse a short event kind name (e.g. `"icp"`, `"evl"`).
    pub fn from_short_name(s: &str) -> Result<Self, KelsError> {
        match s {
            "icp" => Ok(Self::Icp),
            "evl" => Ok(Self::Evl),
            "cnt" => Ok(Self::Cnt),
            "dec" => Ok(Self::Dec),
            _ => Err(KelsError::VerificationFailed(format!(
                "Unknown identity event kind: {}",
                s
            ))),
        }
    }

    /// True for kinds that evaluate `governance_policy` (`Evl` / `Cnt` / `Dec`).
    /// All non-`Icp` kinds evaluate governance — there is no auth-only
    /// equivalent of SE's `Upd` on IEL.
    pub fn evaluates_governance(&self) -> bool {
        matches!(self, Self::Evl | Self::Cnt | Self::Dec)
    }

    /// True for `Icp` only.
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

    /// Sort priority within the same version (lower = earlier in sorted
    /// order). Mirrors SE's `SadEventKind::sort_priority` shape; Icp leads,
    /// Evl normal, Cnt and Dec terminal sort after.
    pub fn sort_priority(&self) -> u8 {
        match self {
            Self::Icp => 0,
            Self::Evl => 1,
            Self::Cnt => 2,
            Self::Dec => 3,
        }
    }

    const ALL: [Self; 4] = [Self::Icp, Self::Evl, Self::Cnt, Self::Dec];

    /// Sort priority mapping for use with `order_by_case` in DB queries.
    pub fn sort_priority_mapping() -> Vec<(&'static str, i64)> {
        Self::ALL
            .iter()
            .map(|k| (k.as_str(), k.sort_priority() as i64))
            .collect()
    }
}

impl fmt::Display for IdentityEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for IdentityEventKind {
    type Err = KelsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "kels/iel/v1/events/icp" => Ok(Self::Icp),
            "kels/iel/v1/events/evl" => Ok(Self::Evl),
            "kels/iel/v1/events/cnt" => Ok(Self::Cnt),
            "kels/iel/v1/events/dec" => Ok(Self::Dec),
            _ => Err(KelsError::VerificationFailed(format!(
                "Unknown identity event kind: {}",
                s
            ))),
        }
    }
}

/// A chained, self-addressed event in the Identity Event Log.
///
/// Both `auth_policy` and `governance_policy` are non-`Option` `Digest256`:
/// IEL `Icp` always declares both, and every subsequent event carries the
/// tracked-state values forward (or, on `Evl`, evolves them). The verifier
/// enforces "no change" at `Cnt` / `Dec` as a chain-state check (the design's
/// "forbidden" rule realized structurally).
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "iel_events")]
#[serde(rename_all = "camelCase")]
pub struct IdentityEvent {
    #[said]
    pub said: cesr::Digest256,
    #[prefix]
    pub prefix: cesr::Digest256,
    #[previous]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub previous: Option<cesr::Digest256>,
    #[version]
    pub version: u64,
    /// The chain's topic (private to the inceptor; not third-party-discoverable).
    pub topic: String,
    /// The event kind.
    pub kind: IdentityEventKind,
    /// Tracked `auth_policy` SAID at this event. Always present.
    pub auth_policy: cesr::Digest256,
    /// Tracked `governance_policy` SAID at this event. Always present.
    pub governance_policy: cesr::Digest256,
}

/// Compute an Identity Event Log prefix.
///
/// Prefix is derived from the v0 `Icp` template with `said` and `prefix`
/// blanked. Anyone with `(auth_policy, governance_policy, topic)` can
/// reproduce the prefix — but those inputs are private to the inceptor on
/// IEL (unlike SE's third-party-discoverable `(write_policy, topic)` shape),
/// so prefix derivation is itself non-discoverable in practice.
///
/// Routes through `IdentityEvent::icp` so prefix derivation and v0 staging
/// share the same structural-validation gate.
pub fn compute_identity_event_prefix(
    auth_policy: cesr::Digest256,
    governance_policy: cesr::Digest256,
    topic: impl Into<String>,
) -> Result<cesr::Digest256, KelsError> {
    Ok(IdentityEvent::icp(auth_policy, governance_policy, topic)?.prefix)
}

impl IdentityEvent {
    /// Build a v0 `Icp` (inception) event.
    pub fn icp(
        auth_policy: cesr::Digest256,
        governance_policy: cesr::Digest256,
        topic: impl Into<String>,
    ) -> Result<Self, KelsError> {
        let event = Self::create(
            topic.into(),
            IdentityEventKind::Icp,
            auth_policy,
            governance_policy,
        )?;
        event
            .validate_structure()
            .map_err(KelsError::InvalidKeyEvent)?;
        Ok(event)
    }

    /// Build a v+1 `Evl` from a chain tip. `auth_policy` / `governance_policy`
    /// are carried forward from `previous` unless overridden.
    pub fn evl(
        previous: &Self,
        auth_policy: Option<cesr::Digest256>,
        governance_policy: Option<cesr::Digest256>,
    ) -> Result<Self, KelsError> {
        let mut event = previous.clone();
        event.kind = IdentityEventKind::Evl;
        event.auth_policy = auth_policy.unwrap_or(previous.auth_policy);
        event.governance_policy = governance_policy.unwrap_or(previous.governance_policy);
        event.increment()?;
        event
            .validate_structure()
            .map_err(KelsError::InvalidKeyEvent)?;
        Ok(event)
    }

    /// Build a v+1 `Cnt` from a chain tip. Carries `auth_policy` /
    /// `governance_policy` forward (the verifier rejects any change at this
    /// kind, mirroring the design's forbid-evolution rule).
    pub fn cnt(previous: &Self) -> Result<Self, KelsError> {
        let mut event = previous.clone();
        event.kind = IdentityEventKind::Cnt;
        event.increment()?;
        event
            .validate_structure()
            .map_err(KelsError::InvalidKeyEvent)?;
        Ok(event)
    }

    /// Build a v+1 `Dec` from a chain tip. Carries `auth_policy` /
    /// `governance_policy` forward.
    pub fn dec(previous: &Self) -> Result<Self, KelsError> {
        let mut event = previous.clone();
        event.kind = IdentityEventKind::Dec;
        event.increment()?;
        event
            .validate_structure()
            .map_err(KelsError::InvalidKeyEvent)?;
        Ok(event)
    }

    /// Per-kind structural validation. Verifier-level checks (policy
    /// evolution discipline at `Cnt` / `Dec`, immunity, anchoring) layer on
    /// top of this.
    pub fn validate_structure(&self) -> Result<(), String> {
        match self.kind {
            IdentityEventKind::Icp => {
                if self.version != 0 {
                    return Err(format!(
                        "Icp event must have version 0, got {}",
                        self.version
                    ));
                }
                if self.previous.is_some() {
                    return Err("Icp event must not have previous".into());
                }
            }
            IdentityEventKind::Evl | IdentityEventKind::Cnt | IdentityEventKind::Dec => {
                if self.version < 1 {
                    return Err(format!(
                        "{} event must have version >= 1, got {}",
                        self.kind, self.version
                    ));
                }
                if self.previous.is_none() {
                    return Err(format!("{} event requires previous", self.kind));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    fn test_digest(label: &[u8]) -> cesr::Digest256 {
        cesr::Digest256::blake3_256(label)
    }

    const TEST_TOPIC: &str = "kels/iel/v1/identity/test";

    #[test]
    fn test_kind_short_name_round_trip() {
        for &kind in &[
            IdentityEventKind::Icp,
            IdentityEventKind::Evl,
            IdentityEventKind::Cnt,
            IdentityEventKind::Dec,
        ] {
            let parsed = IdentityEventKind::from_short_name(kind.short_name()).unwrap();
            assert_eq!(parsed, kind);
        }
    }

    #[test]
    fn test_kind_topic_round_trip() {
        for &kind in &[
            IdentityEventKind::Icp,
            IdentityEventKind::Evl,
            IdentityEventKind::Cnt,
            IdentityEventKind::Dec,
        ] {
            let parsed: IdentityEventKind = kind.as_str().parse().unwrap();
            assert_eq!(parsed, kind);
        }
    }

    #[test]
    fn test_kind_predicates() {
        assert!(IdentityEventKind::Icp.is_inception());
        assert!(!IdentityEventKind::Icp.evaluates_governance());

        assert!(IdentityEventKind::Evl.evaluates_governance());
        assert!(!IdentityEventKind::Evl.is_terminal());

        assert!(IdentityEventKind::Cnt.is_contest());
        assert!(IdentityEventKind::Cnt.is_terminal());
        assert!(IdentityEventKind::Cnt.evaluates_governance());

        assert!(IdentityEventKind::Dec.is_decommission());
        assert!(IdentityEventKind::Dec.is_terminal());
        assert!(IdentityEventKind::Dec.evaluates_governance());
    }

    #[test]
    fn test_sort_priority_ordering() {
        assert!(IdentityEventKind::Icp.sort_priority() < IdentityEventKind::Evl.sort_priority());
        assert!(IdentityEventKind::Evl.sort_priority() < IdentityEventKind::Cnt.sort_priority());
        assert!(IdentityEventKind::Cnt.sort_priority() < IdentityEventKind::Dec.sort_priority());

        let mapping = IdentityEventKind::sort_priority_mapping();
        assert_eq!(mapping.len(), 4);
        assert!(mapping.contains(&("kels/iel/v1/events/icp", 0)));
        assert!(mapping.contains(&("kels/iel/v1/events/dec", 3)));
    }

    #[test]
    fn test_icp_constructor_and_prefix_deterministic() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0_a = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let v0_b = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        assert_eq!(v0_a.version, 0);
        assert!(v0_a.previous.is_none());
        assert_eq!(v0_a.auth_policy, auth);
        assert_eq!(v0_a.governance_policy, gov);
        assert_eq!(v0_a.kind, IdentityEventKind::Icp);
        // Prefix and SAID must be deterministic for the same inputs.
        assert_eq!(v0_a.prefix, v0_b.prefix);
        assert_eq!(v0_a.said, v0_b.said);
    }

    #[test]
    fn test_compute_identity_event_prefix_matches_icp() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let computed = compute_identity_event_prefix(auth, gov, TEST_TOPIC).unwrap();
        assert_eq!(v0.prefix, computed);
    }

    #[test]
    fn test_icp_prefix_changes_with_inputs() {
        let auth1 = test_digest(b"auth-1");
        let auth2 = test_digest(b"auth-2");
        let gov = test_digest(b"gov-policy");
        let p_auth1 = compute_identity_event_prefix(auth1, gov, TEST_TOPIC).unwrap();
        let p_auth2 = compute_identity_event_prefix(auth2, gov, TEST_TOPIC).unwrap();
        assert_ne!(p_auth1, p_auth2);

        let gov2 = test_digest(b"gov-2");
        let p_gov2 = compute_identity_event_prefix(auth1, gov2, TEST_TOPIC).unwrap();
        assert_ne!(p_auth1, p_gov2);

        let p_topic2 =
            compute_identity_event_prefix(auth1, gov, "kels/iel/v1/identity/other").unwrap();
        assert_ne!(p_auth1, p_topic2);
    }

    #[test]
    fn test_evl_carries_forward_when_unchanged() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let v1 = IdentityEvent::evl(&v0, None, None).unwrap();
        assert_eq!(v1.version, 1);
        assert_eq!(v1.previous, Some(v0.said));
        assert_eq!(v1.prefix, v0.prefix);
        assert_eq!(v1.kind, IdentityEventKind::Evl);
        assert_eq!(v1.auth_policy, auth);
        assert_eq!(v1.governance_policy, gov);
    }

    #[test]
    fn test_evl_evolves_auth_policy() {
        let auth1 = test_digest(b"auth-1");
        let auth2 = test_digest(b"auth-2");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth1, gov, TEST_TOPIC).unwrap();
        let v1 = IdentityEvent::evl(&v0, Some(auth2), None).unwrap();
        assert_eq!(v1.auth_policy, auth2);
        assert_eq!(v1.governance_policy, gov); // unchanged
    }

    #[test]
    fn test_cnt_carries_forward() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let v1 = IdentityEvent::cnt(&v0).unwrap();
        assert_eq!(v1.kind, IdentityEventKind::Cnt);
        assert_eq!(v1.auth_policy, auth);
        assert_eq!(v1.governance_policy, gov);
        assert_eq!(v1.previous, Some(v0.said));
        assert_eq!(v1.version, 1);
    }

    #[test]
    fn test_dec_carries_forward() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let v1 = IdentityEvent::dec(&v0).unwrap();
        assert_eq!(v1.kind, IdentityEventKind::Dec);
        assert_eq!(v1.auth_policy, auth);
        assert_eq!(v1.governance_policy, gov);
    }

    #[test]
    fn test_validate_structure_icp_with_previous_rejected() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let mut v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        v0.previous = Some(test_digest(b"bogus"));
        assert!(v0.validate_structure().is_err());
    }

    #[test]
    fn test_validate_structure_icp_wrong_version_rejected() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let mut v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        v0.version = 1;
        assert!(v0.validate_structure().is_err());
    }

    #[test]
    fn test_validate_structure_evl_without_previous_rejected() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let mut v1 = IdentityEvent::evl(&v0, None, None).unwrap();
        v1.previous = None;
        assert!(v1.validate_structure().is_err());
    }

    #[test]
    fn test_validate_structure_cnt_at_v0_rejected() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        let mut cnt = IdentityEvent::cnt(&v0).unwrap();
        cnt.version = 0;
        assert!(cnt.validate_structure().is_err());
    }

    #[test]
    fn test_verify_said_round_trip() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        v0.verify_said().unwrap();
        let v1 = IdentityEvent::evl(&v0, None, None).unwrap();
        v1.verify_said().unwrap();
    }

    #[test]
    fn test_verify_prefix_round_trip() {
        let auth = test_digest(b"auth-policy");
        let gov = test_digest(b"gov-policy");
        let v0 = IdentityEvent::icp(auth, gov, TEST_TOPIC).unwrap();
        v0.verify_prefix().unwrap();
    }
}
