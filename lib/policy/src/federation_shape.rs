//! Federation IEL `(authPolicy, governancePolicy)` shape verification.
//!
//! Validates a policy pair against the federation convention from
//! `docs/design/infrastructure/federation.md §Federation policy shape verification`:
//!
//! - `authPolicy` is `any(iel(X_1), …, iel(X_n))` — i.e.
//!   `threshold(1, [iel(...) only])`.
//! - `governancePolicy` is `threshold(M, [iel(X_1), …, iel(X_n)])` over the
//!   same member set with `M == compute_federation_governance_threshold(n)`.
//! - Both policies have `immune: true`.
//!
//! Consumed by the gossip service at startup (refuses to run on a federation
//! IEL whose policies don't conform) and by trust-evaluation callers that
//! want to confirm a federation has the standard shape before relying on it.
//! Other identities use other policy shapes; this helper is federation-specific.

use std::collections::BTreeSet;

use kels_core::compute_federation_governance_threshold;
use thiserror::Error;

use crate::{Policy, PolicyNode, error::PolicyError};

/// Outcome of a successful federation policy-shape check.
///
/// `members` is the federation member set (peer-identity IEL prefixes)
/// extracted from both policies, in sorted order. `governance_threshold` is
/// `M(n)` where `n = members.len()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationPolicyShape {
    pub members: BTreeSet<cesr::Digest256>,
    pub governance_threshold: u64,
}

#[derive(Error, Debug)]
pub enum FederationPolicyShapeError {
    #[error("auth_policy parse error: {0}")]
    AuthPolicyParse(PolicyError),
    #[error("governance_policy parse error: {0}")]
    GovernancePolicyParse(PolicyError),
    /// `auth_policy` must be `any(iel(...), ...)` (i.e. `threshold(1, ...)`)
    /// over `iel()` leaves only.
    #[error("auth_policy shape: {0}")]
    AuthPolicyShape(String),
    /// `governance_policy` must be `threshold(M, [iel(...), ...])` over
    /// `iel()` leaves only.
    #[error("governance_policy shape: {0}")]
    GovernancePolicyShape(String),
    #[error("auth_policy is not immune")]
    AuthPolicyNotImmune,
    #[error("governance_policy is not immune")]
    GovernancePolicyNotImmune,
    /// `auth_policy` and `governance_policy` must enumerate the same member
    /// IEL prefixes.
    #[error(
        "member set mismatch — auth_policy and governance_policy must enumerate \
         the same identities"
    )]
    MemberSetMismatch,
    /// `governance_policy` threshold must equal `M(n)` per the federation
    /// stair function (`compute_federation_governance_threshold`).
    #[error(
        "governance_policy threshold {actual} != M({n}) = {expected} \
         (federation stair function)"
    )]
    GovernanceThresholdMismatch {
        actual: u64,
        expected: u64,
        n: usize,
    },
}

/// Verify the federation `(authPolicy, governancePolicy)` shape.
///
/// On success returns the extracted member set and governance threshold;
/// every failure mode maps to a specific [`FederationPolicyShapeError`]
/// variant so the caller (gossip startup, trust-evaluation tooling) can
/// surface a precise diagnostic.
pub fn verify_federation_policy_shape(
    auth_policy: &Policy,
    governance_policy: &Policy,
) -> Result<FederationPolicyShape, FederationPolicyShapeError> {
    if !auth_policy.is_immune() {
        return Err(FederationPolicyShapeError::AuthPolicyNotImmune);
    }
    if !governance_policy.is_immune() {
        return Err(FederationPolicyShapeError::GovernancePolicyNotImmune);
    }

    let auth_ast = auth_policy
        .parse()
        .map_err(FederationPolicyShapeError::AuthPolicyParse)?;
    let gov_ast = governance_policy
        .parse()
        .map_err(FederationPolicyShapeError::GovernancePolicyParse)?;

    let auth_members = extract_iel_threshold(
        &auth_ast,
        Some(1),
        FederationPolicyShapeError::AuthPolicyShape,
    )?
    .1;
    let (gov_threshold, gov_members) =
        extract_iel_threshold(&gov_ast, None, FederationPolicyShapeError::GovernancePolicyShape)?;

    if auth_members != gov_members {
        return Err(FederationPolicyShapeError::MemberSetMismatch);
    }

    let n = gov_members.len();
    let expected = compute_federation_governance_threshold(n) as u64;
    if gov_threshold != expected {
        return Err(FederationPolicyShapeError::GovernanceThresholdMismatch {
            actual: gov_threshold,
            expected,
            n,
        });
    }

    Ok(FederationPolicyShape {
        members: gov_members,
        governance_threshold: gov_threshold,
    })
}

/// Extract `(threshold, members)` from a `Weighted(min, [(iel(X), 1) * n])`
/// AST. `required_min` pins the expected min_weight (used for the
/// `any(...)` case where `min` must be exactly 1); pass `None` to accept
/// any `min_weight` (governance side).
fn extract_iel_threshold(
    ast: &PolicyNode,
    required_min: Option<u64>,
    err_ctor: fn(String) -> FederationPolicyShapeError,
) -> Result<(u64, BTreeSet<cesr::Digest256>), FederationPolicyShapeError> {
    let PolicyNode::Weighted(min_weight, pairs) = ast else {
        return Err(err_ctor(format!(
            "expected threshold(...) / any(...) / all(...) node, got: {ast}"
        )));
    };

    if let Some(required) = required_min
        && *min_weight != required
    {
        return Err(err_ctor(format!(
            "expected threshold({required}, ...) (i.e. any(...)), got threshold({min_weight}, ...)"
        )));
    }

    let mut members = BTreeSet::new();
    for (child, weight) in pairs {
        if *weight != 1 {
            return Err(err_ctor(format!(
                "non-unit weight {weight} — only equal-weight threshold(M, [...]) is allowed"
            )));
        }
        match child {
            PolicyNode::Iel(prefix) => {
                if !members.insert(*prefix) {
                    return Err(err_ctor(format!(
                        "duplicate iel({prefix}) leaf"
                    )));
                }
            }
            _ => {
                return Err(err_ctor(format!(
                    "non-iel leaf: {child} (federation policies enumerate only iel(...) leaves)"
                )));
            }
        }
    }

    if members.is_empty() {
        return Err(err_ctor("empty member list".to_string()));
    }

    Ok((*min_weight, members))
}

#[cfg(test)]
mod tests {
    use cesr::test_digest;

    use super::*;

    fn iels(n: usize) -> Vec<cesr::Digest256> {
        (0..n)
            .map(|i| test_digest(&format!("iel-{i}")))
            .collect()
    }

    fn auth_expr(members: &[cesr::Digest256]) -> String {
        let inner: Vec<String> = members.iter().map(|m| format!("iel({m})")).collect();
        format!("any({})", inner.join(", "))
    }

    fn gov_expr(threshold: u64, members: &[cesr::Digest256]) -> String {
        let inner: Vec<String> = members.iter().map(|m| format!("iel({m})")).collect();
        format!("threshold({threshold}, [{}])", inner.join(", "))
    }

    fn build_policies(
        members: &[cesr::Digest256],
        gov_threshold_override: Option<u64>,
    ) -> (Policy, Policy) {
        let auth = Policy::build(&auth_expr(members), None, true).unwrap();
        let n = members.len();
        let m = gov_threshold_override
            .unwrap_or_else(|| compute_federation_governance_threshold(n) as u64);
        let gov = Policy::build(&gov_expr(m, members), None, true).unwrap();
        (auth, gov)
    }

    #[test]
    fn test_minimum_three_member_federation_passes() {
        let members = iels(3);
        let (auth, gov) = build_policies(&members, None);
        let shape = verify_federation_policy_shape(&auth, &gov).unwrap();
        assert_eq!(shape.members.len(), 3);
        assert_eq!(shape.governance_threshold, 3);
    }

    #[test]
    fn test_six_member_federation_threshold_is_four() {
        let members = iels(6);
        let (auth, gov) = build_policies(&members, None);
        let shape = verify_federation_policy_shape(&auth, &gov).unwrap();
        assert_eq!(shape.governance_threshold, 4);
    }

    #[test]
    fn test_ten_member_federation_uses_one_third_quorum() {
        let members = iels(10);
        let (auth, gov) = build_policies(&members, None);
        let shape = verify_federation_policy_shape(&auth, &gov).unwrap();
        // ceil(10/3) = 4
        assert_eq!(shape.governance_threshold, 4);
    }

    #[test]
    fn test_twenty_one_member_federation_uses_one_third_quorum() {
        let members = iels(21);
        let (auth, gov) = build_policies(&members, None);
        let shape = verify_federation_policy_shape(&auth, &gov).unwrap();
        // ceil(21/3) = 7
        assert_eq!(shape.governance_threshold, 7);
    }

    #[test]
    fn test_governance_threshold_mismatch_rejected() {
        let members = iels(10);
        let (auth, gov) = build_policies(&members, Some(5)); // M(10) = 4, not 5
        let err = verify_federation_policy_shape(&auth, &gov).unwrap_err();
        assert!(matches!(
            err,
            FederationPolicyShapeError::GovernanceThresholdMismatch {
                actual: 5,
                expected: 4,
                n: 10
            }
        ));
    }

    #[test]
    fn test_auth_policy_not_immune_rejected() {
        let members = iels(3);
        let auth = Policy::build(&auth_expr(&members), None, false).unwrap();
        let gov = Policy::build(&gov_expr(3, &members), None, true).unwrap();
        let err = verify_federation_policy_shape(&auth, &gov).unwrap_err();
        assert!(matches!(err, FederationPolicyShapeError::AuthPolicyNotImmune));
    }

    #[test]
    fn test_governance_policy_not_immune_rejected() {
        let members = iels(3);
        let auth = Policy::build(&auth_expr(&members), None, true).unwrap();
        let gov = Policy::build(&gov_expr(3, &members), None, false).unwrap();
        let err = verify_federation_policy_shape(&auth, &gov).unwrap_err();
        assert!(matches!(
            err,
            FederationPolicyShapeError::GovernancePolicyNotImmune
        ));
    }

    #[test]
    fn test_auth_policy_not_any_rejected() {
        // auth_policy is threshold(2, ...) — not any(...).
        let members = iels(3);
        let auth = Policy::build(&gov_expr(2, &members), None, true).unwrap();
        let gov = Policy::build(&gov_expr(3, &members), None, true).unwrap();
        let err = verify_federation_policy_shape(&auth, &gov).unwrap_err();
        assert!(matches!(err, FederationPolicyShapeError::AuthPolicyShape(_)));
    }

    #[test]
    fn test_auth_policy_with_kel_leaf_rejected() {
        // auth_policy contains a kel(...) leaf — federation convention only
        // accepts iel(...) leaves. Construct a 3-member-shaped auth_policy
        // with one leaf swapped to kel(), and a matching-sized gov so we
        // exercise the leaf-shape check (not the member-count or threshold).
        let kel_p = test_digest("a-kel");
        let iel_0 = test_digest("iel-0");
        let iel_1 = test_digest("iel-1");
        let auth = Policy::build(
            &format!("any(iel({iel_0}), iel({iel_1}), kel({kel_p}))"),
            None,
            true,
        )
        .unwrap();
        let gov_members = vec![iel_0, iel_1, kel_p];
        let gov = Policy::build(&gov_expr(3, &gov_members), None, true).unwrap();
        let err = verify_federation_policy_shape(&auth, &gov).unwrap_err();
        assert!(matches!(err, FederationPolicyShapeError::AuthPolicyShape(_)));
    }

    #[test]
    fn test_governance_policy_with_nested_threshold_rejected() {
        let members = iels(3);
        let nested = format!(
            "threshold(2, [threshold(1, [iel({}), iel({})]), iel({})])",
            members[0], members[1], members[2]
        );
        let auth = Policy::build(&auth_expr(&members), None, true).unwrap();
        let gov = Policy::build(&nested, None, true).unwrap();
        let err = verify_federation_policy_shape(&auth, &gov).unwrap_err();
        assert!(matches!(
            err,
            FederationPolicyShapeError::GovernancePolicyShape(_)
        ));
    }

    #[test]
    fn test_member_set_mismatch_rejected() {
        let auth_members = iels(3);
        let mut gov_members = auth_members.clone();
        gov_members[2] = test_digest("iel-different");
        let auth = Policy::build(&auth_expr(&auth_members), None, true).unwrap();
        let gov = Policy::build(&gov_expr(3, &gov_members), None, true).unwrap();
        let err = verify_federation_policy_shape(&auth, &gov).unwrap_err();
        assert!(matches!(err, FederationPolicyShapeError::MemberSetMismatch));
    }

    #[test]
    fn test_duplicate_member_rejected() {
        let m = test_digest("iel-dup");
        let auth = Policy::build(&format!("any(iel({m}), iel({m}))"), None, true).unwrap();
        let gov =
            Policy::build(&format!("threshold(3, [iel({m}), iel({m}), iel({m})])"), None, true)
                .unwrap();
        let err = verify_federation_policy_shape(&auth, &gov).unwrap_err();
        assert!(matches!(err, FederationPolicyShapeError::AuthPolicyShape(_)));
    }

    #[test]
    fn test_governance_policy_with_weighted_rejected() {
        // weighted(...) has non-unit weights; federation convention forbids it.
        let members = iels(3);
        let auth = Policy::build(&auth_expr(&members), None, true).unwrap();
        let gov = Policy::build(
            &format!(
                "weighted(3, [iel({}):2, iel({}):1, iel({}):1])",
                members[0], members[1], members[2]
            ),
            None,
            true,
        )
        .unwrap();
        let err = verify_federation_policy_shape(&auth, &gov).unwrap_err();
        assert!(matches!(
            err,
            FederationPolicyShapeError::GovernancePolicyShape(_)
        ));
    }

    #[test]
    fn test_all_alias_on_auth_policy_rejected() {
        // all(...) desugars to threshold(n, ...) — not the any(...) shape.
        let members = iels(3);
        let auth_all = format!(
            "all(iel({}), iel({}), iel({}))",
            members[0], members[1], members[2]
        );
        let auth = Policy::build(&auth_all, None, true).unwrap();
        let gov = Policy::build(&gov_expr(3, &members), None, true).unwrap();
        let err = verify_federation_policy_shape(&auth, &gov).unwrap_err();
        assert!(matches!(err, FederationPolicyShapeError::AuthPolicyShape(_)));
    }
}
