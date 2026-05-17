use std::collections::{BTreeMap, BTreeSet};

use cesr::Digest256;
use kels_core::{IelResolver, KelVerifier, PagedKelSource, verify_key_events};

use crate::{
    Policy, PolicyNode,
    error::PolicyError,
    resolver::PolicyResolver,
    verification::{EndorsementStatus, PolicyVerification},
};

const MAX_POLICY_DEPTH: usize = 10;

/// Compute the poison hash for a credential SAID.
/// `poison_hash = Blake3(b"kels/poison:" || credential_said.as_bytes())`
pub fn poison_hash(credential_said: &str) -> Digest256 {
    let bytes = [b"kels/poison:" as &[u8], credential_said.as_bytes()].concat();
    Digest256::blake3_256(&bytes)
}

/// Per-evaluation state for `iel(...)` leaves.
///
/// The cache is keyed by IEL prefix and is correct for the duration of a
/// single evaluation: within one eval the IEL tip is a momentary snapshot, so
/// repeated `iel(X)` leaves resolve to the same `authPolicy` SAID and the
/// same satisfaction. The design (`docs/design/features/policy.md §Identity
/// Resolution`) frames the cache key as `(identity_prefix, chain_tip_SAID)`
/// for forward-compatibility with hypothetical higher-scope caches; for our
/// per-eval lifetime, the prefix alone is sufficient.
///
/// `stack` tracks IEL prefixes currently being resolved so a transitive
/// `iel(X) → ... → iel(X)` cycle is rejected loudly.
#[derive(Default)]
struct IelContext {
    cache: BTreeMap<Digest256, bool>,
    stack: BTreeSet<Digest256>,
}

/// Evaluate a policy against KEL state for a given credential SAID.
///
/// Walks the policy AST, checking each endorser's KEL for anchoring and poisoning.
/// `iel(...)` leaves resolve through `iel_resolver` to the named IEL's current
/// `authPolicy` and are evaluated recursively in place.
///
/// Returns a `PolicyVerification` with the satisfaction result and per-endorser status.
pub async fn evaluate_anchored_policy(
    policy: &Policy,
    credential_said: &cesr::Digest256,
    source: &(dyn PagedKelSource + Sync),
    resolver: &dyn PolicyResolver,
    iel_resolver: &dyn IelResolver,
) -> Result<PolicyVerification, PolicyError> {
    let mut visited = BTreeSet::new();
    let mut iel_ctx = IelContext::default();
    evaluate_anchored_policy_inner(
        policy,
        credential_said,
        source,
        resolver,
        iel_resolver,
        &mut visited,
        &mut iel_ctx,
        MAX_POLICY_DEPTH,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn evaluate_anchored_policy_inner(
    policy: &Policy,
    credential_said: &cesr::Digest256,
    source: &(dyn PagedKelSource + Sync),
    resolver: &dyn PolicyResolver,
    iel_resolver: &dyn IelResolver,
    visited: &mut BTreeSet<cesr::Digest256>,
    iel_ctx: &mut IelContext,
    remaining_depth: usize,
) -> Result<PolicyVerification, PolicyError> {
    let ast = policy.parse()?;
    let mut endorsements = BTreeMap::new();
    let mut nested = BTreeMap::new();

    // When a poison expression is set, the main expression evaluates without
    // poison checks (endorsers can't individually poison; only the poison
    // expression controls poisoning). When absent, the main expression checks
    // poison hashes per-endorser as before.
    let use_immune_for_main = policy.poison.is_some();
    let effective_policy_for_main = if use_immune_for_main {
        // Create a temporary immune view for the main expression evaluation
        Policy {
            said: policy.said,
            expression: policy.expression.clone(),
            poison: None,
            immune: Some(true),
        }
    } else {
        policy.clone()
    };

    let is_satisfied = evaluate_node(
        &ast,
        credential_said,
        &effective_policy_for_main,
        source,
        resolver,
        iel_resolver,
        &mut endorsements,
        &mut nested,
        visited,
        iel_ctx,
        remaining_depth,
    )
    .await?;

    // Evaluate poison expression if present and policy is not immune
    let is_poisoned = if !policy.is_immune() {
        if let Some(poison_ast) = policy.parse_poison()? {
            // Evaluate the poison expression using the poison hash as the anchor
            let p_hash = poison_hash(credential_said.as_ref());
            let mut poison_endorsements = BTreeMap::new();
            let mut poison_nested = BTreeMap::new();
            let mut poison_visited = BTreeSet::new();
            let mut poison_iel_ctx = IelContext::default();

            // Create an immune policy for poison evaluation (we're checking for
            // poison hash anchoring, not recursively checking for poisoning)
            let poison_eval_policy = Policy {
                said: cesr::Digest256::default(),
                expression: policy.poison.clone().unwrap_or_default(),
                poison: None,
                immune: Some(true),
            };

            let poison_satisfied = evaluate_node(
                &poison_ast,
                &p_hash,
                &poison_eval_policy,
                source,
                resolver,
                iel_resolver,
                &mut poison_endorsements,
                &mut poison_nested,
                &mut poison_visited,
                &mut poison_iel_ctx,
                remaining_depth,
            )
            .await?;

            // Merge poison endorsements into the main endorsements as Poisoned
            if poison_satisfied {
                for (prefix, status) in &poison_endorsements {
                    if matches!(status, EndorsementStatus::Endorsed) {
                        endorsements.insert(*prefix, EndorsementStatus::Poisoned);
                    }
                }
            }

            poison_satisfied
        } else {
            // Default mode: any endorser can soft-poison
            endorsements
                .values()
                .any(|s| matches!(s, EndorsementStatus::Poisoned))
        }
    } else {
        false
    };

    // Determine final satisfaction
    let final_satisfied = if is_poisoned {
        if policy.is_poisonable() {
            // Poison expression satisfied: policy is unsatisfied
            false
        } else {
            // Default mode: poisoned endorsements already don't count in the main evaluation
            is_satisfied
        }
    } else {
        is_satisfied
    };

    Ok(PolicyVerification {
        policy: policy.said,
        is_satisfied: final_satisfied,
        endorsements,
        nested_verifications: nested,
    })
}

#[allow(clippy::too_many_arguments)]
fn evaluate_node<'a>(
    node: &'a PolicyNode,
    credential_said: &'a cesr::Digest256,
    policy: &'a Policy,
    source: &'a (dyn PagedKelSource + Sync),
    resolver: &'a dyn PolicyResolver,
    iel_resolver: &'a dyn IelResolver,
    endorsements: &'a mut BTreeMap<cesr::Digest256, EndorsementStatus>,
    nested: &'a mut BTreeMap<cesr::Digest256, PolicyVerification>,
    visited: &'a mut BTreeSet<cesr::Digest256>,
    iel_ctx: &'a mut IelContext,
    remaining_depth: usize,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, PolicyError>> + Send + 'a>> {
    Box::pin(async move {
        if remaining_depth == 0 {
            return Err(PolicyError::EvaluationError(
                "maximum policy nesting depth exceeded".to_string(),
            ));
        }

        match node {
            PolicyNode::Kel(prefix) => {
                let status =
                    evaluate_kel(prefix, credential_said, policy, source, endorsements).await?;
                Ok(matches!(status, EndorsementStatus::Endorsed))
            }

            PolicyNode::Iel(iel_prefix) => {
                evaluate_iel_anchored(
                    iel_prefix,
                    credential_said,
                    source,
                    resolver,
                    iel_resolver,
                    endorsements,
                    nested,
                    visited,
                    iel_ctx,
                    remaining_depth,
                )
                .await
            }

            PolicyNode::Delegate(delegator, delegate) => {
                // First verify the delegation relationship
                let delegation_valid = verify_delegation(delegator, delegate, source).await?;
                if !delegation_valid {
                    endorsements.insert(
                        *delegate,
                        EndorsementStatus::KelError("delegation not verified".to_string()),
                    );
                    return Ok(false);
                }

                // Then check the delegate's endorsement
                let status =
                    evaluate_kel(delegate, credential_said, policy, source, endorsements).await?;
                Ok(matches!(status, EndorsementStatus::Endorsed))
            }

            PolicyNode::Weighted(min_weight, pairs) => {
                let mut total_weight = 0u64;
                for (child, weight) in pairs {
                    if evaluate_node(
                        child,
                        credential_said,
                        policy,
                        source,
                        resolver,
                        iel_resolver,
                        endorsements,
                        nested,
                        visited,
                        iel_ctx,
                        remaining_depth - 1,
                    )
                    .await?
                    {
                        total_weight = total_weight.saturating_add(*weight);
                    }
                }
                Ok(total_weight >= *min_weight)
            }

            PolicyNode::Policy(said) => {
                if !visited.insert(*said) {
                    return Err(PolicyError::EvaluationError(format!(
                        "circular policy reference detected: {said}"
                    )));
                }

                let resolved = resolver.resolve_policy(said).await?;
                let verification = evaluate_anchored_policy_inner(
                    &resolved,
                    credential_said,
                    source,
                    resolver,
                    iel_resolver,
                    visited,
                    iel_ctx,
                    remaining_depth - 1,
                )
                .await?;
                let satisfied = verification.is_satisfied;
                nested.insert(*said, verification);

                visited.remove(said);
                Ok(satisfied)
            }
        }
    })
}

/// Evaluate a single endorser's status. Caches results by prefix.
async fn evaluate_kel(
    prefix: &cesr::Digest256,
    credential_said: &cesr::Digest256,
    policy: &Policy,
    source: &(dyn PagedKelSource + Sync),
    endorsements: &mut BTreeMap<cesr::Digest256, EndorsementStatus>,
) -> Result<EndorsementStatus, PolicyError> {
    // Return cached result if already evaluated
    if let Some(status) = endorsements.get(prefix) {
        return Ok(status.clone());
    }

    let check_poison = !policy.is_immune();
    let p_hash = if check_poison {
        Some(poison_hash(credential_said.as_ref()))
    } else {
        None
    };

    let mut verifier = KelVerifier::new(prefix);
    let mut saids_to_check = vec![*credential_said];
    if let Some(ref ph) = p_hash {
        saids_to_check.push(*ph);
    }
    verifier.check_anchors(saids_to_check);

    let status = match verify_key_events(
        prefix,
        source,
        verifier,
        kels_core::page_size(),
        kels_core::max_pages(),
    )
    .await
    {
        Ok(kel_v) => {
            let poisoned = p_hash.as_ref().is_some_and(|ph| kel_v.is_said_anchored(ph));
            if poisoned {
                EndorsementStatus::Poisoned
            } else if kel_v.is_said_anchored(credential_said) {
                EndorsementStatus::Endorsed
            } else {
                EndorsementStatus::NotEndorsed
            }
        }
        // #156 I-N1: route contested / decommissioned KELs to the
        // permanent-fail variant so `AnchoredPolicyChecker.evaluate`
        // omits them from `missing_anchors` per the AnchorEvaluation
        // contract. Other KEL errors stay deferrable (chain may catch up).
        Err(e) => match &e {
            kels_core::KelsError::ContestedKel(_) | kels_core::KelsError::KelDecommissioned => {
                EndorsementStatus::KelPermanentFail(e.to_string())
            }
            _ => EndorsementStatus::KelError(e.to_string()),
        },
    };

    endorsements.insert(*prefix, status.clone());
    Ok(status)
}

/// Evaluate an `iel(X)` leaf in anchored context: resolve X's current
/// `authPolicy`, then evaluate that policy in place against the same
/// `credential_said`.
///
/// Cycle guard rejects transitive `iel(X) → ... → iel(X)` recursions. Cache
/// short-circuits repeat `iel(X)` references within one evaluation.
/// Unresolvable IEL (contested, decommissioned, divergent, not found locally)
/// returns `Err` — fails loudly per the design's trust model. Silent `false`
/// would let a policy be "satisfied" by an evaluator that can't see the truth.
#[allow(clippy::too_many_arguments)]
async fn evaluate_iel_anchored(
    iel_prefix: &cesr::Digest256,
    credential_said: &cesr::Digest256,
    source: &(dyn PagedKelSource + Sync),
    resolver: &dyn PolicyResolver,
    iel_resolver: &dyn IelResolver,
    endorsements: &mut BTreeMap<cesr::Digest256, EndorsementStatus>,
    nested: &mut BTreeMap<cesr::Digest256, PolicyVerification>,
    visited: &mut BTreeSet<cesr::Digest256>,
    iel_ctx: &mut IelContext,
    remaining_depth: usize,
) -> Result<bool, PolicyError> {
    if let Some(cached) = iel_ctx.cache.get(iel_prefix) {
        return Ok(*cached);
    }
    if !iel_ctx.stack.insert(*iel_prefix) {
        return Err(PolicyError::EvaluationError(format!(
            "iel({iel_prefix}) cycle detected — \
             leaf references an identity already being resolved on this evaluation path"
        )));
    }

    let policy_said = iel_resolver
        .resolve_current_auth_policy(iel_prefix)
        .await?;
    // Mirror the `Policy(said)` branch's cycle-guard semantics for nested
    // policy resolution — the same SAID space, the same visited set.
    if !visited.insert(policy_said) {
        iel_ctx.stack.remove(iel_prefix);
        return Err(PolicyError::EvaluationError(format!(
            "iel({iel_prefix}) resolved to policy {policy_said} \
             already being evaluated on this path"
        )));
    }
    let resolved = resolver.resolve_policy(&policy_said).await?;
    let verification = evaluate_anchored_policy_inner(
        &resolved,
        credential_said,
        source,
        resolver,
        iel_resolver,
        visited,
        iel_ctx,
        remaining_depth - 1,
    )
    .await?;
    visited.remove(&policy_said);
    iel_ctx.stack.remove(iel_prefix);

    // Carry up endorser-level facts so the top-level PolicyVerification's
    // `endorsements` map reflects what was actually checked. Don't clobber
    // already-recorded statuses (the outer policy may have evaluated the
    // same KEL prefix at a different scope first).
    for (prefix, status) in &verification.endorsements {
        endorsements.entry(*prefix).or_insert_with(|| status.clone());
    }
    let satisfied = verification.is_satisfied;
    nested.insert(policy_said, verification);
    iel_ctx.cache.insert(*iel_prefix, satisfied);
    Ok(satisfied)
}

/// Verify that `delegate` is delegated by `delegator`.
/// Checks: (1) delegate's KEL incepted via dip with delegator as delegating prefix,
/// (2) delegator's KEL anchors delegate's prefix.
async fn verify_delegation(
    delegator: &cesr::Digest256,
    delegate: &cesr::Digest256,
    source: &(dyn PagedKelSource + Sync),
) -> Result<bool, PolicyError> {
    // Verify the delegate's KEL to check delegating_prefix
    let delegate_verifier = KelVerifier::new(delegate);
    let delegate_kel = match verify_key_events(
        delegate,
        source,
        delegate_verifier,
        kels_core::page_size(),
        kels_core::max_pages(),
    )
    .await
    {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };

    // Check that delegate's KEL was incepted via dip with the correct delegator
    if delegate_kel.delegating_prefix() != Some(delegator) {
        return Ok(false);
    }

    // Verify the delegator's KEL anchors the delegate's prefix
    let mut delegator_verifier = KelVerifier::new(delegator);
    delegator_verifier.check_anchors(vec![*delegate]);

    match verify_key_events(
        delegator,
        source,
        delegator_verifier,
        kels_core::page_size(),
        kels_core::max_pages(),
    )
    .await
    {
        Ok(kel_v) => Ok(kel_v.is_said_anchored(delegate)),
        Err(_) => Ok(false),
    }
}

/// Evaluate a policy against a set of verified prefixes (no KEL verification).
///
/// Used for SAD-object read access-control at fetch time and for federation
/// handshake authorization. The caller has already verified the signers' KELs
/// and collected the verified KEL-prefix set.
///
/// This function resolves the policy by SAID, walks the AST, and checks
/// whether the verified prefixes satisfy the policy. `kel(P)` leaves test
/// `verified_prefixes.contains(P)` directly. `iel(X)` leaves resolve X's
/// current `authPolicy` via `iel_resolver` and evaluate recursively against
/// the same verified-prefix set (cycle-guarded, per-evaluation cached).
/// No anchoring, no poison checks, no per-leaf KEL walks.
pub async fn evaluate_signed_policy(
    policy_said: &cesr::Digest256,
    verified_prefixes: &std::collections::HashSet<cesr::Digest256>,
    resolver: &dyn PolicyResolver,
    iel_resolver: &dyn IelResolver,
) -> Result<PolicyVerification, PolicyError> {
    let mut visited = BTreeSet::new();
    let mut iel_ctx = IelContext::default();
    evaluate_signed_policy_inner(
        policy_said,
        verified_prefixes,
        resolver,
        iel_resolver,
        &mut visited,
        &mut iel_ctx,
        MAX_POLICY_DEPTH,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn evaluate_signed_policy_inner(
    policy_said: &cesr::Digest256,
    verified_prefixes: &std::collections::HashSet<cesr::Digest256>,
    resolver: &dyn PolicyResolver,
    iel_resolver: &dyn IelResolver,
    visited: &mut BTreeSet<cesr::Digest256>,
    iel_ctx: &mut IelContext,
    remaining_depth: usize,
) -> Result<PolicyVerification, PolicyError> {
    if remaining_depth == 0 {
        return Err(PolicyError::EvaluationError(
            "maximum policy nesting depth exceeded".to_string(),
        ));
    }

    if !visited.insert(*policy_said) {
        return Err(PolicyError::EvaluationError(format!(
            "circular policy reference detected: {policy_said}"
        )));
    }

    let policy = resolver.resolve_policy(policy_said).await?;
    let ast = policy.parse()?;
    let mut endorsements = BTreeMap::new();
    let mut nested = BTreeMap::new();

    let is_satisfied = evaluate_signed_node(
        &ast,
        verified_prefixes,
        resolver,
        iel_resolver,
        &mut endorsements,
        &mut nested,
        visited,
        iel_ctx,
        remaining_depth,
    )
    .await?;

    visited.remove(policy_said);

    Ok(PolicyVerification {
        policy: *policy_said,
        is_satisfied,
        endorsements,
        nested_verifications: nested,
    })
}

#[allow(clippy::too_many_arguments)]
fn evaluate_signed_node<'a>(
    node: &'a PolicyNode,
    verified_prefixes: &'a std::collections::HashSet<cesr::Digest256>,
    resolver: &'a dyn PolicyResolver,
    iel_resolver: &'a dyn IelResolver,
    endorsements: &'a mut BTreeMap<cesr::Digest256, EndorsementStatus>,
    nested: &'a mut BTreeMap<cesr::Digest256, PolicyVerification>,
    visited: &'a mut BTreeSet<cesr::Digest256>,
    iel_ctx: &'a mut IelContext,
    remaining_depth: usize,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, PolicyError>> + Send + 'a>> {
    Box::pin(async move {
        match node {
            PolicyNode::Kel(prefix) => {
                let endorsed = verified_prefixes.contains(prefix);
                endorsements.insert(
                    *prefix,
                    if endorsed {
                        EndorsementStatus::Endorsed
                    } else {
                        EndorsementStatus::NotEndorsed
                    },
                );
                Ok(endorsed)
            }

            PolicyNode::Iel(iel_prefix) => {
                evaluate_iel_signed(
                    iel_prefix,
                    verified_prefixes,
                    resolver,
                    iel_resolver,
                    endorsements,
                    nested,
                    visited,
                    iel_ctx,
                    remaining_depth,
                )
                .await
            }

            PolicyNode::Delegate(_, _) => {
                // Delegate nodes are an issuance-side concern for scaling credential
                // issuance via delegation chains (see #77 — delegated signing servers).
                // They are not meaningful in fetch-time access-control context where
                // we evaluate against a verified prefix set from a SignedRequest.
                Err(PolicyError::EvaluationError(
                    "delegate() nodes are not supported in signed policy evaluation \
                     — delegation is an issuance concern, not an access-control concern"
                        .to_string(),
                ))
            }

            PolicyNode::Weighted(min_weight, pairs) => {
                let mut total_weight = 0u64;
                for (child, weight) in pairs {
                    if evaluate_signed_node(
                        child,
                        verified_prefixes,
                        resolver,
                        iel_resolver,
                        endorsements,
                        nested,
                        visited,
                        iel_ctx,
                        remaining_depth - 1,
                    )
                    .await?
                    {
                        total_weight = total_weight.saturating_add(*weight);
                    }
                }
                Ok(total_weight >= *min_weight)
            }

            PolicyNode::Policy(said) => {
                let verification = evaluate_signed_policy_inner(
                    said,
                    verified_prefixes,
                    resolver,
                    iel_resolver,
                    visited,
                    iel_ctx,
                    remaining_depth - 1,
                )
                .await?;
                let satisfied = verification.is_satisfied;
                nested.insert(*said, verification);
                Ok(satisfied)
            }
        }
    })
}

/// Evaluate an `iel(X)` leaf in signed-policy context. Same shape as
/// [`evaluate_iel_anchored`]: cycle-guard via `iel_ctx.stack`, per-evaluation
/// cache via `iel_ctx.cache`, loud-fail on unresolvable.
#[allow(clippy::too_many_arguments)]
async fn evaluate_iel_signed(
    iel_prefix: &cesr::Digest256,
    verified_prefixes: &std::collections::HashSet<cesr::Digest256>,
    resolver: &dyn PolicyResolver,
    iel_resolver: &dyn IelResolver,
    endorsements: &mut BTreeMap<cesr::Digest256, EndorsementStatus>,
    nested: &mut BTreeMap<cesr::Digest256, PolicyVerification>,
    visited: &mut BTreeSet<cesr::Digest256>,
    iel_ctx: &mut IelContext,
    remaining_depth: usize,
) -> Result<bool, PolicyError> {
    if let Some(cached) = iel_ctx.cache.get(iel_prefix) {
        return Ok(*cached);
    }
    if !iel_ctx.stack.insert(*iel_prefix) {
        return Err(PolicyError::EvaluationError(format!(
            "iel({iel_prefix}) cycle detected — \
             leaf references an identity already being resolved on this evaluation path"
        )));
    }

    let policy_said = iel_resolver
        .resolve_current_auth_policy(iel_prefix)
        .await?;
    let verification = evaluate_signed_policy_inner(
        &policy_said,
        verified_prefixes,
        resolver,
        iel_resolver,
        visited,
        iel_ctx,
        remaining_depth - 1,
    )
    .await?;
    iel_ctx.stack.remove(iel_prefix);

    for (prefix, status) in &verification.endorsements {
        endorsements.entry(*prefix).or_insert_with(|| status.clone());
    }
    let satisfied = verification.is_satisfied;
    nested.insert(policy_said, verification);
    iel_ctx.cache.insert(*iel_prefix, satisfied);
    Ok(satisfied)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use cesr::test_digest;
    use kels_core::{
        FileKelStore, IdentityEvent, IdentityEventKind, IelChainPositionBatch, IelSatisfaction,
        KelStore, KelsError, KeyEventBuilder, SoftwareKeyProvider, StoreKelSource,
        VerificationKeyCode, forward_key_events,
    };

    use super::*;
    use crate::resolver::InMemoryPolicyResolver;

    /// Stub IEL resolver for tests that don't exercise `iel(...)` leaves.
    /// Every method errors loudly — the evaluator should never call into
    /// these methods unless the policy under test contains an `iel(...)` leaf.
    struct StubIelResolver;

    #[async_trait]
    impl IelResolver for StubIelResolver {
        async fn fetch_iel_event(
            &self,
            _: &cesr::Digest256,
            _: &cesr::Digest256,
        ) -> Result<IdentityEvent, KelsError> {
            Err(KelsError::NotFound("test stub".to_string()))
        }
        async fn resolve_auth_policy_at(
            &self,
            _: &cesr::Digest256,
            _: &cesr::Digest256,
        ) -> Result<cesr::Digest256, KelsError> {
            Err(KelsError::NotFound("test stub".to_string()))
        }
        async fn resolve_governance_policy_at(
            &self,
            _: &cesr::Digest256,
            _: &cesr::Digest256,
        ) -> Result<cesr::Digest256, KelsError> {
            Err(KelsError::NotFound("test stub".to_string()))
        }
        async fn iel_chain_positions(
            &self,
            _: &cesr::Digest256,
            _: &[cesr::Digest256],
        ) -> Result<IelChainPositionBatch, KelsError> {
            Err(KelsError::NotFound("test stub".to_string()))
        }
        async fn is_satisfied(
            &self,
            _: &cesr::Digest256,
            _: &cesr::Digest256,
        ) -> Result<IelSatisfaction, KelsError> {
            Err(KelsError::NotFound("test stub".to_string()))
        }
        async fn resolve_identity_for_event(
            &self,
            _: &cesr::Digest256,
        ) -> Result<cesr::Digest256, KelsError> {
            Err(KelsError::NotFound("test stub".to_string()))
        }
        async fn resolve_current_auth_policy(
            &self,
            _: &cesr::Digest256,
        ) -> Result<cesr::Digest256, KelsError> {
            Err(KelsError::NotFound("test stub".to_string()))
        }
    }

    /// In-memory IEL resolver: maps `iel_prefix → current authPolicy SAID`.
    /// Only `resolve_current_auth_policy` is implemented — that's the only
    /// method the policy evaluator calls today.
    struct InMemoryIelResolver {
        auth_policies: BTreeMap<cesr::Digest256, cesr::Digest256>,
    }

    impl InMemoryIelResolver {
        fn new(map: Vec<(cesr::Digest256, cesr::Digest256)>) -> Self {
            Self {
                auth_policies: map.into_iter().collect(),
            }
        }
    }

    #[async_trait]
    impl IelResolver for InMemoryIelResolver {
        async fn fetch_iel_event(
            &self,
            _: &cesr::Digest256,
            _: &cesr::Digest256,
        ) -> Result<IdentityEvent, KelsError> {
            Err(KelsError::NotFound("not used".to_string()))
        }
        async fn resolve_auth_policy_at(
            &self,
            _: &cesr::Digest256,
            _: &cesr::Digest256,
        ) -> Result<cesr::Digest256, KelsError> {
            Err(KelsError::NotFound("not used".to_string()))
        }
        async fn resolve_governance_policy_at(
            &self,
            _: &cesr::Digest256,
            _: &cesr::Digest256,
        ) -> Result<cesr::Digest256, KelsError> {
            Err(KelsError::NotFound("not used".to_string()))
        }
        async fn iel_chain_positions(
            &self,
            _: &cesr::Digest256,
            _: &[cesr::Digest256],
        ) -> Result<IelChainPositionBatch, KelsError> {
            Err(KelsError::NotFound("not used".to_string()))
        }
        async fn is_satisfied(
            &self,
            _: &cesr::Digest256,
            _: &cesr::Digest256,
        ) -> Result<IelSatisfaction, KelsError> {
            Err(KelsError::NotFound("not used".to_string()))
        }
        async fn resolve_identity_for_event(
            &self,
            _: &cesr::Digest256,
        ) -> Result<cesr::Digest256, KelsError> {
            Err(KelsError::NotFound("not used".to_string()))
        }
        async fn resolve_current_auth_policy(
            &self,
            identity: &cesr::Digest256,
        ) -> Result<cesr::Digest256, KelsError> {
            self.auth_policies.get(identity).copied().ok_or_else(|| {
                KelsError::NotFound(format!("test IEL {identity} not in resolver"))
            })
        }
    }

    // Silence the "kind / event are unused" warning if a test path doesn't
    // actually instantiate those types.
    #[allow(dead_code)]
    fn _silence_event() -> IdentityEventKind {
        IdentityEventKind::Evl
    }

    async fn setup_kel() -> (
        KeyEventBuilder<SoftwareKeyProvider>,
        cesr::Digest256,
        Arc<FileKelStore>,
        tempfile::TempDir,
    ) {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let kel_store = Arc::new(FileKelStore::new(temp_dir.path()).await.unwrap());
        let mut builder = KeyEventBuilder::with_dependencies(
            SoftwareKeyProvider::new(
                VerificationKeyCode::Secp256r1,
                VerificationKeyCode::Secp256r1,
            ),
            None,
            Some(kel_store.clone() as Arc<dyn KelStore>),
            None,
        )
        .await
        .unwrap();
        let icp = builder.incept().await.unwrap();
        let prefix = icp.event.prefix;
        (builder, prefix, kel_store, temp_dir)
    }

    #[tokio::test]
    async fn test_single_endorser_satisfied() {
        let (mut builder, prefix, kel_store, _dir) = setup_kel().await;
        let policy = Policy::build(&format!("kel({prefix})"), None, false).unwrap();
        let credential_said = cesr::test_digest("single-endorser-said");

        // Anchor the credential SAID
        builder.interact(&credential_said).await.unwrap();

        let source = StoreKelSource::new(kel_store.as_ref());
        let resolver = InMemoryPolicyResolver::empty();
        let result =
            evaluate_anchored_policy(&policy, &credential_said, &source, &resolver, &StubIelResolver)
                .await
                .unwrap();

        assert!(result.is_satisfied);
        assert_eq!(
            result.endorsements.get(&prefix),
            Some(&EndorsementStatus::Endorsed)
        );
    }

    #[tokio::test]
    async fn test_single_endorser_not_satisfied() {
        let (_builder, prefix, kel_store, _dir) = setup_kel().await;
        let policy = Policy::build(&format!("kel({prefix})"), None, false).unwrap();
        let credential_said = cesr::test_digest("single-endorser-not-satisfied-said");

        let source = StoreKelSource::new(kel_store.as_ref());
        let resolver = InMemoryPolicyResolver::empty();
        let result =
            evaluate_anchored_policy(&policy, &credential_said, &source, &resolver, &StubIelResolver)
                .await
                .unwrap();

        assert!(!result.is_satisfied);
        assert_eq!(
            result.endorsements.get(&prefix),
            Some(&EndorsementStatus::NotEndorsed)
        );
    }

    #[tokio::test]
    async fn test_threshold_2_of_3() {
        let (mut builder_a, prefix_a, kel_store_a, _dir_a) = setup_kel().await;
        let (mut builder_b, prefix_b, kel_store_b, _dir_b) = setup_kel().await;
        let (_builder_c, prefix_c, _kel_store_c, _dir_c) = setup_kel().await;

        let policy = Policy::build(
            &format!("threshold(2, [kel({prefix_a}), kel({prefix_b}), kel({prefix_c})])"),
            None,
            false,
        )
        .unwrap();
        let credential_said = cesr::test_digest("threshold-2-of-3-said");

        // Only A and B anchor
        builder_a.interact(&credential_said).await.unwrap();
        builder_b.interact(&credential_said).await.unwrap();

        let temp_dir = tempfile::TempDir::new().unwrap();
        let shared_store = Arc::new(FileKelStore::new(temp_dir.path()).await.unwrap());

        // Copy events from each store into the shared store
        copy_kel_events(kel_store_a.as_ref(), &prefix_a, shared_store.as_ref()).await;
        copy_kel_events(kel_store_b.as_ref(), &prefix_b, shared_store.as_ref()).await;

        let source = StoreKelSource::new(shared_store.as_ref());
        let resolver = InMemoryPolicyResolver::empty();
        let result =
            evaluate_anchored_policy(&policy, &credential_said, &source, &resolver, &StubIelResolver)
                .await
                .unwrap();

        assert!(result.is_satisfied);
        assert_eq!(
            result.endorsements.get(&prefix_a),
            Some(&EndorsementStatus::Endorsed)
        );
        assert_eq!(
            result.endorsements.get(&prefix_b),
            Some(&EndorsementStatus::Endorsed)
        );
    }

    #[tokio::test]
    async fn test_threshold_not_met() {
        let (mut builder_a, prefix_a, kel_store_a, _dir_a) = setup_kel().await;
        let (_builder_b, prefix_b, _kel_store_b, _dir_b) = setup_kel().await;
        let (_builder_c, prefix_c, _kel_store_c, _dir_c) = setup_kel().await;

        let policy = Policy::build(
            &format!("threshold(2, [kel({prefix_a}), kel({prefix_b}), kel({prefix_c})])"),
            None,
            false,
        )
        .unwrap();
        let credential_said = cesr::test_digest("threshold-unmet-said");

        // Only A anchors
        builder_a.interact(&credential_said).await.unwrap();

        let source = StoreKelSource::new(kel_store_a.as_ref());
        let resolver = InMemoryPolicyResolver::empty();
        let result =
            evaluate_anchored_policy(&policy, &credential_said, &source, &resolver, &StubIelResolver)
                .await
                .unwrap();

        assert!(!result.is_satisfied);
    }

    #[tokio::test]
    async fn test_poisoned_endorser() {
        let (mut builder, prefix, kel_store, _dir) = setup_kel().await;
        let policy = Policy::build(&format!("kel({prefix})"), None, false).unwrap();
        let credential_said = cesr::test_digest("poisoned-endorser-said");

        // Anchor the credential SAID then poison it
        builder.interact(&credential_said).await.unwrap();
        let ph = poison_hash(credential_said.as_ref());
        builder.interact(&ph).await.unwrap();

        let source = StoreKelSource::new(kel_store.as_ref());
        let resolver = InMemoryPolicyResolver::empty();
        let result =
            evaluate_anchored_policy(&policy, &credential_said, &source, &resolver, &StubIelResolver)
                .await
                .unwrap();

        assert!(!result.is_satisfied);
        assert_eq!(
            result.endorsements.get(&prefix),
            Some(&EndorsementStatus::Poisoned)
        );
    }

    #[tokio::test]
    async fn test_proactive_poisoning() {
        let (mut builder, prefix, kel_store, _dir) = setup_kel().await;
        let policy = Policy::build(&format!("kel({prefix})"), None, false).unwrap();
        let credential_said = cesr::test_digest("proactive-poison-said");

        // Poison without ever endorsing
        let ph = poison_hash(credential_said.as_ref());
        builder.interact(&ph).await.unwrap();

        let source = StoreKelSource::new(kel_store.as_ref());
        let resolver = InMemoryPolicyResolver::empty();
        let result =
            evaluate_anchored_policy(&policy, &credential_said, &source, &resolver, &StubIelResolver)
                .await
                .unwrap();

        assert!(!result.is_satisfied);
        assert_eq!(
            result.endorsements.get(&prefix),
            Some(&EndorsementStatus::Poisoned)
        );
    }

    #[tokio::test]
    async fn test_immune_ignores_poison() {
        let (mut builder, prefix, kel_store, _dir) = setup_kel().await;
        let policy = Policy::build(&format!("kel({prefix})"), None, true).unwrap();
        let credential_said = cesr::test_digest("immune-said");

        // Anchor then poison — immune policy should ignore the poison
        builder.interact(&credential_said).await.unwrap();
        let ph = poison_hash(credential_said.as_ref());
        builder.interact(&ph).await.unwrap();

        let source = StoreKelSource::new(kel_store.as_ref());
        let resolver = InMemoryPolicyResolver::empty();
        let result =
            evaluate_anchored_policy(&policy, &credential_said, &source, &resolver, &StubIelResolver)
                .await
                .unwrap();

        assert!(result.is_satisfied);
        assert_eq!(
            result.endorsements.get(&prefix),
            Some(&EndorsementStatus::Endorsed)
        );
    }

    #[tokio::test]
    async fn test_poisonable_any_poison_kills() {
        let (mut builder_a, prefix_a, kel_store_a, _dir_a) = setup_kel().await;
        let (mut builder_b, prefix_b, kel_store_b, _dir_b) = setup_kel().await;

        let policy = Policy::build(
            &format!("threshold(1, [kel({prefix_a}), kel({prefix_b})])"),
            Some(&format!("threshold(1, [kel({prefix_a}), kel({prefix_b})])")),
            false,
        )
        .unwrap();
        let credential_said = cesr::test_digest("poisonable-any-kills-said");

        // A endorses, B poisons
        builder_a.interact(&credential_said).await.unwrap();
        let ph = poison_hash(credential_said.as_ref());
        builder_b.interact(&ph).await.unwrap();

        let temp_dir = tempfile::TempDir::new().unwrap();
        let shared_store = Arc::new(FileKelStore::new(temp_dir.path()).await.unwrap());
        copy_kel_events(kel_store_a.as_ref(), &prefix_a, shared_store.as_ref()).await;
        copy_kel_events(kel_store_b.as_ref(), &prefix_b, shared_store.as_ref()).await;

        let source = StoreKelSource::new(shared_store.as_ref());
        let resolver = InMemoryPolicyResolver::empty();
        let result =
            evaluate_anchored_policy(&policy, &credential_said, &source, &resolver, &StubIelResolver)
                .await
                .unwrap();

        // Threshold would be met (A endorsed), but poisonable policy means B's poison kills it
        assert!(!result.is_satisfied);
    }

    #[tokio::test]
    async fn test_nested_policy() {
        let (mut builder, prefix, kel_store, _dir) = setup_kel().await;
        let credential_said = cesr::test_digest("nested-said");
        builder.interact(&credential_said).await.unwrap();

        let inner_policy = Policy::build(&format!("kel({prefix})"), None, false).unwrap();
        let outer_policy =
            Policy::build(&format!("policy({})", inner_policy.said), None, false).unwrap();

        let source = StoreKelSource::new(kel_store.as_ref());
        let resolver = InMemoryPolicyResolver::new(vec![inner_policy.clone()]);
        let result = evaluate_anchored_policy(
            &outer_policy,
            &credential_said,
            &source,
            &resolver,
            &StubIelResolver,
        )
        .await
        .unwrap();

        assert!(result.is_satisfied);
        assert!(result.nested_verifications.contains_key(&inner_policy.said));
    }

    #[tokio::test]
    async fn test_cycle_detection() {
        let fake_said = test_digest("cycle-test");
        let self_ref_expr = format!("policy({})", fake_said);
        let policy = Policy {
            said: fake_said,
            expression: self_ref_expr,
            poison: None,
            immune: None,
        };

        let (_builder, _prefix, kel_store, _dir) = setup_kel().await;
        let source = StoreKelSource::new(kel_store.as_ref());
        let resolver = InMemoryPolicyResolver::new(vec![policy.clone()]);

        let result = evaluate_anchored_policy(
            &policy,
            &test_digest("cycle-test"),
            &source,
            &resolver,
            &StubIelResolver,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("circular"));
    }

    #[tokio::test]
    async fn test_weighted_threshold() {
        let (mut builder_a, prefix_a, kel_store_a, _dir_a) = setup_kel().await;
        let (_builder_b, prefix_b, _kel_store_b, _dir_b) = setup_kel().await;

        let policy = Policy::build(
            &format!("weighted(3, [kel({prefix_a}):3, kel({prefix_b}):2])"),
            None,
            false,
        )
        .unwrap();
        let credential_said = cesr::test_digest("weighted-threshold-said");

        // Only A endorses (weight 3 >= threshold 3)
        builder_a.interact(&credential_said).await.unwrap();

        let source = StoreKelSource::new(kel_store_a.as_ref());
        let resolver = InMemoryPolicyResolver::empty();
        let result =
            evaluate_anchored_policy(&policy, &credential_said, &source, &resolver, &StubIelResolver)
                .await
                .unwrap();

        assert!(result.is_satisfied);
    }

    #[tokio::test]
    async fn test_poison_expression_admin_can_poison() {
        let (mut builder_a, prefix_a, kel_store_a, _dir_a) = setup_kel().await;
        let (mut builder_admin, prefix_admin, kel_store_admin, _dir_admin) = setup_kel().await;

        // Policy: A endorses, but only admin can poison
        let policy = Policy::build(
            &format!("kel({prefix_a})"),
            Some(&format!("kel({prefix_admin})")),
            false,
        )
        .unwrap();
        let credential_said = cesr::test_digest("poison-expression-admin-poisons-said");

        // A endorses
        builder_a.interact(&credential_said).await.unwrap();

        // Admin poisons
        let ph = poison_hash(credential_said.as_ref());
        builder_admin.interact(&ph).await.unwrap();

        let temp_dir = tempfile::TempDir::new().unwrap();
        let shared_store = Arc::new(FileKelStore::new(temp_dir.path()).await.unwrap());
        copy_kel_events(kel_store_a.as_ref(), &prefix_a, shared_store.as_ref()).await;
        copy_kel_events(
            kel_store_admin.as_ref(),
            &prefix_admin,
            shared_store.as_ref(),
        )
        .await;

        let source = StoreKelSource::new(shared_store.as_ref());
        let resolver = InMemoryPolicyResolver::empty();
        let result =
            evaluate_anchored_policy(&policy, &credential_said, &source, &resolver, &StubIelResolver)
                .await
                .unwrap();

        // Admin poisoned → policy unsatisfied
        assert!(!result.is_satisfied);
    }

    #[tokio::test]
    async fn test_poison_expression_non_admin_cannot_poison() {
        let (mut builder_a, prefix_a, kel_store_a, _dir_a) = setup_kel().await;
        let (mut builder_b, prefix_b, kel_store_b, _dir_b) = setup_kel().await;
        let (_builder_admin, prefix_admin, _kel_store_admin, _dir_admin) = setup_kel().await;

        // Policy: A and B endorse with threshold 1, but only admin can poison
        let policy = Policy::build(
            &format!("threshold(1, [kel({prefix_a}), kel({prefix_b})])"),
            Some(&format!("kel({prefix_admin})")),
            false,
        )
        .unwrap();
        let credential_said = cesr::test_digest("poison-admin-cannot-poison-said");

        // A endorses
        builder_a.interact(&credential_said).await.unwrap();

        // B tries to poison (not authorized — B is an endorser, not in poison_expression)
        let ph = poison_hash(credential_said.as_ref());
        builder_b.interact(&ph).await.unwrap();

        let temp_dir = tempfile::TempDir::new().unwrap();
        let shared_store = Arc::new(FileKelStore::new(temp_dir.path()).await.unwrap());
        copy_kel_events(kel_store_a.as_ref(), &prefix_a, shared_store.as_ref()).await;
        copy_kel_events(kel_store_b.as_ref(), &prefix_b, shared_store.as_ref()).await;

        let source = StoreKelSource::new(shared_store.as_ref());
        let resolver = InMemoryPolicyResolver::empty();
        let result =
            evaluate_anchored_policy(&policy, &credential_said, &source, &resolver, &StubIelResolver)
                .await
                .unwrap();

        // B is not in poison_expression, so B's poison hash is ignored → still satisfied
        assert!(result.is_satisfied);
    }

    #[tokio::test]
    async fn test_poison_expression_threshold() {
        let (mut builder_a, prefix_a, kel_store_a, _dir_a) = setup_kel().await;
        let (mut builder_admin1, prefix_admin1, kel_store_admin1, _dir_admin1) = setup_kel().await;
        let (_builder_admin2, prefix_admin2, _kel_store_admin2, _dir_admin2) = setup_kel().await;

        // Policy: A endorses, 2-of-2 admins required to poison
        let policy = Policy::build(
            &format!("kel({prefix_a})"),
            Some(&format!(
                "threshold(2, [kel({prefix_admin1}), kel({prefix_admin2})])"
            )),
            false,
        )
        .unwrap();
        let credential_said = cesr::test_digest("poison-expression-threshold-said");

        // A endorses
        builder_a.interact(&credential_said).await.unwrap();

        // Only admin1 poisons (threshold not met — need both admins)
        let ph = poison_hash(credential_said.as_ref());
        builder_admin1.interact(&ph).await.unwrap();

        let temp_dir = tempfile::TempDir::new().unwrap();
        let shared_store = Arc::new(FileKelStore::new(temp_dir.path()).await.unwrap());
        copy_kel_events(kel_store_a.as_ref(), &prefix_a, shared_store.as_ref()).await;
        copy_kel_events(
            kel_store_admin1.as_ref(),
            &prefix_admin1,
            shared_store.as_ref(),
        )
        .await;

        let source = StoreKelSource::new(shared_store.as_ref());
        let resolver = InMemoryPolicyResolver::empty();
        let result =
            evaluate_anchored_policy(&policy, &credential_said, &source, &resolver, &StubIelResolver)
                .await
                .unwrap();

        // Only 1-of-2 admins poisoned → poison threshold not met → still satisfied
        assert!(result.is_satisfied);
    }

    /// Helper to copy KEL events from one FileKelStore to another.
    async fn copy_kel_events(from: &FileKelStore, prefix: &cesr::Digest256, to: &FileKelStore) {
        let source = StoreKelSource::new(from);
        let sink = kels_core::KelStoreSink(to);
        forward_key_events(
            prefix,
            &source,
            &sink,
            kels_core::page_size(),
            kels_core::max_pages(),
            None,
        )
        .await
        .unwrap();
    }

    // ==================== evaluate_signed_policy Tests ====================

    #[tokio::test]
    async fn test_signed_policy_single_endorser_satisfied() {
        let prefix = test_digest("signer-a");
        let policy = Policy::build(&format!("kel({prefix})"), None, false).unwrap();

        let resolver = InMemoryPolicyResolver::new(vec![policy.clone()]);
        let verified = std::collections::HashSet::from([prefix]);

        let result = evaluate_signed_policy(&policy.said, &verified, &resolver, &StubIelResolver)
            .await
            .unwrap();
        assert!(result.is_satisfied);
        assert_eq!(
            result.endorsements.get(&prefix),
            Some(&EndorsementStatus::Endorsed)
        );
    }

    #[tokio::test]
    async fn test_signed_policy_single_endorser_not_satisfied() {
        let prefix = test_digest("signer-a");
        let policy = Policy::build(&format!("kel({prefix})"), None, false).unwrap();

        let resolver = InMemoryPolicyResolver::new(vec![policy.clone()]);
        let verified = std::collections::HashSet::new(); // nobody verified

        let result = evaluate_signed_policy(&policy.said, &verified, &resolver, &StubIelResolver)
            .await
            .unwrap();
        assert!(!result.is_satisfied);
    }

    #[tokio::test]
    async fn test_signed_policy_threshold_2_of_3() {
        let a = test_digest("signer-a");
        let b = test_digest("signer-b");
        let c = test_digest("signer-c");
        let policy = Policy::build(
            &format!("threshold(2, [kel({a}), kel({b}), kel({c})])"),
            None,
            false,
        )
        .unwrap();

        let resolver = InMemoryPolicyResolver::new(vec![policy.clone()]);
        let verified = std::collections::HashSet::from([a, b]);

        let result = evaluate_signed_policy(&policy.said, &verified, &resolver, &StubIelResolver)
            .await
            .unwrap();
        assert!(result.is_satisfied);
    }

    #[tokio::test]
    async fn test_signed_policy_threshold_not_met() {
        let a = test_digest("signer-a");
        let b = test_digest("signer-b");
        let c = test_digest("signer-c");
        let policy = Policy::build(
            &format!("threshold(2, [kel({a}), kel({b}), kel({c})])"),
            None,
            false,
        )
        .unwrap();

        let resolver = InMemoryPolicyResolver::new(vec![policy.clone()]);
        let verified = std::collections::HashSet::from([a]); // only 1 of 2

        let result = evaluate_signed_policy(&policy.said, &verified, &resolver, &StubIelResolver)
            .await
            .unwrap();
        assert!(!result.is_satisfied);
    }

    #[tokio::test]
    async fn test_signed_policy_nested() {
        let prefix = test_digest("signer-a");
        let inner = Policy::build(&format!("kel({prefix})"), None, false).unwrap();
        let outer = Policy::build(&format!("policy({})", inner.said), None, false).unwrap();

        let resolver = InMemoryPolicyResolver::new(vec![inner.clone(), outer.clone()]);
        let verified = std::collections::HashSet::from([prefix]);

        let result = evaluate_signed_policy(&outer.said, &verified, &resolver, &StubIelResolver)
            .await
            .unwrap();
        assert!(result.is_satisfied);
        assert!(result.nested_verifications.contains_key(&inner.said));
    }

    #[tokio::test]
    async fn test_signed_policy_rejects_delegate_nodes() {
        // Delegate is an issuance-side concern (#77 — delegated signing servers).
        // It is not meaningful for fetch-time access-control evaluation.
        let delegator = test_digest("delegator");
        let delegate = test_digest("delegate");
        let policy =
            Policy::build(&format!("delegate({delegator}, {delegate})"), None, false).unwrap();

        let resolver = InMemoryPolicyResolver::new(vec![policy.clone()]);
        let verified = std::collections::HashSet::from([delegator, delegate]);

        let result =
            evaluate_signed_policy(&policy.said, &verified, &resolver, &StubIelResolver).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("delegate()"),
            "Expected delegate rejection error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_signed_policy_no_poison_checks() {
        // Signed policy evaluation ignores poison — it's prefix membership only.
        // Even if the policy has a poison expression, it's not evaluated.
        let prefix = test_digest("signer-a");
        let policy = Policy::build(
            &format!("kel({prefix})"),
            Some(&format!("kel({prefix})")),
            false,
        )
        .unwrap();

        let resolver = InMemoryPolicyResolver::new(vec![policy.clone()]);
        let verified = std::collections::HashSet::from([prefix]);

        let result = evaluate_signed_policy(&policy.said, &verified, &resolver, &StubIelResolver)
            .await
            .unwrap();
        // Satisfied — no poison checks in signed policy evaluation
        assert!(result.is_satisfied);
    }

    // ==================== iel(...) leaf tests ====================

    #[tokio::test]
    async fn test_signed_policy_iel_resolves_through_inner_policy() {
        // Federation-shaped: outer is `any(iel(X))`; X's current authPolicy is
        // `kel(signer)`. Verified prefix = {signer} → satisfies.
        let signer = test_digest("signer-a");
        let iel_x = test_digest("iel-x");

        let inner = Policy::build(&format!("kel({signer})"), None, true).unwrap();
        let outer = Policy::build(&format!("any(iel({iel_x}))"), None, true).unwrap();

        let policy_resolver = InMemoryPolicyResolver::new(vec![inner.clone(), outer.clone()]);
        let iel_resolver = InMemoryIelResolver::new(vec![(iel_x, inner.said)]);
        let verified = std::collections::HashSet::from([signer]);

        let result =
            evaluate_signed_policy(&outer.said, &verified, &policy_resolver, &iel_resolver)
                .await
                .unwrap();
        assert!(result.is_satisfied);
        assert!(result.nested_verifications.contains_key(&inner.said));
    }

    #[tokio::test]
    async fn test_signed_policy_iel_with_unverified_prefix_fails() {
        // outer is `iel(X)`; X's authPolicy is `kel(signer)`; verified = {other}.
        // Should not satisfy.
        let signer = test_digest("signer-a");
        let other = test_digest("signer-other");
        let iel_x = test_digest("iel-x");

        let inner = Policy::build(&format!("kel({signer})"), None, true).unwrap();
        let outer = Policy::build(&format!("iel({iel_x})"), None, true).unwrap();

        let policy_resolver = InMemoryPolicyResolver::new(vec![inner.clone(), outer.clone()]);
        let iel_resolver = InMemoryIelResolver::new(vec![(iel_x, inner.said)]);
        let verified = std::collections::HashSet::from([other]);

        let result =
            evaluate_signed_policy(&outer.said, &verified, &policy_resolver, &iel_resolver)
                .await
                .unwrap();
        assert!(!result.is_satisfied);
    }

    #[tokio::test]
    async fn test_signed_policy_iel_unresolvable_fails_loud() {
        // outer is `iel(X)`; X is not in the IelResolver → loud error,
        // not silent false. Per design `policy.md §Identity Resolution`.
        let iel_x = test_digest("iel-unknown");
        let outer = Policy::build(&format!("iel({iel_x})"), None, true).unwrap();

        let policy_resolver = InMemoryPolicyResolver::new(vec![outer.clone()]);
        let iel_resolver = InMemoryIelResolver::new(vec![]); // empty
        let verified = std::collections::HashSet::new();

        let result =
            evaluate_signed_policy(&outer.said, &verified, &policy_resolver, &iel_resolver).await;
        assert!(result.is_err(), "expected loud error on unresolvable iel(X)");
    }

    #[tokio::test]
    async fn test_signed_policy_iel_threshold_over_iels() {
        // 2-of-3 over iel(...) leaves: A's authPolicy admits sig_a, B's admits
        // sig_b, C's admits sig_c. Verified = {sig_a, sig_b} → satisfies.
        let sig_a = test_digest("sig-a");
        let sig_b = test_digest("sig-b");
        let sig_c = test_digest("sig-c");
        let iel_a = test_digest("iel-a");
        let iel_b = test_digest("iel-b");
        let iel_c = test_digest("iel-c");

        let inner_a = Policy::build(&format!("kel({sig_a})"), None, true).unwrap();
        let inner_b = Policy::build(&format!("kel({sig_b})"), None, true).unwrap();
        let inner_c = Policy::build(&format!("kel({sig_c})"), None, true).unwrap();
        let outer = Policy::build(
            &format!("threshold(2, [iel({iel_a}), iel({iel_b}), iel({iel_c})])"),
            None,
            true,
        )
        .unwrap();

        let policy_resolver = InMemoryPolicyResolver::new(vec![
            inner_a.clone(),
            inner_b.clone(),
            inner_c.clone(),
            outer.clone(),
        ]);
        let iel_resolver = InMemoryIelResolver::new(vec![
            (iel_a, inner_a.said),
            (iel_b, inner_b.said),
            (iel_c, inner_c.said),
        ]);
        let verified = std::collections::HashSet::from([sig_a, sig_b]);

        let result =
            evaluate_signed_policy(&outer.said, &verified, &policy_resolver, &iel_resolver)
                .await
                .unwrap();
        assert!(result.is_satisfied);
    }

    #[tokio::test]
    async fn test_signed_policy_iel_cycle_rejected() {
        // iel(A) → authPolicy `iel(B)` → authPolicy `iel(A)` is a cycle and
        // must be rejected. Distinct expression shapes at each level so
        // policy SAIDs all differ — exercises the iel-stack cycle guard
        // (not the broader policy-SAID-visited guard which catches direct
        // policy-SAID self-reference).
        let iel_a = test_digest("iel-a");
        let iel_b = test_digest("iel-b");
        let policy_a = Policy::build(&format!("iel({iel_b})"), None, true).unwrap();
        let policy_b =
            Policy::build(&format!("threshold(1, [iel({iel_a})])"), None, true).unwrap();
        let outer = Policy::build(&format!("iel({iel_a})"), None, true).unwrap();
        // Sanity: all three SAIDs must be distinct, otherwise the
        // visited-policy guard short-circuits before the iel-stack guard.
        assert_ne!(outer.said, policy_a.said);
        assert_ne!(outer.said, policy_b.said);
        assert_ne!(policy_a.said, policy_b.said);

        let policy_resolver = InMemoryPolicyResolver::new(vec![
            policy_a.clone(),
            policy_b.clone(),
            outer.clone(),
        ]);
        let iel_resolver = InMemoryIelResolver::new(vec![
            (iel_a, policy_a.said),
            (iel_b, policy_b.said),
        ]);
        let verified = std::collections::HashSet::new();

        let result =
            evaluate_signed_policy(&outer.said, &verified, &policy_resolver, &iel_resolver).await;
        assert!(result.is_err(), "expected cycle rejection");
        let err_str = result.unwrap_err().to_string();
        assert!(
            err_str.contains("iel(") && err_str.contains("cycle"),
            "expected iel-stack cycle error, got: {err_str}",
        );
    }

    #[tokio::test]
    async fn test_signed_policy_iel_cache_avoids_double_resolution() {
        // outer policy mentions iel(X) twice (via two threshold children
        // pointing to the same leaf). A counting resolver verifies that the
        // per-evaluation cache fires.
        struct CountingIelResolver {
            inner: InMemoryIelResolver,
            calls: std::sync::Mutex<usize>,
        }

        #[async_trait]
        impl IelResolver for CountingIelResolver {
            async fn fetch_iel_event(
                &self,
                _: &cesr::Digest256,
                _: &cesr::Digest256,
            ) -> Result<IdentityEvent, KelsError> {
                Err(KelsError::NotFound("not used".to_string()))
            }
            async fn resolve_auth_policy_at(
                &self,
                _: &cesr::Digest256,
                _: &cesr::Digest256,
            ) -> Result<cesr::Digest256, KelsError> {
                Err(KelsError::NotFound("not used".to_string()))
            }
            async fn resolve_governance_policy_at(
                &self,
                _: &cesr::Digest256,
                _: &cesr::Digest256,
            ) -> Result<cesr::Digest256, KelsError> {
                Err(KelsError::NotFound("not used".to_string()))
            }
            async fn iel_chain_positions(
                &self,
                _: &cesr::Digest256,
                _: &[cesr::Digest256],
            ) -> Result<IelChainPositionBatch, KelsError> {
                Err(KelsError::NotFound("not used".to_string()))
            }
            async fn is_satisfied(
                &self,
                _: &cesr::Digest256,
                _: &cesr::Digest256,
            ) -> Result<IelSatisfaction, KelsError> {
                Err(KelsError::NotFound("not used".to_string()))
            }
            async fn resolve_identity_for_event(
                &self,
                _: &cesr::Digest256,
            ) -> Result<cesr::Digest256, KelsError> {
                Err(KelsError::NotFound("not used".to_string()))
            }
            async fn resolve_current_auth_policy(
                &self,
                identity: &cesr::Digest256,
            ) -> Result<cesr::Digest256, KelsError> {
                {
                    let mut guard = self.calls.lock().unwrap();
                    *guard += 1;
                }
                self.inner.resolve_current_auth_policy(identity).await
            }
        }

        let signer = test_digest("signer-a");
        let iel_x = test_digest("iel-x");
        let inner = Policy::build(&format!("kel({signer})"), None, true).unwrap();
        // Two iel(X) children — both should hit the cache after the first walk.
        let outer = Policy::build(&format!("any(iel({iel_x}), iel({iel_x}))"), None, true).unwrap();

        let policy_resolver = InMemoryPolicyResolver::new(vec![inner.clone(), outer.clone()]);
        let iel_resolver = CountingIelResolver {
            inner: InMemoryIelResolver::new(vec![(iel_x, inner.said)]),
            calls: std::sync::Mutex::new(0),
        };
        let verified = std::collections::HashSet::from([signer]);

        let result =
            evaluate_signed_policy(&outer.said, &verified, &policy_resolver, &iel_resolver)
                .await
                .unwrap();
        assert!(result.is_satisfied);
        let calls = *iel_resolver.calls.lock().unwrap();
        assert_eq!(calls, 1, "per-evaluation cache must short-circuit repeat iel(X)");
    }

    #[tokio::test]
    async fn test_anchored_policy_iel_resolves() {
        // Anchored path: outer is `iel(X)`; X's authPolicy is `kel(signer)`;
        // signer's KEL anchors the credential SAID. Should satisfy.
        let (mut builder, prefix, kel_store, _dir) = setup_kel().await;
        let credential_said = cesr::test_digest("anchored-iel-said");
        builder.interact(&credential_said).await.unwrap();

        let iel_x = test_digest("iel-x");
        let inner = Policy::build(&format!("kel({prefix})"), None, true).unwrap();
        let outer = Policy::build(&format!("iel({iel_x})"), None, true).unwrap();

        let source = StoreKelSource::new(kel_store.as_ref());
        let policy_resolver = InMemoryPolicyResolver::new(vec![inner.clone(), outer.clone()]);
        let iel_resolver = InMemoryIelResolver::new(vec![(iel_x, inner.said)]);

        let result =
            evaluate_anchored_policy(&outer, &credential_said, &source, &policy_resolver, &iel_resolver)
                .await
                .unwrap();
        assert!(result.is_satisfied);
        assert!(result.nested_verifications.contains_key(&inner.said));
    }
}
