use std::collections::{BTreeMap, BTreeSet};

use cesr::Digest256;
use kels_core::{KelVerifier, PagedKelSource, verify_key_events};

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

/// Evaluate a policy against KEL state for a given credential SAID.
///
/// Walks the policy AST, checking each endorser's KEL for anchoring and poisoning.
/// Returns a `PolicyVerification` with the satisfaction result and per-endorser status.
pub async fn evaluate_policy(
    policy: &Policy,
    credential_said: &cesr::Digest256,
    source: &(dyn PagedKelSource + Sync),
    resolver: &dyn PolicyResolver,
) -> Result<PolicyVerification, PolicyError> {
    let mut visited = BTreeSet::new();
    evaluate_policy_inner(
        policy,
        credential_said,
        source,
        resolver,
        &mut visited,
        MAX_POLICY_DEPTH,
    )
    .await
}

async fn evaluate_policy_inner(
    policy: &Policy,
    credential_said: &cesr::Digest256,
    source: &(dyn PagedKelSource + Sync),
    resolver: &dyn PolicyResolver,
    visited: &mut BTreeSet<cesr::Digest256>,
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
        &mut endorsements,
        &mut nested,
        visited,
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
                &mut poison_endorsements,
                &mut poison_nested,
                &mut poison_visited,
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
    endorsements: &'a mut BTreeMap<cesr::Digest256, EndorsementStatus>,
    nested: &'a mut BTreeMap<cesr::Digest256, PolicyVerification>,
    visited: &'a mut BTreeSet<cesr::Digest256>,
    remaining_depth: usize,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, PolicyError>> + Send + 'a>> {
    Box::pin(async move {
        if remaining_depth == 0 {
            return Err(PolicyError::EvaluationError(
                "maximum policy nesting depth exceeded".to_string(),
            ));
        }

        match node {
            PolicyNode::Endorse(prefix) => {
                let status =
                    evaluate_endorser(prefix, credential_said, policy, source, endorsements)
                        .await?;
                Ok(matches!(status, EndorsementStatus::Endorsed))
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
                    evaluate_endorser(delegate, credential_said, policy, source, endorsements)
                        .await?;
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
                        endorsements,
                        nested,
                        visited,
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
                let verification = evaluate_policy_inner(
                    &resolved,
                    credential_said,
                    source,
                    resolver,
                    visited,
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
async fn evaluate_endorser(
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
        Err(e) => EndorsementStatus::KelError(e.to_string()),
    };

    endorsements.insert(*prefix, status.clone());
    Ok(status)
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use cesr::test_digest;
    use kels_core::{
        FileKelStore, KelStore, KeyEventBuilder, SoftwareKeyProvider, StoreKelSource,
        VerificationKeyCode, forward_key_events,
    };

    use super::*;
    use crate::resolver::InMemoryPolicyResolver;

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
        let policy = Policy::build(&format!("endorse({prefix})"), None, false).unwrap();
        let credential_said = cesr::test_digest("single-endorser-said");

        // Anchor the credential SAID
        builder.interact(&credential_said).await.unwrap();

        let source = StoreKelSource::new(kel_store.as_ref());
        let resolver = InMemoryPolicyResolver::empty();
        let result = evaluate_policy(&policy, &credential_said, &source, &resolver)
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
        let policy = Policy::build(&format!("endorse({prefix})"), None, false).unwrap();
        let credential_said = cesr::test_digest("single-endorser-not-satisfied-said");

        let source = StoreKelSource::new(kel_store.as_ref());
        let resolver = InMemoryPolicyResolver::empty();
        let result = evaluate_policy(&policy, &credential_said, &source, &resolver)
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
            &format!(
                "threshold(2, [endorse({prefix_a}), endorse({prefix_b}), endorse({prefix_c})])"
            ),
            None,
            false,
        )
        .unwrap();
        let credential_said = cesr::test_digest("threshold-2-of-3-said");

        // Only A and B anchor
        builder_a.interact(&credential_said).await.unwrap();
        builder_b.interact(&credential_said).await.unwrap();

        // Combine stores — use A's store as the primary, copy B's events into it
        // Actually, FileKelStore is per-directory. We need a single source that has all KELs.
        // For simplicity, use a shared temp dir and write all KELs there.
        let temp_dir = tempfile::TempDir::new().unwrap();
        let shared_store = Arc::new(FileKelStore::new(temp_dir.path()).await.unwrap());

        // Copy events from each store into the shared store
        copy_kel_events(kel_store_a.as_ref(), &prefix_a, shared_store.as_ref()).await;
        copy_kel_events(kel_store_b.as_ref(), &prefix_b, shared_store.as_ref()).await;

        let source = StoreKelSource::new(shared_store.as_ref());
        let resolver = InMemoryPolicyResolver::empty();
        let result = evaluate_policy(&policy, &credential_said, &source, &resolver)
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
            &format!(
                "threshold(2, [endorse({prefix_a}), endorse({prefix_b}), endorse({prefix_c})])"
            ),
            None,
            false,
        )
        .unwrap();
        let credential_said = cesr::test_digest("threshold-unmet-said");

        // Only A anchors
        builder_a.interact(&credential_said).await.unwrap();

        let source = StoreKelSource::new(kel_store_a.as_ref());
        let resolver = InMemoryPolicyResolver::empty();
        let result = evaluate_policy(&policy, &credential_said, &source, &resolver)
            .await
            .unwrap();

        assert!(!result.is_satisfied);
    }

    #[tokio::test]
    async fn test_poisoned_endorser() {
        let (mut builder, prefix, kel_store, _dir) = setup_kel().await;
        let policy = Policy::build(&format!("endorse({prefix})"), None, false).unwrap();
        let credential_said = cesr::test_digest("poisoned-endorser-said");

        // Anchor the credential SAID then poison it
        builder.interact(&credential_said).await.unwrap();
        let ph = poison_hash(credential_said.as_ref());
        builder.interact(&ph).await.unwrap();

        let source = StoreKelSource::new(kel_store.as_ref());
        let resolver = InMemoryPolicyResolver::empty();
        let result = evaluate_policy(&policy, &credential_said, &source, &resolver)
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
        let policy = Policy::build(&format!("endorse({prefix})"), None, false).unwrap();
        let credential_said = cesr::test_digest("proactive-poison-said");

        // Poison without ever endorsing
        let ph = poison_hash(credential_said.as_ref());
        builder.interact(&ph).await.unwrap();

        let source = StoreKelSource::new(kel_store.as_ref());
        let resolver = InMemoryPolicyResolver::empty();
        let result = evaluate_policy(&policy, &credential_said, &source, &resolver)
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
        let policy = Policy::build(&format!("endorse({prefix})"), None, true).unwrap();
        let credential_said = cesr::test_digest("immune-said");

        // Anchor then poison — immune policy should ignore the poison
        builder.interact(&credential_said).await.unwrap();
        let ph = poison_hash(credential_said.as_ref());
        builder.interact(&ph).await.unwrap();

        let source = StoreKelSource::new(kel_store.as_ref());
        let resolver = InMemoryPolicyResolver::empty();
        let result = evaluate_policy(&policy, &credential_said, &source, &resolver)
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
            &format!("threshold(1, [endorse({prefix_a}), endorse({prefix_b})])"),
            Some(&format!(
                "threshold(1, [endorse({prefix_a}), endorse({prefix_b})])"
            )),
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
        let result = evaluate_policy(&policy, &credential_said, &source, &resolver)
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

        let inner_policy = Policy::build(&format!("endorse({prefix})"), None, false).unwrap();
        let outer_policy =
            Policy::build(&format!("policy({})", inner_policy.said), None, false).unwrap();

        let source = StoreKelSource::new(kel_store.as_ref());
        let resolver = InMemoryPolicyResolver::new(vec![inner_policy.clone()]);
        let result = evaluate_policy(&outer_policy, &credential_said, &source, &resolver)
            .await
            .unwrap();

        assert!(result.is_satisfied);
        assert!(result.nested_verifications.contains_key(&inner_policy.said));
    }

    #[tokio::test]
    async fn test_cycle_detection() {
        // Create two policies that reference each other
        // We can't actually create a real cycle since SAIDs are content-addressed,
        // but we can test that the visited set catches it by using a resolver
        // that returns a policy referencing itself.
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

        let result = evaluate_policy(&policy, &test_digest("cycle-test"), &source, &resolver).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("circular"));
    }

    #[tokio::test]
    async fn test_weighted_threshold() {
        let (mut builder_a, prefix_a, kel_store_a, _dir_a) = setup_kel().await;
        let (_builder_b, prefix_b, _kel_store_b, _dir_b) = setup_kel().await;

        let policy = Policy::build(
            &format!("weighted(3, [endorse({prefix_a}):3, endorse({prefix_b}):2])"),
            None,
            false,
        )
        .unwrap();
        let credential_said = cesr::test_digest("weighted-threshold-said");

        // Only A endorses (weight 3 >= threshold 3)
        builder_a.interact(&credential_said).await.unwrap();

        let source = StoreKelSource::new(kel_store_a.as_ref());
        let resolver = InMemoryPolicyResolver::empty();
        let result = evaluate_policy(&policy, &credential_said, &source, &resolver)
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
            &format!("endorse({prefix_a})"),
            Some(&format!("endorse({prefix_admin})")),
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
        let result = evaluate_policy(&policy, &credential_said, &source, &resolver)
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
            &format!("threshold(1, [endorse({prefix_a}), endorse({prefix_b})])"),
            Some(&format!("endorse({prefix_admin})")),
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
        let result = evaluate_policy(&policy, &credential_said, &source, &resolver)
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
            &format!("endorse({prefix_a})"),
            Some(&format!(
                "threshold(2, [endorse({prefix_admin1}), endorse({prefix_admin2})])"
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
        let result = evaluate_policy(&policy, &credential_said, &source, &resolver)
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
}
