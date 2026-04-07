use std::collections::BTreeMap;

use serde::Serialize;

use kels_core::PagedKelSource;
use kels_policy::{PolicyResolver, PolicyVerification, evaluate_policy};
use verifiable_storage::{StorageDatetime, compute_said_from_value};

use crate::{
    compaction::{MAX_RECURSION_DEPTH, expand_with_schema},
    credential::{Claims, Credential},
    error::CredentialError,
    schema::{Schema, SchemaValidationReport, validate_credential_report},
    store::SADStore,
};

/// The result of verifying a single credential.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialVerification {
    pub credential: cesr::Digest,
    pub policy: cesr::Digest,
    pub subject: Option<cesr::Digest>,
    pub is_expired: bool,
    pub policy_verification: PolicyVerification,
    pub schema_validation: SchemaValidationReport,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub edge_verifications: BTreeMap<String, CredentialVerification>,
}

impl CredentialVerification {
    /// Returns `Ok(())` if the credential is fully trustworthy: policy satisfied,
    /// not expired, and all edge credentials also valid. If
    /// `require_valid_schema` is true, also requires schema validation to pass
    /// (recursively for edges).
    pub fn is_valid(&self, require_valid_schema: bool) -> Result<(), CredentialError> {
        if !self.policy_verification.is_satisfied {
            return Err(CredentialError::VerificationError(
                "policy is not satisfied".to_string(),
            ));
        }
        if self.is_expired {
            return Err(CredentialError::VerificationError(
                "credential is expired".to_string(),
            ));
        }
        if require_valid_schema {
            self.schema_validation.require_valid()?;
        }
        for (label, edge_v) in &self.edge_verifications {
            edge_v
                .is_valid(require_valid_schema)
                .map_err(|e| CredentialError::VerificationError(format!("edge '{label}': {e}")))?;
        }
        Ok(())
    }
}

/// Verify a credential against the KEL, with schema validation and optional
/// recursive edge verification.
///
/// Checks:
/// 1. Expanded SAID integrity — recompute SAID from credential data
/// 2. Compacted SAID integrity — compact to canonical form, verify consistency
/// 3. Policy SAID match — credential's policy field matches provided policy
/// 4. Policy evaluation — evaluate policy against KEL state
/// 5. Expiration — `expiresAt` vs current time
/// 6. Schema validation — validate credential against provided schema
/// 7. Edge verification — if edges are expanded and a SADStore + edge schemas
///    are provided, recursively verify referenced credentials
///
/// `edge_schemas` maps schema SAIDs to Schema objects for edge credentials.
pub async fn verify_credential<T: Claims>(
    credential: &Credential<T>,
    schema: &Schema,
    policy: &kels_policy::Policy,
    resolver: &dyn PolicyResolver,
    source: &(dyn PagedKelSource + Sync),
    sad_store: Option<&dyn SADStore>,
    edge_schemas: &BTreeMap<String, Schema>,
) -> Result<CredentialVerification, CredentialError> {
    verify_credential_bounded(
        credential,
        schema,
        policy,
        resolver,
        source,
        sad_store,
        edge_schemas,
        MAX_RECURSION_DEPTH,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
fn verify_credential_bounded<'a, T: Claims>(
    credential: &'a Credential<T>,
    schema: &'a Schema,
    policy: &'a kels_policy::Policy,
    resolver: &'a dyn PolicyResolver,
    source: &'a (dyn PagedKelSource + Sync),
    sad_store: Option<&'a dyn SADStore>,
    edge_schemas: &'a BTreeMap<String, Schema>,
    remaining_depth: usize,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<Output = Result<CredentialVerification, CredentialError>>
            + Send
            + 'a,
    >,
> {
    Box::pin(async move {
        if remaining_depth == 0 {
            return Err(CredentialError::VerificationError(
                "maximum edge verification depth exceeded".to_string(),
            ));
        }

        // Verify schema SAID matches credential's schema reference
        if credential.schema != schema.said {
            return Err(CredentialError::VerificationError(format!(
                "schema SAID mismatch: credential references {}, provided schema has {}",
                credential.schema, schema.said
            )));
        }

        // Verify policy SAID matches credential's policy reference
        if credential.policy != policy.said {
            return Err(CredentialError::VerificationError(format!(
                "policy SAID mismatch: credential references {}, provided policy has {}",
                credential.policy, policy.said
            )));
        }

        // Expanded SAID integrity — verify the credential's own SAID is consistent with data
        let value = serde_json::to_value(credential)?;
        let computed_said = compute_said_from_value(&value)?;
        if computed_said != credential.said {
            return Err(CredentialError::VerificationError(format!(
                "SAID mismatch: credential has {}, data produces {}",
                credential.said, computed_said
            )));
        }

        // Compacted SAID integrity — compact and derive the anchored SAID
        let (compacted_said, _) = credential.compact(schema)?;

        // Schema validation
        let schema_validation = validate_credential_report(credential, schema)?;

        // Policy evaluation — check anchoring and poisoning via policy evaluator
        let policy_verification = evaluate_policy(policy, &compacted_said, source, resolver)
            .await
            .map_err(|e| CredentialError::VerificationError(e.to_string()))?;

        // Check expiration
        let is_expired = credential
            .expires_at
            .as_ref()
            .is_some_and(|exp| exp <= &StorageDatetime::now());

        // Edge verification — recursively verify referenced credentials
        let edge_verifications = if let Some(sad_store) = sad_store {
            verify_edges(
                credential,
                resolver,
                source,
                sad_store,
                edge_schemas,
                remaining_depth - 1,
            )
            .await?
        } else {
            BTreeMap::new()
        };

        Ok(CredentialVerification {
            credential: credential.said.clone(),
            policy: policy.said.clone(),
            subject: credential.subject.clone(),
            is_expired,
            policy_verification,
            schema_validation,
            edge_verifications,
        })
    })
}

/// Verify all edge credentials that have a `credential` SAID reference.
/// Looks up each referenced credential in the SADStore, expands it using
/// schema-aware expansion (with schema from `edge_schemas`), parses as
/// `Credential<Value>`, and recursively verifies.
async fn verify_edges<T: Claims>(
    credential: &Credential<T>,
    resolver: &dyn PolicyResolver,
    source: &(dyn PagedKelSource + Sync),
    sad_store: &dyn SADStore,
    edge_schemas: &BTreeMap<String, Schema>,
    remaining_depth: usize,
) -> Result<BTreeMap<String, CredentialVerification>, CredentialError> {
    let mut results = BTreeMap::new();

    let edges = match credential.edges.as_ref().and_then(|e| e.as_expanded()) {
        Some(edges) => edges,
        None => return Ok(results),
    };

    for (label, edge) in &edges.edges {
        let credential_said = match &edge.credential {
            Some(said) => said,
            None => continue,
        };

        // Look up the edge credential's schema
        let edge_schema = edge_schemas.get(&edge.schema).ok_or_else(|| {
            CredentialError::VerificationError(format!(
                "edge '{label}': no schema provided for SAID {}",
                edge.schema
            ))
        })?;

        // Look up and expand the referenced credential from the SADStore
        let root_chunk = sad_store.get_chunk(credential_said).await?.ok_or_else(|| {
            CredentialError::VerificationError(format!(
                "edge '{label}': referenced credential {credential_said} not found in store"
            ))
        })?;

        // Verify the edge credential references the expected schema before expanding
        let cred_schema_said = root_chunk
            .get("schema")
            .and_then(|s| s.as_str())
            .unwrap_or("");
        if cred_schema_said != AsRef::<str>::as_ref(&edge_schema.said) {
            return Err(CredentialError::VerificationError(format!(
                "edge '{label}': credential schema {cred_schema_said} does not match \
                 edge schema {}",
                edge_schema.said
            )));
        }

        let mut expanded = root_chunk;
        expand_with_schema(&mut expanded, edge_schema, sad_store).await?;

        let edge_credential: Credential<serde_json::Value> = serde_json::from_value(expanded)
            .map_err(|e| {
                CredentialError::VerificationError(format!(
                    "edge '{label}': failed to parse referenced credential {credential_said}: {e}"
                ))
            })?;

        // Enforce edge.policy constraint — the edge declares the expected canonical policy SAID.
        // Compact the credential's policy to canonical form and compare SAIDs,
        // allowing delegate flexibility (different delegates produce different full SAIDs
        // but the same canonical SAID).
        if let Some(ref expected_policy) = edge.policy {
            let edge_cred_policy = resolver
                .resolve_policy(edge_credential.policy.as_ref())
                .await
                .map_err(|e| {
                    CredentialError::VerificationError(format!(
                        "edge '{label}': failed to resolve credential policy {}: {e}",
                        edge_credential.policy
                    ))
                })?;
            let canonical = edge_cred_policy.compact().map_err(|e| {
                CredentialError::VerificationError(format!(
                    "edge '{label}': failed to compact credential policy: {e}"
                ))
            })?;
            if expected_policy.as_str() != canonical.said.as_ref() {
                return Err(CredentialError::VerificationError(format!(
                    "edge '{label}': policy mismatch — edge declares {expected_policy}, \
                     credential's canonical policy is {}",
                    canonical.said
                )));
            }
        }

        // Resolve the edge credential's policy for verification
        let edge_policy_said = &edge_credential.policy;
        let edge_policy = resolver
            .resolve_policy(edge_policy_said.as_ref())
            .await
            .map_err(|e| {
                CredentialError::VerificationError(format!(
                    "edge '{label}': failed to resolve policy {edge_policy_said}: {e}"
                ))
            })?;

        let verification = verify_credential_bounded(
            &edge_credential,
            edge_schema,
            &edge_policy,
            resolver,
            source,
            Some(sad_store),
            edge_schemas,
            remaining_depth,
        )
        .await?;

        results.insert(label.clone(), verification);
    }

    Ok(results)
}
