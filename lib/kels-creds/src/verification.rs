use std::collections::BTreeMap;

use serde::Serialize;

use kels::{
    KelVerifier, MAX_EVENTS_PER_KEL_QUERY, PagedKelSource, max_verification_pages,
    verify_key_events,
};
use verifiable_storage::{StorageDatetime, compute_said_from_value};

use crate::{
    compaction::{MAX_RECURSION_DEPTH, expand_with_schema},
    credential::{Claims, Credential},
    error::CredentialError,
    revocation::revocation_hash,
    schema::{Schema, SchemaValidationReport, validate_credential_report},
    store::SADStore,
};

/// The result of verifying a single credential.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialVerification {
    pub credential_said: String,
    pub issuer: String,
    pub subject: Option<String>,
    pub is_issued: bool,
    pub is_revoked: bool,
    pub is_expired: bool,
    pub kel_error: Option<String>,
    /// The delegating prefix from the issuer's KEL inception, if it was a `dip`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegating_prefix: Option<String>,
    pub schema_validation: SchemaValidationReport,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub edge_verifications: BTreeMap<String, CredentialVerification>,
}

impl CredentialVerification {
    /// Returns `Ok(())` if the credential is fully trustworthy: issued, not revoked,
    /// not expired, no KEL errors, and all edge credentials also valid. If
    /// `require_valid_schema` is true, also requires schema validation to pass
    /// (recursively for edges).
    pub fn is_valid(&self, require_valid_schema: bool) -> Result<(), CredentialError> {
        if !self.is_issued {
            return Err(CredentialError::VerificationError(
                "credential is not issued".to_string(),
            ));
        }
        if self.is_revoked {
            return Err(CredentialError::VerificationError(
                "credential is revoked".to_string(),
            ));
        }
        if self.is_expired {
            return Err(CredentialError::VerificationError(
                "credential is expired".to_string(),
            ));
        }
        if let Some(ref err) = self.kel_error {
            return Err(CredentialError::VerificationError(format!(
                "KEL error: {err}"
            )));
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
/// 3. KEL anchoring — issuer's KEL contains the compacted credential SAID
/// 4. Revocation — issuer's KEL contains the revocation hash (unless irrevocable)
/// 5. Expiration — `expiresAt` vs current time
/// 6. Schema validation — validate credential against provided schema
/// 7. Edge verification — if edges are expanded and a SADStore + edge schemas
///    are provided, recursively verify referenced credentials
///
/// `edge_schemas` maps schema SAIDs to Schema objects for edge credentials.
pub async fn verify_credential<T: Claims>(
    credential: &Credential<T>,
    schema: &Schema,
    source: &dyn PagedKelSource,
    sad_store: Option<&dyn SADStore>,
    edge_schemas: &BTreeMap<String, Schema>,
) -> Result<CredentialVerification, CredentialError> {
    verify_credential_bounded(
        credential,
        schema,
        source,
        sad_store,
        edge_schemas,
        MAX_RECURSION_DEPTH,
    )
    .await
}

fn verify_credential_bounded<'a, T: Claims>(
    credential: &'a Credential<T>,
    schema: &'a Schema,
    source: &'a dyn PagedKelSource,
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
        let (compacted_said, _) = credential.compact()?;

        // Schema validation
        let schema_validation = validate_credential_report(credential, schema)?;

        // KEL verification — check anchoring (compacted SAID) and revocation
        let irrevocable = credential.irrevocable.unwrap_or(false);
        let rev_hash = if irrevocable {
            None
        } else {
            Some(revocation_hash(&compacted_said))
        };

        let mut saids_to_check = vec![compacted_said.clone()];
        if let Some(ref rh) = rev_hash {
            saids_to_check.push(rh.clone());
        }

        let mut verifier = KelVerifier::new(&credential.issuer);
        verifier.check_anchors(saids_to_check);

        let (is_issued, is_revoked, kel_error, delegating_prefix) = match verify_key_events(
            &credential.issuer,
            source,
            verifier,
            MAX_EVENTS_PER_KEL_QUERY,
            max_verification_pages(),
        )
        .await
        {
            Ok(kel_v) => {
                let issued = kel_v.is_said_anchored(&compacted_said);
                let revoked = rev_hash
                    .as_ref()
                    .is_some_and(|rh| kel_v.is_said_anchored(rh));
                let dp = kel_v.delegating_prefix().map(String::from);
                (issued, revoked, None, dp)
            }
            Err(e) => (false, false, Some(e), None),
        };

        // Check expiration
        let is_expired = credential
            .expires_at
            .as_ref()
            .is_some_and(|exp| exp <= &StorageDatetime::now());

        // Edge verification — recursively verify referenced credentials
        let edge_verifications = if let Some(sad_store) = sad_store {
            verify_edges(
                credential,
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
            credential_said: credential.said.clone(),
            issuer: credential.issuer.clone(),
            subject: credential.subject.clone(),
            is_issued,
            is_revoked,
            is_expired,
            kel_error: kel_error.map(|e| e.to_string()),
            delegating_prefix,
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
    source: &dyn PagedKelSource,
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

        let mut expanded = root_chunk;
        expand_with_schema(&mut expanded, edge_schema, sad_store).await?;

        let edge_credential: Credential<serde_json::Value> = serde_json::from_value(expanded)
            .map_err(|e| {
                CredentialError::VerificationError(format!(
                    "edge '{label}': failed to parse referenced credential {credential_said}: {e}"
                ))
            })?;

        // Enforce edge.issuer constraint — the edge declares which issuer is expected
        if let Some(ref expected_issuer) = edge.issuer
            && *expected_issuer != edge_credential.issuer
        {
            return Err(CredentialError::VerificationError(format!(
                "edge '{label}': issuer mismatch — edge declares {expected_issuer}, \
                 credential has {}",
                edge_credential.issuer
            )));
        }

        let verification = verify_credential_bounded(
            &edge_credential,
            edge_schema,
            source,
            Some(sad_store),
            edge_schemas,
            remaining_depth,
        )
        .await?;

        // Enforce edge.delegated constraint — verify the issuer's prefix is anchored
        // in the delegating prefix's KEL
        if edge.delegated == Some(true) {
            let dp = verification.delegating_prefix.as_deref().ok_or_else(|| {
                CredentialError::VerificationError(format!(
                    "edge '{label}': credential claims delegation but issuer's KEL \
                     has no delegating prefix (not a dip inception)"
                ))
            })?;

            // Verify the delegating prefix's KEL anchors the delegated prefix
            let mut delegator_verifier = KelVerifier::new(dp);
            delegator_verifier.check_anchors(vec![edge_credential.issuer.clone()]);

            match verify_key_events(
                dp,
                source,
                delegator_verifier,
                MAX_EVENTS_PER_KEL_QUERY,
                max_verification_pages(),
            )
            .await
            {
                Ok(kel_v) => {
                    if !kel_v.is_said_anchored(&edge_credential.issuer) {
                        return Err(CredentialError::VerificationError(format!(
                            "edge '{label}': delegating prefix {dp} does not anchor \
                             issuer prefix {}",
                            edge_credential.issuer
                        )));
                    }
                }
                Err(e) => {
                    return Err(CredentialError::VerificationError(format!(
                        "edge '{label}': failed to verify delegating prefix {dp}: {e}"
                    )));
                }
            }
        }

        results.insert(label.clone(), verification);
    }

    Ok(results)
}
