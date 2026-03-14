use std::collections::BTreeMap;

use serde::Serialize;

use kels::{KelVerifier, MAX_EVENTS_PER_KEL_QUERY, PagedKelSource, verify_key_events};
use verifiable_storage::{StorageDatetime, compute_said_from_value};

use crate::{
    compaction::{MAX_RECURSION_DEPTH, expand_all},
    credential::{Claims, Credential},
    error::CredentialError,
    revocation::revocation_hash,
    schema::{SchemaValidationReport, SchemaValidationResult, validate_credential_report},
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
    pub schema_validation: SchemaValidationReport,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub edge_verifications: BTreeMap<String, CredentialVerification>,
}

impl CredentialVerification {
    /// Returns `Ok(())` if the credential is fully trustworthy: issued, not revoked,
    /// not expired, no KEL errors, and all edge credentials also valid. If
    /// `require_valid_schema` is true, also requires all expanded schema fields
    /// to pass validation (recursively for edges).
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
            self.schema_validation.require_all_valid()?;
        }
        for (label, edge_v) in &self.edge_verifications {
            edge_v
                .is_valid(require_valid_schema)
                .map_err(|e| CredentialError::VerificationError(format!("edge '{label}': {e}")))?;
        }
        Ok(())
    }
}

/// Verify a credential against the KEL, optionally with recursive edge verification.
///
/// Checks:
/// 1. Expanded SAID integrity — recompute SAID from credential data
/// 2. Compacted SAID integrity — compact to canonical form, verify consistency
/// 3. KEL anchoring — issuer's KEL contains the compacted credential SAID
/// 4. Revocation — issuer's KEL contains the revocation hash (unless irrevocable)
/// 5. Expiration — `expiresAt` vs current time
/// 6. Schema validation — if both schema and claims are expanded
/// 7. Edge verification — if edges are expanded and a SADStore is provided,
///    recursively verify referenced credentials
pub async fn verify_credential<T: Claims>(
    credential: &Credential<T>,
    source: &dyn PagedKelSource,
    sad_store: Option<&dyn SADStore>,
) -> Result<CredentialVerification, CredentialError> {
    verify_credential_bounded(credential, source, sad_store, MAX_RECURSION_DEPTH).await
}

fn verify_credential_bounded<'a, T: Claims>(
    credential: &'a Credential<T>,
    source: &'a dyn PagedKelSource,
    sad_store: Option<&'a dyn SADStore>,
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

        // Schema validation — validate what's expanded, NotValidated for compacted fields
        let schema_validation = if let Some(schema) = credential.schema.as_expanded() {
            validate_credential_report(credential, schema)?
        } else {
            SchemaValidationReport {
                claims: SchemaValidationResult::NotValidated,
                edges: SchemaValidationResult::NotValidated,
                rules: SchemaValidationResult::NotValidated,
            }
        };

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

        let (is_issued, is_revoked, kel_error) = match verify_key_events(
            &credential.issuer,
            source,
            verifier,
            MAX_EVENTS_PER_KEL_QUERY,
            1024,
        )
        .await
        {
            Ok(kel_v) => {
                let issued = kel_v.is_said_anchored(&compacted_said);
                let revoked = rev_hash
                    .as_ref()
                    .is_some_and(|rh| kel_v.is_said_anchored(rh));
                (issued, revoked, None)
            }
            Err(e) => (false, false, Some(e)),
        };

        // Check expiration
        let is_expired = credential
            .expires_at
            .as_ref()
            .is_some_and(|exp| exp <= &StorageDatetime::now());

        // Edge verification — recursively verify referenced credentials
        let edge_verifications = if let Some(sad_store) = sad_store {
            verify_edges(credential, source, sad_store, remaining_depth - 1).await?
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
            schema_validation,
            edge_verifications,
        })
    })
}

/// Verify all edge credentials that have a `credential` SAID reference.
/// Looks up each referenced credential in the SADStore, expands it fully,
/// parses as `Credential<Value>`, and recursively verifies.
async fn verify_edges<T: Claims>(
    credential: &Credential<T>,
    source: &dyn PagedKelSource,
    sad_store: &dyn SADStore,
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

        // Look up and expand the referenced credential from the SADStore
        let mut expanded = serde_json::Value::String(credential_said.clone());
        expand_all(&mut expanded, sad_store).await?;

        let edge_credential: Credential<serde_json::Value> = serde_json::from_value(expanded)
            .map_err(|e| {
                CredentialError::VerificationError(format!(
                    "edge '{label}': failed to parse referenced credential {credential_said}: {e}"
                ))
            })?;

        let verification =
            verify_credential_bounded(&edge_credential, source, Some(sad_store), remaining_depth)
                .await?;

        results.insert(label.clone(), verification);
    }

    Ok(results)
}
