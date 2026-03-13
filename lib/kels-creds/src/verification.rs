use std::collections::{BTreeMap, HashMap};

use kels::{
    KelStore, KelVerification, KelVerifier, MAX_EVENTS_PER_KEL_QUERY, StoreKelSource,
    verify_key_events,
};

use verifiable_storage::compact_value;

use crate::error::CredentialError;
use crate::revocation::revocation_hash;
use crate::schema::{CredentialSchema, validate_claims};
use crate::store::SADStore;

/// The result of verifying a credential, including edge verifications.
#[derive(Debug, Clone)]
pub struct CredentialVerification {
    pub credential_said: String,
    pub issuer: String,
    pub subject: Option<String>,
    pub is_issued: bool,
    pub is_revoked: bool,
    pub schema_valid: Option<bool>,
    pub edge_verifications: BTreeMap<String, CredentialVerification>,
}

/// Collected anchor info for a single credential in the graph.
struct CredentialAnchor {
    said: String,
    issuer: String,
    revocation_hash: Option<String>,
    irrevocable: bool,
}

/// Verify a credential, its anchoring in the issuer's KEL, and any edges recursively.
///
/// Steps:
/// 1. Walk the credential graph collecting (issuer, said, revocation_hash) per credential
/// 2. Batch KEL verification — one verify_key_events per unique issuer
/// 3. Per-credential structural checks, anchoring, revocation, and edge verification
pub fn verify_credential<'a>(
    said: &'a str,
    sad_store: &'a dyn SADStore,
    kel_store: &'a dyn KelStore,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<Output = Result<CredentialVerification, CredentialError>>
            + Send
            + 'a,
    >,
> {
    Box::pin(async move {
        let Some(credential) = sad_store.get_chunk(said).await? else {
            return Err(CredentialError::StorageError(
                "Cannot find credential in store".to_string(),
            ));
        };

        // Phase 1: Collect all credential anchors from the graph
        let mut anchors: Vec<CredentialAnchor> = Vec::new();
        collect_anchors(&credential, sad_store, &mut anchors).await?;

        // Phase 2: Batch KEL verification — one per unique issuer
        let mut kel_verifications: HashMap<String, KelVerification> = HashMap::new();

        // Group anchors by issuer
        let mut issuer_anchors: HashMap<String, Vec<(String, Option<String>)>> = HashMap::new();
        for anchor in &anchors {
            issuer_anchors
                .entry(anchor.issuer.clone())
                .or_default()
                .push((anchor.said.clone(), anchor.revocation_hash.clone()));
        }

        for (issuer_prefix, anchor_saids) in &issuer_anchors {
            let mut verifier = KelVerifier::new(issuer_prefix);

            // Register all SAIDs and revocation hashes for this issuer
            let all_saids: Vec<String> = anchor_saids
                .iter()
                .flat_map(|(said, rev_hash)| {
                    let mut v = vec![said.clone()];
                    if let Some(rh) = rev_hash {
                        v.push(rh.clone());
                    }
                    v
                })
                .collect();
            verifier.check_anchors(all_saids);

            let source = StoreKelSource::new(kel_store);
            let max_pages = 1024;
            if let Ok(verification) = verify_key_events(
                issuer_prefix,
                &source,
                verifier,
                MAX_EVENTS_PER_KEL_QUERY,
                max_pages,
            )
            .await
            {
                kel_verifications.insert(issuer_prefix.clone(), verification);
            }
            // KEL verification failure means issuer's credentials show as not issued
        }

        // Phase 3: Build verification results
        build_verification(
            &credential,
            &anchors,
            &kel_verifications,
            sad_store,
            kel_store,
        )
        .await
    })
}

/// Walk the credential graph, collecting anchors for all credentials.
fn collect_anchors<'a>(
    credential: &'a serde_json::Value,
    sad_store: &'a dyn SADStore,
    anchors: &'a mut Vec<CredentialAnchor>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), CredentialError>> + Send + 'a>> {
    Box::pin(async move {
        let said = credential
            .get("said")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CredentialError::InvalidCredential("missing SAID".to_string()))?
            .to_string();

        let issuer = credential
            .get("issuer")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CredentialError::InvalidCredential("missing issuer".to_string()))?
            .to_string();

        let irrevocable = credential
            .get("irrevocable")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let rev_hash = if irrevocable {
            None
        } else {
            Some(revocation_hash(&said))
        };

        anchors.push(CredentialAnchor {
            said,
            issuer,
            revocation_hash: rev_hash,
            irrevocable,
        });

        // Walk edges if expanded
        if let Some(edges_val) = credential.get("edges")
            && let Some(edges_obj) = edges_val.as_object()
        {
            for (label, edge_val) in edges_obj {
                if label == "said" {
                    continue;
                }

                let edge_obj = match edge_val.as_object() {
                    Some(obj) => obj,
                    None => continue,
                };

                let cred_said = match edge_obj.get("credential").and_then(|v| v.as_str()) {
                    Some(s) => s,
                    None => continue,
                };

                if let Some(ref_value) = sad_store.get_chunk(cred_said).await? {
                    collect_anchors(&ref_value, sad_store, anchors).await?;
                }
            }
        }

        Ok(())
    })
}

/// Build the verification result tree from collected anchors and KEL verifications.
async fn build_verification(
    credential: &serde_json::Value,
    anchors: &[CredentialAnchor],
    kel_verifications: &HashMap<String, KelVerification>,
    sad_store: &dyn SADStore,
    kel_store: &dyn KelStore,
) -> Result<CredentialVerification, CredentialError> {
    let said = credential
        .get("said")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CredentialError::InvalidCredential("missing SAID".to_string()))?
        .to_string();

    let issuer = credential
        .get("issuer")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CredentialError::InvalidCredential("missing issuer".to_string()))?
        .to_string();

    // Structural check: compact to canonical form and verify SAID
    let mut compacted = credential.clone();
    compact_value(&mut compacted, &mut std::collections::HashMap::new())?;
    let compacted_said = compacted.as_str().ok_or_else(|| {
        CredentialError::VerificationError("compacted credential missing SAID".to_string())
    })?;

    if compacted_said != said {
        return Err(CredentialError::VerificationError(format!(
            "SAID mismatch: credential has {}, canonical form produces {}",
            said, compacted_said
        )));
    }

    // Schema validation (if schema is expanded)
    let schema_valid = validate_schema_if_expanded(credential);

    // Find this credential's anchor info
    let anchor = anchors.iter().find(|a| a.said == said);

    // Check anchoring and revocation via KEL verification
    let (is_issued, is_revoked) = if let Some(kel_v) = kel_verifications.get(&issuer) {
        let issued = kel_v.is_said_anchored(&said);
        let revoked = if let Some(anchor) = anchor
            && !anchor.irrevocable
            && let Some(ref rh) = anchor.revocation_hash
        {
            kel_v.is_said_anchored(rh)
        } else {
            false
        };
        (issued, revoked)
    } else {
        (false, false)
    };

    // Edge verifications
    let mut edge_verifications = BTreeMap::new();

    if let Some(edges_val) = credential.get("edges")
        && let Some(edges_obj) = edges_val.as_object()
    {
        for (label, edge_val) in edges_obj {
            if label == "said" {
                continue;
            }

            let edge_obj = match edge_val.as_object() {
                Some(obj) => obj,
                None => continue,
            };

            let edge_said = match edge_obj.get("credential").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => continue,
            };

            // Recursively verify the edge credential
            let edge_verification = verify_credential(edge_said, sad_store, kel_store).await?;

            // Check edge constraints
            let edge_schema = edge_obj.get("schema").and_then(|v| v.as_str());
            let edge_issuer = edge_obj.get("issuer").and_then(|v| v.as_str());
            let delegated = edge_obj
                .get("delegated")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            // Schema constraint: referenced credential's schema must match
            if let Some(expected_schema) = edge_schema {
                let store_value =
                    sad_store
                        .get_chunk(edge_said)
                        .await?
                        .ok_or(CredentialError::StorageError(
                            "Cannot find edge credential in sad store".to_string(),
                        ))?;
                let schema_said = store_value.get("schema").and_then(|v| v.as_str()).ok_or(
                    CredentialError::StorageError(
                        "Cannot find schema said in sad store credential".to_string(),
                    ),
                )?;

                if schema_said != expected_schema {
                    return Err(CredentialError::VerificationError(format!(
                        "edge '{}' schema mismatch: expected {}, got {:?}",
                        label, expected_schema, schema_said
                    )));
                }
            }

            // Issuer constraint
            if let Some(expected_issuer) = edge_issuer {
                if delegated {
                    // Delegated: referenced credential's issuer must be delegated by edge.issuer
                    if let Some(ref_kel_v) = kel_verifications.get(&edge_verification.issuer) {
                        let delegating = ref_kel_v.delegating_prefix();
                        if delegating != Some(expected_issuer) {
                            return Err(CredentialError::VerificationError(format!(
                                "edge '{}' delegation check failed: expected delegating prefix {}, got {:?}",
                                label, expected_issuer, delegating
                            )));
                        }
                    } else {
                        return Err(CredentialError::VerificationError(format!(
                            "edge '{}' delegation check failed: no KEL verification for issuer {}",
                            label, edge_verification.issuer
                        )));
                    }
                } else if edge_verification.issuer != expected_issuer {
                    return Err(CredentialError::VerificationError(format!(
                        "edge '{}' issuer mismatch: expected {}, got {}",
                        label, expected_issuer, edge_verification.issuer
                    )));
                }
            }

            edge_verifications.insert(label.clone(), edge_verification);
        }
    }

    Ok(CredentialVerification {
        credential_said: said,
        issuer,
        subject: credential
            .get("subject")
            .and_then(|v| v.as_str())
            .map(String::from),
        is_issued,
        is_revoked,
        schema_valid,
        edge_verifications,
    })
}

/// Validate claims against schema if the schema field is expanded.
fn validate_schema_if_expanded(credential: &serde_json::Value) -> Option<bool> {
    let schema_val = credential.get("schema")?;

    // Schema must be expanded (an object) for validation
    let schema_obj = schema_val.as_object()?;

    // Try to deserialize as CredentialSchema
    let schema: CredentialSchema =
        serde_json::from_value(serde_json::Value::Object(schema_obj.clone())).ok()?;

    let claims_val = credential.get("claims")?;

    // If claims is compacted (string), skip validation
    if claims_val.is_string() {
        return None;
    }

    Some(validate_claims(&schema, claims_val).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_verification_struct() {
        let v = CredentialVerification {
            credential_said: "EAbc".to_string(),
            issuer: "EIssuer".to_string(),
            subject: Some("ESubject".to_string()),
            is_issued: true,
            is_revoked: false,
            schema_valid: Some(true),
            edge_verifications: BTreeMap::new(),
        };

        assert_eq!(v.credential_said, "EAbc");
        assert!(v.is_issued);
        assert!(!v.is_revoked);
        assert_eq!(v.schema_valid, Some(true));
        assert!(v.edge_verifications.is_empty());
    }

    #[test]
    fn test_credential_verification_with_edges() {
        let edge_v = CredentialVerification {
            credential_said: "EEdge".to_string(),
            issuer: "EEdgeIssuer".to_string(),
            subject: None,
            is_issued: true,
            is_revoked: false,
            schema_valid: None,
            edge_verifications: BTreeMap::new(),
        };

        let mut edges = BTreeMap::new();
        edges.insert("license".to_string(), edge_v);

        let v = CredentialVerification {
            credential_said: "ERoot".to_string(),
            issuer: "ERootIssuer".to_string(),
            subject: None,
            is_issued: true,
            is_revoked: false,
            schema_valid: None,
            edge_verifications: edges,
        };

        assert_eq!(v.edge_verifications.len(), 1);
        assert!(v.edge_verifications.contains_key("license"));
    }

    #[test]
    fn test_validate_schema_if_expanded_compacted_schema() {
        let cv = serde_json::json!({
            "said": "EAbc1234567890123456789012345678901234567890",
            "schema": "ESchema23456789012345678901234567890abcdef",
            "issuer": "EIssuer123456789012345678901234567890abcde",
            "claims": {"said": "EClaims", "name": "Alice"},
        });

        // Schema is compacted (string), should return None
        assert_eq!(validate_schema_if_expanded(&cv), None);
    }

    #[test]
    fn test_validate_schema_if_expanded_compacted_claims() {
        let cv = serde_json::json!({
            "said": "EAbc1234567890123456789012345678901234567890",
            "schema": {
                "said": "ESchema23456789012345678901234567890abcdef",
                "name": "Test",
                "description": "test",
                "version": "1.0",
                "fields": {"name": "string"},
            },
            "issuer": "EIssuer123456789012345678901234567890abcde",
            "claims": "EClaims234567890123456789012345678901234567",
        });

        // Claims is compacted (string), should return None
        assert_eq!(validate_schema_if_expanded(&cv), None);
    }
}
