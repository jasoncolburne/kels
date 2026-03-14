use kels::{KelStore, KelVerifier, MAX_EVENTS_PER_KEL_QUERY, StoreKelSource, verify_key_events};

use verifiable_storage::{StorageDatetime, compute_said_from_value};

use crate::credential::{
    Claims, Compactable, Credential, CredentialVerification, SchemaValidationResult,
};
use crate::error::CredentialError;
use crate::revocation::revocation_hash;
use crate::schema::validate_claims;

/// Verify a credential against the KEL.
///
/// Checks:
/// 1. Expanded SAID integrity — recompute SAID from credential data
/// 2. Compacted SAID integrity — compact to canonical form, verify consistency
/// 3. KEL anchoring — issuer's KEL contains the compacted credential SAID
/// 4. Revocation — issuer's KEL contains the revocation hash (unless irrevocable)
/// 5. Expiration — `expiresAt` vs current time
/// 6. Schema validation — if both schema and claims are expanded
pub async fn verify_credential<T: Claims>(
    credential: &Credential<T>,
    kel_store: &dyn KelStore,
) -> Result<CredentialVerification, CredentialError> {
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

    // Schema validation (if both schema and claims are expanded)
    let schema_validation = match (&credential.schema, &credential.claims) {
        (Compactable::Expanded(schema), Compactable::Expanded(claims)) => {
            if validate_claims(schema, &serde_json::to_value(claims)?).is_ok() {
                SchemaValidationResult::Valid
            } else {
                SchemaValidationResult::Invalid
            }
        }
        _ => SchemaValidationResult::NotValidated,
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

    let source = StoreKelSource::new(kel_store);
    let (is_issued, is_revoked, kel_error) = match verify_key_events(
        &credential.issuer,
        &source,
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

    Ok(CredentialVerification {
        credential_said: credential.said.clone(),
        issuer: credential.issuer.clone(),
        subject: credential.subject.clone(),
        is_issued,
        is_revoked,
        is_expired,
        kel_error: kel_error.map(|e| e.to_string()),
        schema_validation,
    })
}
