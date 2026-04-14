//! Authentication & request signing

use std::collections::{HashMap, HashSet};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use verifiable_storage::SelfAddressed;

use super::kel::KelVerification;
use crate::KelsError;

/// Validate that a timestamp is within the acceptable window.
///
/// Uses asymmetric bounds: allows up to 5 seconds of clock skew into the future,
/// but the full `max_age_secs` into the past. This prevents attackers from
/// pre-signing requests with far-future timestamps for delayed replay.
pub fn validate_timestamp(timestamp: i64, max_age_secs: i64) -> bool {
    let now = Utc::now().timestamp();
    let max_future_skew = 5;
    timestamp <= now + max_future_skew && timestamp >= now - max_age_secs
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedRequest<T: SelfAddressed> {
    pub payload: T,
    pub signatures: HashMap<cesr::Digest256, cesr::Signature>,
}

impl<T: SelfAddressed + Serialize> SignedRequest<T> {
    /// Verify a single signer's signature against their verified KEL.
    ///
    /// Verifies the payload SAID, then checks the signature against the SAID's
    /// QB64 bytes using the current public key from the `KelVerification`.
    /// Fails secure if the KEL is divergent (no unambiguous key).
    pub fn verify_one(
        &self,
        prefix: &cesr::Digest256,
        kel_verification: &KelVerification,
    ) -> Result<(), KelsError> {
        self.payload
            .verify_said()
            .map_err(|_| KelsError::VerificationFailed("SAID verification failed".into()))?;

        self.verify_signature_only(prefix, kel_verification)
    }

    /// Verify a single signature without re-checking the payload SAID.
    /// Used by `verify_signatures()` which checks the SAID once upfront.
    fn verify_signature_only(
        &self,
        prefix: &cesr::Digest256,
        kel_verification: &KelVerification,
    ) -> Result<(), KelsError> {
        if kel_verification.is_divergent() {
            return Err(KelsError::Divergent);
        }

        let public_key = kel_verification
            .current_public_key()
            .ok_or_else(|| KelsError::VerificationFailed("No public key in verified KEL".into()))?;

        let signature = self
            .signatures
            .get(prefix)
            .ok_or(KelsError::SignatureVerificationFailed)?;

        public_key
            .verify(self.payload.get_said().qb64b(), signature)
            .map_err(|_| KelsError::SignatureVerificationFailed)?;

        Ok(())
    }

    /// Verify all signatures. Returns set of verified prefixes.
    ///
    /// Verifies the payload SAID once, then checks each signature individually.
    /// Does NOT error on individual failures — just excludes unverified signers.
    /// Callers decide if the set meets their threshold.
    pub fn verify_signatures(
        &self,
        verifications: &HashMap<cesr::Digest256, KelVerification>,
    ) -> HashSet<cesr::Digest256> {
        if self.payload.verify_said().is_err() {
            return HashSet::new();
        }

        self.signatures
            .keys()
            .filter(|prefix| {
                verifications
                    .get(prefix)
                    .and_then(|v| self.verify_signature_only(prefix, v).ok())
                    .is_some()
            })
            .copied()
            .collect()
    }
}

/// Extract the single signer prefix from a verified set.
///
/// Returns an error if the set does not contain exactly one prefix.
/// Callers map the `KelsError` to their service-specific error type.
#[allow(clippy::expect_used)]
pub fn single_signer(verified: &HashSet<cesr::Digest256>) -> Result<cesr::Digest256, KelsError> {
    if verified.len() != 1 {
        return Err(KelsError::VerificationFailed(
            "Expected single signer".into(),
        ));
    }
    Ok(*verified
        .iter()
        .next()
        .expect("verified set has exactly one entry"))
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use cesr::test_digest;

    // ==================== validate_timestamp Tests ====================

    #[test]
    fn test_timestamp_current_is_valid() {
        let now = chrono::Utc::now().timestamp();
        assert!(validate_timestamp(now, 60));
    }

    #[test]
    fn test_timestamp_past_within_window() {
        let now = chrono::Utc::now().timestamp();
        assert!(validate_timestamp(now - 30, 60));
    }

    #[test]
    fn test_timestamp_past_outside_window() {
        let now = chrono::Utc::now().timestamp();
        assert!(!validate_timestamp(now - 61, 60));
    }

    #[test]
    fn test_timestamp_future_within_skew() {
        let now = chrono::Utc::now().timestamp();
        assert!(validate_timestamp(now + 3, 60));
    }

    #[test]
    fn test_timestamp_future_at_skew_boundary() {
        let now = chrono::Utc::now().timestamp();
        assert!(validate_timestamp(now + 5, 60));
    }

    #[test]
    fn test_timestamp_future_beyond_skew() {
        let now = chrono::Utc::now().timestamp();
        assert!(!validate_timestamp(now + 6, 60));
    }

    #[test]
    fn test_timestamp_far_future_rejected() {
        let now = chrono::Utc::now().timestamp();
        assert!(!validate_timestamp(now + 60, 60));
    }

    #[test]
    fn test_timestamp_past_at_boundary() {
        let now = chrono::Utc::now().timestamp();
        assert!(validate_timestamp(now - 60, 60));
    }

    #[derive(Debug, Clone, Serialize, Deserialize, verifiable_storage::SelfAddressed)]
    #[serde(rename_all = "camelCase")]
    struct TestPayload {
        #[said]
        said: cesr::Digest256,
        data: String,
    }

    #[tokio::test]
    async fn test_verify_one_rejects_divergent_kel() {
        use crate::{KelVerifier, KeyEventBuilder, SoftwareKeyProvider};
        use cesr::VerificationKeyCode;

        let mut builder1 = KeyEventBuilder::new(
            SoftwareKeyProvider::new(
                VerificationKeyCode::Secp256r1,
                VerificationKeyCode::Secp256r1,
            ),
            None,
        );
        let icp = builder1.incept().await.unwrap();
        let prefix = icp.event.prefix;
        let mut builder2 = builder1.clone();
        let anchor1 = test_digest("anchor1");
        let anchor2 = test_digest("anchor2");
        let ixn1 = builder1.interact(&anchor1).await.unwrap();
        let ixn2 = builder2.interact(&anchor2).await.unwrap();

        // Sort events the way the DB would: serial ASC, kind sort_priority ASC, said ASC
        let mut events = vec![icp, ixn1, ixn2];
        events.sort_by(|a, b| {
            a.event
                .serial
                .cmp(&b.event.serial)
                .then(
                    a.event
                        .kind
                        .sort_priority()
                        .cmp(&b.event.kind.sort_priority()),
                )
                .then(a.event.said.cmp(&b.event.said))
        });

        let mut verifier = KelVerifier::new(&prefix);
        verifier.verify_page(&events).unwrap();
        let kel_verification = verifier.into_verification().unwrap();
        assert!(kel_verification.is_divergent());

        let payload = TestPayload::create("test".to_string()).unwrap();

        let signer_prefix = test_digest("test-prefix");
        let (_, sk) = cesr::generate_secp256r1().unwrap();
        let signature = sk.sign(payload.get_said().qb64b()).unwrap();

        let signed = SignedRequest {
            payload,
            signatures: HashMap::from([(signer_prefix, signature)]),
        };

        let result = signed.verify_one(&signer_prefix, &kel_verification);
        assert!(
            matches!(result, Err(crate::KelsError::Divergent)),
            "Expected Divergent error, got: {:?}",
            result
        );
    }

    /// Helper: create a non-divergent KEL and return (prefix, KelVerification, KeyEventBuilder).
    async fn make_verified_kel() -> (
        cesr::Digest256,
        crate::KelVerification,
        crate::KeyEventBuilder<crate::SoftwareKeyProvider>,
    ) {
        use crate::{KelVerifier, KeyEventBuilder, SoftwareKeyProvider};
        use cesr::VerificationKeyCode;

        let mut builder = KeyEventBuilder::new(
            SoftwareKeyProvider::new(
                VerificationKeyCode::Secp256r1,
                VerificationKeyCode::Secp256r1,
            ),
            None,
        );
        let icp = builder.incept().await.unwrap();
        let prefix = icp.event.prefix;

        let mut verifier = KelVerifier::new(&prefix);
        verifier.verify_page(&[icp]).unwrap();
        let verification = verifier.into_verification().unwrap();

        (prefix, verification, builder)
    }

    #[tokio::test]
    async fn test_verify_one_valid_signature() {
        use crate::crypto::KeyProvider;

        let (prefix, verification, builder) = make_verified_kel().await;

        let payload = TestPayload::create("hello".to_string()).unwrap();

        let signature = builder
            .key_provider()
            .sign(payload.get_said().qb64b())
            .await
            .unwrap();

        let signed = SignedRequest {
            payload,
            signatures: HashMap::from([(prefix, signature)]),
        };

        signed.verify_one(&prefix, &verification).unwrap();
    }

    #[tokio::test]
    async fn test_verify_signatures_multi_signer() {
        use crate::crypto::KeyProvider;

        let (prefix1, verification1, builder1) = make_verified_kel().await;
        let (prefix2, verification2, builder2) = make_verified_kel().await;

        let payload = TestPayload::create("multi".to_string()).unwrap();

        let sig1 = builder1
            .key_provider()
            .sign(payload.get_said().qb64b())
            .await
            .unwrap();
        let sig2 = builder2
            .key_provider()
            .sign(payload.get_said().qb64b())
            .await
            .unwrap();

        let signed = SignedRequest {
            payload,
            signatures: HashMap::from([(prefix1, sig1), (prefix2, sig2)]),
        };

        let verifications = HashMap::from([(prefix1, verification1), (prefix2, verification2)]);
        let verified = signed.verify_signatures(&verifications);
        assert_eq!(verified.len(), 2);
        assert!(verified.contains(&prefix1));
        assert!(verified.contains(&prefix2));
    }

    #[tokio::test]
    async fn test_verify_signatures_partial_invalid() {
        use crate::crypto::KeyProvider;

        let (prefix1, verification1, builder1) = make_verified_kel().await;
        let (prefix2, verification2, _builder2) = make_verified_kel().await;

        let payload = TestPayload::create("partial".to_string()).unwrap();

        let sig1 = builder1
            .key_provider()
            .sign(payload.get_said().qb64b())
            .await
            .unwrap();
        // Deliberately use a wrong signature for prefix2 (sign with builder1 instead of builder2)
        let bad_sig = builder1
            .key_provider()
            .sign(payload.get_said().qb64b())
            .await
            .unwrap();

        let signed = SignedRequest {
            payload,
            signatures: HashMap::from([(prefix1, sig1), (prefix2, bad_sig)]),
        };

        let verifications = HashMap::from([(prefix1, verification1), (prefix2, verification2)]);
        let verified = signed.verify_signatures(&verifications);
        // Only prefix1 should verify; prefix2 has wrong key
        assert_eq!(verified.len(), 1);
        assert!(verified.contains(&prefix1));
    }

    #[tokio::test]
    async fn test_verify_one_rejects_tampered_said() {
        use crate::crypto::KeyProvider;

        let (prefix, verification, builder) = make_verified_kel().await;

        // Create normally, then mutate after to simulate tampering
        let mut payload = TestPayload::create("original".to_string()).unwrap();

        let signature = builder
            .key_provider()
            .sign(payload.get_said().qb64b())
            .await
            .unwrap();

        // Tamper with the payload data after signing
        payload.data = "tampered".to_string();

        let signed = SignedRequest {
            payload,
            signatures: HashMap::from([(prefix, signature)]),
        };

        let result = signed.verify_one(&prefix, &verification);
        assert!(
            matches!(result, Err(crate::KelsError::VerificationFailed(_))),
            "Expected VerificationFailed for tampered SAID, got: {:?}",
            result
        );
    }
}
