//! Authentication & request signing

use chrono::Utc;
use serde::{Deserialize, Serialize};

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
pub struct SignedRequest<T> {
    pub payload: T,
    pub prefix: cesr::Digest,
    pub signature: cesr::Signature,
}

impl<T: Serialize> SignedRequest<T> {
    /// Verify the request signature against a verified KEL context.
    ///
    /// Uses the current public key from the `KelVerification` (proof-of-verification token).
    /// Fails secure if the KEL is divergent (no unambiguous key).
    pub fn verify_signature(&self, kel_verification: &KelVerification) -> Result<(), KelsError> {
        if kel_verification.is_divergent() {
            return Err(KelsError::Divergent);
        }

        let public_key = kel_verification
            .current_public_key()
            .ok_or_else(|| KelsError::VerificationFailed("No public key in verified KEL".into()))?;

        let payload_json = serde_json::to_vec(&self.payload)?;

        public_key
            .verify(&payload_json, &self.signature)
            .map_err(|_| KelsError::SignatureVerificationFailed)?;

        Ok(())
    }
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

    #[tokio::test]
    async fn test_verify_signature_rejects_divergent_kel() {
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

        let signed = SignedRequest {
            payload: "test".to_string(),
            prefix: test_digest("test-prefix"),
            signature: {
                // Generate a dummy signature for the test — the test only checks
                // that divergent KELs are rejected, not signature correctness.
                let (_, sk) = cesr::generate_secp256r1().unwrap();
                sk.sign(b"dummy").unwrap()
            },
        };

        let result = signed.verify_signature(&kel_verification);
        assert!(
            matches!(result, Err(crate::KelsError::Divergent)),
            "Expected Divergent error, got: {:?}",
            result
        );
    }
}
