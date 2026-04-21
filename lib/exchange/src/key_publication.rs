//! Encapsulation key publication — stored as a SAD object, referenced by SadEvent chains.

use serde::{Deserialize, Serialize};
use verifiable_storage::SelfAddressed;

/// Well-known SadEvent kind for ML-KEM encapsulation key publication.
pub const ENCAP_KEY_KIND: &str = "kels/sad/v1/keys/mlkem";

/// ML-KEM encapsulation key publication, stored as a SAD object in the SADStore.
///
/// The owner publishes this by creating a `SadEvent` chain with kind
/// [`ENCAP_KEY_KIND`] and `content_said` pointing to this object's SAID.
/// Anyone can discover the key by computing the deterministic event prefix:
/// `compute_sad_event_prefix(kel_prefix, ENCAP_KEY_KIND)`.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[serde(rename_all = "camelCase")]
pub struct EncapsulationKeyPublication {
    #[said]
    pub said: cesr::Digest256,
    /// Algorithm identifier: `"ML-KEM-768"` or `"ML-KEM-1024"`.
    pub algorithm: String,
    /// CESR-encoded ML-KEM encapsulation key.
    pub encapsulation_key: cesr::EncapsulationKey,
}

/// Known ML-KEM algorithm identifiers.
pub const ML_KEM_768: &str = "ML-KEM-768";
pub const ML_KEM_1024: &str = "ML-KEM-1024";

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use verifiable_storage::SelfAddressed;

    use super::*;

    #[test]
    fn said_derivation_is_deterministic() {
        let (ek, _dk) = cesr::generate_ml_kem_768().unwrap();

        let mut pub1 = EncapsulationKeyPublication {
            said: cesr::Digest256::default(),
            algorithm: ML_KEM_768.to_string(),
            encapsulation_key: ek.clone(),
        };
        pub1.derive_said().unwrap();

        let mut pub2 = EncapsulationKeyPublication {
            said: cesr::Digest256::default(),
            algorithm: ML_KEM_768.to_string(),
            encapsulation_key: ek,
        };
        pub2.derive_said().unwrap();

        assert_eq!(pub1.said, pub2.said);
        assert_ne!(pub1.said, cesr::Digest256::default());
    }

    #[test]
    fn different_keys_produce_different_saids() {
        let (ek_a, _dk_a) = cesr::generate_ml_kem_768().unwrap();
        let (ek_b, _dk_b) = cesr::generate_ml_kem_768().unwrap();

        let mut pub1 = EncapsulationKeyPublication {
            said: cesr::Digest256::default(),
            algorithm: ML_KEM_768.to_string(),
            encapsulation_key: ek_a,
        };
        pub1.derive_said().unwrap();

        let mut pub2 = EncapsulationKeyPublication {
            said: cesr::Digest256::default(),
            algorithm: ML_KEM_768.to_string(),
            encapsulation_key: ek_b,
        };
        pub2.derive_said().unwrap();

        assert_ne!(pub1.said, pub2.said);
    }
}
