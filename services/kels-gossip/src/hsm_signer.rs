//! HSM-backed signer for libp2p identity
//!
//! Implements the ExternalSigner trait to allow libp2p to use HSM-stored keys.

use base64::{engine::general_purpose::URL_SAFE as BASE64, Engine as _};
use cesr::{Matter, PublicKey as CesrPublicKey, Signature as CesrSignature};
use libp2p_identity::ExternalSigner;
use p256::{ecdsa::DerSignature, elliptic_curve::sec1::ToEncodedPoint, PublicKey as P256PublicKey};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tokio::runtime::Handle;

#[derive(Error, Debug)]
pub enum HsmSignerError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("HSM error: {0}")]
    Hsm(String),
    #[error("CESR error: {0}")]
    Cesr(#[from] cesr::CesrError),
    #[error("Key error: {0}")]
    Key(String),
    #[error("Signature error: {0}")]
    Signature(String),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GenerateKeyRequest {
    label: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GenerateKeyResponse {
    #[allow(dead_code)]
    label: String,
    public_key: String, // CESR qb64
    #[allow(dead_code)]
    created: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SignRequest {
    data: String, // base64-encoded
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignResponse {
    signature: String, // CESR qb64
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: String,
}

/// HSM-backed signer that implements ExternalSigner for libp2p
pub struct HsmSigner {
    hsm_url: String,
    key_label: String,
    /// Cached uncompressed public key (65 bytes, SEC1 format)
    public_key_uncompressed: Vec<u8>,
    client: Client,
}

impl HsmSigner {
    /// Create a new HSM signer, fetching or creating the key
    pub async fn new(hsm_url: String, key_label: String) -> Result<Self, HsmSignerError> {
        let client = Client::new();

        // Get or create the key
        let public_key_cesr = Self::get_or_create_key(&client, &hsm_url, &key_label).await?;

        // Decompress the public key for libp2p (needs uncompressed SEC1 format)
        let public_key_uncompressed = Self::decompress_public_key(&public_key_cesr)?;

        Ok(Self {
            hsm_url,
            key_label,
            public_key_uncompressed,
            client,
        })
    }

    async fn get_or_create_key(
        client: &Client,
        hsm_url: &str,
        label: &str,
    ) -> Result<CesrPublicKey, HsmSignerError> {
        let url = format!("{}/api/hsm/keys", hsm_url);
        let request = GenerateKeyRequest {
            label: label.to_string(),
        };

        let response = client.post(&url).json(&request).send().await?;

        if !response.status().is_success() {
            let error: ErrorResponse = response.json().await?;
            return Err(HsmSignerError::Hsm(error.error));
        }

        let result: GenerateKeyResponse = response.json().await?;
        let public_key = CesrPublicKey::from_qb64(&result.public_key)?;

        Ok(public_key)
    }

    /// Decompress a CESR public key to uncompressed SEC1 format (65 bytes)
    fn decompress_public_key(cesr_key: &CesrPublicKey) -> Result<Vec<u8>, HsmSignerError> {
        let compressed = cesr_key.raw();
        if compressed.len() != 33 {
            return Err(HsmSignerError::Key(format!(
                "Expected 33-byte compressed key, got {} bytes",
                compressed.len()
            )));
        }

        // Parse as p256 compressed point and convert to uncompressed
        let public_key = P256PublicKey::from_sec1_bytes(compressed)
            .map_err(|e| HsmSignerError::Key(format!("Failed to parse public key: {}", e)))?;

        let uncompressed = public_key.to_encoded_point(false);
        Ok(uncompressed.as_bytes().to_vec())
    }

    /// Sign data using the HSM (async version)
    async fn sign_async(&self, data: &[u8]) -> Result<Vec<u8>, HsmSignerError> {
        let url = format!("{}/api/hsm/keys/{}/sign", self.hsm_url, self.key_label);
        let request = SignRequest {
            data: BASE64.encode(data),
        };

        let response = self.client.post(&url).json(&request).send().await?;

        if !response.status().is_success() {
            let error: ErrorResponse = response.json().await?;
            return Err(HsmSignerError::Hsm(error.error));
        }

        let result: SignResponse = response.json().await?;
        let signature = CesrSignature::from_qb64(&result.signature)?;

        // Convert raw signature (r||s, 64 bytes) to DER format
        let der_signature = Self::raw_to_der(signature.raw())?;

        Ok(der_signature)
    }

    /// Convert raw ECDSA signature (r||s, 64 bytes) to DER format
    fn raw_to_der(raw: &[u8]) -> Result<Vec<u8>, HsmSignerError> {
        if raw.len() != 64 {
            return Err(HsmSignerError::Signature(format!(
                "Expected 64-byte raw signature, got {} bytes",
                raw.len()
            )));
        }

        // Split into r and s components
        let r_bytes: [u8; 32] = raw[..32]
            .try_into()
            .map_err(|_| HsmSignerError::Signature("Failed to convert r component".into()))?;
        let s_bytes: [u8; 32] = raw[32..]
            .try_into()
            .map_err(|_| HsmSignerError::Signature("Failed to convert s component".into()))?;

        // Create p256 signature from components and convert to DER
        let signature = p256::ecdsa::Signature::from_scalars(r_bytes, s_bytes).map_err(|e| {
            HsmSignerError::Signature(format!("Invalid signature components: {}", e))
        })?;

        let der: DerSignature = signature.to_der();
        Ok(der.as_bytes().to_vec())
    }
}

impl ExternalSigner for HsmSigner {
    fn sign_blocking(&self, data: &[u8]) -> Result<Vec<u8>, libp2p_identity::SigningError> {
        // Block on the async sign operation
        tokio::task::block_in_place(|| {
            Handle::current()
                .block_on(self.sign_async(data))
                .map_err(|e| libp2p_identity::SigningError::from_message(e.to_string()))
        })
    }

    fn public_key_bytes(&self) -> &[u8] {
        &self.public_key_uncompressed
    }
}

/// Create an HSM-backed libp2p keypair
pub async fn create_hsm_keypair(
    hsm_url: &str,
    node_id: &str,
) -> Result<libp2p_identity::Keypair, HsmSignerError> {
    let key_label = format!("kels-gossip-{}", node_id);
    let signer = HsmSigner::new(hsm_url.to_string(), key_label).await?;
    let signer_arc: Arc<dyn ExternalSigner> = Arc::new(signer);

    libp2p_identity::Keypair::from_external(signer_arc)
        .map_err(|e| HsmSignerError::Key(format!("Failed to create keypair: {}", e)))
}

/// HSM sign response containing signature and public key
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HsmSignResponse {
    signature: String,  // CESR qb64
    public_key: String, // CESR qb64
}

/// Registry signer implementation using HSM.
///
/// This wraps the HSM to provide signing for registry API requests.
/// Each sign call returns the signature, public key, and derived peer ID.
pub struct HsmRegistrySigner {
    hsm_url: String,
    key_label: String,
    client: Client,
}

impl HsmRegistrySigner {
    /// Create a new HSM registry signer
    pub fn new(hsm_url: String, node_id: &str) -> Self {
        let key_label = format!("kels-gossip-{}", node_id);
        Self {
            hsm_url,
            key_label,
            client: Client::new(),
        }
    }

    /// Sign data and return signature, public key, and peer ID
    async fn sign_async(&self, data: &[u8]) -> Result<kels::SignResult, HsmSignerError> {
        let url = format!("{}/api/hsm/keys/{}/sign", self.hsm_url, self.key_label);
        let request = SignRequest {
            data: BASE64.encode(data),
        };

        let response = self.client.post(&url).json(&request).send().await?;

        if !response.status().is_success() {
            let error: ErrorResponse = response.json().await?;
            return Err(HsmSignerError::Hsm(error.error));
        }

        let result: HsmSignResponse = response.json().await?;

        // Parse the public key and derive peer ID
        let cesr_pubkey = CesrPublicKey::from_qb64(&result.public_key)?;
        let uncompressed = HsmSigner::decompress_public_key(&cesr_pubkey)?;
        let libp2p_pubkey = libp2p_identity::ecdsa::PublicKey::try_from_bytes(&uncompressed)
            .map_err(|e| HsmSignerError::Key(format!("Failed to create libp2p key: {}", e)))?;
        let libp2p_keypair_pubkey = libp2p_identity::PublicKey::from(libp2p_pubkey);
        let peer_id = libp2p_keypair_pubkey.to_peer_id().to_string();

        Ok(kels::SignResult {
            signature: result.signature,
            public_key: result.public_key,
            peer_id,
        })
    }
}

#[async_trait::async_trait]
impl kels::RegistrySigner for HsmRegistrySigner {
    async fn sign(&self, data: &[u8]) -> Result<kels::SignResult, kels::KelsError> {
        self.sign_async(data)
            .await
            .map_err(|e| kels::KelsError::SigningFailed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_to_der() {
        // Test with a known signature (all 1s to avoid zero scalar issues)
        let mut raw = vec![1u8; 64];
        // Make sure the values are valid scalars (less than curve order)
        raw[0] = 0x01;
        raw[32] = 0x01;
        let result = HsmSigner::raw_to_der(&raw);
        assert!(result.is_ok());
        let der = result.unwrap();
        // DER signatures start with 0x30 (SEQUENCE)
        assert_eq!(der[0], 0x30);
    }

    #[test]
    fn test_raw_to_der_wrong_length_short() {
        let raw = vec![1u8; 32]; // Too short
        let result = HsmSigner::raw_to_der(&raw);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, HsmSignerError::Signature(_)));
        assert!(err.to_string().contains("64-byte"));
    }

    #[test]
    fn test_raw_to_der_wrong_length_long() {
        let raw = vec![1u8; 128]; // Too long
        let result = HsmSigner::raw_to_der(&raw);
        assert!(result.is_err());
    }

    #[test]
    fn test_raw_to_der_empty() {
        let result = HsmSigner::raw_to_der(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decompress_public_key_valid() {
        // Use a valid compressed public key
        // Generate using p256
        use p256::ecdsa::SigningKey;

        let seed: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let signing_key = SigningKey::from_slice(&seed).unwrap();
        let verifying_key = signing_key.verifying_key();
        let compressed = verifying_key.to_encoded_point(true);

        let cesr_key =
            CesrPublicKey::from_raw(cesr::KeyCode::Secp256r1, compressed.as_bytes().to_vec())
                .unwrap();

        let result = HsmSigner::decompress_public_key(&cesr_key);
        assert!(result.is_ok());
        let uncompressed = result.unwrap();
        // Uncompressed SEC1 format is 65 bytes (0x04 || x || y)
        assert_eq!(uncompressed.len(), 65);
        assert_eq!(uncompressed[0], 0x04);
    }

    // ==================== HsmSignerError Display Tests ====================

    #[test]
    fn test_hsm_signer_error_hsm_display() {
        let err = HsmSignerError::Hsm("HSM unavailable".to_string());
        assert_eq!(err.to_string(), "HSM error: HSM unavailable");
    }

    #[test]
    fn test_hsm_signer_error_key_display() {
        let err = HsmSignerError::Key("Invalid key format".to_string());
        assert_eq!(err.to_string(), "Key error: Invalid key format");
    }

    #[test]
    fn test_hsm_signer_error_signature_display() {
        let err = HsmSignerError::Signature("Bad signature".to_string());
        assert_eq!(err.to_string(), "Signature error: Bad signature");
    }

    // ==================== HsmRegistrySigner Tests ====================

    #[test]
    fn test_hsm_registry_signer_new() {
        let signer = HsmRegistrySigner::new("http://localhost:8080".to_string(), "node-1");
        assert_eq!(signer.hsm_url, "http://localhost:8080");
        assert_eq!(signer.key_label, "kels-gossip-node-1");
    }

    #[test]
    fn test_hsm_registry_signer_key_label_format() {
        let signer = HsmRegistrySigner::new("http://hsm".to_string(), "my-node-id");
        assert!(signer.key_label.starts_with("kels-gossip-"));
        assert!(signer.key_label.ends_with("my-node-id"));
    }
}
