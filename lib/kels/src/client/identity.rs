//! Client for the identity service

use base64::Engine;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::{Kel, KelsError};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityInfo {
    prefix: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AnchorRequest {
    said: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AnchorResponse {
    event_said: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignRequest {
    data: String, // JSON string to sign
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignResponse {
    pub signature: String,  // QB64-encoded signature
    pub public_key: String, // QB64-encoded public key
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcdhRequest {
    peer_public_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcdhResponse {
    shared_secret: String,
}

/// Identity service error response (simpler than the kels service's ErrorResponse).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityErrorResponse {
    error: String,
}

#[derive(Debug)]
pub struct IdentityClient {
    client: Client,
    base_url: String,
}

impl IdentityClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    async fn request_error(&self, response: reqwest::Response) -> KelsError {
        match response.json::<IdentityErrorResponse>().await {
            Ok(e) => KelsError::HardwareError(e.error),
            Err(e) => e.into(),
        }
    }

    async fn parse_response<T: serde::de::DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> Result<T, KelsError> {
        if !response.status().is_success() {
            return Err(self.request_error(response).await);
        }
        Ok(response.json().await?)
    }

    pub async fn get_prefix(&self) -> Result<String, KelsError> {
        let url = format!("{}/api/identity", self.base_url);
        let response = self.client.get(&url).send().await?;
        let info: IdentityInfo = self.parse_response(response).await?;
        Ok(info.prefix)
    }

    pub async fn get_kel(&self) -> Result<Kel, KelsError> {
        let url = format!("{}/api/identity/kel", self.base_url);
        let response = self.client.get(&url).send().await?;
        self.parse_response(response).await
    }

    pub async fn anchor(&self, said: &str) -> Result<String, KelsError> {
        let url = format!("{}/api/identity/anchor", self.base_url);

        let response = self
            .client
            .post(&url)
            .json(&AnchorRequest {
                said: said.to_string(),
            })
            .send()
            .await?;

        let resp: AnchorResponse = self.parse_response(response).await?;

        Ok(resp.event_said)
    }

    /// Sign a JSON string with the registry's identity key.
    /// Returns signature and public_key as QB64-encoded strings.
    pub async fn sign(&self, data: &str) -> Result<SignResponse, KelsError> {
        let url = format!("{}/api/identity/sign", self.base_url);

        let response = self
            .client
            .post(&url)
            .json(&SignRequest {
                data: data.to_string(),
            })
            .send()
            .await?;

        self.parse_response(response).await
    }

    /// Perform ECDH key agreement using the registry's current signing key.
    ///
    /// `peer_public_key` is compressed SEC1 (33 bytes). Returns the 32-byte shared secret.
    pub async fn ecdh(&self, peer_public_key: &[u8]) -> Result<Vec<u8>, KelsError> {
        let url = format!("{}/api/identity/ecdh", self.base_url);

        let request = EcdhRequest {
            peer_public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(peer_public_key),
        };

        let response = self.client.post(&url).json(&request).send().await?;

        let resp: EcdhResponse = self.parse_response(response).await?;

        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&resp.shared_secret)
            .map_err(|e| KelsError::CryptoError(format!("Invalid base64 shared secret: {}", e)))
    }
}
