//! Client for the identity service

use reqwest::Client;
use serde::{Deserialize, Serialize};
use verifiable_storage::SelfAddressed;

use crate::{KelsError, SignedKeyEventPage};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityInfo {
    pub prefix: cesr::Digest256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityStatus {
    pub initialized: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<cesr::Digest256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_said: Option<cesr::Digest256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_key_handle: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum RotateMode {
    #[default]
    Scheduled,
    Standard,
    Recovery,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum ManageKelOperation {
    Rotate {
        #[serde(default)]
        mode: RotateMode,
    },
    Recover,
    Contest,
    Decommission,
}

#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[serde(rename_all = "camelCase")]
pub struct ManageKelRequest {
    #[said]
    pub said: cesr::Digest256,
    #[created_at]
    pub created_at: verifiable_storage::StorageDatetime,
    pub prefix: cesr::Digest256,
    pub operation: ManageKelOperation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManageKelResponse {
    pub prefix: cesr::Digest256,
    pub said: cesr::Digest256,
    pub event_kind: crate::KeyEventKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation_number: Option<usize>,
    pub current_key_handle: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AnchorRequest {
    said: cesr::Digest256,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AnchorResponse {
    event_said: cesr::Digest256,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignRequest {
    data: String, // JSON string to sign
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignResponse {
    pub signature: cesr::Signature, // QB64-encoded signature
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
    pub fn new(base_url: &str) -> Result<Self, KelsError> {
        Ok(Self {
            client: Client::builder()
                .connect_timeout(std::time::Duration::from_secs(5))
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
            base_url: base_url.trim_end_matches('/').to_string(),
        })
    }

    /// The base URL of the identity service.
    pub fn base_url(&self) -> &str {
        &self.base_url
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

    pub async fn get_status(&self) -> Result<IdentityStatus, KelsError> {
        let url = format!("{}/api/v1/identity/status", self.base_url);
        let response = self.client.get(&url).send().await?;
        self.parse_response(response).await
    }

    pub async fn get_prefix(&self) -> Result<cesr::Digest256, KelsError> {
        let url = format!("{}/api/v1/identity", self.base_url);
        let response = self.client.get(&url).send().await?;
        let info: IdentityInfo = self.parse_response(response).await?;
        Ok(info.prefix)
    }

    pub async fn get_key_events(
        &self,
        since: Option<&cesr::Digest256>,
        limit: usize,
    ) -> Result<SignedKeyEventPage, KelsError> {
        let url = format!("{}/api/v1/identity/kel", self.base_url);
        let body = crate::IdentityKelPageRequest {
            since: since.copied(),
            limit: Some(limit),
        };
        let response = self.client.post(&url).json(&body).send().await?;
        self.parse_response(response).await
    }

    pub async fn anchor(&self, said: &cesr::Digest256) -> Result<cesr::Digest256, KelsError> {
        let url = format!("{}/api/v1/identity/anchor", self.base_url);

        let response = self
            .client
            .post(&url)
            .json(&AnchorRequest { said: *said })
            .send()
            .await?;

        let resp: AnchorResponse = self.parse_response(response).await?;

        Ok(resp.event_said)
    }

    /// Sign a JSON string with the registry's identity key.
    /// Returns signature as a QB64-encoded string.
    pub async fn sign(&self, data: &str) -> Result<SignResponse, KelsError> {
        let url = format!("{}/api/v1/identity/sign", self.base_url);

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

    /// Manage the identity KEL (rotate, recover, contest, decommission).
    /// Signs the request internally. The request must be created via `create()`.
    pub async fn manage_kel(
        &self,
        request: &ManageKelRequest,
    ) -> Result<ManageKelResponse, KelsError> {
        let prefix = self.get_prefix().await?;

        // as_ref() returns the QB64 &str — same bytes as qb64b() but the identity
        // sign endpoint takes &str, not &[u8].
        let sign_result = self.sign(request.get_said().as_ref()).await?;

        let signed = crate::SignedRequest {
            payload: request.clone(),
            signatures: std::collections::HashMap::from([(prefix, sign_result.signature)]),
        };

        let url = format!("{}/api/v1/identity/kel/manage", self.base_url);
        let response = self.client.post(&url).json(&signed).send().await?;
        self.parse_response(response).await
    }
}
