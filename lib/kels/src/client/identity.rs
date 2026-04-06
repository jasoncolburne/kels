//! Client for the identity service

use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::{KelsError, SignedKeyEventPage};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityInfo {
    pub prefix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityStatus {
    pub initialized: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_said: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManageKelRequest {
    pub prefix: String,
    pub operation: ManageKelOperation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManageKelResponse {
    pub prefix: String,
    pub said: String,
    pub event_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation_number: Option<usize>,
    pub current_key_handle: String,
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
    pub signature: String, // QB64-encoded signature
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

    pub async fn get_prefix(&self) -> Result<String, KelsError> {
        let url = format!("{}/api/v1/identity", self.base_url);
        let response = self.client.get(&url).send().await?;
        let info: IdentityInfo = self.parse_response(response).await?;
        Ok(info.prefix)
    }

    pub async fn get_key_events(
        &self,
        since: Option<&str>,
        limit: usize,
    ) -> Result<SignedKeyEventPage, KelsError> {
        let mut url = format!("{}/api/v1/identity/kel?limit={}", self.base_url, limit);
        if let Some(since) = since {
            url.push_str(&format!("&since={}", since));
        }
        let response = self.client.get(&url).send().await?;
        self.parse_response(response).await
    }

    pub async fn anchor(&self, said: &str) -> Result<String, KelsError> {
        let url = format!("{}/api/v1/identity/anchor", self.base_url);

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
    /// Signs the request internally.
    pub async fn manage_kel(
        &self,
        request: &ManageKelRequest,
    ) -> Result<ManageKelResponse, KelsError> {
        let prefix = self.get_prefix().await?;

        let payload_json = serde_json::to_string(request)
            .map_err(|e| KelsError::SigningFailed(format!("Failed to serialize request: {}", e)))?;
        let sign_result = self.sign(&payload_json).await?;

        let signed = crate::SignedRequest {
            payload: request.clone(),
            prefix,
            signature: sign_result.signature,
        };

        let url = format!("{}/api/v1/identity/kel/manage", self.base_url);
        let response = self.client.post(&url).json(&signed).send().await?;
        self.parse_response(response).await
    }
}
