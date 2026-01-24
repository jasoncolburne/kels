//! Client for the identity service
//!
//! Used by kels-registry to fetch the registry's KEL and anchor SAIDs.

use kels::{Kel, KelsError};
use reqwest::Client;
use serde::{Deserialize, Serialize};

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
    event_version: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ErrorResponse {
    error: String,
}

/// Client for interacting with the identity service.
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

    /// Get the registry's prefix from the identity service.
    pub async fn get_prefix(&self) -> Result<String, KelsError> {
        let url = format!("{}/api/identity", self.base_url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| KelsError::ServerError(format!("Identity service request failed: {}", e)))?;

        if !response.status().is_success() {
            let error: ErrorResponse = response
                .json()
                .await
                .map_err(|e| KelsError::ServerError(format!("Failed to parse error: {}", e)))?;
            return Err(KelsError::ServerError(error.error));
        }

        let info: IdentityInfo = response
            .json()
            .await
            .map_err(|e| KelsError::ServerError(format!("Failed to parse response: {}", e)))?;

        Ok(info.prefix)
    }

    /// Get the registry's full KEL from the identity service.
    pub async fn get_kel(&self) -> Result<Kel, KelsError> {
        let url = format!("{}/api/identity/kel", self.base_url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| KelsError::ServerError(format!("Identity service request failed: {}", e)))?;

        if !response.status().is_success() {
            let error: ErrorResponse = response
                .json()
                .await
                .map_err(|e| KelsError::ServerError(format!("Failed to parse error: {}", e)))?;
            return Err(KelsError::ServerError(error.error));
        }

        let kel: Kel = response
            .json()
            .await
            .map_err(|e| KelsError::ServerError(format!("Failed to parse KEL: {}", e)))?;

        Ok(kel)
    }

    /// Anchor a SAID in the registry's KEL via the identity service.
    pub async fn anchor(&self, said: &str) -> Result<(String, u64), KelsError> {
        let url = format!("{}/api/identity/anchor", self.base_url);

        let request = AnchorRequest {
            said: said.to_string(),
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| KelsError::ServerError(format!("Identity service request failed: {}", e)))?;

        if !response.status().is_success() {
            let error: ErrorResponse = response
                .json()
                .await
                .map_err(|e| KelsError::ServerError(format!("Failed to parse error: {}", e)))?;
            return Err(KelsError::ServerError(error.error));
        }

        let resp: AnchorResponse = response
            .json()
            .await
            .map_err(|e| KelsError::ServerError(format!("Failed to parse response: {}", e)))?;

        Ok((resp.event_said, resp.event_version))
    }
}
