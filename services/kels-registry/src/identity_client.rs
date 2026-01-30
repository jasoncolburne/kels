//! Client for the identity service

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
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ErrorResponse {
    error: String,
}

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
        match response.json::<ErrorResponse>().await {
            Ok(e) => KelsError::ServerError(e.error),
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
}
