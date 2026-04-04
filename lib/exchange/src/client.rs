//! Mail service HTTP client.

use std::time::Duration;

use kels_core::{PeerSigner, sign_request};

use crate::{MailAnnouncement, MailMessage};

/// Mail service API client.
#[derive(Clone)]
pub struct MailClient {
    base_url: String,
    client: reqwest::Client,
}

/// Replicate request payload.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicateRequest {
    pub timestamp: i64,
    pub nonce: String,
    pub message: MailMessage,
}

/// Remove request payload.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveRequest {
    pub timestamp: i64,
    pub nonce: String,
    pub said: String,
}

impl MailClient {
    pub fn new(base_url: &str) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        })
    }

    /// Replicate a mail message (gossip-received metadata).
    pub async fn replicate(
        &self,
        message: &MailMessage,
        signer: &dyn PeerSigner,
    ) -> Result<(), MailClientError> {
        let payload = ReplicateRequest {
            timestamp: chrono::Utc::now().timestamp(),
            nonce: kels_core::crypto::generate_nonce(),
            message: message.clone(),
        };
        let signed = sign_request(signer, &payload)
            .await
            .map_err(|e| MailClientError::Signing(e.to_string()))?;

        let resp = self
            .client
            .post(format!("{}/api/v1/mail/replicate", self.base_url))
            .json(&signed)
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(MailClientError::Http(
                resp.status(),
                resp.text().await.unwrap_or_default(),
            ))
        }
    }

    /// Remove a mail message by SAID (gossip-received removal).
    pub async fn remove(&self, said: &str, signer: &dyn PeerSigner) -> Result<(), MailClientError> {
        let payload = RemoveRequest {
            timestamp: chrono::Utc::now().timestamp(),
            nonce: kels_core::crypto::generate_nonce(),
            said: said.to_string(),
        };
        let signed = sign_request(signer, &payload)
            .await
            .map_err(|e| MailClientError::Signing(e.to_string()))?;

        let resp = self
            .client
            .post(format!("{}/api/v1/mail/remove", self.base_url))
            .json(&signed)
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(MailClientError::Http(
                resp.status(),
                resp.text().await.unwrap_or_default(),
            ))
        }
    }

    /// Process a mail announcement (replicate or remove).
    pub async fn handle_announcement(
        &self,
        announcement: &MailAnnouncement,
        signer: &dyn PeerSigner,
    ) -> Result<(), MailClientError> {
        match announcement {
            MailAnnouncement::Message(message) => self.replicate(message, signer).await,
            MailAnnouncement::Removal { said } => self.remove(said, signer).await,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MailClientError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("HTTP {0}: {1}")]
    Http(reqwest::StatusCode, String),
    #[error("Signing failed: {0}")]
    Signing(String),
}
