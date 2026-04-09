//! Mail service HTTP client.

use std::time::Duration;

use base64::Engine;
use kels_core::{KeyProvider, PeerSigner, SignedRequest, sign_request};

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
    pub said: cesr::Digest,
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
            nonce: kels_core::crypto::generate_nonce().to_string(),
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
            Err(MailClientError::Http(resp.status(), resp.text().await?))
        }
    }

    /// Remove a mail message by SAID (gossip-received removal).
    pub async fn remove(
        &self,
        said: &cesr::Digest,
        signer: &dyn PeerSigner,
    ) -> Result<(), MailClientError> {
        let payload = RemoveRequest {
            timestamp: chrono::Utc::now().timestamp(),
            nonce: kels_core::crypto::generate_nonce().to_string(),
            said: *said,
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
            Err(MailClientError::Http(resp.status(), resp.text().await?))
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

    /// Send an ESSR-encrypted envelope to a recipient.
    pub async fn send(
        &self,
        prefix: &cesr::Digest,
        recipient: &cesr::Digest,
        envelope_bytes: &[u8],
        provider: &dyn KeyProvider,
    ) -> Result<(), MailClientError> {
        let send_request = crate::SendRequest {
            timestamp: chrono::Utc::now().timestamp(),
            nonce: kels_core::crypto::generate_nonce().to_string(),
            recipient_kel_prefix: *recipient,
            blob: base64::engine::general_purpose::STANDARD.encode(envelope_bytes),
        };

        let request_json = serde_json::to_vec(&send_request)
            .map_err(|e| MailClientError::Signing(e.to_string()))?;
        let signature = provider
            .sign(&request_json)
            .await
            .map_err(|e| MailClientError::Signing(e.to_string()))?;

        let signed_request = SignedRequest {
            payload: send_request,
            prefix: *prefix,
            signature,
        };

        let resp = self
            .client
            .post(format!("{}/api/v1/mail/send", self.base_url))
            .json(&signed_request)
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(MailClientError::Http(resp.status(), resp.text().await?))
        }
    }

    /// Check inbox for messages.
    pub async fn inbox(
        &self,
        prefix: &cesr::Digest,
        provider: &dyn KeyProvider,
    ) -> Result<crate::InboxResponse, MailClientError> {
        let inbox_request = crate::InboxRequest {
            timestamp: chrono::Utc::now().timestamp(),
            nonce: kels_core::crypto::generate_nonce().to_string(),
            limit: None,
            offset: None,
        };

        let request_json = serde_json::to_vec(&inbox_request)
            .map_err(|e| MailClientError::Signing(e.to_string()))?;
        let signature = provider
            .sign(&request_json)
            .await
            .map_err(|e| MailClientError::Signing(e.to_string()))?;

        let signed_request = SignedRequest {
            payload: inbox_request,
            prefix: *prefix,
            signature,
        };

        let resp = self
            .client
            .post(format!("{}/api/v1/mail/inbox", self.base_url))
            .json(&signed_request)
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            Err(MailClientError::Http(resp.status(), resp.text().await?))
        }
    }

    /// Fetch a mail blob by SAID.
    pub async fn fetch(
        &self,
        prefix: &cesr::Digest,
        mail_said: &cesr::Digest,
        provider: &dyn KeyProvider,
    ) -> Result<Vec<u8>, MailClientError> {
        let fetch_request = crate::FetchRequest {
            timestamp: chrono::Utc::now().timestamp(),
            nonce: kels_core::crypto::generate_nonce().to_string(),
            mail_said: *mail_said,
        };

        let request_json = serde_json::to_vec(&fetch_request)
            .map_err(|e| MailClientError::Signing(e.to_string()))?;
        let signature = provider
            .sign(&request_json)
            .await
            .map_err(|e| MailClientError::Signing(e.to_string()))?;

        let signed_request = SignedRequest {
            payload: fetch_request,
            prefix: *prefix,
            signature,
        };

        let resp = self
            .client
            .post(format!("{}/api/v1/mail/fetch", self.base_url))
            .json(&signed_request)
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.bytes().await?.to_vec())
        } else {
            Err(MailClientError::Http(resp.status(), resp.text().await?))
        }
    }

    /// Acknowledge (delete) messages by SAIDs.
    pub async fn ack(
        &self,
        prefix: &cesr::Digest,
        saids: &[cesr::Digest],
        provider: &dyn KeyProvider,
    ) -> Result<(), MailClientError> {
        let ack_request = crate::AckRequest {
            timestamp: chrono::Utc::now().timestamp(),
            nonce: kels_core::crypto::generate_nonce().to_string(),
            saids: saids.to_vec(),
        };

        let request_json = serde_json::to_vec(&ack_request)
            .map_err(|e| MailClientError::Signing(e.to_string()))?;
        let signature = provider
            .sign(&request_json)
            .await
            .map_err(|e| MailClientError::Signing(e.to_string()))?;

        let signed_request = SignedRequest {
            payload: ack_request,
            prefix: *prefix,
            signature,
        };

        let resp = self
            .client
            .post(format!("{}/api/v1/mail/ack", self.base_url))
            .json(&signed_request)
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(MailClientError::Http(resp.status(), resp.text().await?))
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
