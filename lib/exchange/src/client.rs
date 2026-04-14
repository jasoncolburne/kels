//! Mail service HTTP client.

use std::{collections::HashMap, time::Duration};

use base64::Engine;
use kels_core::{KeyProvider, PeerSigner, SignedRequest, sign_request};
use verifiable_storage::SelfAddressed;

use crate::{MailAnnouncement, MailMessage, RemoveRequest, ReplicateRequest};

/// Mail service API client.
#[derive(Clone)]
pub struct MailClient {
    base_url: String,
    client: reqwest::Client,
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
        let payload =
            ReplicateRequest::create(kels_core::crypto::generate_nonce(), message.clone())
                .map_err(|e| MailClientError::Signing(e.to_string()))?;

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
            let (status, text) = read_error_body(resp).await?;
            Err(MailClientError::Http(status, text))
        }
    }

    /// Remove a mail message by SAID (gossip-received removal).
    pub async fn remove(
        &self,
        said: &cesr::Digest256,
        signer: &dyn PeerSigner,
    ) -> Result<(), MailClientError> {
        let payload = RemoveRequest::create(kels_core::crypto::generate_nonce(), *said)
            .map_err(|e| MailClientError::Signing(e.to_string()))?;

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
            let (status, text) = read_error_body(resp).await?;
            Err(MailClientError::Http(status, text))
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
        prefix: &cesr::Digest256,
        recipient: &cesr::Digest256,
        envelope_bytes: &[u8],
        provider: &dyn KeyProvider,
    ) -> Result<(), MailClientError> {
        let send_request = crate::SendRequest::create(
            kels_core::crypto::generate_nonce(),
            *recipient,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(envelope_bytes),
        )
        .map_err(|e| MailClientError::Signing(e.to_string()))?;

        let signature = provider
            .sign(send_request.get_said().qb64b())
            .await
            .map_err(|e| MailClientError::Signing(e.to_string()))?;

        let signed_request = SignedRequest {
            payload: send_request,
            signatures: HashMap::from([(*prefix, signature)]),
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
            let (status, text) = read_error_body(resp).await?;
            Err(MailClientError::Http(status, text))
        }
    }

    /// Check inbox for messages.
    pub async fn inbox(
        &self,
        prefix: &cesr::Digest256,
        provider: &dyn KeyProvider,
    ) -> Result<crate::InboxResponse, MailClientError> {
        let inbox_request =
            crate::InboxRequest::create(kels_core::crypto::generate_nonce(), None, None)
                .map_err(|e| MailClientError::Signing(e.to_string()))?;

        let signature = provider
            .sign(inbox_request.get_said().qb64b())
            .await
            .map_err(|e| MailClientError::Signing(e.to_string()))?;

        let signed_request = SignedRequest {
            payload: inbox_request,
            signatures: HashMap::from([(*prefix, signature)]),
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
            let (status, text) = read_error_body(resp).await?;
            Err(MailClientError::Http(status, text))
        }
    }

    /// Fetch a mail blob by SAID.
    pub async fn fetch(
        &self,
        prefix: &cesr::Digest256,
        mail_said: &cesr::Digest256,
        provider: &dyn KeyProvider,
    ) -> Result<Vec<u8>, MailClientError> {
        let fetch_request =
            crate::FetchRequest::create(kels_core::crypto::generate_nonce(), *mail_said)
                .map_err(|e| MailClientError::Signing(e.to_string()))?;

        let signature = provider
            .sign(fetch_request.get_said().qb64b())
            .await
            .map_err(|e| MailClientError::Signing(e.to_string()))?;

        let signed_request = SignedRequest {
            payload: fetch_request,
            signatures: HashMap::from([(*prefix, signature)]),
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
            let (status, text) = read_error_body(resp).await?;
            Err(MailClientError::Http(status, text))
        }
    }

    /// Acknowledge (delete) messages by SAIDs.
    pub async fn ack(
        &self,
        prefix: &cesr::Digest256,
        saids: &[cesr::Digest256],
        provider: &dyn KeyProvider,
    ) -> Result<(), MailClientError> {
        let ack_request =
            crate::AckRequest::create(kels_core::crypto::generate_nonce(), saids.to_vec())
                .map_err(|e| MailClientError::Signing(e.to_string()))?;

        let signature = provider
            .sign(ack_request.get_said().qb64b())
            .await
            .map_err(|e| MailClientError::Signing(e.to_string()))?;

        let signed_request = SignedRequest {
            payload: ack_request,
            signatures: HashMap::from([(*prefix, signature)]),
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
            let (status, text) = read_error_body(resp).await?;
            Err(MailClientError::Http(status, text))
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

/// Read the response body text from an error response, preserving the HTTP
/// status code in the error if the body read itself fails.
pub(crate) async fn read_error_body(
    resp: reqwest::Response,
) -> Result<(reqwest::StatusCode, String), MailClientError> {
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| MailClientError::Http(status, format!("body unreadable: {e}")))?;
    Ok((status, text))
}
