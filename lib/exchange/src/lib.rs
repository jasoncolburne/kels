//! KELS Exchange Protocol
//!
//! Provides ESSR (Encrypt-Sender-Sign-Receiver) authenticated encryption and
//! IPEX-style credential exchange message types for the KELS ecosystem.

#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result)
)]

pub mod client;
pub mod error;
pub mod essr;
pub mod key_publication;
pub mod mail;
pub mod message;

pub use client::{MailClient, MailClientError};
pub use error::ExchangeError;
pub use essr::{EssrEnvelope, EssrInner, SignedEssrEnvelope, open, seal};
pub use key_publication::{ENCAP_KEY_KIND, EncapsulationKeyPublication, ML_KEM_768, ML_KEM_1024};
pub use mail::{
    AckRequest, FetchRequest, InboxRequest, InboxResponse, MAIL_GOSSIP_TOPIC, MailAnnouncement,
    MailMessage, RemoveRequest, ReplicateRequest, SendRequest, compute_blob_digest,
};
pub use message::{EXCHANGE_TOPIC, ExchangeKind, ExchangeMessage, ExchangePayload};
