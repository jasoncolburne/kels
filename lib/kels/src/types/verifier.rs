//! Streaming incremental KEL verifier and sync abstraction.
//!
//! `KelVerifier` verifies events page by page without holding the full chain in memory.
//! Tracks evolving cryptographic state as it walks forward through a linear chain.
//!
//! `PagedKelSource` / `PagedKelSink` / `sync_and_verify` provide a generic pattern
//! for streaming events from a source through a verifier into a destination.

use async_trait::async_trait;
use cesr::{Digest, Matter, PublicKey, Signature};
use verifiable_storage::Chained;

use super::events::SignedKeyEvent;
use crate::error::KelsError;

/// Compute the rotation hash (Blake3-256 of the public key qb64 string).
fn compute_rotation_hash(public_key: &str) -> String {
    Digest::blake3_256(public_key.as_bytes()).qb64()
}

/// Stateful forward-walking chain verifier.
///
/// Verifies events incrementally, page by page. Tracks evolving cryptographic state
/// so the full chain never needs to be in memory. Single-branch only — the caller
/// always feeds it a linear chain.
pub struct KelVerifier {
    prefix: String,
    last_serial: Option<u64>,
    last_said: Option<String>,
    current_public_key: Option<String>,
    pending_rotation_hash: Option<String>,
    pending_recovery_hash: Option<String>,
}

impl KelVerifier {
    /// Start from inception. Used for full verification (e.g., streaming a peer's KEL).
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
            last_serial: None,
            last_said: None,
            current_public_key: None,
            pending_rotation_hash: None,
            pending_recovery_hash: None,
        }
    }

    /// Resume from known DB state. Used by the submit handler fast path.
    ///
    /// `tip_serial` and `tip_said` come from `MergeContext.tips[0]`.
    /// `last_establishment` provides the current cryptographic state.
    pub fn from_merge_context(
        prefix: impl Into<String>,
        tip_serial: u64,
        tip_said: impl Into<String>,
        last_establishment: &SignedKeyEvent,
    ) -> Self {
        Self {
            prefix: prefix.into(),
            last_serial: Some(tip_serial),
            last_said: Some(tip_said.into()),
            current_public_key: last_establishment.event.public_key.clone(),
            pending_rotation_hash: last_establishment.event.rotation_hash.clone(),
            pending_recovery_hash: last_establishment.event.recovery_hash.clone(),
        }
    }

    /// The current public key (qb64) after the last verified establishment event.
    pub fn current_public_key(&self) -> Option<&str> {
        self.current_public_key.as_deref()
    }

    /// Verify a page of events against the running state.
    /// Updates internal state after each event.
    /// Call repeatedly with successive pages to verify an entire chain.
    pub fn verify_page(&mut self, events: &[SignedKeyEvent]) -> Result<(), KelsError> {
        for signed_event in events {
            self.verify_event(signed_event)?;
        }
        Ok(())
    }

    fn verify_event(&mut self, signed_event: &SignedKeyEvent) -> Result<(), KelsError> {
        let event = &signed_event.event;

        // 1. SAID integrity
        event.verify().map_err(|e| {
            KelsError::InvalidKel(format!(
                "Event {} SAID verification failed: {}",
                &event.said, e
            ))
        })?;

        // 2. Prefix matches
        if event.prefix != self.prefix {
            return Err(KelsError::InvalidKel(format!(
                "Event {} has different prefix",
                &event.said,
            )));
        }

        // 3. Serial and previous-pointer continuity
        match self.last_serial {
            None => {
                // First event must be inception at serial 0
                if event.serial != 0 {
                    return Err(KelsError::InvalidSerial(format!(
                        "First event {} has serial {} but expected 0",
                        event.said, event.serial
                    )));
                }
                if event.previous.is_some() {
                    return Err(KelsError::InvalidKel(format!(
                        "Inception event {} has previous pointer",
                        event.said,
                    )));
                }
                if !event.kind.is_inception() {
                    return Err(KelsError::InvalidKel(format!(
                        "First event {} is not an inception event",
                        event.said,
                    )));
                }
            }
            Some(last_serial) => {
                if event.serial != last_serial + 1 {
                    return Err(KelsError::InvalidSerial(format!(
                        "Event {} has serial {} but expected {}",
                        event.said,
                        event.serial,
                        last_serial + 1,
                    )));
                }
                let expected_previous = self.last_said.as_deref().ok_or_else(|| {
                    KelsError::InvalidKel("Verifier state missing last_said".to_string())
                })?;
                match &event.previous {
                    Some(prev) if prev == expected_previous => {}
                    Some(prev) => {
                        return Err(KelsError::InvalidKel(format!(
                            "Event {} previous {} does not match expected {}",
                            event.said, prev, expected_previous,
                        )));
                    }
                    None => {
                        return Err(KelsError::InvalidKel(format!(
                            "Non-inception event {} has no previous pointer",
                            event.said,
                        )));
                    }
                }
            }
        }

        // 4. Structure validation
        event.validate_structure().map_err(KelsError::InvalidKel)?;

        // 5. Cryptographic verification
        if event.is_establishment() {
            let qb64 = event.public_key.as_ref().ok_or_else(|| {
                KelsError::InvalidKel("Establishment event missing public key".to_string())
            })?;

            // 5a. Verify forward commitment: pending_rotation_hash matches this event's public_key
            if let Some(ref rotation_hash) = self.pending_rotation_hash {
                let computed = compute_rotation_hash(qb64);
                if computed != *rotation_hash {
                    return Err(KelsError::InvalidKel(
                        "Public key does not match previous rotation hash".to_string(),
                    ));
                }
            }

            // 5b. Verify recovery key revelation (for dual-sig events)
            if event.reveals_recovery_key() {
                let recovery_key = event.recovery_key.as_ref().ok_or_else(|| {
                    KelsError::InvalidKel(format!(
                        "Recovery event {} has no recovery_key field",
                        &event.said,
                    ))
                })?;

                if let Some(ref recovery_hash) = self.pending_recovery_hash {
                    let computed = compute_rotation_hash(recovery_key);
                    if computed != *recovery_hash {
                        return Err(KelsError::InvalidKel(
                            "Recovery key does not match previous recovery hash".to_string(),
                        ));
                    }
                }
            }

            // 5c. Verify signature with this event's own public key
            let public_key = PublicKey::from_qb64(qb64)?;
            Self::verify_signatures(signed_event, &public_key)?;

            // 5d. Update cryptographic state
            self.current_public_key = Some(qb64.clone());
            self.pending_rotation_hash = event.rotation_hash.clone();
            self.pending_recovery_hash = event.recovery_hash.clone();
        } else {
            // Non-establishment event: verify signature with current public key
            let qb64 = self.current_public_key.as_ref().ok_or_else(|| {
                KelsError::InvalidKel(format!(
                    "No public key available to verify event {}",
                    &event.said,
                ))
            })?;
            let public_key = PublicKey::from_qb64(qb64)?;
            Self::verify_signatures(signed_event, &public_key)?;
        }

        // 6. Update state
        self.last_serial = Some(event.serial);
        self.last_said = Some(event.said.clone());

        Ok(())
    }

    fn verify_signatures(
        signed_event: &SignedKeyEvent,
        public_key: &PublicKey,
    ) -> Result<(), KelsError> {
        let event = &signed_event.event;
        let expected_qb64 = public_key.qb64();

        let sig = signed_event.signature(&expected_qb64).ok_or_else(|| {
            KelsError::InvalidKel(format!(
                "Event {} has no signature for expected key",
                &event.said,
            ))
        })?;

        let signature = Signature::from_qb64(&sig.signature)?;
        public_key
            .verify(event.said.as_bytes(), &signature)
            .map_err(|_| {
                KelsError::InvalidKel(format!(
                    "Event {} signature verification failed",
                    &event.said,
                ))
            })?;

        // Dual-signature requirement for recovery events
        if event.reveals_recovery_key() {
            let recovery_key_qb64 = event.recovery_key.as_ref().ok_or_else(|| {
                KelsError::InvalidKel(format!(
                    "Recovery event {} has no recovery_key field",
                    &event.said,
                ))
            })?;

            let recovery_sig = signed_event.signature(recovery_key_qb64).ok_or_else(|| {
                KelsError::InvalidKel(format!(
                    "Recovery event {} has no signature for recovery key",
                    &event.said,
                ))
            })?;

            let recovery_public_key = PublicKey::from_qb64(recovery_key_qb64)?;
            let recovery_signature = Signature::from_qb64(&recovery_sig.signature)?;
            recovery_public_key
                .verify(event.said.as_bytes(), &recovery_signature)
                .map_err(|_| {
                    KelsError::InvalidKel(format!(
                        "Recovery event {} recovery signature verification failed",
                        &event.said,
                    ))
                })?;
        }

        Ok(())
    }
}

// ==================== Sync Abstraction ====================

/// Source of paginated signed key events (e.g., HTTP client, local DB).
#[async_trait]
pub trait PagedKelSource: Send + Sync {
    async fn fetch_page(
        &self,
        prefix: &str,
        since: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<SignedKeyEvent>, bool), KelsError>;
}

/// Destination for signed key events (e.g., local DB).
#[async_trait]
pub trait PagedKelSink: Send + Sync {
    async fn store_page(&self, prefix: &str, events: &[SignedKeyEvent]) -> Result<(), KelsError>;
}

/// Stream pages from source → verify with KelVerifier → store in sink.
///
/// Loops: fetch page → `verifier.verify_page()` → `sink.store_page()` → advance cursor.
/// Stops when `!has_more` or `max_pages` reached.
pub async fn sync_and_verify(
    prefix: &str,
    source: &impl PagedKelSource,
    sink: &impl PagedKelSink,
    verifier: &mut KelVerifier,
    page_size: usize,
    max_pages: usize,
) -> Result<(), KelsError> {
    let mut since: Option<String> = None;

    for _ in 0..max_pages {
        let (events, has_more) = source
            .fetch_page(prefix, since.as_deref(), page_size)
            .await?;

        if events.is_empty() {
            break;
        }

        verifier.verify_page(&events)?;

        let last_said = events.last().map(|e| e.event.said.clone());

        sink.store_page(prefix, &events).await?;

        if !has_more {
            break;
        }

        since = last_said;
    }

    Ok(())
}
