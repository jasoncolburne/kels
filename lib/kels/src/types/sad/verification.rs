//! SAD Event Log verification (structural + policy authorization).
//!
//! **Round-12 Gap 1 stub.** The pre-round-12 verifier was tightly coupled to
//! the dropped `write_policy` / `governance_policy` SE fields and to `Est` /
//! `Evl` semantics that no longer exist. Gap 2 rebuilds this file end-to-end
//! per `~/.claude-plan-round12.md` (new `SadBranchTip` shape with `identity` +
//! `last_identity_event`, IelResolver-driven authorization, content-based
//! terminal flags, soft/hard mapping).
//!
//! Until then, this module exposes the same public API surface as before
//! (`SelVerifier::new` / `resume` / `verify_page` / `finish` /
//! `is_divergent`) so downstream call sites (handlers, builder, sync helpers)
//! keep compiling. The verifier's internal logic is reduced to a structural
//! pass-through that produces a permissive `SelVerification`. Test coverage
//! is intentionally absent here — Gap 2 lands the round-12 test taxonomy.
//!
//! **Do not rely on this stub's semantics for security.** It is not a
//! correctness boundary; it exists only to keep the workspace compiling
//! between Gap 1 and Gap 2.

use std::{collections::HashMap, sync::Arc};

use verifiable_storage::SelfAddressed;

use super::event::{SadBranchTip, SadEvent, SelVerification};
use crate::{KelsError, types::PolicyChecker};

/// Streaming structural verifier — Gap-1 stub. See module docs.
pub struct SelVerifier {
    prefix: Option<cesr::Digest256>,
    topic: Option<String>,
    branches: HashMap<cesr::Digest256, SadBranchTip>,
    saw_any_events: bool,
    diverged_at_version: Option<u64>,
    /// Held purely to preserve the constructor signature; Gap 2 wires it (and
    /// an `IelResolver`) into actual authorization checks.
    #[allow(dead_code)]
    checker: Arc<dyn PolicyChecker + Send + Sync>,
}

impl SelVerifier {
    pub fn new(
        prefix: Option<&cesr::Digest256>,
        checker: Arc<dyn PolicyChecker + Send + Sync>,
    ) -> Self {
        Self {
            prefix: prefix.copied(),
            topic: None,
            branches: HashMap::new(),
            saw_any_events: false,
            diverged_at_version: None,
            checker,
        }
    }

    /// Re-hydrate a verifier from a prior verification token. Gap 2 will
    /// re-implement to carry round-12 per-branch state across the resume
    /// boundary; this stub re-seats the existing branches as-is.
    pub fn resume(
        verification: &SelVerification,
        checker: Arc<dyn PolicyChecker + Send + Sync>,
    ) -> Result<Self, KelsError> {
        let mut branches: HashMap<cesr::Digest256, SadBranchTip> = HashMap::new();
        for branch in verification.branches() {
            branches.insert(branch.tip.said, branch.clone());
        }
        let prefix = *verification.prefix();
        let topic = verification.topic().to_string();
        Ok(Self {
            prefix: Some(prefix),
            topic: Some(topic),
            branches,
            saw_any_events: !verification.branches().is_empty(),
            diverged_at_version: verification.diverged_at_version(),
            checker,
        })
    }

    pub fn is_divergent(&self) -> bool {
        self.branches.len() > 1
    }

    /// Verify a page of events. Gap-1 stub: enforces SAID/prefix/topic
    /// integrity per event and updates the per-branch tip map by tip-SAID.
    /// Real chain-state advancement (auth resolution, monotonic ratchet,
    /// terminal flag handling) lands in Gap 2.
    pub async fn verify_page(&mut self, events: &[SadEvent]) -> Result<(), KelsError> {
        for event in events {
            event.verify_said()?;
            event
                .validate_structure()
                .map_err(KelsError::VerificationFailed)?;

            if let Some(ref expected) = self.prefix {
                if event.prefix != *expected {
                    return Err(KelsError::VerificationFailed(format!(
                        "SAD event {} prefix {} doesn't match SEL prefix {}",
                        event.said, event.prefix, expected,
                    )));
                }
            } else {
                self.prefix = Some(event.prefix);
            }

            if let Some(ref expected) = self.topic {
                if event.topic != *expected {
                    return Err(KelsError::VerificationFailed(format!(
                        "SAD event {} topic {} doesn't match SEL topic {}",
                        event.said, event.topic, expected,
                    )));
                }
            } else {
                self.topic = Some(event.topic.clone());
            }

            self.saw_any_events = true;

            // Stub branch update: replace the matching `previous`-keyed entry,
            // or insert as a new branch tip. Gap 2 reworks per-branch state
            // entirely.
            if let Some(prev_said) = event.previous {
                self.branches.remove(&prev_said);
            }
            self.branches.insert(
                event.said,
                SadBranchTip {
                    tip: event.clone(),
                    events_since_evaluation: 0,
                    last_governance_version: None,
                },
            );
        }
        Ok(())
    }

    /// Finalize verification, producing a `SelVerification` token. Gap-1
    /// stub: trusts the events it has seen and returns a permissive token.
    pub async fn finish(self) -> Result<SelVerification, KelsError> {
        if !self.saw_any_events {
            return Err(KelsError::VerificationFailed(
                "SelVerifier::finish: no events were verified".into(),
            ));
        }
        let mut branches: Vec<SadBranchTip> = self.branches.into_values().collect();
        branches.sort_by(|a, b| a.tip.said.as_ref().cmp(b.tip.said.as_ref()));
        Ok(SelVerification::new(
            branches,
            true,
            self.diverged_at_version,
        ))
    }
}
