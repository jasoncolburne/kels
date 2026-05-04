//! #156: wire-format types for the deferred-deps 422 response.
//!
//! When sadstore's verifier walk in collect-mode accumulates deferrable
//! failures, the submit handler emits a 422 response carrying the deps
//! as a [`DeferredDepsResponse`]. The gossip deferred-deps layer parses
//! this response, parks the message, and drains when a dep commits.
//!
//! Wire shape:
//!
//! ```json
//! {
//!   "kind": "rejected",
//!   "missing_dependencies": [
//!     { "type": "kel_anchor",  "kelPrefix": "...", "anchorSaid": "...", "chainEffSaid": "..." },
//!     { "type": "iel_event",   "ielPrefix": "...", "eventSaid":  "...", "chainEffSaid": "..." },
//!     { "type": "iel_prefix",  "ielPrefix": "..." },
//!     { "type": "sad_object",  "said":      "..." }
//!   ],
//!   "transient_chain_state": [
//!     { "prefix": "...", "effectiveSaid": "..." }
//!   ]
//! }
//! ```

use serde::{Deserialize, Serialize};

/// 422 response body for deferrable rejection.
///
/// Carries both `missing_dependencies` (per-SAID deferrable deps) and
/// `transient_chain_state` (chain-state-divergent deferrals). Either may
/// be empty; both are populated when both are observed in a single walk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeferredDepsResponse {
    Rejected {
        missing_dependencies: Vec<MissingDependency>,
        transient_chain_state: Vec<TransientChainState>,
    },
}

impl DeferredDepsResponse {
    pub fn new(
        missing_dependencies: Vec<MissingDependency>,
        transient_chain_state: Vec<TransientChainState>,
    ) -> Self {
        Self::Rejected {
            missing_dependencies,
            transient_chain_state,
        }
    }

    /// True iff there is no deferrable content. Caller treats an empty
    /// rejection as a logic error (handler shouldn't emit 422 with no
    /// deps); kept as a defensive check.
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Rejected {
                missing_dependencies,
                transient_chain_state,
            } => missing_dependencies.is_empty() && transient_chain_state.is_empty(),
        }
    }
}

/// Deferrable dep on a specific SAID.
///
/// `chain_eff_said` is the chain's current effective SAID at
/// sadstore-evaluation time, included on chain-referencing deps so the
/// gossip park layer can use it as the `eff_said_at_park` when enrolling
/// in `pending:chain:{prefix}`. `iel_prefix` and `sad_object` deps don't
/// carry it: `iel_prefix` has no chain state to point at (no events
/// observed locally), and SAD objects aren't chains.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MissingDependency {
    KelAnchor {
        #[serde(rename = "kelPrefix")]
        kel_prefix: cesr::Digest256,
        #[serde(rename = "anchorSaid")]
        anchor_said: cesr::Digest256,
        #[serde(rename = "chainEffSaid")]
        chain_eff_said: cesr::Digest256,
    },
    IelEvent {
        #[serde(rename = "ielPrefix")]
        iel_prefix: cesr::Digest256,
        #[serde(rename = "eventSaid")]
        event_said: cesr::Digest256,
        #[serde(rename = "chainEffSaid")]
        chain_eff_said: cesr::Digest256,
    },
    IelPrefix {
        #[serde(rename = "ielPrefix")]
        iel_prefix: cesr::Digest256,
    },
    SadObject {
        said: cesr::Digest256,
    },
}

/// Deferrable chain-state entry.
///
/// `effective_said` is either the synthetic SAID for divergent chains
/// (`hash_effective_said("divergent:{prefix}")`) or the contested
/// synthetic, whichever the verifier observed at evaluation time. The
/// gossip park layer uses it as the `eff_said_at_park` for the
/// `pending:chain:{prefix}` enrolment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransientChainState {
    pub prefix: cesr::Digest256,
    #[serde(rename = "effectiveSaid")]
    pub effective_said: cesr::Digest256,
}
