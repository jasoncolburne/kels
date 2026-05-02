//! HTTP request and response types for the IEL submit / fetch surface.
//!
//! Mirrors `lib/kels/src/types/sad/request.rs` for the IEL primitive.

use serde::{Deserialize, Serialize};

use super::event::IdentityEvent;

/// Request body for fetching a page of IEL events.
#[derive(Debug, Deserialize, Serialize)]
pub struct IdentityEventPageRequest {
    pub prefix: cesr::Digest256,
    pub since: Option<cesr::Digest256>,
    pub limit: Option<usize>,
}

/// Request body for checking whether an IEL event SAID exists on the server.
#[derive(Debug, Deserialize, Serialize)]
pub struct IdentityEventExistsRequest {
    pub said: cesr::Digest256,
}

/// Request body for fetching the effective SAID of an IEL chain.
#[derive(Debug, Deserialize, Serialize)]
pub struct IdentityEventEffectiveSaidRequest {
    pub prefix: cesr::Digest256,
}

/// A page of stored IEL events returned by the IEL fetch endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityEventPage {
    pub events: Vec<IdentityEvent>,
    pub has_more: bool,
}

/// Terminal state of an IEL chain at the moment a submission was rejected
/// because the chain is already terminal. Returned via
/// `SubmitIdentityEventsResponse.terminal` on a 200 OK response so gossip
/// relays / forwarders see idempotent success while owner-side callers can
/// still distinguish the cause.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentityEventTerminalState {
    Contested,
    Decommissioned,
}

/// Response from an IEL submit.
///
/// - `applied=true` — at least one event committed.
/// - `applied=false`, `terminal=None` — dedup short-circuit (every event
///   submitted was already in the chain).
/// - `applied=false`, `terminal=Some(_)` — the chain was already terminal
///   when the batch arrived; no events committed but the receiver reports
///   the state for caller dispatch.
///
/// `diverged_at` is set when the submit produced or observed a fork at
/// that version (or, on the dedup / terminal-skip paths, when the chain
/// is divergent at submit time).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[must_use = "SubmitIdentityEventsResponse.applied / .terminal must be checked — events may be rejected"]
pub struct SubmitIdentityEventsResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diverged_at: Option<u64>,
    pub applied: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<IdentityEventTerminalState>,
}
