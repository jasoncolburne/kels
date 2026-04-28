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

/// Response from an IEL submit. `diverged_at` is set when the submit produced
/// or observed a fork at that version.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[must_use = "SubmitIdentityEventsResponse.applied must be checked — events may be rejected"]
pub struct SubmitIdentityEventsResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diverged_at: Option<u64>,
    pub applied: bool,
}
