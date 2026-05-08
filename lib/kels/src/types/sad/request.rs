use serde::{Deserialize, Serialize};
use verifiable_storage::{SelfAddressed, StorageDatetime};

/// Authenticated fetch request for a SAD object.
///
/// Used as `SignedRequest<SadFetchRequest>` for objects whose `custody.read`
/// gates user-facing reads (per #167). The `object_said` binds the request
/// to a specific object — the server resolves the IEL prefix's current
/// auth_policy and evaluates it against the verified signer set.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[serde(rename_all = "camelCase")]
pub struct SignedSadFetchRequest {
    #[said]
    pub said: cesr::Digest256,
    #[created_at]
    pub created_at: StorageDatetime,
    pub nonce: cesr::Nonce256,
    pub object_said: cesr::Digest256,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disclosure: Option<String>,
}

/// Request body for fetching or checking existence of a SAD object or event by SAID.
#[derive(Debug, Deserialize, Serialize)]
pub struct SadFetchRequest {
    pub said: cesr::Digest256,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure: Option<String>,
}

/// Request body for fetching a page of SAD Event Log events.
#[derive(Debug, Deserialize, Serialize)]
pub struct SadEventPageRequest {
    pub prefix: cesr::Digest256,
    pub since: Option<cesr::Digest256>,
    pub limit: Option<usize>,
}

/// Request body for fetching the tail of a SAD Event Log.
///
/// Returns the last `limit` events ordered by `(version DESC, said DESC)`,
/// then reversed so the page reads `(version ASC, said ASC)` for caller
/// convenience. Lets `SadEventBuilder::repair` find the truncation boundary
/// in a single round-trip regardless of chain length — bounded by
/// `MINIMUM_PAGE_SIZE` server-side because that's exactly what the
/// adversary-extension walk-back can possibly need.
#[derive(Debug, Deserialize, Serialize)]
pub struct SadEventTailRequest {
    pub prefix: cesr::Digest256,
    pub limit: Option<usize>,
}

/// Request body for fetching the effective SAID of a SAD Event Log.
#[derive(Debug, Deserialize, Serialize)]
pub struct SadEventEffectiveSaidRequest {
    pub prefix: cesr::Digest256,
}

/// Terminal state of an SEL at the moment a submission was rejected
/// because the chain is already terminal. Returned via
/// `SubmitSadEventsResponse.terminal` on a 200 OK response so gossip
/// relays / forwarders see idempotent success while owner-side callers can
/// still distinguish the cause. Mirrors IEL's `IdentityEventTerminalState`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SadEventTerminalState {
    Contested,
    Decommissioned,
}

/// Response from SAD event submission.
///
/// - `applied=true` — at least one event committed.
/// - `applied=false`, `terminal=None` — dedup short-circuit (every event
///   submitted was already in the chain).
/// - `applied=false`, `terminal=Some(_)` — the chain was already terminal
///   when the batch arrived; no events committed but the receiver reports
///   the state for caller dispatch.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[must_use = "SubmitSadEventsResponse.applied / .terminal must be checked — events may be rejected"]
pub struct SubmitSadEventsResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diverged_at: Option<u64>,
    pub applied: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<SadEventTerminalState>,
}

/// Response from a successful SAD object submission.
///
/// Carries the **canonical** SAID under which the server stored the object —
/// after compaction of any inline nested SADs. Clients submitting an expanded-form
/// SAD cannot recompute this without redoing the server's compaction, so the
/// server returns it authoritatively. Returned on both 200 ("exists") and 201
/// ("stored") responses; pre-compacted submissions will see this equal to the
/// SAID they computed locally.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostSadObjectResponse {
    pub said: cesr::Digest256,
}

/// Request body for listing repairs for a SAD Event Log.
#[derive(Debug, Deserialize, Serialize)]
pub struct SadRepairsRequest {
    pub prefix: cesr::Digest256,
    pub limit: Option<usize>,
    pub offset: Option<u64>,
}

/// Request body for fetching archived events of a specific repair.
#[derive(Debug, Deserialize, Serialize)]
pub struct SadRepairPageRequest {
    pub prefix: cesr::Digest256,
    pub said: cesr::Digest256,
    pub limit: Option<usize>,
    pub offset: Option<u64>,
}
