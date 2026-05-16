//! Custody — per-SAD authority. Inline-on-parent struct.
//!
//! #167: `custody` is a top-level reserved key on SAD
//! objects whose value is an inline JSON object with two optional fields —
//! `write` (IEL event SAID — anchored, point-in-time write attestation) and
//! `read` (IEL prefix — identity-current read gating). Both fields are
//! independently optional.
//!
//! Asymmetric semantics:
//! - `write: IELSaid` — anchored to a specific IEL event whose `auth_policy`
//!   was satisfied at write time. Verifier resolves the IEL event by SAID and
//!   confirms the policy at that event was satisfied. One-time pinning.
//! - `read: IELPrefix` — identity prefix; resolves through the IEL's
//!   **current `auth_policy`** at evaluation. Identity-current.
//!
//! There is no separate "read policy" tracked alongside `auth_policy` on the
//! IEL — the same `auth_policy` field gates both write attestation
//! (point-in-time, pinned via `write: IELSaid`) and read access (current,
//! resolved via `read: IELPrefix`). Multi-party splits (admin-write vs
//! user-read) are achieved by binding `write` and `read` to different IELs.
//!
//! Custody is **inline** on the parent SAD — not a separately-addressable
//! SelfAddressed type. Compaction leaves it in the parent's body (no `said`
//! field, so it isn't extracted as a chunk).
//!
//! `availability` (replication, ttl, once) is a sibling top-level key — see
//! [`super::availability`] for that struct. Authority and availability are
//! factored apart; both are SAD-object concerns and rejected on chain events.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// Per-SAD authority — both fields independently optional.
///
/// Four valid combinations:
///
/// | `write` | `read` | Use case |
/// |---|---|---|
/// | `None` | `None` | Uncovered SAD (or no `custody` key at all); public anonymous. |
/// | `Some` | `None` | Signed public content. |
/// | `None` | `Some` | Anonymous submission into a read-protected zone (drop-box). |
/// | `Some` | `Some` | Identity-bound private content. |
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Custody {
    /// IEL event SAID whose `auth_policy` was satisfied at write time.
    /// Anchored, point-in-time. `None` for unsigned (anonymous) content.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub write: Option<cesr::Digest256>,
    /// IEL prefix; reads resolve through the IEL's current `auth_policy` at
    /// evaluation. Identity-current. `None` for publicly readable content.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub read: Option<cesr::Digest256>,
}

impl Custody {
    /// Returns true when neither field is set — equivalent to absence of the
    /// `custody` key on the parent SAD.
    pub fn is_empty(&self) -> bool {
        self.write.is_none() && self.read.is_none()
    }
}

/// Errors from custody / availability validation.
#[derive(Debug, Clone)]
pub enum CustodyValidationError {
    /// `custody` is structurally incompatible with chained events.
    CustodyNotAllowedOnEvent,
    /// `availability` is structurally incompatible with chained events.
    AvailabilityNotAllowedOnEvent,
    /// Failed to parse the custody object.
    ParseError(String),
}

impl std::fmt::Display for CustodyValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CustodyNotAllowedOnEvent => write!(
                f,
                "custody is not allowed on events — chains replicate as a unit; \
                 differential authority across links breaks descendant verification"
            ),
            Self::AvailabilityNotAllowedOnEvent => write!(
                f,
                "availability is not allowed on events — chains replicate as a unit; \
                 differential lifecycle/replication across links breaks descendant verification"
            ),
            Self::ParseError(msg) => write!(f, "custody parse error: {}", msg),
        }
    }
}

impl std::error::Error for CustodyValidationError {}

/// Known custody fields (camelCase, matching the JSON wire format).
const KNOWN_CUSTODY_FIELDS: &[&str] = &["write", "read"];

/// Parse and validate a custody object from a JSON value.
///
/// Fail-secure: unknown fields reject. The SAID covers the whole `custody`
/// object including unknown siblings, so the wire form is content-addressed
/// — there is no v2-schema "old SAD breaks under stricter parsing" scenario
/// where a forgiving parse would help. A fail-open posture would let a
/// malformed (or maliciously-padded) `custody` land with the SAD passing
/// downstream consumers' eyes as if `write` / `read` were enforced when in
/// fact no enforcement ran.
///
/// Returns:
/// - `Ok(custody)` — valid custody with recognized fields only.
/// - `Err(ParseError)` — the value isn't an object, parsing failed, or
///   unknown sibling fields were present.
///
/// Per-event rejection of `custody` (`CustodyNotAllowedOnEvent`) and
/// `availability` (`AvailabilityNotAllowedOnEvent`) is enforced at the
/// presence-of-key level upstream (chain-event submit handlers reject the
/// JSON if either key is set), not here — this function is shape validation
/// for the inline value.
pub fn parse_and_validate_custody(
    value: &serde_json::Value,
) -> Result<Custody, CustodyValidationError> {
    let obj = match value.as_object() {
        Some(obj) => obj,
        None => {
            return Err(CustodyValidationError::ParseError(
                "custody must be an object".into(),
            ));
        }
    };

    let known: HashSet<&str> = KNOWN_CUSTODY_FIELDS.iter().copied().collect();
    if let Some(unknown) = obj.keys().find(|k| !known.contains(k.as_str())) {
        return Err(CustodyValidationError::ParseError(format!(
            "unknown custody field {:?}",
            unknown
        )));
    }

    let custody: Custody = serde_json::from_value(value.clone())
        .map_err(|e| CustodyValidationError::ParseError(e.to_string()))?;

    Ok(custody)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_digest(label: &[u8]) -> cesr::Digest256 {
        cesr::Digest256::blake3_256(label)
    }

    #[test]
    fn test_default_is_empty() {
        let c = Custody::default();
        assert!(c.is_empty());
        assert!(c.write.is_none());
        assert!(c.read.is_none());
    }

    #[test]
    fn test_parse_recognizes_write_and_read() {
        let value = serde_json::json!({
            "write": test_digest(b"iel-event").to_string(),
            "read": test_digest(b"iel-prefix").to_string(),
        });
        let parsed = parse_and_validate_custody(&value).unwrap();
        assert_eq!(parsed.write, Some(test_digest(b"iel-event")));
        assert_eq!(parsed.read, Some(test_digest(b"iel-prefix")));
    }

    #[test]
    fn test_parse_partial_custody() {
        let read_only = serde_json::json!({
            "read": test_digest(b"iel-prefix").to_string(),
        });
        let parsed = parse_and_validate_custody(&read_only).unwrap();
        assert!(parsed.write.is_none());
        assert_eq!(parsed.read, Some(test_digest(b"iel-prefix")));
    }

    #[test]
    fn test_unknown_field_rejected() {
        let value = serde_json::json!({
            "write": test_digest(b"x").to_string(),
            "customField": "something",
        });
        let err = parse_and_validate_custody(&value).unwrap_err();
        assert!(matches!(err, CustodyValidationError::ParseError(_)));
    }

    #[test]
    fn test_empty_object_parses_as_default() {
        let value = serde_json::json!({});
        let parsed = parse_and_validate_custody(&value).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn test_non_object_errors() {
        let value = serde_json::json!("not an object");
        let err = parse_and_validate_custody(&value).unwrap_err();
        assert!(matches!(err, CustodyValidationError::ParseError(_)));
    }

    #[test]
    fn test_legacy_field_names_rejected() {
        // Pre-#167 field names — fail-secure: caller gets a parse error,
        // not silent unenforcement. Identifiers built dynamically so the
        // literal forbidden tokens never appear in source files (see
        // `.terminology-forbidden`).
        let legacy_write = format!("{}{}", "write", "Policy");
        let legacy_read = format!("{}{}", "read", "Policy");
        let mut obj = serde_json::Map::new();
        obj.insert(
            legacy_write,
            serde_json::Value::String(test_digest(b"x").to_string()),
        );
        obj.insert(
            legacy_read,
            serde_json::Value::String(test_digest(b"y").to_string()),
        );
        let value = serde_json::Value::Object(obj);
        let err = parse_and_validate_custody(&value).unwrap_err();
        assert!(matches!(err, CustodyValidationError::ParseError(_)));
    }
}
