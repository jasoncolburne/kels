//! Caching & sync types

use std::collections::HashSet;

use cesr::{Digest, Matter};
use serde::{Deserialize, Serialize};

/// Generate a cryptographic nonce: 32 random bytes hashed with BLAKE3-256, CESR-encoded.
pub fn generate_nonce() -> String {
    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy).unwrap_or_else(|e| unreachable!("getrandom failed: {}", e));
    Digest::blake3_256(&entropy).qb64()
}

/// Compute the effective SAID for a set of events belonging to a single prefix.
///
/// For non-divergent KELs (single tip), returns the tip SAID directly.
/// For divergent KELs (multiple tips from forked branches), sorts the tip SAIDs
/// alphabetically and returns their concatenated Blake3 hash, CESR-encoded.
///
/// This ensures deterministic comparison between nodes that have the same divergent
/// branches but may have received them in different order. Both nodes will produce
/// identical effective SAIDs for the same set of events.
///
/// # Why hashed tip SAIDs?
///
/// When a KEL diverges (e.g., from a race-condition key compromise attack), both
/// branches are stored and the KEL is frozen — only recovery events can resolve it.
/// A `DISTINCT ON(prefix)` query would return a nondeterministic SAID, making
/// anti-entropy comparison unreliable. By hashing all sorted tip SAIDs together,
/// we get a stable fingerprint that detects both "in sync" and "out of sync" states.
///
/// # Known-divergent edge case
///
/// If Node A has branches (X, Y) and Node B has branches (X, Z) — where Y and Z
/// are different adversary events injected via race condition — the hashed SAIDs
/// will differ. Anti-entropy will detect the mismatch but cannot resolve it because
/// frozen KELs reject non-recovery events. The gossip layer tracks these as
/// "known-divergent" prefixes and skips them in future sampling cycles to avoid
/// infinite retry loops. Only a recovery event (rec/ror) can resolve the divergence.
///
/// # Arguments
///
/// * `said_previous_pairs` - Pairs of `(said, optional_previous)` for each event
///   in the prefix. Tips are events whose SAID is not referenced as `previous` by
///   any other event in the set.
pub fn compute_effective_tail_said(said_previous_pairs: &[(&str, Option<&str>)]) -> Option<String> {
    if said_previous_pairs.is_empty() {
        return None;
    }

    let all_saids: HashSet<&str> = said_previous_pairs.iter().map(|(s, _)| *s).collect();
    let referenced: HashSet<&str> = said_previous_pairs
        .iter()
        .filter_map(|(_, prev)| *prev)
        .filter(|p| all_saids.contains(p))
        .collect();

    let mut tips: Vec<&str> = all_saids.difference(&referenced).copied().collect();
    tips.sort();

    match tips.len() {
        0 => None,
        1 => Some(tips[0].to_string()),
        _ => Some(hash_tip_saids(&tips)),
    }
}

/// Hash sorted tip SAIDs into a single deterministic CESR-encoded Blake3 digest.
///
/// Used to represent the state of a divergent KEL where multiple branch tips exist.
/// The SAIDs are sorted alphabetically, concatenated, and Blake3-hashed.
pub fn hash_tip_saids(saids: &[&str]) -> String {
    let mut sorted: Vec<&str> = saids.to_vec();
    sorted.sort();
    let concatenated = sorted.join("");
    Digest::blake3_256(concatenated.as_bytes()).qb64()
}

/// Request payload for authenticated prefix listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrefixesRequest {
    pub timestamp: i64,
    pub nonce: String,
    pub since: Option<String>,
    pub limit: Option<usize>,
}

/// Response for paginated prefix listing
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrefixListResponse {
    pub prefixes: Vec<PrefixState>,
    pub next_cursor: Option<String>,
}

/// A prefix with its latest SAID, used for bootstrap sync
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefixState {
    pub prefix: String,
    pub said: String,
}
