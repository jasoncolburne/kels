//! Allowlist-based peer authorization.
//!
//! Manages the shared allowlist of authorized peers, keyed by peer KEL prefix.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use thiserror::Error;
use verifiable_storage::Chained;

#[derive(Error, Debug)]
pub enum AllowlistRefreshError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("KEL verification failed: {0}")]
    KelVerificationFailed(String),
}

/// Shared allowlist type - maps peer KEL prefix to full Peer data
pub type SharedAllowlist = Arc<RwLock<HashMap<cesr::Digest, kels_core::Peer>>>;

/// Fetch peers from registry and update the allowlist with full KEL verification.
///
/// This performs cryptographic verification:
/// 1. Fetches peers from any available registry (with failover)
/// 2. Checks that the registry prefix matches the expected trust anchor
/// 3. Verifies each peer's SAID is anchored in the registry's KEL
/// 4. For peers: verifies an approved proposal exists with sufficient votes,
///    where each vote passes SAID integrity (`verify()`) and KEL anchoring checks
///
/// Returns the number of authorized peers in the updated allowlist.
pub async fn refresh_allowlist(
    registry_urls: &[String],
    registry_kel_store: &(dyn kels_core::KelStore + Sync),
    allowlist: &SharedAllowlist,
    exclude_node_id: Option<&str>,
) -> Result<usize, AllowlistRefreshError> {
    let original_peers = allowlist.read().await;
    let original_saids: HashSet<_> = original_peers.values().map(|p| p.said).collect();
    drop(original_peers);

    let trusted = kels_core::trusted_prefixes();

    // Fetch peers from any available registry
    let t0 = std::time::Instant::now();
    debug!("Fetching peers from registries");
    let response =
        kels_core::with_failover(registry_urls, Duration::from_secs(10), |c| async move {
            c.fetch_peers().await
        })
        .await
        .map_err(|e| AllowlistRefreshError::KelVerificationFailed(e.to_string()))?;
    debug!("fetch_peers completed in {:?}", t0.elapsed());

    // Fetch completed proposals for peer vote verification
    let proposals_response =
        kels_core::with_failover(registry_urls, Duration::from_secs(10), |c| async move {
            c.fetch_completed_proposals().await
        })
        .await
        .ok();
    debug!(
        "fetch_completed_proposals completed in {:?} (total {:?})",
        t0.elapsed(),
        t0.elapsed()
    );

    let mut authorized_peers = HashMap::new();

    let t1 = std::time::Instant::now();
    for history in response.peers {
        // Get the latest (last) record
        if let Some(latest) = history.records.last() {
            // Verify the peer record's SAID matches its content
            if let Err(e) = latest.verify() {
                warn!(
                    peer_kel_prefix = %latest.kel_prefix,
                    said = %latest.said,
                    error = %e,
                    "Peer record SAID verification failed, skipping"
                );
                continue;
            }

            // Verify peer record anchoring in authorizing registry KEL
            match kels_core::verify_peer_anchoring(registry_kel_store, latest, registry_urls).await
            {
                Ok(true) => {}
                Ok(false) => {
                    warn!(
                        peer_kel_prefix = %latest.kel_prefix,
                        said = %latest.said,
                        "Peer SAID not anchored in registry KEL, skipping"
                    );
                    continue;
                }
                Err(e) => {
                    warn!(
                        peer_kel_prefix = %latest.kel_prefix,
                        error = %e,
                        "Failed to verify peer anchoring, skipping"
                    );
                    continue;
                }
            }

            debug!(peer_kel_prefix = %latest.kel_prefix, "allowlist: peer anchoring OK, checking votes...");

            // Verify the proposal has sufficient verified votes
            let tv = std::time::Instant::now();
            if !kels_core::verify_peer_votes(
                registry_kel_store,
                &latest.kel_prefix,
                &proposals_response,
                &trusted,
                registry_urls,
            )
            .await
            {
                warn!(
                    peer_kel_prefix = %latest.kel_prefix,
                    "Peer not backed by sufficient verified votes, skipping"
                );
                continue;
            }

            debug!(
                peer_kel_prefix = %latest.kel_prefix,
                elapsed = ?tv.elapsed(),
                "allowlist: vote verification complete"
            );

            if latest.active {
                authorized_peers.insert(latest.kel_prefix, latest.clone());
            }
        }
    }

    // Filter out the excluded node (e.g., self) from the authorized peers
    if let Some(excluded) = exclude_node_id {
        authorized_peers.retain(|_, peer| peer.node_id != excluded);
    }

    let count = authorized_peers.len();
    debug!(
        "allowlist: peer verification loop took {:?} for {} peers",
        t1.elapsed(),
        count
    );

    if original_saids.len() != count
        || authorized_peers
            .iter()
            .any(|(_, p)| !original_saids.contains(&p.said))
    {
        // Update the shared allowlist
        *allowlist.write().await = authorized_peers;

        info!(
            "Allowlist refreshed with {} verified authorized peers (total {:?})",
            count,
            t0.elapsed()
        );
    }

    Ok(count)
}

/// Run the allowlist refresh loop in the background.
///
/// Periodically fetches the peer list from the registry and updates the allowlist.
/// Performs full KEL verification against the trust anchor.
pub async fn run_allowlist_refresh_loop(
    registry_urls: &[String],
    registry_kel_store: &(dyn kels_core::KelStore + Sync),
    allowlist: SharedAllowlist,
    refresh_interval: Duration,
    node_id: &str,
) {
    info!(
        "Starting allowlist refresh loop (interval: {:?})",
        refresh_interval
    );

    loop {
        match refresh_allowlist(registry_urls, registry_kel_store, &allowlist, Some(node_id)).await
        {
            Ok(count) => {
                debug!("Allowlist refresh successful: {} peers", count);
            }
            Err(e) => {
                error!("Allowlist refresh failed: {}", e);
            }
        }

        tokio::time::sleep(refresh_interval).await;
    }
}

#[cfg(test)]
mod tests {
    use cesr::test_digest;

    use super::*;

    fn _create_test_peer(peer_kel_prefix: &str) -> kels_core::Peer {
        kels_core::Peer {
            said: test_digest("test-said"),
            prefix: test_digest("test-prefix"),
            previous: None,
            version: 1,
            created_at: verifiable_storage::StorageDatetime::now(),
            kel_prefix: cesr::Digest::blake3_256(peer_kel_prefix.as_bytes()),
            node_id: "test-node".to_string(),
            authorizing_kel: test_digest("authorizing-kel"),
            active: true,
            base_domain: "test.kels".to_string(),
            gossip_addr: "127.0.0.1:4001".to_string(),
        }
    }

    // ==================== AllowlistRefreshError Tests ====================

    #[test]
    fn test_allowlist_refresh_error_http_display() {
        let err = AllowlistRefreshError::KelVerificationFailed("Invalid KEL".to_string());
        assert_eq!(err.to_string(), "KEL verification failed: Invalid KEL");
    }

    #[test]
    fn test_allowlist_refresh_error_kel_verification_display() {
        let err = AllowlistRefreshError::KelVerificationFailed("SAID mismatch".to_string());
        assert!(err.to_string().contains("SAID mismatch"));
    }
}
