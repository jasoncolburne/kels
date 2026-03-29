//! Bootstrap synchronization for new gossip nodes.
//!
//! When a new node joins the network, it needs to sync existing KELs from peers.
//! The bootstrap process handles the allowlist authorization check and avoids
//! missing events during the transition from unauthorized to authorized state.
//!
//! # Algorithm
//!
//! 1. **Authorization check**: Check if peer is in allowlist via `/api/v1/peers`
//! 2. **If NOT authorized**: Loop:
//!    - Log alert with PeerId (so admin can add it)
//!    - **preload_kels()**: Sync KELs from Ready peers (read-only via HTTP)
//!    - Sleep 5 minutes and recheck allowlist
//! 3. **Once authorized**:
//!    - **discover_peers()**: Query registry, register as Bootstrapping
//!    - Start gossip swarm with discovered peers
//! 4. **If Ready peers exist**: Wait for first `PeerConnected` event
//!    - **resync_kels()**: Catch events missed between preload and connection
//! 5. **If no Ready peers**: Skip resync (we're the first/only node)
//! 6. **mark_ready()**: Update status to Ready
//!
//! The resync in step 4 is critical: while the node was unauthorized, it could
//! preload KELs via HTTP. But events occurring between the last preload and
//! joining the gossip network would be missed. The resync catches these events.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::{debug, info, warn};

use futures::future::join_all;
use kels::{KelsClient, KelsError, KelsRegistryClient, PeerSigner, PrefixState};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BootstrapError {
    #[error("KELS/Registry error: {0}")]
    Kels(#[from] KelsError),
    #[error("Bootstrap failed: {0}")]
    Failed(String),
}

/// Configuration for bootstrap sync
#[derive(Clone)]
pub struct BootstrapConfig {
    /// Node identifier
    pub node_id: String,
    /// Local KELS URL (for this node to use)
    pub kels_url: String,
    /// Local SADStore URL
    pub sadstore_url: String,
    /// HTTP port for the gossip service (used to query peer /ready endpoints)
    pub http_port: u16,
    /// Page size for prefix listing
    pub page_size: usize,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            node_id: String::new(),
            kels_url: String::new(),
            sadstore_url: String::new(),
            http_port: 80,
            page_size: 100,
        }
    }
}

/// Result of peer discovery phase.
pub struct DiscoveryResult {
    pub peers: Vec<kels::Peer>,
}

/// Handles bootstrap synchronization from existing peers.
pub struct BootstrapSync {
    config: BootstrapConfig,
    urls: Vec<String>,
    allowlist: crate::allowlist::SharedAllowlist,
    signer: Arc<dyn PeerSigner>,
    http_client: reqwest::Client,
    redis: Option<Arc<redis::aio::ConnectionManager>>,
}

impl BootstrapSync {
    /// Create a new BootstrapSync with registry URLs, shared allowlist, and signer.
    pub fn new(
        config: BootstrapConfig,
        urls: Vec<String>,
        allowlist: crate::allowlist::SharedAllowlist,
        signer: Arc<dyn PeerSigner>,
    ) -> Self {
        let http_client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();

        Self {
            config,
            urls,
            allowlist,
            signer,
            http_client,
            redis: None,
        }
    }

    /// Set the Redis connection for stale prefix tracking.
    pub fn with_redis(mut self, redis: Arc<redis::aio::ConnectionManager>) -> Self {
        self.redis = Some(redis);
        self
    }

    /// Phase 1: Discover peers from the allowlist.
    /// Returns peers to connect to for gossip. Call this BEFORE starting the gossip swarm.
    pub async fn discover_peers(&self) -> Result<DiscoveryResult, BootstrapError> {
        info!("Discovering peers for node {}", self.config.node_id);

        let allowlist = self.allowlist.read().await;
        let peers: Vec<kels::Peer> = allowlist.values().cloned().collect();
        info!("Found {} peer(s) in allowlist", peers.len());

        Ok(DiscoveryResult { peers })
    }

    /// Preload KELs from Ready peers while not yet in the allowlist.
    ///
    /// This allows unauthorized nodes to stay in sync with KEL data while waiting
    /// to be added to the allowlist. Called in the unauthorized wait loop.
    /// No registration is performed - just HTTP-based KEL sync.
    pub async fn preload_kels(&self) -> Result<(), BootstrapError> {
        // Get Ready peers from allowlist
        let ready_peers = self.get_ready_peers().await;

        if ready_peers.is_empty() {
            info!("No Ready peers found for preload");
            return Ok(());
        }

        info!(
            "Preloading KELs from {} Ready peer(s)...",
            ready_peers.len()
        );
        self.sync_from_peers(&ready_peers).await?;
        info!("KEL preload complete");

        Ok(())
    }

    /// Preload SAD records from Ready peers.
    ///
    /// Lists chain prefixes from each Ready peer's SADStore, compares with local
    /// state, and syncs any chains that are missing or behind.
    pub async fn preload_sad_records(&self) -> Result<(), BootstrapError> {
        let ready_peers = self.get_ready_peers().await;

        if ready_peers.is_empty() {
            info!("No Ready peers found for SAD preload");
            return Ok(());
        }

        info!(
            "Preloading SAD records from {} Ready peer(s)...",
            ready_peers.len()
        );

        let local_client = kels::SadStoreClient::new(&self.config.sadstore_url);

        for peer in &ready_peers {
            let peer_sadstore_url = format!("http://kels-sadstore.{}", peer.base_domain);
            let remote_client = kels::SadStoreClient::new(&peer_sadstore_url);

            let mut cursor: Option<String> = None;
            loop {
                let page = match remote_client
                    .fetch_sad_prefixes(cursor.as_deref(), self.config.page_size)
                    .await
                {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("Failed to fetch SAD prefixes from {}: {}", peer.node_id, e);
                        break;
                    }
                };

                for state in &page.prefixes {
                    // Check if we already have this chain at the same state
                    let local_said = local_client
                        .fetch_sad_effective_said(&state.prefix)
                        .await
                        .ok()
                        .flatten();

                    if local_said.as_deref() == Some(&state.said) {
                        continue;
                    }

                    // Fetch and sync the chain
                    if let Ok(chain_page) = remote_client.fetch_sad_chain(&state.prefix, None).await
                    {
                        // Fetch content objects first
                        for stored in &chain_page.records {
                            if let Some(ref content_said) = stored.record.content_said
                                && let Ok(object) = remote_client.get_sad_object(content_said).await
                            {
                                let _ = local_client.put_sad_object(&object).await;
                            }
                        }
                        // Batch submit (single KEL verification)
                        if let Err(e) = local_client
                            .submit_sad_records_batch(&chain_page.records)
                            .await
                        {
                            warn!(
                                "Failed to batch-submit SAD records for {} during bootstrap: {}",
                                state.prefix, e
                            );
                        }
                    }
                }

                cursor = page.next_cursor;
                if cursor.is_none() {
                    break;
                }
            }
        }

        info!("SAD record preload complete");
        Ok(())
    }

    /// Get peers from allowlist that are ready (respond to /ready with success).
    async fn get_ready_peers(&self) -> Vec<kels::Peer> {
        let allowlist = self.allowlist.read().await;
        let mut ready_peers = Vec::new();
        for peer in allowlist.values() {
            if self.is_peer_ready(peer).await {
                ready_peers.push(peer.clone());
            }
        }
        ready_peers
    }

    /// Check if a peer is authorized in the allowlist.
    pub async fn is_peer_authorized(&self, peer_prefix: &str) -> Result<bool, BootstrapError> {
        // Try each registry URL until one succeeds
        for url in &self.urls {
            let client = KelsRegistryClient::new(url);
            match client.fetch_peers().await {
                Ok((peers_response, _)) => {
                    return Ok(peers_response.peers.iter().any(|history| {
                        history
                            .records
                            .last()
                            .map(|peer| peer.peer_prefix == peer_prefix && peer.active)
                            .unwrap_or(false)
                    }));
                }
                Err(e) => {
                    warn!(url = %url, error = %e, "Failed to check peer authorization, trying next");
                }
            }
        }
        Err(BootstrapError::Failed(
            "Could not check peer authorization from any registry".to_string(),
        ))
    }

    /// Check if there are Ready peers we should resync from.
    /// Queries each peer's HTTP /ready endpoint directly.
    pub async fn has_ready_peers(&self) -> bool {
        let allowlist = self.allowlist.read().await;
        for peer in allowlist.values() {
            if self.is_peer_ready(peer).await {
                return true;
            }
        }
        false
    }

    /// Check if a peer is ready by querying its HTTP /ready endpoint.
    ///
    /// Constructs the URL from the peer's gossip address hostname and the
    /// configured HTTP port (all gossip services share the same HTTP port).
    async fn is_peer_ready(&self, peer: &kels::Peer) -> bool {
        let host = peer
            .gossip_addr
            .rsplit_once(':')
            .map_or(peer.gossip_addr.as_str(), |(h, _)| h);
        let url = format!("http://{}:{}/ready", host, self.config.http_port);
        match self.http_client.get(&url).send().await {
            Ok(response) => response.status().is_success(),
            Err(e) => {
                debug!("Peer {} not ready: {}", peer.peer_prefix, e);
                false
            }
        }
    }

    /// Get the URL to use for node-to-node sync.
    fn get_sync_url(peer: &kels::Peer) -> String {
        format!("http://kels.{}", peer.base_domain)
    }

    /// Sync KELs from bootstrap peers.
    ///
    /// This collects all unique prefixes from all peers, assigns each prefix to
    /// its source peer (the peer that reported it), then batch-fetches KELs
    /// (50 at a time) from each peer.
    async fn sync_from_peers(&self, peers: &[kels::Peer]) -> Result<(), BootstrapError> {
        if peers.is_empty() {
            return Ok(());
        }

        let local_client = KelsClient::new(&self.config.kels_url);

        // Step 1: Collect all unique prefixes from all peers that need syncing.
        // Track (since_said, source_kels_url, source_peer_prefix) per kel prefix.
        info!("Collecting prefixes from {} peer(s)...", peers.len());
        let mut all_prefixes: HashMap<String, (Option<String>, String, String)> = HashMap::new();

        for peer in peers {
            let peer_url = Self::get_sync_url(peer);
            let peer_client = KelsClient::new(&peer_url);
            let mut cursor: Option<String> = None;

            loop {
                match peer_client
                    .fetch_prefixes(
                        self.signer.as_ref(),
                        cursor.as_deref(),
                        self.config.page_size,
                    )
                    .await
                {
                    Ok(page) => {
                        for state in &page.prefixes {
                            if let Some(since) = self.sync_check(state, &local_client).await {
                                all_prefixes.entry(state.prefix.clone()).or_insert((
                                    since,
                                    peer_url.to_string(),
                                    peer.peer_prefix.clone(),
                                ));
                            }
                        }
                        cursor = page.next_cursor;
                        if cursor.is_none() {
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("Failed to fetch prefixes from {}: {}", peer.node_id, e);
                        break;
                    }
                }
            }
        }

        let prefix_count = all_prefixes.len();
        if prefix_count == 0 {
            info!("No prefixes need syncing");
            return Ok(());
        }

        info!("Found {} unique prefixes needing sync", prefix_count);

        // Step 2: Sync all prefixes concurrently using forward_key_events
        let tasks: Vec<_> = all_prefixes
            .into_iter()
            .map(|(prefix, (since, source_url, source_peer_prefix))| {
                let local = local_client.clone();
                async move {
                    let remote = KelsClient::new(&source_url);
                    let result =
                        crate::sync::sync_prefix(&remote, &local, &prefix, since.as_deref()).await;
                    (prefix, source_peer_prefix, result)
                }
            })
            .collect();

        let results = join_all(tasks).await;

        let mut total_synced = 0;
        let mut total_errors = 0;

        for (prefix, source_peer_prefix, result) in results {
            match result {
                crate::sync::RepairResult::Repaired => {
                    info!("Synced KEL for {}", prefix);
                    total_synced += 1;
                }
                crate::sync::RepairResult::NoOp => {}
                crate::sync::RepairResult::Contested => {
                    warn!("KEL contested for {}", prefix);
                }
                crate::sync::RepairResult::Failed => {
                    warn!("Failed to sync prefix {}", prefix);
                    total_errors += 1;
                    if let Some(ref redis) = self.redis {
                        crate::sync::record_stale_prefix(
                            redis.as_ref(),
                            &prefix,
                            &source_peer_prefix,
                        )
                        .await;
                    }
                }
            }
        }

        info!(
            "Bootstrap sync complete: {} KELs synced, {} errors",
            total_synced, total_errors
        );

        Ok(())
    }

    /// Check if a prefix needs syncing by comparing with local state.
    ///
    /// Returns:
    /// - `None` = up to date, skip
    /// - `Some(None)` = no local KEL, full fetch
    /// - `Some(Some(said))` = has partial KEL, delta from effective tail SAID
    ///
    /// Resolving: compare local effective SAID with remote to decide if sync needed.
    /// A wrong answer triggers an unnecessary sync (which itself verifies).
    async fn sync_check(
        &self,
        remote_state: &PrefixState,
        local_client: &KelsClient,
    ) -> Option<Option<String>> {
        match local_client
            .fetch_effective_said(&remote_state.prefix)
            .await
        {
            Ok(Some((local_effective, _))) => {
                if local_effective == remote_state.said {
                    None // In sync
                } else {
                    Some(Some(local_effective)) // Delta fetch from this SAID
                }
            }
            Ok(None) => Some(None), // No local KEL, full fetch
            Err(_) => Some(None),   // Error, try full fetch
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bootstrap_config_default() {
        let config = BootstrapConfig::default();
        assert!(config.node_id.is_empty());
        assert!(config.kels_url.is_empty());
        assert_eq!(config.page_size, 100);
    }

    #[test]
    fn test_bootstrap_config_custom() {
        let config = BootstrapConfig {
            node_id: "node-1".to_string(),
            kels_url: "http://localhost:8080".to_string(),
            sadstore_url: "http://localhost:8082".to_string(),
            http_port: 8081,
            page_size: 50,
        };
        assert_eq!(config.node_id, "node-1");
        assert_eq!(config.kels_url, "http://localhost:8080");
        assert_eq!(config.http_port, 8081);
        assert_eq!(config.page_size, 50);
    }

    #[test]
    fn test_bootstrap_error_display() {
        let kels_error = BootstrapError::Kels(KelsError::ServerError(
            "test".to_string(),
            kels::ErrorCode::InternalError,
        ));
        assert!(kels_error.to_string().contains("KELS/Registry error"));

        let failed_error = BootstrapError::Failed("bootstrap failed".to_string());
        assert_eq!(
            failed_error.to_string(),
            "Bootstrap failed: bootstrap failed"
        );
    }

    #[test]
    fn test_bootstrap_error_from_kels_error() {
        let kels_error =
            KelsError::ServerError("server error".to_string(), kels::ErrorCode::InternalError);
        let bootstrap_error: BootstrapError = kels_error.into();
        assert!(matches!(bootstrap_error, BootstrapError::Kels(_)));
    }

    #[test]
    fn test_discovery_result_creation() {
        let result = DiscoveryResult { peers: vec![] };
        assert!(result.peers.is_empty());
    }

    #[test]
    fn test_get_sync_url() {
        let peer = kels::Peer {
            said: "test-said".to_string(),
            prefix: "test-prefix".to_string(),
            previous: None,
            version: 1,
            created_at: verifiable_storage::StorageDatetime::now(),
            peer_prefix: "test-peer".to_string(),
            node_id: "node-1".to_string(),
            authorizing_kel: "EAuthorizingKel_____________________________".to_string(),
            active: true,
            base_domain: "node-1.kels".to_string(),
            gossip_addr: "/ip4/127.0.0.1/tcp/4001".to_string(),
        };
        assert_eq!(
            BootstrapSync::get_sync_url(&peer),
            "http://kels.node-1.kels"
        );
    }
}
