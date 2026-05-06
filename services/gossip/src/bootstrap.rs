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

use cesr::Matter;
use futures::stream::{self, StreamExt};
use kels_core::{KelsClient, KelsError, KelsRegistryClient, PeerSigner, PrefixState};
use thiserror::Error;

/// Concurrency cap for bootstrap preload tasks (KEL / SAD object / IEL /
/// SE). Mirrors `KELS_SAD_AE_TASK_CONCURRENCY`'s posture: bootstrap fires
/// the whole world at once on cold-start, so an unbounded `join_all`
/// saturates the source peer (observed: 282 of 579 KELs failed to sync at
/// scale). 16 is conservative; tune via env on deployments with bigger
/// data sets or beefier source peers.
fn bootstrap_task_concurrency() -> usize {
    kels_core::env_usize("KELS_BOOTSTRAP_CONCURRENCY", 16)
}

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
    pub peers: Vec<kels_core::Peer>,
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
    ) -> Result<Self, BootstrapError> {
        let http_client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| BootstrapError::Failed(format!("Failed to build HTTP client: {}", e)))?;

        Ok(Self {
            config,
            urls,
            allowlist,
            signer,
            http_client,
            redis: None,
        })
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
        let peers: Vec<kels_core::Peer> = allowlist.values().cloned().collect();
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

    /// Preload SAD objects from Ready peers.
    ///
    /// Paginates through the remote object listing, checks local existence, and
    /// fetches any missing objects. Runs before SAD event sync so that
    /// content objects are available when chains reference them.
    pub async fn preload_sad_objects(&self) -> Result<(), BootstrapError> {
        let ready_peers = self.get_ready_peers().await;

        if ready_peers.is_empty() {
            info!("No Ready peers found for SAD object preload");
            return Ok(());
        }

        info!(
            "Preloading SAD objects from {} Ready peer(s)...",
            ready_peers.len()
        );

        let local_client = kels_core::SadStoreClient::new(&self.config.sadstore_url)?;
        let mut total_synced = 0u64;
        let concurrency = bootstrap_task_concurrency();

        for peer in &ready_peers {
            let peer_sadstore_url = format!("http://sadstore.{}", peer.base_domain);
            let remote_client = kels_core::SadStoreClient::new(&peer_sadstore_url)?;

            let mut cursor: Option<cesr::Digest256> = None;
            loop {
                let page = match remote_client
                    .fetch_sad_objects(self.signer.as_ref(), cursor.as_ref(), self.config.page_size)
                    .await
                {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("Failed to fetch SAD objects from {}: {}", peer.node_id, e);
                        break;
                    }
                };

                // Bound per-page concurrency. Each task does
                // existence-check → fetch → post. At 1060 objects
                // sequential took 3:05; bounded parallel keeps the local
                // sadstore from being saturated by an unbounded fan-out.
                let saids = page.saids.clone();
                let synced: u64 = stream::iter(saids)
                    .map(|said| {
                        let local = local_client.clone();
                        let remote = remote_client.clone();
                        async move {
                            match local.sad_object_exists(&said).await {
                                Ok(true) => return 0u64,
                                Ok(false) => {}
                                Err(e) => {
                                    debug!("Failed to check SAD object {} existence: {}", said, e);
                                    return 0;
                                }
                            }
                            match remote.get_sad_object(&said).await {
                                Ok(object) => match local.post_sad_object(&object).await {
                                    Ok(_) => 1,
                                    Err(e) => {
                                        debug!("Failed to store SAD object {}: {}", said, e);
                                        0
                                    }
                                },
                                Err(e) => {
                                    debug!("Failed to fetch SAD object {} from peer: {}", said, e);
                                    0
                                }
                            }
                        }
                    })
                    .buffer_unordered(concurrency)
                    .fold(0u64, |acc, n| async move { acc + n })
                    .await;
                total_synced += synced;

                cursor = page.next_cursor;
                if cursor.is_none() {
                    break;
                }
            }
        }

        info!(
            "SAD object preload complete: {} objects synced",
            total_synced
        );
        Ok(())
    }

    /// Preload Identity Event Logs (IELs) from Ready peers.
    ///
    /// Lists IEL prefixes from each Ready peer's SADStore, compares with
    /// local state, and syncs any chains that are missing or behind. Mirrors
    /// `preload_sad_events` for the IEL primitive (#172). Sequenced after
    /// `preload_sad_objects` (so policy SAD objects referenced by IEL events
    /// are present) and before `preload_sad_events` (so SE chains binding to
    /// IEL events can resolve those bindings).
    pub async fn preload_iels(&self) -> Result<(), BootstrapError> {
        let ready_peers = self.get_ready_peers().await;

        if ready_peers.is_empty() {
            info!("No Ready peers found for IEL preload");
            return Ok(());
        }

        info!(
            "Preloading Identity Event Logs from {} Ready peer(s)...",
            ready_peers.len()
        );

        let local_client = kels_core::SadStoreClient::new(&self.config.sadstore_url)?;
        let mut synced_chains = 0usize;
        let concurrency = bootstrap_task_concurrency();

        for peer in &ready_peers {
            let peer_sadstore_url = format!("http://sadstore.{}", peer.base_domain);
            let remote_client = kels_core::SadStoreClient::new(&peer_sadstore_url)?;
            let peer_node_id = peer.node_id.clone();

            let mut cursor: Option<cesr::Digest256> = None;
            loop {
                let page = match remote_client
                    .fetch_iel_prefixes(
                        self.signer.as_ref(),
                        cursor.as_ref(),
                        self.config.page_size,
                    )
                    .await
                {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("Failed to fetch IEL prefixes from {}: {}", peer.node_id, e);
                        break;
                    }
                };

                // Bound per-page concurrency. Each task does
                // effective-SAID compare → forward_identity_events.
                // Sequential at scale stalled SE preload behind this
                // (~3:32 for 34 chains observed); bounded parallel keeps
                // the local sadstore submit pipeline saturated without
                // overwhelming it.
                let prefixes = page.prefixes.clone();
                let synced: usize = stream::iter(prefixes)
                    .map(|state| {
                        let local = local_client.clone();
                        let remote = remote_client.clone();
                        let peer_node_id = peer_node_id.clone();
                        async move {
                            let local_said = local
                                .fetch_iel_effective_said(&state.prefix)
                                .await
                                .ok()
                                .flatten()
                                .map(|(s, _)| s);

                            if local_said.as_deref() == Some(state.said.as_ref()) {
                                return 0usize;
                            }

                            let since_digest = local_said
                                .as_deref()
                                .and_then(|s| cesr::Digest256::from_qb64(s).ok());
                            let source = match remote.as_iel_source() {
                                Ok(s) => s,
                                Err(e) => {
                                    warn!("Failed to build IEL source for {}: {}", state.prefix, e);
                                    return 0;
                                }
                            };
                            let sink = match local.as_iel_sink() {
                                Ok(s) => s,
                                Err(e) => {
                                    warn!("Failed to build IEL sink for {}: {}", state.prefix, e);
                                    return 0;
                                }
                            };
                            match kels_core::forward_identity_events(
                                &state.prefix,
                                &source,
                                &sink,
                                kels_core::page_size(),
                                kels_core::max_pages(),
                                since_digest.as_ref(),
                            )
                            .await
                            {
                                Ok(()) => 1,
                                Err(e) => {
                                    warn!(
                                        "Failed to sync IEL {} from {} during bootstrap: {}",
                                        state.prefix, peer_node_id, e
                                    );
                                    0
                                }
                            }
                        }
                    })
                    .buffer_unordered(concurrency)
                    .fold(0usize, |acc, n| async move { acc + n })
                    .await;
                synced_chains += synced;

                cursor = page.next_cursor;
                if cursor.is_none() {
                    break;
                }
            }
        }

        info!("IEL preload complete: {} chains synced", synced_chains);
        Ok(())
    }

    /// Preload SAD events from Ready peers.
    ///
    /// Lists SEL prefixes from each Ready peer's SADStore, compares with local
    /// state, and syncs any chains that are missing or behind.
    pub async fn preload_sad_events(&self) -> Result<(), BootstrapError> {
        let ready_peers = self.get_ready_peers().await;

        if ready_peers.is_empty() {
            info!("No Ready peers found for SAD preload");
            return Ok(());
        }

        info!(
            "Preloading SAD Event Logs from {} Ready peer(s)...",
            ready_peers.len()
        );

        let local_client = kels_core::SadStoreClient::new(&self.config.sadstore_url)?;
        let mut synced_chains = 0usize;
        let concurrency = bootstrap_task_concurrency();

        for peer in &ready_peers {
            let peer_sadstore_url = format!("http://sadstore.{}", peer.base_domain);
            let remote_client = kels_core::SadStoreClient::new(&peer_sadstore_url)?;
            let peer_node_id = peer.node_id.clone();

            let mut cursor: Option<cesr::Digest256> = None;
            loop {
                let page = match remote_client
                    .fetch_sel_prefixes(
                        self.signer.as_ref(),
                        cursor.as_ref(),
                        self.config.page_size,
                    )
                    .await
                {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("Failed to fetch SAD prefixes from {}: {}", peer.node_id, e);
                        break;
                    }
                };

                // Bound per-page concurrency. Same posture as IEL preload
                // above: each task does effective-SAID compare → forward.
                let prefixes = page.prefixes.clone();
                let synced: usize = stream::iter(prefixes)
                    .map(|state| {
                        let local = local_client.clone();
                        let remote = remote_client.clone();
                        let peer_node_id = peer_node_id.clone();
                        async move {
                            let local_said = local
                                .fetch_sel_effective_said(&state.prefix)
                                .await
                                .ok()
                                .flatten()
                                .map(|(s, _)| s);

                            if local_said.as_deref() == Some(state.said.as_ref()) {
                                return 0usize;
                            }

                            let since_digest = local_said
                                .as_deref()
                                .and_then(|s| cesr::Digest256::from_qb64(s).ok());
                            let source = match remote.as_sel_source() {
                                Ok(s) => s,
                                Err(e) => {
                                    warn!(
                                        "Failed to build SEL source for {}: {}",
                                        state.prefix, e
                                    );
                                    return 0;
                                }
                            };
                            let sink = match local.as_sel_sink() {
                                Ok(s) => s,
                                Err(e) => {
                                    warn!("Failed to build SEL sink for {}: {}", state.prefix, e);
                                    return 0;
                                }
                            };
                            match kels_core::forward_sel_events(
                                &state.prefix,
                                &source,
                                &sink,
                                kels_core::page_size(),
                                kels_core::max_pages(),
                                since_digest.as_ref(),
                            )
                            .await
                            {
                                Ok(()) => 1,
                                Err(e) => {
                                    warn!(
                                        "Failed to sync SAD Event Log {} from {} during bootstrap: {}",
                                        state.prefix, peer_node_id, e
                                    );
                                    0
                                }
                            }
                        }
                    })
                    .buffer_unordered(concurrency)
                    .fold(0usize, |acc, n| async move { acc + n })
                    .await;
                synced_chains += synced;

                cursor = page.next_cursor;
                if cursor.is_none() {
                    break;
                }
            }
        }

        info!(
            "SAD Event Log preload complete: {} chains synced",
            synced_chains
        );
        Ok(())
    }

    /// Get peers from allowlist that are ready (respond to /ready with success).
    async fn get_ready_peers(&self) -> Vec<kels_core::Peer> {
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
    pub async fn is_peer_authorized(&self, peer_kel_prefix: &str) -> Result<bool, BootstrapError> {
        // Try each registry URL until one succeeds
        for url in &self.urls {
            let client = KelsRegistryClient::new(url)?;
            match client.fetch_peers().await {
                Ok(peers_response) => {
                    return Ok(peers_response.peers.iter().any(|history| {
                        history
                            .records
                            .last()
                            .map(|peer| peer.kel_prefix.as_ref() == peer_kel_prefix && peer.active)
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
    async fn is_peer_ready(&self, peer: &kels_core::Peer) -> bool {
        let host = peer
            .gossip_addr
            .rsplit_once(':')
            .map_or(peer.gossip_addr.as_str(), |(h, _)| h);
        let url = format!("http://{}:{}/ready", host, self.config.http_port);
        match self.http_client.get(&url).send().await {
            Ok(response) => response.status().is_success(),
            Err(e) => {
                debug!("Peer {} not ready: {}", peer.kel_prefix, e);
                false
            }
        }
    }

    /// Get the URL to use for node-to-node sync.
    fn get_sync_url(peer: &kels_core::Peer) -> String {
        format!("http://kels.{}", peer.base_domain)
    }

    /// Sync KELs from bootstrap peers.
    ///
    /// This collects all unique prefixes from all peers, assigns each prefix to
    /// its source peer (the peer that reported it), then batch-fetches KELs
    /// (50 at a time) from each peer.
    async fn sync_from_peers(&self, peers: &[kels_core::Peer]) -> Result<(), BootstrapError> {
        if peers.is_empty() {
            return Ok(());
        }

        let local_client = KelsClient::new(&self.config.kels_url)?;

        // Step 1: Collect all unique prefixes from all peers that need syncing.
        // Track (since_said, source_kels_url, source_peer_kel_prefix) per kel prefix.
        info!("Collecting prefixes from {} peer(s)...", peers.len());
        let mut all_prefixes: HashMap<
            cesr::Digest256,
            (Option<cesr::Digest256>, String, cesr::Digest256),
        > = HashMap::new();

        for peer in peers {
            let peer_url = Self::get_sync_url(peer);
            let peer_client = KelsClient::new(&peer_url)?;
            let mut cursor: Option<cesr::Digest256> = None;

            loop {
                match peer_client
                    .fetch_prefixes(self.signer.as_ref(), cursor.as_ref(), self.config.page_size)
                    .await
                {
                    Ok(page) => {
                        for state in &page.prefixes {
                            if let Some(since) = self.sync_check(state, &local_client).await {
                                all_prefixes.entry(state.prefix).or_insert((
                                    since,
                                    peer_url.to_string(),
                                    peer.kel_prefix,
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

        // Step 2: Sync prefixes with bounded concurrency. Unbounded
        // `join_all` saturates the source peer at scale (observed at 579
        // prefixes / 1 source: 282 of 579 syncs failed). Mirror SAD AE's
        // posture via `bootstrap_task_concurrency()`.
        let tasks = all_prefixes.into_iter().map(
            |(prefix, (since, source_url, source_peer_kel_prefix))| {
                let local = local_client.clone();
                async move {
                    let remote = match KelsClient::new(&source_url) {
                        Ok(c) => c,
                        Err(e) => {
                            warn!(prefix = %prefix, error = %e, "Failed to build HTTP client for KEL sync");
                            return (prefix, source_peer_kel_prefix, crate::sync::RepairResult::Failed);
                        }
                    };
                    let result =
                        crate::sync::sync_prefix(&remote, &local, &prefix, since.as_ref()).await;
                    (prefix, source_peer_kel_prefix, result)
                }
            },
        );

        let concurrency = bootstrap_task_concurrency();
        let results: Vec<_> = stream::iter(tasks)
            .buffer_unordered(concurrency)
            .collect()
            .await;

        let mut total_synced = 0;
        let mut total_errors = 0;

        for (prefix, source_peer_kel_prefix, result) in results {
            match result {
                crate::sync::RepairResult::Repaired => {
                    debug!("Synced KEL for {}", prefix);
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
                            &source_peer_kel_prefix,
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
    ) -> Option<Option<cesr::Digest256>> {
        match local_client
            .fetch_effective_said(&remote_state.prefix)
            .await
        {
            Ok(Some((local_effective, _))) => {
                if local_effective.as_ref() == remote_state.said.as_ref() {
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
    use cesr::test_digest;

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
            kels_core::ErrorCode::InternalError,
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
        let kels_error = KelsError::ServerError(
            "server error".to_string(),
            kels_core::ErrorCode::InternalError,
        );
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
        let peer = kels_core::Peer {
            said: test_digest("test-said"),
            prefix: test_digest("test-prefix"),
            previous: None,
            version: 1,
            created_at: verifiable_storage::StorageDatetime::now(),
            kel_prefix: test_digest("test-peer"),
            node_id: "node-1".to_string(),
            authorizing_kel: test_digest("authorizing-kel"),
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
