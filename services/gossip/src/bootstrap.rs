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
use tokio::sync::Mutex;
use tokio::time::Duration;
use tracing::{debug, info, warn};

use kels_core::{KelsClient, KelsError, KelsRegistryClient, PeerSigner};
use thiserror::Error;

use crate::pending::{ParkRecord, ParkSubject, PendingMap};
use crate::sync::{deferred_deps_to_park_inputs, try_parse_deferred_deps};

/// Concurrency cap for bootstrap preload tasks (KEL / SAD object / IEL /
/// SE). Mirrors `KELS_SAD_AE_TASK_CONCURRENCY`'s posture: bootstrap fires
/// the whole world at once on cold-start, so an unbounded `join_all`
/// saturates the source peer (observed: 282 of 579 KELs failed to sync at
/// scale). Default 4 — bootstrap correctness matters more than speed, and
/// staggered-rollout federation events around vote time create a resource
/// storm at ~5 min post-vote when later nodes come online while earlier
/// nodes are still bootstrapping (8 caused IEL submit failures on
/// cross-pressure between bootstrap-fetch and AE+gossip submits). RustFS
/// has known concurrency-scaling issues (upstream #1016); the structural
/// fix for the tx-holds-RustFS-read pattern is #157. Tune via env on
/// deployments with different capacity profiles.
fn bootstrap_task_concurrency() -> usize {
    kels_core::env_usize("KELS_BOOTSTRAP_CONCURRENCY", 4)
}

#[derive(Error, Debug)]
pub enum BootstrapError {
    #[error("KELS/Registry error: {0}")]
    Kels(#[from] KelsError),
    #[error("Bootstrap failed: {0}")]
    Failed(String),
    #[error("Failed to sync: {0}")]
    Sync(String),
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
    /// Shared deferred-deps pending map. When set, IEL/SE preload failures
    /// carrying a typed-422 deferred-deps body are parked here so the live
    /// `kel_updates` / `iel_updates` / `sad_updates` drainers replay them on
    /// dep arrival. When `None` (no Redis), preload reverts to fail-and-skip
    /// — gossip + AE backstop is the only recovery path.
    pending: Option<PendingMap>,
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
            pending: None,
        })
    }

    /// Set the Redis connection for stale prefix tracking.
    pub fn with_redis(mut self, redis: Arc<redis::aio::ConnectionManager>) -> Self {
        self.redis = Some(redis);
        self
    }

    /// Wire the deferred-deps pending map. When set, IEL/SE preload failures
    /// that surface as typed-422 are parked into the same Redis-backed map
    /// the inline gossip POST handler uses, so drain on dep arrival picks
    /// them up automatically.
    pub fn with_pending(mut self, pending: PendingMap) -> Self {
        self.pending = Some(pending);
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

    /// Preload SAD objects from Ready peers via sort-merge against local
    /// listing.
    ///
    /// Both sides return SAIDs in `sad_said ASC`; the merge driver
    /// (`bootstrap_merge`) walks them pairwise, enqueues remote-only SAIDs,
    /// and drains via bounded-concurrency fetch+post. Eliminates the
    /// per-object existence-check storm: a federation-symmetric peer's
    /// merge against a caught-up local degenerates to two paginated
    /// listings with zero sync work.
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
        let concurrency = bootstrap_task_concurrency();
        let page_size = self.config.page_size;
        let inflight = crate::telemetry::LocalInflight::new("bootstrap-sad-objects");
        let mut total_synced: usize = 0;
        let mut total_failed: usize = 0;

        for peer in &ready_peers {
            let peer_sadstore_url = format!("http://sadstore.{}", peer.base_domain);
            let remote_client = kels_core::SadStoreClient::new(&peer_sadstore_url)?;

            let remote_for_fetch = remote_client.clone();
            let signer = self.signer.clone();
            let remote_stream = crate::bootstrap_merge::SortedKeyStream::new(
                move |cursor: Option<cesr::Digest256>| {
                    let client = remote_for_fetch.clone();
                    let signer = signer.clone();
                    async move {
                        let resp = client
                            .fetch_sad_objects(signer.as_ref(), cursor.as_ref(), page_size)
                            .await?;
                        Ok::<_, KelsError>(crate::bootstrap_merge::KeyPage {
                            keys: resp.saids,
                            next_cursor: resp.next_cursor,
                        })
                    }
                },
            );

            let local_for_fetch = local_client.clone();
            let signer = self.signer.clone();
            let inflight_fetch = inflight.clone();
            let local_stream = crate::bootstrap_merge::SortedKeyStream::new(
                move |cursor: Option<cesr::Digest256>| {
                    let client = local_for_fetch.clone();
                    let signer = signer.clone();
                    let inflight = inflight_fetch.clone();
                    async move {
                        let _g = inflight.enter("fetch_sad_objects");
                        let resp = client
                            .fetch_sad_objects(signer.as_ref(), cursor.as_ref(), page_size)
                            .await?;
                        Ok::<_, KelsError>(crate::bootstrap_merge::KeyPage {
                            keys: resp.saids,
                            next_cursor: resp.next_cursor,
                        })
                    }
                },
            );

            let local_for_sync = local_client.clone();
            let remote_for_sync = remote_client.clone();
            let peer_node_id = peer.node_id.clone();
            let inflight_sync = inflight.clone();
            let stats = match crate::bootstrap_merge::merge_sync(
                remote_stream,
                local_stream,
                page_size,
                concurrency,
                move |said: cesr::Digest256| {
                    let local = local_for_sync.clone();
                    let remote = remote_for_sync.clone();
                    let peer_node_id = peer_node_id.clone();
                    let inflight = inflight_sync.clone();
                    async move {
                        match remote.get_sad_object(&said).await {
                            Ok(object) => {
                                let _g = inflight.enter("post_sad_object");
                                match local.post_sad_object(&object).await {
                                    Ok(_) => true,
                                    Err(e) => {
                                        debug!(
                                            "Failed to store SAD object {} from {}: {}",
                                            said, peer_node_id, e
                                        );
                                        false
                                    }
                                }
                            }
                            Err(e) => {
                                debug!(
                                    "Failed to fetch SAD object {} from {}: {}",
                                    said, peer_node_id, e
                                );
                                false
                            }
                        }
                    }
                },
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        "SAD object merge-sync against {} failed: {}",
                        peer.node_id, e
                    );
                    continue;
                }
            };
            total_synced += stats.synced;
            total_failed += stats.failed;
        }

        info!(
            "SAD object preload complete: {} objects synced, {} failed",
            total_synced, total_failed
        );

        if total_failed > 0 {
            return Err(BootstrapError::Sync(format!(
                "Failed to preload {} sad objects",
                total_failed
            )));
        }

        Ok(())
    }

    /// Preload Identity Event Logs (IELs) from Ready peers via sort-merge
    /// against local listing.
    ///
    /// Both sides return prefixes in `prefix ASC`; the merge enqueues
    /// remote-only prefixes and drains by full-chain `forward_identity_events`
    /// (no `since` — bootstrap only ensures the prefix is present locally;
    /// AE catches event-level deltas after the join). Sequenced after
    /// `preload_sad_objects` (policy SAD objects referenced by IEL events)
    /// and before `preload_sad_events` (SE chains binding to IEL events).
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
        let concurrency = bootstrap_task_concurrency();
        let page_size = self.config.page_size;
        let inflight = crate::telemetry::LocalInflight::new("bootstrap-iel");
        let mut total_synced: usize = 0;
        let mut total_failed: usize = 0;

        let mut total_parked: usize = 0;
        for peer in &ready_peers {
            let peer_sadstore_url = format!("http://sadstore.{}", peer.base_domain);
            let remote_client = kels_core::SadStoreClient::new(&peer_sadstore_url)?;

            // Remote effective SAIDs captured during the remote listing
            // pagination, indexed by chain prefix. The `sync_one` closure
            // reads this map to construct `ParkSubject::IelChain` when
            // parking a deferred-deps failure: drain replays from the
            // recorded origin/effective state, matching the inline POST
            // park flow's contract.
            let remote_eff_saids: Arc<Mutex<HashMap<cesr::Digest256, cesr::Digest256>>> =
                Arc::new(Mutex::new(HashMap::new()));

            let remote_for_fetch = remote_client.clone();
            let signer = self.signer.clone();
            let eff_saids_for_fetch = remote_eff_saids.clone();
            let remote_stream = crate::bootstrap_merge::SortedKeyStream::new(
                move |cursor: Option<cesr::Digest256>| {
                    let client = remote_for_fetch.clone();
                    let signer = signer.clone();
                    let eff_saids = eff_saids_for_fetch.clone();
                    async move {
                        let resp = client
                            .fetch_iel_prefixes(signer.as_ref(), cursor.as_ref(), page_size)
                            .await?;
                        let mut keys = Vec::with_capacity(resp.prefixes.len());
                        let mut map = eff_saids.lock().await;
                        for s in resp.prefixes {
                            map.insert(s.prefix, s.said);
                            keys.push(s.prefix);
                        }
                        drop(map);
                        Ok::<_, KelsError>(crate::bootstrap_merge::KeyPage {
                            keys,
                            next_cursor: resp.next_cursor,
                        })
                    }
                },
            );

            let local_for_fetch = local_client.clone();
            let signer = self.signer.clone();
            let inflight_fetch = inflight.clone();
            let local_stream = crate::bootstrap_merge::SortedKeyStream::new(
                move |cursor: Option<cesr::Digest256>| {
                    let client = local_for_fetch.clone();
                    let signer = signer.clone();
                    let inflight = inflight_fetch.clone();
                    async move {
                        let _g = inflight.enter("fetch_iel_prefixes");
                        let resp = client
                            .fetch_iel_prefixes(signer.as_ref(), cursor.as_ref(), page_size)
                            .await?;
                        let keys = resp.prefixes.into_iter().map(|s| s.prefix).collect();
                        Ok::<_, KelsError>(crate::bootstrap_merge::KeyPage {
                            keys,
                            next_cursor: resp.next_cursor,
                        })
                    }
                },
            );

            let local_for_sync = local_client.clone();
            let remote_for_sync = remote_client.clone();
            let peer_node_id = peer.node_id.clone();
            let peer_kel_prefix = peer.kel_prefix;
            let inflight_sync = inflight.clone();
            let pending_for_sync = self.pending.clone();
            let eff_saids_for_sync = remote_eff_saids.clone();
            let parked_counter: Arc<std::sync::atomic::AtomicUsize> =
                Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let parked_for_sync = parked_counter.clone();
            let stats = match crate::bootstrap_merge::merge_sync(
                remote_stream,
                local_stream,
                page_size,
                concurrency,
                move |prefix: cesr::Digest256| {
                    let local = local_for_sync.clone();
                    let remote = remote_for_sync.clone();
                    let peer_node_id = peer_node_id.clone();
                    let inflight = inflight_sync.clone();
                    let pending = pending_for_sync.clone();
                    let eff_saids = eff_saids_for_sync.clone();
                    let parked = parked_for_sync.clone();
                    async move {
                        let source = match remote.as_iel_source() {
                            Ok(s) => s,
                            Err(e) => {
                                warn!("Failed to build IEL source for {}: {}", prefix, e);
                                return false;
                            }
                        };
                        let sink = match local.as_iel_sink() {
                            Ok(s) => s,
                            Err(e) => {
                                warn!("Failed to build IEL sink for {}: {}", prefix, e);
                                return false;
                            }
                        };
                        let _g = inflight.enter("forward_identity_events");
                        match kels_core::forward_identity_events(
                            &prefix,
                            &source,
                            &sink,
                            kels_core::page_size(),
                            kels_core::max_pages(),
                            None,
                        )
                        .await
                        {
                            Ok(()) => true,
                            Err(e) => {
                                if let Some(pending) = pending.as_ref()
                                    && let Some(response) = try_parse_deferred_deps(&e)
                                {
                                    let remote_eff = eff_saids.lock().await.get(&prefix).copied();
                                    if let Some(remote_eff_said) = remote_eff {
                                        let (deps, chain_eff) =
                                            deferred_deps_to_park_inputs(&response);
                                        let subject = ParkSubject::IelChain {
                                            prefix,
                                            remote_eff_said,
                                        };
                                        let record = match ParkRecord::create(
                                            subject,
                                            peer_kel_prefix,
                                            deps,
                                        ) {
                                            Ok(r) => r,
                                            Err(rec_err) => {
                                                warn!(
                                                    "ParkRecord::create failed during IEL bootstrap park: {}",
                                                    rec_err
                                                );
                                                warn!(
                                                    "Failed to sync IEL {} from {} during bootstrap: {}",
                                                    prefix, peer_node_id, e
                                                );
                                                return false;
                                            }
                                        };
                                        match pending
                                            .park(&record, |p| chain_eff.get(p).copied())
                                            .await
                                        {
                                            Ok(()) => {
                                                debug!(
                                                    record_said = %record.said,
                                                    prefix = %prefix,
                                                    origin = %peer_kel_prefix,
                                                    "parked bootstrap IEL deferred-deps for drain"
                                                );
                                                parked.fetch_add(
                                                    1,
                                                    std::sync::atomic::Ordering::Relaxed,
                                                );
                                                return false;
                                            }
                                            Err(park_err) => {
                                                warn!(
                                                    record_said = %record.said,
                                                    "PendingMap::park failed during IEL bootstrap: {}",
                                                    park_err
                                                );
                                            }
                                        }
                                    }
                                }
                                warn!(
                                    "Failed to sync IEL {} from {} during bootstrap: {}",
                                    prefix, peer_node_id, e
                                );
                                false
                            }
                        }
                    }
                },
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    warn!("IEL merge-sync against {} failed: {}", peer.node_id, e);
                    continue;
                }
            };
            total_synced += stats.synced;
            total_failed += stats.failed;
            total_parked += parked_counter.load(std::sync::atomic::Ordering::Relaxed);
        }

        info!(
            "IEL preload complete: {} chains synced, {} failed ({} parked for drain — will retry)",
            total_synced, total_failed, total_parked
        );

        if total_failed > 0 {
            return Err(BootstrapError::Sync(format!(
                "Failed to preload {} IELs (incl. {} parked for drain)",
                total_failed, total_parked
            )));
        }

        Ok(())
    }

    /// Preload SAD events from Ready peers.
    ///
    /// Lists SEL prefixes from each Ready peer's SADStore via sort-merge
    /// against local listing; syncs missing prefixes by full-chain
    /// `forward_sel_events` (no `since` — bootstrap only ensures the prefix
    /// is present; AE catches event-level deltas after the join).
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
        let concurrency = bootstrap_task_concurrency();
        let page_size = self.config.page_size;
        let inflight = crate::telemetry::LocalInflight::new("bootstrap-sel");
        let mut total_synced: usize = 0;
        let mut total_failed: usize = 0;

        let mut total_parked: usize = 0;
        for peer in &ready_peers {
            let peer_sadstore_url = format!("http://sadstore.{}", peer.base_domain);
            let remote_client = kels_core::SadStoreClient::new(&peer_sadstore_url)?;

            // Mirrors the `preload_iels` shape — capture remote effective
            // SAID per SEL prefix so deferred-deps failures can park into
            // `ParkSubject::SelChain { prefix, remote_eff_said }`.
            let remote_eff_saids: Arc<Mutex<HashMap<cesr::Digest256, cesr::Digest256>>> =
                Arc::new(Mutex::new(HashMap::new()));

            let remote_for_fetch = remote_client.clone();
            let signer = self.signer.clone();
            let eff_saids_for_fetch = remote_eff_saids.clone();
            let remote_stream = crate::bootstrap_merge::SortedKeyStream::new(
                move |cursor: Option<cesr::Digest256>| {
                    let client = remote_for_fetch.clone();
                    let signer = signer.clone();
                    let eff_saids = eff_saids_for_fetch.clone();
                    async move {
                        let resp = client
                            .fetch_sel_prefixes(signer.as_ref(), cursor.as_ref(), page_size)
                            .await?;
                        let mut keys = Vec::with_capacity(resp.prefixes.len());
                        let mut map = eff_saids.lock().await;
                        for s in resp.prefixes {
                            map.insert(s.prefix, s.said);
                            keys.push(s.prefix);
                        }
                        drop(map);
                        Ok::<_, KelsError>(crate::bootstrap_merge::KeyPage {
                            keys,
                            next_cursor: resp.next_cursor,
                        })
                    }
                },
            );

            let local_for_fetch = local_client.clone();
            let signer = self.signer.clone();
            let inflight_fetch = inflight.clone();
            let local_stream = crate::bootstrap_merge::SortedKeyStream::new(
                move |cursor: Option<cesr::Digest256>| {
                    let client = local_for_fetch.clone();
                    let signer = signer.clone();
                    let inflight = inflight_fetch.clone();
                    async move {
                        let _g = inflight.enter("fetch_sel_prefixes");
                        let resp = client
                            .fetch_sel_prefixes(signer.as_ref(), cursor.as_ref(), page_size)
                            .await?;
                        let keys = resp.prefixes.into_iter().map(|s| s.prefix).collect();
                        Ok::<_, KelsError>(crate::bootstrap_merge::KeyPage {
                            keys,
                            next_cursor: resp.next_cursor,
                        })
                    }
                },
            );

            let local_for_sync = local_client.clone();
            let remote_for_sync = remote_client.clone();
            let peer_node_id = peer.node_id.clone();
            let peer_kel_prefix = peer.kel_prefix;
            let inflight_sync = inflight.clone();
            let pending_for_sync = self.pending.clone();
            let eff_saids_for_sync = remote_eff_saids.clone();
            let parked_counter: Arc<std::sync::atomic::AtomicUsize> =
                Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let parked_for_sync = parked_counter.clone();
            let stats = match crate::bootstrap_merge::merge_sync(
                remote_stream,
                local_stream,
                page_size,
                concurrency,
                move |prefix: cesr::Digest256| {
                    let local = local_for_sync.clone();
                    let remote = remote_for_sync.clone();
                    let peer_node_id = peer_node_id.clone();
                    let inflight = inflight_sync.clone();
                    let pending = pending_for_sync.clone();
                    let eff_saids = eff_saids_for_sync.clone();
                    let parked = parked_for_sync.clone();
                    async move {
                        let source = match remote.as_sel_source() {
                            Ok(s) => s,
                            Err(e) => {
                                warn!("Failed to build SEL source for {}: {}", prefix, e);
                                return false;
                            }
                        };
                        let sink = match local.as_sel_sink() {
                            Ok(s) => s,
                            Err(e) => {
                                warn!("Failed to build SEL sink for {}: {}", prefix, e);
                                return false;
                            }
                        };
                        let _g = inflight.enter("forward_sel_events");
                        match kels_core::forward_sel_events(
                            &prefix,
                            &source,
                            &sink,
                            kels_core::page_size(),
                            kels_core::max_pages(),
                            None,
                        )
                        .await
                        {
                            Ok(()) => true,
                            Err(e) => {
                                if let Some(pending) = pending.as_ref()
                                    && let Some(response) = try_parse_deferred_deps(&e)
                                {
                                    let remote_eff = eff_saids.lock().await.get(&prefix).copied();
                                    if let Some(remote_eff_said) = remote_eff {
                                        let (deps, chain_eff) =
                                            deferred_deps_to_park_inputs(&response);
                                        let subject = ParkSubject::SelChain {
                                            prefix,
                                            remote_eff_said,
                                        };
                                        let record = match ParkRecord::create(
                                            subject,
                                            peer_kel_prefix,
                                            deps,
                                        ) {
                                            Ok(r) => r,
                                            Err(rec_err) => {
                                                warn!(
                                                    "ParkRecord::create failed during SEL bootstrap park: {}",
                                                    rec_err
                                                );
                                                warn!(
                                                    "Failed to sync SAD Event Log {} from {} during bootstrap: {}",
                                                    prefix, peer_node_id, e
                                                );
                                                return false;
                                            }
                                        };
                                        match pending
                                            .park(&record, |p| chain_eff.get(p).copied())
                                            .await
                                        {
                                            Ok(()) => {
                                                debug!(
                                                    record_said = %record.said,
                                                    prefix = %prefix,
                                                    origin = %peer_kel_prefix,
                                                    "parked bootstrap SEL deferred-deps for drain"
                                                );
                                                parked.fetch_add(
                                                    1,
                                                    std::sync::atomic::Ordering::Relaxed,
                                                );
                                                return false;
                                            }
                                            Err(park_err) => {
                                                warn!(
                                                    record_said = %record.said,
                                                    "PendingMap::park failed during SEL bootstrap: {}",
                                                    park_err
                                                );
                                            }
                                        }
                                    }
                                }
                                warn!(
                                    "Failed to sync SAD Event Log {} from {} during bootstrap: {}",
                                    prefix, peer_node_id, e
                                );
                                false
                            }
                        }
                    }
                },
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        "SAD Event Log merge-sync against {} failed: {}",
                        peer.node_id, e
                    );
                    continue;
                }
            };
            total_synced += stats.synced;
            total_failed += stats.failed;
            total_parked += parked_counter.load(std::sync::atomic::Ordering::Relaxed);
        }

        info!(
            "SAD Event Log preload complete: {} chains synced, {} failed ({} parked for drain — will retry)",
            total_synced, total_failed, total_parked
        );

        if total_failed > 0 {
            return Err(BootstrapError::Sync(format!(
                "Failed to preload {} SELs (incl. {} parked for drain)",
                total_failed, total_parked
            )));
        }

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

    /// Sync KELs from bootstrap peers via sort-merge against local listing.
    ///
    /// Per peer, walks remote and local KEL prefix listings in lockstep and
    /// enqueues remote-only prefixes for full-chain sync (`sync_prefix` with
    /// `since=None`). Mirrors the SAD-objects/IEL/SE preload shape: bootstrap
    /// only ensures the prefix is present locally; AE catches event-level
    /// deltas after the join. Eliminates the per-prefix
    /// `fetch_effective_said` storm (observed at 579 prefixes × N peers,
    /// 282 of 579 syncs failed under saturation).
    async fn sync_from_peers(&self, peers: &[kels_core::Peer]) -> Result<(), BootstrapError> {
        if peers.is_empty() {
            return Ok(());
        }

        let local_client = KelsClient::new(&self.config.kels_url)?;
        let concurrency = bootstrap_task_concurrency();
        let page_size = self.config.page_size;
        let inflight = crate::telemetry::LocalInflight::new("bootstrap-kel");
        let mut total_synced: usize = 0;
        let mut total_failed: usize = 0;

        for peer in peers {
            let peer_url = Self::get_sync_url(peer);
            let remote_client = KelsClient::new(&peer_url)?;

            let remote_for_fetch = remote_client.clone();
            let signer = self.signer.clone();
            let remote_stream = crate::bootstrap_merge::SortedKeyStream::new(
                move |cursor: Option<cesr::Digest256>| {
                    let client = remote_for_fetch.clone();
                    let signer = signer.clone();
                    async move {
                        let resp = client
                            .fetch_prefixes(signer.as_ref(), cursor.as_ref(), page_size)
                            .await?;
                        let keys = resp.prefixes.into_iter().map(|s| s.prefix).collect();
                        Ok::<_, KelsError>(crate::bootstrap_merge::KeyPage {
                            keys,
                            next_cursor: resp.next_cursor,
                        })
                    }
                },
            );

            let local_for_fetch = local_client.clone();
            let signer = self.signer.clone();
            let local_stream = crate::bootstrap_merge::SortedKeyStream::new(
                move |cursor: Option<cesr::Digest256>| {
                    let client = local_for_fetch.clone();
                    let signer = signer.clone();
                    async move {
                        let resp = client
                            .fetch_prefixes(signer.as_ref(), cursor.as_ref(), page_size)
                            .await?;
                        let keys = resp.prefixes.into_iter().map(|s| s.prefix).collect();
                        Ok::<_, KelsError>(crate::bootstrap_merge::KeyPage {
                            keys,
                            next_cursor: resp.next_cursor,
                        })
                    }
                },
            );

            let local_for_sync = local_client.clone();
            let remote_for_sync = remote_client.clone();
            let peer_node_id = peer.node_id.clone();
            let inflight_sync = inflight.clone();
            let stats = match crate::bootstrap_merge::merge_sync(
                remote_stream,
                local_stream,
                page_size,
                concurrency,
                move |prefix: cesr::Digest256| {
                    let local = local_for_sync.clone();
                    let remote = remote_for_sync.clone();
                    let peer_node_id = peer_node_id.clone();
                    let inflight = inflight_sync.clone();
                    async move {
                        let _g = inflight.enter("sync_prefix");
                        match crate::sync::sync_prefix(&remote, &local, &prefix, None).await {
                            crate::sync::RepairResult::Repaired
                            | crate::sync::RepairResult::NoOp => true,
                            crate::sync::RepairResult::Contested => {
                                debug!(
                                    "KEL {} from {} contested during bootstrap (gossip handles)",
                                    prefix, peer_node_id
                                );
                                false
                            }
                            crate::sync::RepairResult::Failed => {
                                warn!(
                                    "Failed to sync KEL {} from {} during bootstrap",
                                    prefix, peer_node_id
                                );
                                false
                            }
                        }
                    }
                },
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    warn!("KEL merge-sync against {} failed: {}", peer.node_id, e);
                    continue;
                }
            };
            total_synced += stats.synced;
            total_failed += stats.failed;
        }

        info!(
            "KEL preload complete: {} prefixes synced, {} failed",
            total_synced, total_failed
        );

        if total_failed > 0 {
            return Err(BootstrapError::Sync(format!(
                "Failed to preload {} KELs",
                total_failed
            )));
        }

        Ok(())
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
