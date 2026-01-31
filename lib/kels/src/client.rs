//! KELS HTTP Client

use crate::error::KelsError;
use crate::kel::Kel;
use crate::types::{
    BatchKelsRequest, BatchSubmitResponse, ErrorResponse, KelMergeResult, KelResponse, NodeInfo,
    NodeStatus, NodesResponse, SignedKeyEvent,
};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

#[cfg(feature = "redis")]
use redis::aio::ConnectionManager;

#[doc(hidden)]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct CachedKelEntry {
    kel: Kel,
    last_access: u64,
}

#[doc(hidden)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct KelCacheInner {
    entries: HashMap<String, CachedKelEntry>,
    access_counter: u64,
    max_entries: usize,
}

impl KelCacheInner {
    fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            access_counter: 0,
            max_entries,
        }
    }

    fn set(&mut self, prefix: String, kel: Kel) {
        if self.entries.len() >= self.max_entries
            && !self.entries.contains_key(&prefix)
            && let Some(lru_key) = self
                .entries
                .iter()
                .min_by_key(|(_, v)| v.last_access)
                .map(|(k, _)| k.clone())
        {
            self.entries.remove(&lru_key);
        }

        self.access_counter += 1;
        self.entries.insert(
            prefix,
            CachedKelEntry {
                kel,
                last_access: self.access_counter,
            },
        );
    }

    fn invalidate(&mut self, prefix: &str) {
        self.entries.remove(prefix);
    }

    fn resize(&mut self, max_entries: usize) {
        self.max_entries = max_entries;
        while self.entries.len() > self.max_entries {
            if let Some(lru_key) = self
                .entries
                .iter()
                .min_by_key(|(_, v)| v.last_access)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&lru_key);
            } else {
                break;
            }
        }
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.access_counter = 0;
    }
}

/// Redis-backed KEL cache. No local caching - must see latest state from Redis for anchor verification.
#[cfg(feature = "redis")]
#[derive(Clone)]
pub struct RedisKelCache {
    conn: ConnectionManager,
    key_prefix: String,
}

#[cfg(feature = "redis")]
impl RedisKelCache {
    /// Entries never expire - eviction handled by Redis's maxmemory-policy.
    pub fn new(conn: ConnectionManager, key_prefix: &str) -> Self {
        Self {
            conn,
            key_prefix: key_prefix.to_string(),
        }
    }

    fn cache_key(&self, prefix: &str) -> String {
        format!("{}:{}", self.key_prefix, prefix)
    }

    pub async fn get(&self, prefix: &str) -> Result<Option<Kel>, KelsError> {
        use redis::AsyncCommands;
        let key = self.cache_key(prefix);
        let mut conn = self.conn.clone();
        let result: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| KelsError::CacheError(format!("Redis get failed: {}", e)))?;

        match result {
            Some(json) => {
                let events: Vec<SignedKeyEvent> = serde_json::from_str(&json)?;
                let kel = Kel::from_events(events, true)?;
                Ok(Some(kel))
            }
            None => Ok(None),
        }
    }

    pub async fn set(&self, prefix: &str, kel: &Kel) -> Result<(), KelsError> {
        use redis::AsyncCommands;
        let key = self.cache_key(prefix);
        let json = serde_json::to_string(kel.events())?;
        let mut conn = self.conn.clone();
        let _: () = conn
            .set(&key, &json)
            .await
            .map_err(|e| KelsError::CacheError(format!("Redis set failed: {}", e)))?;
        Ok(())
    }

    pub async fn invalidate(&self, prefix: &str) -> Result<(), KelsError> {
        use redis::AsyncCommands;
        let key = self.cache_key(prefix);
        let mut conn = self.conn.clone();
        let _: () = conn
            .del(&key)
            .await
            .map_err(|e| KelsError::CacheError(format!("Redis del failed: {}", e)))?;
        Ok(())
    }

    pub async fn clear(&self) -> Result<(), KelsError> {
        use redis::AsyncCommands;
        let pattern = format!("{}:*", self.key_prefix);
        let mut conn = self.conn.clone();
        let keys: Vec<String> = conn
            .keys(&pattern)
            .await
            .map_err(|e| KelsError::CacheError(format!("Redis keys failed: {}", e)))?;
        if !keys.is_empty() {
            conn.del::<_, ()>(keys)
                .await
                .map_err(|e| KelsError::CacheError(format!("Redis del failed: {}", e)))?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub enum KelCache {
    InMemory(Arc<RwLock<KelCacheInner>>),
    #[cfg(feature = "redis")]
    Redis(Box<RedisKelCache>),
}

#[derive(Clone, Debug)]
pub struct KelCacheConfig {
    pub max_entries: usize,
    pub enabled: bool,
}

impl Default for KelCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 256,
            enabled: true,
        }
    }
}

/// KELS API Client - fetches/submits key events, caches KELs for anchor verification
#[derive(Clone)]
pub struct KelsClient {
    base_url: String,
    client: reqwest::Client,
    cache: Option<KelCache>,
}

impl KelsClient {
    pub fn new(base_url: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        KelsClient {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
            cache: None,
        }
    }

    /// Create a client with a custom timeout (useful for latency testing).
    pub fn with_timeout(base_url: &str, timeout: Duration) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_default();
        KelsClient {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
            cache: None,
        }
    }

    pub fn with_caching(base_url: &str) -> Self {
        Self::with_cache_config(base_url, KelCacheConfig::default())
    }

    pub fn with_cache_config(base_url: &str, config: KelCacheConfig) -> Self {
        let cache = if config.enabled {
            Some(KelCache::InMemory(Arc::new(RwLock::new(
                KelCacheInner::new(config.max_entries),
            ))))
        } else {
            None
        };

        KelsClient {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
            cache,
        }
    }

    #[cfg(feature = "redis")]
    pub fn with_redis_cache(base_url: &str, redis_cache: RedisKelCache) -> Self {
        KelsClient {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
            cache: Some(KelCache::Redis(Box::new(redis_cache))),
        }
    }

    /// Load cache from file. max_entries takes precedence over stored size, evicting LRU if needed.
    pub fn with_cache_file(base_url: &str, cache_path: &Path, max_entries: usize) -> Self {
        let mut inner = if cache_path.exists() {
            std::fs::read_to_string(cache_path)
                .ok()
                .and_then(|s| serde_json::from_str::<KelCacheInner>(&s).ok())
        } else {
            None
        }
        .unwrap_or_else(|| KelCacheInner::new(max_entries));

        inner.resize(max_entries);

        KelsClient {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
            cache: Some(KelCache::InMemory(Arc::new(RwLock::new(inner)))),
        }
    }

    pub fn save_cache(&self, cache_path: &Path) {
        if let Some(KelCache::InMemory(cache)) = &self.cache
            && let Ok(cache) = cache.read()
        {
            if let Some(parent) = cache_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(json) = serde_json::to_string(&*cache) {
                let _ = std::fs::write(cache_path, json);
            }
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn clear_cache(&self) {
        if let Some(KelCache::InMemory(cache)) = &self.cache
            && let Ok(mut cache) = cache.write()
        {
            cache.clear();
        }
    }

    #[cfg(feature = "redis")]
    pub async fn clear_cache_async(&self) -> Result<(), KelsError> {
        match &self.cache {
            Some(KelCache::InMemory(cache)) => {
                if let Ok(mut cache) = cache.write() {
                    cache.clear();
                }
                Ok(())
            }
            Some(KelCache::Redis(redis)) => redis.clear().await,
            None => Ok(()),
        }
    }

    pub fn invalidate_cache(&self, prefix: &str) {
        if let Some(KelCache::InMemory(cache)) = &self.cache
            && let Ok(mut cache) = cache.write()
        {
            cache.invalidate(prefix);
        }
    }

    pub async fn invalidate_cache_async(&self, prefix: &str) -> Result<(), KelsError> {
        match &self.cache {
            Some(KelCache::InMemory(cache)) => {
                if let Ok(mut cache) = cache.write() {
                    cache.invalidate(prefix);
                }
                Ok(())
            }
            #[cfg(feature = "redis")]
            Some(KelCache::Redis(redis)) => redis.invalidate(prefix).await,
            None => Ok(()),
        }
    }

    async fn cache_get(&self, prefix: &str) -> Result<Option<Kel>, KelsError> {
        match &self.cache {
            Some(KelCache::InMemory(cache)) => {
                let cache_read = cache.read().map_err(|e| {
                    KelsError::CacheError(format!("Failed to acquire cache read lock: {}", e))
                })?;
                Ok(cache_read.entries.get(prefix).map(|e| e.kel.clone()))
            }
            #[cfg(feature = "redis")]
            Some(KelCache::Redis(redis)) => redis.get(prefix).await,
            None => Ok(None),
        }
    }

    async fn cache_set(&self, prefix: &str, kel: &Kel) -> Result<(), KelsError> {
        match &self.cache {
            Some(KelCache::InMemory(cache)) => {
                let mut cache_write = cache.write().map_err(|e| {
                    KelsError::CacheError(format!("Failed to acquire cache write lock: {}", e))
                })?;
                cache_write.set(prefix.to_string(), kel.clone());
                Ok(())
            }
            #[cfg(feature = "redis")]
            Some(KelCache::Redis(redis)) => redis.set(prefix, kel).await,
            None => Ok(()),
        }
    }

    pub async fn health(&self) -> Result<String, KelsError> {
        let resp = self
            .client
            .get(format!("{}/health", self.base_url))
            .send()
            .await?;

        if resp.status().is_success() {
            Ok("OK".to_string())
        } else {
            Err(KelsError::ServerError(format!(
                "Health check failed: {}",
                resp.status()
            )))
        }
    }

    /// Test latency to this node by measuring health check round-trip time.
    pub async fn test_latency(&self) -> Result<Duration, KelsError> {
        let start = Instant::now();
        self.health().await?;
        Ok(start.elapsed())
    }

    /// Discover nodes from registry and test latency to each.
    /// Returns nodes sorted by latency (fastest first), with Ready nodes prioritized.
    pub async fn discover_nodes(registry_url: &str) -> Result<Vec<NodeInfo>, KelsError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| KelsError::ServerError(format!("Failed to create HTTP client: {}", e)))?;

        // Paginate through all nodes
        let base_url = registry_url.trim_end_matches('/');
        let mut all_nodes: Vec<NodeInfo> = Vec::new();
        let mut cursor: Option<String> = None;

        loop {
            let mut url = format!("{}/api/nodes?limit=100", base_url);
            if let Some(ref c) = cursor {
                url.push_str(&format!("&cursor={}", c));
            }

            let resp = client.get(&url).send().await?;

            if !resp.status().is_success() {
                return Err(KelsError::ServerError(format!(
                    "Failed to fetch nodes from registry: {}",
                    resp.status()
                )));
            }

            let page: NodesResponse = resp.json().await?;
            all_nodes.extend(page.nodes.into_iter().map(NodeInfo::from));

            match page.next_cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }

        let mut nodes = all_nodes;

        // Test latency to each Ready node concurrently (with short timeout)
        let latency_futures: Vec<_> = nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.status == NodeStatus::Ready)
            .map(|(i, n)| {
                let url = n.kels_url.clone();
                let node_id = n.node_id.clone();
                async move {
                    let client = KelsClient::with_timeout(&url, Duration::from_millis(500));
                    let latency = client.test_latency().await.ok();
                    if let Some(ref lat) = latency {
                        tracing::info!("Node {} latency: {}ms", node_id, lat.as_millis());
                    } else {
                        tracing::warn!("Node {} latency test failed/timed out", node_id);
                    }
                    (i, latency)
                }
            })
            .collect();

        let results = futures::future::join_all(latency_futures).await;
        for (i, latency) in results {
            if let Some(lat) = latency {
                nodes[i].latency_ms = Some(lat.as_millis() as u64);
            }
        }

        // Sort: Ready nodes with latency first (by latency), then Ready without latency, then others
        nodes.sort_by(|a, b| match (&a.status, &b.status) {
            (NodeStatus::Ready, NodeStatus::Ready) => match (&a.latency_ms, &b.latency_ms) {
                (Some(a_lat), Some(b_lat)) => a_lat.cmp(b_lat),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            },
            (NodeStatus::Ready, _) => std::cmp::Ordering::Less,
            (_, NodeStatus::Ready) => std::cmp::Ordering::Greater,
            _ => std::cmp::Ordering::Equal,
        });

        Ok(nodes)
    }

    /// Create a client connected to the fastest available node from the registry.
    /// Only considers Ready nodes. Returns error if no Ready nodes are available.
    pub async fn with_discovery(registry_url: &str) -> Result<Self, KelsError> {
        let nodes = Self::discover_nodes(registry_url).await?;

        let best_node = nodes
            .into_iter()
            .find(|n| n.status == NodeStatus::Ready && n.latency_ms.is_some())
            .ok_or_else(|| {
                KelsError::ServerError("No ready nodes available in registry".to_string())
            })?;

        Ok(Self::new(&best_node.kels_url))
    }

    pub async fn submit_events(
        &self,
        events: &[SignedKeyEvent],
    ) -> Result<BatchSubmitResponse, KelsError> {
        let resp = self
            .client
            .post(format!("{}/api/kels/events", self.base_url))
            .json(events)
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else if resp.status() == reqwest::StatusCode::GONE {
            let err: ErrorResponse = resp.json().await?;
            Err(KelsError::ContestedKel(err.error))
        } else {
            let err: ErrorResponse = resp.json().await?;
            if err.code == Some(crate::types::ErrorCode::RecoveryProtected) {
                Err(KelsError::RecoveryProtected)
            } else {
                Err(KelsError::ServerError(err.error))
            }
        }
    }

    pub async fn get_kel(&self, prefix: &str) -> Result<Kel, KelsError> {
        if self.cache.is_some()
            && let Some(cached_kel) = self.cache_get(prefix).await?
        {
            return Ok(cached_kel);
        }

        let kel = self.fetch_full_kel(prefix, false).await?;
        self.cache_set(prefix, &kel).await?;

        Ok(kel)
    }

    pub async fn fetch_full_kel(&self, prefix: &str, skip_verify: bool) -> Result<Kel, KelsError> {
        let resp = self
            .client
            .get(format!("{}/api/kels/kel/{}", self.base_url, prefix))
            .send()
            .await?;

        if resp.status().is_success() {
            let signed_events: Vec<SignedKeyEvent> = resp.json().await?;
            Kel::from_events(signed_events, skip_verify)
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Err(KelsError::KeyNotFound(prefix.to_string()))
        } else {
            let err: ErrorResponse = resp.json().await?;
            Err(KelsError::ServerError(err.error))
        }
    }

    pub async fn fetch_kel_with_audit(&self, prefix: &str) -> Result<KelResponse, KelsError> {
        let resp = self
            .client
            .get(format!(
                "{}/api/kels/kel/{}?audit=true",
                self.base_url, prefix
            ))
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Err(KelsError::KeyNotFound(prefix.to_string()))
        } else {
            let err: ErrorResponse = resp.json().await?;
            Err(KelsError::ServerError(err.error))
        }
    }

    pub async fn get_kels(
        &self,
        prefixes: &[&str],
        anchors: &HashMap<&str, &[&str]>,
    ) -> Result<Vec<Kel>, KelsError> {
        if prefixes.is_empty() {
            return Ok(vec![]);
        }

        let mut cached_kels: HashMap<String, Kel> = HashMap::new();
        for p in prefixes {
            if let Some(kel) = self.cache_get(p).await? {
                cached_kels.insert((*p).to_string(), kel);
            }
        }

        // Find prefixes that are cached but missing required anchors
        let prefixes_missing_anchors: Vec<&str> = prefixes
            .iter()
            .copied()
            .filter(|p| {
                let Some(prefix_anchors) = anchors.get(p) else {
                    return false;
                };
                if prefix_anchors.is_empty() {
                    return false;
                }
                cached_kels
                    .get(*p)
                    .map(|kel| prefix_anchors.iter().any(|a| !kel.contains_anchor(a)))
                    .unwrap_or(true)
            })
            .collect();

        // Find prefixes not in cache at all
        let missing_prefixes: Vec<&str> = prefixes
            .iter()
            .copied()
            .filter(|p| !cached_kels.contains_key(*p))
            .collect();

        // All cached and no missing anchors - return from cache
        if missing_prefixes.is_empty() && prefixes_missing_anchors.is_empty() {
            return Ok(prefixes
                .iter()
                .filter_map(|p| cached_kels.remove(*p))
                .collect());
        }

        // Build batch request for missing and stale prefixes
        let batch_prefixes: Vec<&str> = missing_prefixes
            .iter()
            .chain(prefixes_missing_anchors.iter())
            .copied()
            .collect();

        let request = BatchKelsRequest {
            prefixes: batch_prefixes.iter().map(|p| (*p).to_string()).collect(),
        };

        let resp = self
            .client
            .post(format!("{}/api/kels/kels", self.base_url))
            .json(&request)
            .send()
            .await?;

        if !resp.status().is_success() {
            let err: ErrorResponse = resp.json().await?;
            return Err(KelsError::ServerError(err.error));
        }

        let new_events: HashMap<String, Vec<SignedKeyEvent>> = resp.json().await?;

        let mut result_kels: HashMap<String, Kel> = HashMap::new();
        let mut diverged_prefixes: Vec<String> = Vec::new();

        // Move cached KELs that don't need updating to result
        for prefix in prefixes {
            if !batch_prefixes.contains(prefix)
                && let Some(kel) = cached_kels.remove(*prefix)
            {
                result_kels.insert((*prefix).to_string(), kel);
            }
        }

        // Merge new events into cached KELs or create new ones
        for prefix in &batch_prefixes {
            let new = new_events.get(*prefix);

            if let Some(mut kel) = cached_kels.remove(*prefix) {
                if let Some(events) = new
                    && !events.is_empty()
                {
                    match kel.merge(events.clone()) {
                        Ok((_, _, KelMergeResult::Verified)) => {
                            result_kels.insert((*prefix).to_string(), kel);
                        }
                        Ok(_) | Err(_) => {
                            diverged_prefixes.push((*prefix).to_string());
                        }
                    }
                } else {
                    result_kels.insert((*prefix).to_string(), kel);
                }
            } else if let Some(events) = new
                && !events.is_empty()
            {
                let kel = Kel::from_events(events.clone(), false)?;
                result_kels.insert((*prefix).to_string(), kel);
            }
        }

        // Re-fetch diverged KELs from scratch
        for prefix in &diverged_prefixes {
            self.invalidate_cache_async(prefix).await?;
            let fresh_kel = self.get_kel(prefix).await?;
            result_kels.insert(prefix.clone(), fresh_kel);
        }

        // Update cache with all fetched KELs
        for (prefix, kel) in &result_kels {
            self.cache_set(prefix, kel).await?;
        }

        // Verify all required anchors are present
        let all_anchors_present = prefixes.iter().all(|p| {
            let Some(prefix_anchors) = anchors.get(p) else {
                return true;
            };
            result_kels
                .get(*p)
                .map(|kel| prefix_anchors.iter().all(|a| kel.contains_anchor(a)))
                .unwrap_or(false)
        });

        if !all_anchors_present {
            return Err(KelsError::AnchorVerificationFailed(
                "Some anchors not found in KELs".to_string(),
            ));
        }

        // Return KELs in requested order
        prefixes
            .iter()
            .map(|p| {
                result_kels
                    .remove(*p)
                    .ok_or_else(|| KelsError::KeyNotFound((*p).to_string()))
            })
            .collect::<Result<Vec<_>, _>>()
    }

    /// Skips signature verification - only for benchmarking/testing
    #[cfg(feature = "dev-tools")]
    pub async fn fetch_kels_unverified(&self, prefixes: &[&str]) -> Result<Vec<Kel>, KelsError> {
        if prefixes.is_empty() {
            return Ok(vec![]);
        }

        let request = BatchKelsRequest {
            prefixes: prefixes.iter().map(|p| p.to_string()).collect(),
        };

        let resp = self
            .client
            .post(format!("{}/api/kels/kels", self.base_url))
            .json(&request)
            .send()
            .await?;

        if !resp.status().is_success() {
            let err: ErrorResponse = resp.json().await?;
            return Err(KelsError::ServerError(err.error));
        }

        let events_map: HashMap<String, Vec<SignedKeyEvent>> = resp.json().await?;

        let mut kels = Vec::with_capacity(prefixes.len());
        for prefix in prefixes {
            if let Some(events) = events_map.get(*prefix) {
                let kel = Kel::from_events(events.clone(), true)?;
                kels.push(kel);
            } else {
                kels.push(Kel::default());
            }
        }

        Ok(kels)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kels_client_creation() {
        let client = KelsClient::new("http://kels:8091");
        assert_eq!(client.base_url(), "http://kels:8091");
    }

    #[test]
    fn test_kels_client_strips_trailing_slash() {
        let client = KelsClient::new("http://kels:8091/");
        assert_eq!(client.base_url(), "http://kels:8091");
    }
}
