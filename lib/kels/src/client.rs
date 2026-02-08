//! KELS HTTP Client

use crate::{
    error::KelsError,
    kel::Kel,
    types::{
        BatchKelsRequest, BatchSubmitResponse, ErrorCode, ErrorResponse, KelMergeResult,
        KelResponse, SignedKeyEvent,
    },
};
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

#[cfg(feature = "redis")]
use redis::aio::ConnectionManager;

#[doc(hidden)]
#[derive(Clone, Serialize, Deserialize)]
pub struct CachedKelEntry {
    kel: Kel,
    last_access: u64,
}

#[doc(hidden)]
#[derive(Serialize, Deserialize)]
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
            Err(KelsError::ServerError(
                format!("Health check failed: {}", resp.status()),
                ErrorCode::InternalError,
            ))
        }
    }

    /// Test latency to this node by measuring health check round-trip time.
    pub async fn test_latency(&self) -> Result<Duration, KelsError> {
        let start = Instant::now();
        self.health().await?;
        Ok(start.elapsed())
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
            if err.code == ErrorCode::RecoveryProtected {
                Err(KelsError::RecoveryProtected)
            } else {
                Err(KelsError::ServerError(err.error, err.code))
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
            Err(KelsError::ServerError(err.error, err.code))
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
            Err(KelsError::ServerError(err.error, err.code))
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
        let batch_prefixes: HashSet<&str> = missing_prefixes
            .iter()
            .chain(prefixes_missing_anchors.iter())
            .copied()
            .collect();

        let request = BatchKelsRequest {
            prefixes: batch_prefixes.iter().map(|p| p.to_string()).collect(),
        };

        let resp = self
            .client
            .post(format!("{}/api/kels/kels", self.base_url))
            .json(&request)
            .send()
            .await?;

        if !resp.status().is_success() {
            let err: ErrorResponse = resp.json().await?;
            return Err(KelsError::ServerError(err.error, err.code));
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
                        _ => {
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

        let mut futures = Vec::new();
        // Re-fetch diverged KELs from scratch
        for prefix in &diverged_prefixes {
            self.invalidate_cache_async(prefix).await?;
            futures.push(async move {
                let kel = match self.get_kel(prefix).await {
                    Ok(k) => k,
                    Err(_) => return None,
                };

                Some((prefix.clone(), kel))
            });
        }

        let diverged_results = join_all(futures).await;

        // Merge diverged KELs back and update cache
        for (prefix, kel) in diverged_results.into_iter().flatten() {
            self.cache_set(&prefix, &kel).await?;
            result_kels.insert(prefix, kel);
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
                    .ok_or(KelsError::KeyNotFound((*p).to_string()))
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
            return Err(KelsError::ServerError(err.error, err.code));
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
    use crate::SoftwareKeyProvider;
    use crate::builder::KeyEventBuilder;

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

    #[test]
    fn test_kels_client_strips_multiple_trailing_slashes() {
        let client = KelsClient::new("http://kels:8091///");
        assert_eq!(client.base_url(), "http://kels:8091");
    }

    // ==================== LRU Cache Tests ====================

    async fn create_test_kel_with_prefix(_data: &str) -> Kel {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder.incept().await.unwrap();
        Kel::from_events(vec![icp], true).unwrap()
    }

    #[tokio::test]
    async fn test_cache_set_and_get() {
        let mut cache = KelCacheInner::new(2);
        let kel1 = create_test_kel_with_prefix("kel1").await;
        let kel2 = create_test_kel_with_prefix("kel2").await;

        cache.set("prefix1".to_string(), kel1);
        cache.set("prefix2".to_string(), kel2);

        assert_eq!(cache.entries.len(), 2);
        assert!(cache.entries.contains_key("prefix1"));
        assert!(cache.entries.contains_key("prefix2"));
    }

    #[tokio::test]
    async fn test_cache_lru_eviction_when_full() {
        let mut cache = KelCacheInner::new(2);
        let kel1 = create_test_kel_with_prefix("k1").await;
        let kel2 = create_test_kel_with_prefix("k2").await;
        let kel3 = create_test_kel_with_prefix("k3").await;

        cache.set("p1".to_string(), kel1); // access_counter: 1
        cache.set("p2".to_string(), kel2); // access_counter: 2
        cache.set("p3".to_string(), kel3); // access_counter: 3, should evict p1

        assert_eq!(cache.entries.len(), 2);
        assert!(!cache.entries.contains_key("p1")); // LRU evicted
        assert!(cache.entries.contains_key("p2"));
        assert!(cache.entries.contains_key("p3"));
    }

    #[tokio::test]
    async fn test_cache_update_existing_doesnt_evict() {
        let mut cache = KelCacheInner::new(2);
        let kel1 = create_test_kel_with_prefix("k1").await;
        let kel2 = create_test_kel_with_prefix("k2").await;
        let kel1_new = create_test_kel_with_prefix("k1new").await;

        cache.set("p1".to_string(), kel1);
        cache.set("p2".to_string(), kel2);

        // Update p1 - should not trigger eviction
        cache.set("p1".to_string(), kel1_new);

        assert_eq!(cache.entries.len(), 2);
        assert!(cache.entries.contains_key("p1"));
        assert!(cache.entries.contains_key("p2"));
    }

    #[tokio::test]
    async fn test_cache_invalidate() {
        let mut cache = KelCacheInner::new(2);
        let kel = create_test_kel_with_prefix("k").await;

        cache.set("prefix1".to_string(), kel);
        assert_eq!(cache.entries.len(), 1);

        cache.invalidate("prefix1");
        assert_eq!(cache.entries.len(), 0);
    }

    #[tokio::test]
    async fn test_cache_invalidate_nonexistent() {
        let mut cache = KelCacheInner::new(2);
        // Should not panic
        cache.invalidate("nonexistent");
        assert_eq!(cache.entries.len(), 0);
    }

    #[tokio::test]
    async fn test_cache_resize_shrink_evicts_lru() {
        let mut cache = KelCacheInner::new(3);
        let kel1 = create_test_kel_with_prefix("k1").await;
        let kel2 = create_test_kel_with_prefix("k2").await;
        let kel3 = create_test_kel_with_prefix("k3").await;

        cache.set("p1".to_string(), kel1); // access: 1
        cache.set("p2".to_string(), kel2); // access: 2
        cache.set("p3".to_string(), kel3); // access: 3

        cache.resize(2); // Should evict p1 (lowest access)

        assert_eq!(cache.entries.len(), 2);
        assert!(!cache.entries.contains_key("p1"));
        assert!(cache.entries.contains_key("p2"));
        assert!(cache.entries.contains_key("p3"));
    }

    #[tokio::test]
    async fn test_cache_resize_expand() {
        let mut cache = KelCacheInner::new(2);
        let kel = create_test_kel_with_prefix("k").await;

        cache.set("p1".to_string(), kel);

        cache.resize(5);
        assert_eq!(cache.max_entries, 5);
        assert_eq!(cache.entries.len(), 1);
    }

    #[tokio::test]
    async fn test_cache_clear() {
        let mut cache = KelCacheInner::new(3);
        let kel1 = create_test_kel_with_prefix("k1").await;
        let kel2 = create_test_kel_with_prefix("k2").await;

        cache.set("p1".to_string(), kel1);
        cache.set("p2".to_string(), kel2);
        assert_eq!(cache.entries.len(), 2);
        assert_eq!(cache.access_counter, 2);

        cache.clear();
        assert_eq!(cache.entries.len(), 0);
        assert_eq!(cache.access_counter, 0);
    }

    // ==================== Cache Config Tests ====================

    #[test]
    fn test_default_cache_config() {
        let config = KelCacheConfig::default();
        assert_eq!(config.max_entries, 256);
        assert!(config.enabled);
    }

    #[test]
    fn test_client_with_caching_creates_cache() {
        let client = KelsClient::with_caching("http://localhost:8080");
        assert!(client.cache.is_some());
    }

    #[test]
    fn test_client_without_caching_no_cache() {
        let client = KelsClient::new("http://localhost:8080");
        assert!(client.cache.is_none());
    }

    #[test]
    fn test_client_with_timeout() {
        let client = KelsClient::with_timeout("http://localhost:8080", Duration::from_secs(60));
        assert_eq!(client.base_url(), "http://localhost:8080");
    }

    #[test]
    fn test_client_with_cache_config_disabled() {
        let config = KelCacheConfig {
            max_entries: 100,
            enabled: false,
        };
        let client = KelsClient::with_cache_config("http://localhost:8080", config);
        assert!(client.cache.is_none());
    }

    #[test]
    fn test_client_with_cache_config_enabled() {
        let config = KelCacheConfig {
            max_entries: 50,
            enabled: true,
        };
        let client = KelsClient::with_cache_config("http://localhost:8080", config);
        assert!(client.cache.is_some());
    }

    #[test]
    fn test_client_clear_cache() {
        let client = KelsClient::with_caching("http://localhost:8080");
        // Should not panic even when cache is empty
        client.clear_cache();

        // Test with no cache
        let client_no_cache = KelsClient::new("http://localhost:8080");
        client_no_cache.clear_cache(); // Should not panic
    }

    #[test]
    fn test_client_invalidate_cache() {
        let client = KelsClient::with_caching("http://localhost:8080");
        // Should not panic on nonexistent prefix
        client.invalidate_cache("nonexistent");

        // Test with no cache
        let client_no_cache = KelsClient::new("http://localhost:8080");
        client_no_cache.invalidate_cache("prefix"); // Should not panic
    }

    #[test]
    fn test_client_save_and_load_cache() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let cache_path = temp_dir.path().join("cache.json");

        // Create client with cache and save
        let client = KelsClient::with_cache_config(
            "http://localhost:8080",
            KelCacheConfig {
                max_entries: 10,
                enabled: true,
            },
        );
        client.save_cache(&cache_path);

        // Load from file
        let client2 = KelsClient::with_cache_file("http://localhost:8080", &cache_path, 10);
        assert!(client2.cache.is_some());
    }

    #[test]
    fn test_client_with_cache_file_nonexistent() {
        let path = std::path::PathBuf::from("/nonexistent/path/cache.json");
        let client = KelsClient::with_cache_file("http://localhost:8080", &path, 10);
        // Should create new cache when file doesn't exist
        assert!(client.cache.is_some());
    }

    #[test]
    fn test_client_save_cache_no_cache() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let cache_path = temp_dir.path().join("cache.json");

        // Client without cache
        let client = KelsClient::new("http://localhost:8080");
        client.save_cache(&cache_path);

        // File should not be created
        assert!(!cache_path.exists());
    }

    // ==================== HTTP Client Tests with Mock Server ====================

    mod http_tests {
        use super::*;
        use crate::types::{BatchSubmitResponse, ErrorCode, ErrorResponse, KelResponse};
        use wiremock::matchers::{method, path, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        #[tokio::test]
        async fn test_health_success() {
            let mock_server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/health"))
                .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
                .mount(&mock_server)
                .await;

            let client = KelsClient::new(&mock_server.uri());
            let result = client.health().await;

            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "OK");
        }

        #[tokio::test]
        async fn test_health_failure() {
            let mock_server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/health"))
                .respond_with(ResponseTemplate::new(503))
                .mount(&mock_server)
                .await;

            let client = KelsClient::new(&mock_server.uri());
            let result = client.health().await;

            assert!(result.is_err());
            assert!(matches!(result, Err(KelsError::ServerError(..))));
        }

        #[tokio::test]
        async fn test_test_latency() {
            let mock_server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/health"))
                .respond_with(ResponseTemplate::new(200))
                .mount(&mock_server)
                .await;

            let client = KelsClient::new(&mock_server.uri());
            let result = client.test_latency().await;

            assert!(result.is_ok());
            // Latency should be positive
            assert!(result.unwrap().as_micros() > 0);
        }

        #[tokio::test]
        async fn test_submit_events_success() {
            let mock_server = MockServer::start().await;

            let response = BatchSubmitResponse {
                accepted: true,
                diverged_at: None,
            };

            Mock::given(method("POST"))
                .and(path("/api/kels/events"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&response))
                .mount(&mock_server)
                .await;

            // Create a test event
            let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
            let signed = builder.incept().await.unwrap();

            let client = KelsClient::new(&mock_server.uri());
            let result = client.submit_events(&[signed]).await;

            assert!(result.is_ok());
            let resp = result.unwrap();
            assert!(resp.accepted);
            assert!(resp.diverged_at.is_none());
        }

        #[tokio::test]
        async fn test_submit_events_divergence() {
            let mock_server = MockServer::start().await;

            let response = BatchSubmitResponse {
                accepted: true,
                diverged_at: Some(1),
            };

            Mock::given(method("POST"))
                .and(path("/api/kels/events"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&response))
                .mount(&mock_server)
                .await;

            let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
            let signed = builder.incept().await.unwrap();

            let client = KelsClient::new(&mock_server.uri());
            let result = client.submit_events(&[signed]).await;

            assert!(result.is_ok());
            let resp = result.unwrap();
            assert!(resp.accepted);
            assert_eq!(resp.diverged_at, Some(1));
        }

        #[tokio::test]
        async fn test_submit_events_contested() {
            let mock_server = MockServer::start().await;

            let error = ErrorResponse {
                error: "KEL is contested".to_string(),
                code: ErrorCode::Contested,
            };

            Mock::given(method("POST"))
                .and(path("/api/kels/events"))
                .respond_with(ResponseTemplate::new(410).set_body_json(&error))
                .mount(&mock_server)
                .await;

            let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
            let signed = builder.incept().await.unwrap();

            let client = KelsClient::new(&mock_server.uri());
            let result = client.submit_events(&[signed]).await;

            assert!(matches!(result, Err(KelsError::ContestedKel(_))));
        }

        #[tokio::test]
        async fn test_submit_events_recovery_protected() {
            let mock_server = MockServer::start().await;

            let error = ErrorResponse {
                error: "Recovery protected".to_string(),
                code: ErrorCode::RecoveryProtected,
            };

            Mock::given(method("POST"))
                .and(path("/api/kels/events"))
                .respond_with(ResponseTemplate::new(400).set_body_json(&error))
                .mount(&mock_server)
                .await;

            let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
            let signed = builder.incept().await.unwrap();

            let client = KelsClient::new(&mock_server.uri());
            let result = client.submit_events(&[signed]).await;

            assert!(matches!(result, Err(KelsError::RecoveryProtected)));
        }

        #[tokio::test]
        async fn test_submit_events_server_error() {
            let mock_server = MockServer::start().await;

            let error = ErrorResponse {
                error: "Internal error".to_string(),
                code: ErrorCode::InternalError,
            };

            Mock::given(method("POST"))
                .and(path("/api/kels/events"))
                .respond_with(ResponseTemplate::new(500).set_body_json(&error))
                .mount(&mock_server)
                .await;

            let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
            let signed = builder.incept().await.unwrap();

            let client = KelsClient::new(&mock_server.uri());
            let result = client.submit_events(&[signed]).await;

            assert!(matches!(result, Err(KelsError::ServerError(..))));
        }

        #[tokio::test]
        async fn test_fetch_full_kel_success() {
            let mock_server = MockServer::start().await;

            // Create a test KEL
            let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
            let icp = builder.incept().await.unwrap();
            let prefix = icp.event.prefix.clone();

            Mock::given(method("GET"))
                .and(path_regex(r"/api/kels/kel/.*"))
                .respond_with(ResponseTemplate::new(200).set_body_json(vec![icp.clone()]))
                .mount(&mock_server)
                .await;

            let client = KelsClient::new(&mock_server.uri());
            let result = client.fetch_full_kel(&prefix, true).await;

            assert!(result.is_ok());
            let kel = result.unwrap();
            assert_eq!(kel.len(), 1);
        }

        #[tokio::test]
        async fn test_fetch_full_kel_not_found() {
            let mock_server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path_regex(r"/api/kels/kel/.*"))
                .respond_with(ResponseTemplate::new(404))
                .mount(&mock_server)
                .await;

            let client = KelsClient::new(&mock_server.uri());
            let result = client.fetch_full_kel("nonexistent", true).await;

            assert!(matches!(result, Err(KelsError::KeyNotFound(_))));
        }

        #[tokio::test]
        async fn test_fetch_full_kel_server_error() {
            let mock_server = MockServer::start().await;

            let error = ErrorResponse {
                error: "Database error".to_string(),
                code: ErrorCode::InternalError,
            };

            Mock::given(method("GET"))
                .and(path_regex(r"/api/kels/kel/.*"))
                .respond_with(ResponseTemplate::new(500).set_body_json(&error))
                .mount(&mock_server)
                .await;

            let client = KelsClient::new(&mock_server.uri());
            let result = client.fetch_full_kel("prefix", true).await;

            assert!(matches!(result, Err(KelsError::ServerError(..))));
        }

        #[tokio::test]
        async fn test_get_kel_with_cache_miss() {
            let mock_server = MockServer::start().await;

            let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
            let icp = builder.incept().await.unwrap();
            let prefix = icp.event.prefix.clone();

            Mock::given(method("GET"))
                .and(path_regex(r"/api/kels/kel/.*"))
                .respond_with(ResponseTemplate::new(200).set_body_json(vec![icp.clone()]))
                .expect(1) // Should only be called once
                .mount(&mock_server)
                .await;

            let client = KelsClient::with_caching(&mock_server.uri());

            // First call - cache miss, fetches from server
            let result1 = client.get_kel(&prefix).await;
            assert!(result1.is_ok());

            // Second call - should be cached (mock expects only 1 call)
            let result2 = client.get_kel(&prefix).await;
            assert!(result2.is_ok());
        }

        #[tokio::test]
        async fn test_fetch_kel_with_audit_success() {
            let mock_server = MockServer::start().await;

            let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
            let icp = builder.incept().await.unwrap();
            let prefix = icp.event.prefix.clone();

            let response = KelResponse {
                events: vec![icp],
                audit_records: Some(vec![]),
            };

            Mock::given(method("GET"))
                .and(path_regex(r"/api/kels/kel/.*"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&response))
                .mount(&mock_server)
                .await;

            let client = KelsClient::new(&mock_server.uri());
            let result = client.fetch_kel_with_audit(&prefix).await;

            assert!(result.is_ok());
            let resp = result.unwrap();
            assert_eq!(resp.events.len(), 1);
            assert!(resp.audit_records.as_ref().is_none_or(|v| v.is_empty()));
        }

        #[tokio::test]
        async fn test_fetch_kel_with_audit_not_found() {
            let mock_server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path_regex(r"/api/kels/kel/.*"))
                .respond_with(ResponseTemplate::new(404))
                .mount(&mock_server)
                .await;

            let client = KelsClient::new(&mock_server.uri());
            let result = client.fetch_kel_with_audit("nonexistent").await;

            assert!(matches!(result, Err(KelsError::KeyNotFound(_))));
        }

        #[tokio::test]
        async fn test_cache_get_no_cache() {
            let client = KelsClient::new("http://localhost:8080");
            let result = client.cache_get("prefix").await;
            assert!(result.is_ok());
            assert!(result.unwrap().is_none());
        }

        #[tokio::test]
        async fn test_cache_set_no_cache() {
            let kel = Kel::new();
            let client = KelsClient::new("http://localhost:8080");
            let result = client.cache_set("prefix", &kel).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_invalidate_cache_async_no_cache() {
            let client = KelsClient::new("http://localhost:8080");
            let result = client.invalidate_cache_async("prefix").await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_invalidate_cache_async_with_cache() {
            let client = KelsClient::with_caching("http://localhost:8080");
            let result = client.invalidate_cache_async("prefix").await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_get_kels_empty_prefixes() {
            let client = KelsClient::new("http://localhost:8080");
            let result = client.get_kels(&[], &HashMap::new()).await;
            assert!(result.is_ok());
            assert!(result.unwrap().is_empty());
        }

        #[tokio::test]
        async fn test_get_kels_from_server() {
            let mock_server = MockServer::start().await;

            let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
            let icp = builder.incept().await.unwrap();
            let prefix = icp.event.prefix.clone();

            let mut response: HashMap<String, Vec<SignedKeyEvent>> = HashMap::new();
            response.insert(prefix.clone(), vec![icp]);

            Mock::given(method("POST"))
                .and(path("/api/kels/kels"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&response))
                .mount(&mock_server)
                .await;

            let client = KelsClient::new(&mock_server.uri());
            let result = client.get_kels(&[&prefix], &HashMap::new()).await;

            assert!(result.is_ok());
            let kels = result.unwrap();
            assert_eq!(kels.len(), 1);
        }

        #[tokio::test]
        async fn test_get_kels_server_error() {
            let mock_server = MockServer::start().await;

            let error = ErrorResponse {
                error: "Server error".to_string(),
                code: ErrorCode::InternalError,
            };

            Mock::given(method("POST"))
                .and(path("/api/kels/kels"))
                .respond_with(ResponseTemplate::new(500).set_body_json(&error))
                .mount(&mock_server)
                .await;

            let client = KelsClient::new(&mock_server.uri());
            let result = client.get_kels(&["prefix"], &HashMap::new()).await;

            assert!(matches!(result, Err(KelsError::ServerError(..))));
        }
    }
}
