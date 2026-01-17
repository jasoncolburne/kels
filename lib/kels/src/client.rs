//! KELS HTTP Client
//!
//! Provides async client for interacting with the KELS server.

use crate::error::KelsError;
use crate::kel::Kel;
use crate::types::{
    BatchKelPrefixRequest, BatchKelsRequest, BatchSubmitResponse, ErrorResponse, KelMergeResult,
    KeyEvent, SignedKeyEvent,
};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};
use verifiable_storage::StorageDatetime;

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

/// Redis-backed KEL cache
///
/// Note: No local caching here - anchor verification in KelsClient requires
/// seeing the latest KEL state from Redis to detect missing anchors.
#[cfg(feature = "redis")]
#[derive(Clone)]
pub struct RedisKelCache {
    conn: ConnectionManager,
    key_prefix: String,
}

#[cfg(feature = "redis")]
impl RedisKelCache {
    /// Create a new Redis cache with connection manager.
    ///
    /// Entries never expire - eviction is handled by Redis's `maxmemory-policy`.
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

/// KELS (Key Event Log Service) API Client
///
/// Provides methods for interacting with the key event log service,
/// which stores and retrieves key events (icp, rot, ixn) with their signatures.
#[derive(Clone)]
pub struct KelsClient {
    base_url: String,
    client: reqwest::Client,
    cache: Option<KelCache>,
}

impl KelsClient {
    /// Create a new KELS client without caching
    pub fn new(base_url: &str) -> Self {
        KelsClient {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
            cache: None,
        }
    }

    /// Create a new KELS client with default in-memory caching (256 KELs max)
    pub fn with_caching(base_url: &str) -> Self {
        Self::with_cache_config(base_url, KelCacheConfig::default())
    }

    /// Create a new KELS client with custom cache configuration (in-memory)
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

    /// Create a new KELS client with Redis-backed caching
    #[cfg(feature = "redis")]
    pub fn with_redis_cache(base_url: &str, redis_cache: RedisKelCache) -> Self {
        KelsClient {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
            cache: Some(KelCache::Redis(Box::new(redis_cache))),
        }
    }

    /// Create a new KELS client with caching loaded from a file.
    ///
    /// The `max_entries` parameter controls the maximum cache size. This value
    /// takes precedence over any size stored in the cache file, allowing the
    /// cache size to be reconfigured. If the loaded cache exceeds this size,
    /// LRU entries are evicted.
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

    /// Save the cache to a file.
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
            Err(KelsError::ServerError(err.error))
        }
    }

    pub async fn submit_event(
        &self,
        event: KeyEvent,
        public_key: String,
        signature: String,
    ) -> Result<BatchSubmitResponse, KelsError> {
        self.submit_events(&[SignedKeyEvent::new(event, public_key, signature)])
            .await
    }

    pub async fn get_kel(&self, prefix: &str, anchors: &[&str]) -> Result<Kel, KelsError> {
        if self.cache.is_some() {
            if let Some(cached_kel) = self.cache_get(prefix).await? {
                let all_anchors_present = anchors.iter().all(|a| cached_kel.contains_anchor(a));
                if all_anchors_present {
                    return Ok(cached_kel);
                }

                let max_timestamp = cached_kel
                    .max_event_timestamp()
                    .ok_or(KelsError::KeyNotFound(prefix.to_string()))?;
                let new_events = self.get_kel_since(prefix, max_timestamp).await?;
                if new_events.is_empty() {
                    return Err(KelsError::AnchorVerificationFailed(
                        "Some anchors not found in KEL".to_string(),
                    ));
                }

                let mut kel = cached_kel;
                let merge_result = kel.merge(new_events);

                match merge_result {
                    Ok((_, KelMergeResult::Verified)) => {
                        self.cache_set(prefix, &kel).await?;

                        let all_anchors_present = anchors.iter().all(|a| kel.contains_anchor(a));
                        if !all_anchors_present {
                            return Err(KelsError::AnchorVerificationFailed(
                                "Some anchors not found in KEL".to_string(),
                            ));
                        }

                        return Ok(kel);
                    }
                    Ok(_) | Err(_) => {
                        self.invalidate_cache_async(prefix).await?;
                        let fresh_kel = self.fetch_full_kel(prefix).await?;
                        self.cache_set(prefix, &fresh_kel).await?;

                        let all_anchors_present =
                            anchors.iter().all(|a| fresh_kel.contains_anchor(a));
                        if !all_anchors_present {
                            return Err(KelsError::AnchorVerificationFailed(
                                "Some anchors not found in KEL".to_string(),
                            ));
                        }

                        return Ok(fresh_kel);
                    }
                }
            }

            let kel = self.fetch_full_kel(prefix).await?;
            self.cache_set(prefix, &kel).await?;

            let all_anchors_present = anchors.iter().all(|a| kel.contains_anchor(a));
            if !all_anchors_present {
                return Err(KelsError::AnchorVerificationFailed(
                    "Some anchors not found in KEL".to_string(),
                ));
            }

            return Ok(kel);
        }

        let kel = self.fetch_full_kel(prefix).await?;
        let all_anchors_present = anchors.iter().all(|a| kel.contains_anchor(a));
        if !all_anchors_present {
            return Err(KelsError::AnchorVerificationFailed(
                "Some anchors not found in KEL".to_string(),
            ));
        }

        Ok(kel)
    }

    /// Fetch full KEL from server (no caching)
    pub async fn fetch_full_kel(&self, prefix: &str) -> Result<Kel, KelsError> {
        let resp = self
            .client
            .get(format!("{}/api/kels/kel/{}", self.base_url, prefix))
            .send()
            .await?;

        if resp.status().is_success() {
            let signed_events: Vec<SignedKeyEvent> = resp.json().await?;
            Kel::from_events(signed_events, false)
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Err(KelsError::KeyNotFound(prefix.to_string()))
        } else {
            let err: ErrorResponse = resp.json().await?;
            Err(KelsError::ServerError(err.error))
        }
    }

    /// Fetch full KEL from server without verification (dev-tools only)
    ///
    /// # Safety
    /// This skips signature verification - only use for benchmarking/testing!
    #[cfg(feature = "dev-tools")]
    pub async fn fetch_full_kel_unverified(&self, prefix: &str) -> Result<Kel, KelsError> {
        let resp = self
            .client
            .get(format!("{}/api/kels/kel/{}", self.base_url, prefix))
            .send()
            .await?;

        if resp.status().is_success() {
            let signed_events: Vec<SignedKeyEvent> = resp.json().await?;
            Kel::from_events(signed_events, true)
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Err(KelsError::KeyNotFound(prefix.to_string()))
        } else {
            let err: ErrorResponse = resp.json().await?;
            Err(KelsError::ServerError(err.error))
        }
    }

    async fn get_kel_since(
        &self,
        prefix: &str,
        since_timestamp: &StorageDatetime,
    ) -> Result<Vec<SignedKeyEvent>, KelsError> {
        let resp = self
            .client
            .get(format!(
                "{}/api/kels/kel/{}/since/{}",
                self.base_url, prefix, since_timestamp
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

    pub async fn get_event(&self, said: &str) -> Result<SignedKeyEvent, KelsError> {
        let resp = self
            .client
            .get(format!("{}/api/kels/events/{}", self.base_url, said))
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            Err(KelsError::InvalidSaid(said.to_string()))
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
            prefixes: batch_prefixes
                .iter()
                .map(|p| {
                    // Use timestamp-based since to catch divergent events at earlier versions
                    let since = if missing_prefixes.contains(p) {
                        None
                    } else {
                        cached_kels
                            .get(*p)
                            .and_then(|kel| kel.max_event_timestamp().map(|ts| ts.0.to_rfc3339()))
                    };
                    BatchKelPrefixRequest {
                        prefix: (*p).to_string(),
                        since,
                    }
                })
                .collect(),
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
                        Ok((_, KelMergeResult::Verified)) => {
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
            let fresh_kel = self.fetch_full_kel(prefix).await?;
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

    /// Fetch multiple KELs without caching or verification (dev-tools only)
    ///
    /// # Safety
    /// This skips signature verification - only use for benchmarking/testing!
    #[cfg(feature = "dev-tools")]
    pub async fn fetch_kels_unverified(&self, prefixes: &[&str]) -> Result<Vec<Kel>, KelsError> {
        if prefixes.is_empty() {
            return Ok(vec![]);
        }

        let request = BatchKelsRequest {
            prefixes: prefixes
                .iter()
                .map(|p| BatchKelPrefixRequest {
                    prefix: p.to_string(),
                    since: None,
                })
                .collect(),
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
