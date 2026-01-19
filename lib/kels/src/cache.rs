//! Redis-backed KEL cache with pre-serialized responses and tail caching.
//!
//! # Architecture
//!
//! - **Redis**: Pre-serialized JSON stored for full KEL + last 2 tails
//! - **Local LRU**: Caches pre-serialized bytes to avoid Redis round trips
//! - **Redis Pub/Sub**: Publishes `{prefix}:{said}` on changes for cross-replica invalidation
//!
//! # Cache Keys
//!
//! - `{prefix}:full` - Full KEL serialized
//! - `{prefix}:tail:1` - Last 1 event serialized
//! - `{prefix}:tail:2` - Last 2 events serialized
//!
//! For `since` queries, if `latest_version - since_version <= 2`, we return the
//! appropriate pre-serialized tail. Otherwise, we deserialize the full KEL and filter.

use crate::{KelsError, SignedKeyEvent};
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

const LOCAL_CACHE_MAX_ENTRIES: usize = 768; // ~256 KELs * 3 entries each (full + 2 tails)
const PUBSUB_CHANNEL: &str = "kel_updates";
const MAX_TAIL_SIZE: usize = 2;

struct LocalCacheEntry {
    bytes: Arc<Vec<u8>>,
    last_access: u64,
}

pub struct LocalCache {
    entries: HashMap<String, LocalCacheEntry>,
    access_counter: u64,
    max_entries: usize,
}

impl LocalCache {
    fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            access_counter: 0,
            max_entries,
        }
    }

    fn get(&mut self, key: &str) -> Option<Arc<Vec<u8>>> {
        let entry = self.entries.get_mut(key)?;
        self.access_counter += 1;
        entry.last_access = self.access_counter;
        Some(Arc::clone(&entry.bytes))
    }

    fn set(&mut self, key: String, bytes: Vec<u8>) {
        if self.entries.len() >= self.max_entries
            && !self.entries.contains_key(&key)
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
            key,
            LocalCacheEntry {
                bytes: Arc::new(bytes),
                last_access: self.access_counter,
            },
        );
    }

    pub fn clear(&mut self, prefix: &str) {
        self.entries.remove(&format!("{}:full", prefix));
        for i in 1..=MAX_TAIL_SIZE {
            self.entries.remove(&format!("{}:tail:{}", prefix, i));
        }
    }
}

/// Pre-serialized KEL response (either full or tail)
pub enum SerializedKel {
    /// Pre-serialized bytes ready to return
    Bytes(Arc<Vec<u8>>),
    /// Need to deserialize, filter, and re-serialize (for old `since` queries)
    NeedsProcessing(Vec<SignedKeyEvent>),
}

/// Redis-backed KEL cache with pre-serialized responses (server-side with pub/sub)
pub struct ServerKelCache {
    conn: ConnectionManager,
    key_prefix: String,
    local_cache: Arc<RwLock<LocalCache>>,
}

impl ServerKelCache {
    pub fn new(conn: ConnectionManager, key_prefix: &str) -> Self {
        Self {
            conn,
            key_prefix: key_prefix.to_string(),
            local_cache: Arc::new(RwLock::new(LocalCache::new(LOCAL_CACHE_MAX_ENTRIES))),
        }
    }

    pub fn local_cache(&self) -> Arc<RwLock<LocalCache>> {
        Arc::clone(&self.local_cache)
    }

    fn redis_key_full(&self, prefix: &str) -> String {
        format!("{}:{}:full", self.key_prefix, prefix)
    }

    fn redis_key_tail(&self, prefix: &str, size: usize) -> String {
        format!("{}:{}:tail:{}", self.key_prefix, prefix, size)
    }

    fn redis_key_version(&self, prefix: &str) -> String {
        format!("{}:{}:version", self.key_prefix, prefix)
    }

    fn local_key_full(&self, prefix: &str) -> String {
        format!("{}:full", prefix)
    }

    fn local_key_tail(&self, prefix: &str, size: usize) -> String {
        format!("{}:tail:{}", prefix, size)
    }

    async fn publish_update(&self, prefix: &str, said: &str) -> Result<(), KelsError> {
        let mut conn = self.conn.clone();
        let message = format!("{}:{}", prefix, said);
        let _: () = conn
            .publish(PUBSUB_CHANNEL, &message)
            .await
            .map_err(|e| KelsError::CacheError(format!("Redis PUBLISH failed: {}", e)))?;
        Ok(())
    }

    /// Store a complete KEL with pre-serialized full + tails
    pub async fn store(&self, prefix: &str, events: &[SignedKeyEvent]) -> Result<(), KelsError> {
        if events.is_empty() {
            return Ok(());
        }

        let latest_event = match events.last() {
            Some(e) => e,
            None => return Ok(()),
        };
        let latest_version = latest_event.event.version;
        let latest_said = &latest_event.event.said;

        // Serialize full KEL
        let full_json = serde_json::to_vec(events)?;

        // Serialize tails (last 1, 2 events)
        let mut tail_jsons = Vec::new();
        for size in 1..=MAX_TAIL_SIZE {
            let tail: Vec<_> = events.iter().rev().take(size).rev().cloned().collect();
            tail_jsons.push(serde_json::to_vec(&tail)?);
        }

        // Store in Redis (pipeline for efficiency)
        let mut conn = self.conn.clone();
        let mut pipe = redis::pipe();
        pipe.set(self.redis_key_full(prefix), &full_json);
        pipe.set(self.redis_key_version(prefix), latest_version);
        for (i, tail_json) in tail_jsons.iter().enumerate() {
            pipe.set(self.redis_key_tail(prefix, i + 1), tail_json);
        }
        let _: () = pipe
            .query_async(&mut conn)
            .await
            .map_err(|e| KelsError::CacheError(format!("Redis pipeline failed: {}", e)))?;

        // Update local cache
        {
            let mut local = self.local_cache.write().await;
            local.set(self.local_key_full(prefix), full_json);
            for (i, tail_json) in tail_jsons.into_iter().enumerate() {
                local.set(self.local_key_tail(prefix, i + 1), tail_json);
            }
        }

        // Publish for other replicas
        self.publish_update(prefix, latest_said).await?;

        Ok(())
    }

    /// Get full KEL as pre-serialized bytes (for returning directly to client)
    pub async fn get_full_serialized(
        &self,
        prefix: &str,
    ) -> Result<Option<Arc<Vec<u8>>>, KelsError> {
        let local_key = self.local_key_full(prefix);

        // Check local cache first
        {
            let mut local = self.local_cache.write().await;
            if let Some(bytes) = local.get(&local_key) {
                return Ok(Some(bytes));
            }
        }

        // Fetch from Redis
        let redis_key = self.redis_key_full(prefix);
        let mut conn = self.conn.clone();
        let bytes: Option<Vec<u8>> = conn
            .get(&redis_key)
            .await
            .map_err(|e| KelsError::CacheError(format!("Redis GET failed: {}", e)))?;

        match bytes {
            Some(b) => {
                let arc_bytes = Arc::new(b.clone());
                // Cache locally
                {
                    let mut local = self.local_cache.write().await;
                    local.set(local_key, b);
                }
                Ok(Some(arc_bytes))
            }
            None => Ok(None),
        }
    }

    /// Get full KEL deserialized (for processing)
    pub async fn get_full(&self, prefix: &str) -> Result<Vec<SignedKeyEvent>, KelsError> {
        match self.get_full_serialized(prefix).await? {
            Some(bytes) => Ok(serde_json::from_slice(&bytes)?),
            None => Ok(vec![]),
        }
    }

    /// Get events since a version - returns pre-serialized if possible
    pub async fn get_since_serialized(
        &self,
        prefix: &str,
        since_version: u64,
    ) -> Result<Option<SerializedKel>, KelsError> {
        // Get latest version from Redis
        let version_key = self.redis_key_version(prefix);
        let mut conn = self.conn.clone();
        let latest_version: Option<u64> = conn
            .get(&version_key)
            .await
            .map_err(|e| KelsError::CacheError(format!("Redis GET version failed: {}", e)))?;

        let latest_version = match latest_version {
            Some(v) => v,
            None => return Ok(None), // No KEL cached
        };

        let events_needed = latest_version.saturating_sub(since_version) as usize;

        if events_needed == 0 {
            // Client is up to date, return empty array
            return Ok(Some(SerializedKel::Bytes(Arc::new(b"[]".to_vec()))));
        }

        if events_needed <= MAX_TAIL_SIZE {
            // We have a pre-serialized tail for this
            let local_key = self.local_key_tail(prefix, events_needed);

            // Check local cache first
            {
                let mut local = self.local_cache.write().await;
                if let Some(bytes) = local.get(&local_key) {
                    return Ok(Some(SerializedKel::Bytes(bytes)));
                }
            }

            // Fetch tail from Redis
            let redis_key = self.redis_key_tail(prefix, events_needed);
            let bytes: Option<Vec<u8>> = conn
                .get(&redis_key)
                .await
                .map_err(|e| KelsError::CacheError(format!("Redis GET tail failed: {}", e)))?;

            if let Some(b) = bytes {
                let arc_bytes = Arc::new(b.clone());
                // Cache locally
                {
                    let mut local = self.local_cache.write().await;
                    local.set(local_key, b);
                }
                return Ok(Some(SerializedKel::Bytes(arc_bytes)));
            }
        }

        // Need more events than we have tails for - get full and filter
        let events = self.get_full(prefix).await?;
        if events.is_empty() {
            return Ok(None);
        }

        let filtered: Vec<_> = events
            .into_iter()
            .filter(|e| e.event.version > since_version)
            .collect();

        Ok(Some(SerializedKel::NeedsProcessing(filtered)))
    }

    pub async fn get_since(
        &self,
        prefix: &str,
        since_version: u64,
    ) -> Result<Vec<SignedKeyEvent>, KelsError> {
        match self.get_since_serialized(prefix, since_version).await? {
            Some(SerializedKel::Bytes(bytes)) => Ok(serde_json::from_slice(&bytes)?),
            Some(SerializedKel::NeedsProcessing(events)) => Ok(events),
            None => Ok(vec![]),
        }
    }

    pub async fn delete(&self, prefix: &str) -> Result<(), KelsError> {
        let mut conn = self.conn.clone();

        // Delete all keys for this prefix
        let keys = vec![
            self.redis_key_full(prefix),
            self.redis_key_version(prefix),
            self.redis_key_tail(prefix, 1),
            self.redis_key_tail(prefix, 2),
        ];

        let _: () = conn
            .del(&keys)
            .await
            .map_err(|e| KelsError::CacheError(format!("Redis DEL failed: {}", e)))?;

        // Clear local cache
        {
            let mut local = self.local_cache.write().await;
            local.clear(prefix);
        }

        self.publish_update(prefix, "").await?;
        Ok(())
    }
}

pub fn parse_pubsub_message(message: &str) -> Option<(&str, &str)> {
    let mut parts = message.splitn(2, ':');
    let prefix = parts.next()?;
    let version = parts.next().unwrap_or("");
    Some((prefix, version))
}

pub fn pubsub_channel() -> &'static str {
    PUBSUB_CHANNEL
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pubsub_message() {
        assert_eq!(
            parse_pubsub_message("Eprefix123:42"),
            Some(("Eprefix123", "42"))
        );
        assert_eq!(
            parse_pubsub_message("Eprefix123:"),
            Some(("Eprefix123", ""))
        );
    }

    #[test]
    fn test_local_cache_basic() {
        let mut cache = LocalCache::new(100);
        let bytes = b"test data".to_vec();
        cache.set("key1".to_string(), bytes.clone());

        let retrieved = cache.get("key1");
        assert!(retrieved.is_some());
        assert_eq!(&*retrieved.unwrap(), &bytes);
    }

    #[test]
    fn test_local_cache_lru_eviction() {
        let mut cache = LocalCache::new(2);

        cache.set("k1".to_string(), b"data1".to_vec());
        cache.set("k2".to_string(), b"data2".to_vec());
        let _ = cache.get("k1"); // Touch k1
        cache.set("k3".to_string(), b"data3".to_vec()); // Evicts k2

        assert!(cache.get("k1").is_some());
        assert!(cache.get("k2").is_none());
        assert!(cache.get("k3").is_some());
    }
}
