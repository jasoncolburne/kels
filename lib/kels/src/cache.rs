//! Redis-backed KEL cache with pre-serialized responses.
//!
//! # Architecture
//!
//! - **Redis**: Pre-serialized JSON stored for full KEL
//! - **Local LRU**: Caches pre-serialized bytes to avoid Redis round trips
//! - **Redis Pub/Sub**: Publishes `{prefix}:{said}` on changes for cross-replica invalidation

use crate::{KelsError, SignedKeyEvent};
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

const LOCAL_CACHE_MAX_ENTRIES: usize = 256;
const PUBSUB_CHANNEL: &str = "kel_updates";

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
        self.entries.remove(prefix);
    }
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

    fn redis_key(&self, prefix: &str) -> String {
        format!("{}:{}", self.key_prefix, prefix)
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

    /// Store a complete KEL as pre-serialized JSON
    pub async fn store(&self, prefix: &str, events: &[SignedKeyEvent]) -> Result<(), KelsError> {
        if events.is_empty() {
            return Ok(());
        }

        let latest_said = match events.last() {
            Some(e) => &e.event.said,
            None => return Ok(()),
        };

        let json = serde_json::to_vec(events)?;

        // Store in Redis
        let mut conn = self.conn.clone();
        let redis_key = self.redis_key(prefix);
        let _: () = conn
            .set(&redis_key, &json)
            .await
            .map_err(|e| KelsError::CacheError(format!("Redis SET failed: {}", e)))?;

        // Update local cache
        {
            let mut local = self.local_cache.write().await;
            local.set(prefix.to_string(), json);
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
        // Check local cache first
        {
            let mut local = self.local_cache.write().await;
            if let Some(bytes) = local.get(prefix) {
                return Ok(Some(bytes));
            }
        }

        // Fetch from Redis
        let redis_key = self.redis_key(prefix);
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
                    local.set(prefix.to_string(), b);
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
}

pub fn parse_pubsub_message(message: &str) -> Option<(&str, &str)> {
    let mut parts = message.splitn(2, ':');
    let prefix = parts.next()?;
    let said = parts.next().unwrap_or("");
    Some((prefix, said))
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
            parse_pubsub_message("Eprefix123:Esaid456"),
            Some(("Eprefix123", "Esaid456"))
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

    #[test]
    fn test_local_cache_clear() {
        let mut cache = LocalCache::new(10);
        cache.set("k1".to_string(), b"data1".to_vec());
        cache.set("k2".to_string(), b"data2".to_vec());

        cache.clear("k1");

        assert!(cache.get("k1").is_none());
        assert!(cache.get("k2").is_some());
    }

    #[test]
    fn test_local_cache_get_nonexistent() {
        let mut cache = LocalCache::new(10);
        assert!(cache.get("nonexistent").is_none());
    }

    #[test]
    fn test_local_cache_update_existing() {
        let mut cache = LocalCache::new(2);
        cache.set("k1".to_string(), b"data1".to_vec());
        cache.set("k2".to_string(), b"data2".to_vec());

        // Update k1 - should not evict k2
        cache.set("k1".to_string(), b"updated".to_vec());

        assert!(cache.get("k1").is_some());
        assert!(cache.get("k2").is_some());
        assert_eq!(&*cache.get("k1").unwrap(), b"updated");
    }

    #[test]
    fn test_pubsub_channel() {
        assert_eq!(pubsub_channel(), "kel_updates");
    }

    #[test]
    fn test_parse_pubsub_empty_said() {
        // When message is just prefix without colon
        let result = parse_pubsub_message("prefixonly");
        assert_eq!(result, Some(("prefixonly", "")));
    }
}
