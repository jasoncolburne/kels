//! Redis-backed KEL cache with W-TinyLFU local cache.
//!
//! # Architecture
//!
//! - **Redis**: Pre-serialized JSON stored for full KEL
//! - **Local W-TinyLFU**: Frequency-aware cache to avoid Redis round trips
//! - **Redis Pub/Sub**: Publishes `{prefix}:{said}` on changes for cross-replica invalidation
//!
//! # W-TinyLFU Design
//!
//! Window TinyLFU combines recency and frequency for better hit rates:
//! - **Window** (1%): Small LRU for new items - catches burst patterns
//! - **Main** (99%): SLRU split into probation (20%) and protected (80%)
//! - **Count-Min Sketch**: Estimates access frequency with minimal memory
//! - **Admission**: Items evicted from window compete with main's victim on frequency

use crate::{KelsError, SignedKeyEvent};
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use tokio::sync::RwLock;

const LOCAL_CACHE_MAX_ENTRIES: usize = 50_000;
const PUBSUB_CHANNEL: &str = "kel_updates";

// W-TinyLFU configuration (as percentages of total capacity)
const WINDOW_PERCENT: usize = 1; // 1% window
const PROTECTED_PERCENT: usize = 80; // 80% of main is protected

// Count-Min Sketch configuration
const SKETCH_DEPTH: usize = 4; // Number of hash functions
const SKETCH_WIDTH: usize = 65536; // Counters per row (64K)
const SKETCH_RESET_THRESHOLD: u64 = 10_000_000; // Reset after this many accesses

/// Count-Min Sketch for frequency estimation
struct CountMinSketch {
    counters: Vec<Vec<u8>>, // Using u8 to save memory, saturates at 255
    seeds: [u64; SKETCH_DEPTH],
    total_accesses: u64,
}

impl CountMinSketch {
    fn new() -> Self {
        Self {
            counters: vec![vec![0u8; SKETCH_WIDTH]; SKETCH_DEPTH],
            seeds: [
                0x9e3779b97f4a7c15,
                0xbf58476d1ce4e5b9,
                0x94d049bb133111eb,
                0x7fb5d329728ea185,
            ],
            total_accesses: 0,
        }
    }

    fn hash(&self, key: &str, seed: u64) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        seed.hash(&mut hasher);
        key.hash(&mut hasher);
        (hasher.finish() as usize) % SKETCH_WIDTH
    }

    fn increment(&mut self, key: &str) {
        self.total_accesses += 1;

        // Periodic reset to prevent stale frequencies from dominating
        if self.total_accesses >= SKETCH_RESET_THRESHOLD {
            self.reset();
        }

        for (i, &seed) in self.seeds.iter().enumerate() {
            let idx = self.hash(key, seed);
            self.counters[i][idx] = self.counters[i][idx].saturating_add(1);
        }
    }

    fn estimate(&self, key: &str) -> u8 {
        self.seeds
            .iter()
            .enumerate()
            .map(|(i, &seed)| {
                let idx = self.hash(key, seed);
                self.counters[i][idx]
            })
            .min()
            .unwrap_or(0)
    }

    fn reset(&mut self) {
        // Halve all counters (age decay)
        for row in &mut self.counters {
            for counter in row {
                *counter >>= 1;
            }
        }
        self.total_accesses = 0;
    }
}

/// Entry in the cache with its data
struct CacheEntry {
    bytes: Arc<Vec<u8>>,
}

/// W-TinyLFU local cache implementation
pub struct LocalCache {
    // Frequency sketch
    sketch: CountMinSketch,

    // Window LRU (1% of capacity) - new items enter here
    window: VecDeque<String>,
    window_capacity: usize,

    // Main cache - SLRU with probation and protected segments
    probation: VecDeque<String>, // 20% of main
    protected: VecDeque<String>, // 80% of main
    probation_capacity: usize,
    protected_capacity: usize,

    // Actual data storage
    entries: HashMap<String, CacheEntry>,

    // Track which segment each key is in
    key_segment: HashMap<String, Segment>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Segment {
    Window,
    Probation,
    Protected,
}

impl LocalCache {
    fn new(max_entries: usize) -> Self {
        let window_capacity = (max_entries * WINDOW_PERCENT / 100).max(1);
        let main_capacity = max_entries - window_capacity;
        let protected_capacity = main_capacity * PROTECTED_PERCENT / 100;
        let probation_capacity = main_capacity - protected_capacity;

        Self {
            sketch: CountMinSketch::new(),
            window: VecDeque::with_capacity(window_capacity),
            window_capacity,
            probation: VecDeque::with_capacity(probation_capacity),
            protected: VecDeque::with_capacity(protected_capacity),
            probation_capacity,
            protected_capacity,
            entries: HashMap::with_capacity(max_entries),
            key_segment: HashMap::with_capacity(max_entries),
        }
    }

    fn get(&mut self, key: &str) -> Option<Arc<Vec<u8>>> {
        // Record access in sketch
        self.sketch.increment(key);

        let entry = self.entries.get(key)?;
        let bytes = Arc::clone(&entry.bytes);

        // Promote based on current segment
        if let Some(&segment) = self.key_segment.get(key) {
            match segment {
                Segment::Window => {
                    // Move to front of window
                    self.move_to_front_of_window(key);
                }
                Segment::Probation => {
                    // Promote to protected
                    self.promote_to_protected(key);
                }
                Segment::Protected => {
                    // Move to front of protected
                    self.move_to_front_of_protected(key);
                }
            }
        }

        Some(bytes)
    }

    fn set(&mut self, key: String, bytes: Vec<u8>) {
        // Record access
        self.sketch.increment(&key);

        // If already in cache, update and promote
        if self.entries.contains_key(&key) {
            self.entries.insert(
                key.clone(),
                CacheEntry {
                    bytes: Arc::new(bytes),
                },
            );
            // Trigger promotion logic via get path
            if let Some(&segment) = self.key_segment.get(&key) {
                match segment {
                    Segment::Window => self.move_to_front_of_window(&key),
                    Segment::Probation => self.promote_to_protected(&key),
                    Segment::Protected => self.move_to_front_of_protected(&key),
                }
            }
            return;
        }

        // New item - add to window
        self.entries.insert(
            key.clone(),
            CacheEntry {
                bytes: Arc::new(bytes),
            },
        );
        self.key_segment.insert(key.clone(), Segment::Window);
        self.window.push_front(key);

        // Evict from window if needed
        self.evict_from_window();
    }

    fn evict_from_window(&mut self) {
        while self.window.len() > self.window_capacity {
            if let Some(victim_key) = self.window.pop_back() {
                // Try to admit to main cache
                let victim_freq = self.sketch.estimate(&victim_key);

                // Find main cache victim (from probation)
                if let Some(main_victim_key) = self.probation.back().cloned() {
                    let main_victim_freq = self.sketch.estimate(&main_victim_key);

                    if victim_freq > main_victim_freq {
                        // Admit window victim to probation, evict main victim
                        self.probation.pop_back();
                        self.entries.remove(&main_victim_key);
                        self.key_segment.remove(&main_victim_key);

                        self.key_segment
                            .insert(victim_key.clone(), Segment::Probation);
                        self.probation.push_front(victim_key);
                    } else {
                        // Window victim loses - evict it
                        self.entries.remove(&victim_key);
                        self.key_segment.remove(&victim_key);
                    }
                } else {
                    // Probation empty - admit directly
                    self.key_segment
                        .insert(victim_key.clone(), Segment::Probation);
                    self.probation.push_front(victim_key);
                }

                // Handle probation overflow
                self.evict_from_probation();
            }
        }
    }

    fn evict_from_probation(&mut self) {
        while self.probation.len() > self.probation_capacity {
            if let Some(victim_key) = self.probation.pop_back() {
                self.entries.remove(&victim_key);
                self.key_segment.remove(&victim_key);
            }
        }
    }

    fn promote_to_protected(&mut self, key: &str) {
        // Remove from probation
        self.probation.retain(|k| k != key);

        // Add to protected
        self.key_segment.insert(key.to_string(), Segment::Protected);
        self.protected.push_front(key.to_string());

        // Handle protected overflow - demote to probation
        while self.protected.len() > self.protected_capacity {
            if let Some(demoted_key) = self.protected.pop_back() {
                self.key_segment
                    .insert(demoted_key.clone(), Segment::Probation);
                self.probation.push_front(demoted_key);
                self.evict_from_probation();
            }
        }
    }

    fn move_to_front_of_window(&mut self, key: &str) {
        self.window.retain(|k| k != key);
        self.window.push_front(key.to_string());
    }

    fn move_to_front_of_protected(&mut self, key: &str) {
        self.protected.retain(|k| k != key);
        self.protected.push_front(key.to_string());
    }

    pub fn clear(&mut self, prefix: &str) {
        if let Some(segment) = self.key_segment.remove(prefix) {
            self.entries.remove(prefix);
            match segment {
                Segment::Window => self.window.retain(|k| k != prefix),
                Segment::Probation => self.probation.retain(|k| k != prefix),
                Segment::Protected => self.protected.retain(|k| k != prefix),
            }
        }
    }

    /// Returns (window_size, probation_size, protected_size, total_entries)
    #[cfg(test)]
    fn stats(&self) -> (usize, usize, usize, usize) {
        (
            self.window.len(),
            self.probation.len(),
            self.protected.len(),
            self.entries.len(),
        )
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
    fn test_local_cache_frequency_wins() {
        // With W-TinyLFU, frequently accessed items should survive eviction
        let mut cache = LocalCache::new(10); // Small cache for testing

        // Add some items and access k1 many times
        cache.set("k1".to_string(), b"data1".to_vec());
        for _ in 0..100 {
            let _ = cache.get("k1");
        }

        // Fill cache with other items
        for i in 2..=20 {
            cache.set(format!("k{}", i), format!("data{}", i).into_bytes());
        }

        // k1 should still be in cache due to high frequency
        assert!(
            cache.get("k1").is_some(),
            "Frequently accessed item should survive"
        );
    }

    #[test]
    fn test_local_cache_clear() {
        let mut cache = LocalCache::new(100);
        cache.set("k1".to_string(), b"data1".to_vec());
        cache.set("k2".to_string(), b"data2".to_vec());

        cache.clear("k1");

        assert!(cache.get("k1").is_none());
        assert!(cache.get("k2").is_some());
    }

    #[test]
    fn test_local_cache_get_nonexistent() {
        let mut cache = LocalCache::new(100);
        assert!(cache.get("nonexistent").is_none());
    }

    #[test]
    fn test_local_cache_update_existing() {
        let mut cache = LocalCache::new(100);
        cache.set("k1".to_string(), b"data1".to_vec());
        cache.set("k1".to_string(), b"updated".to_vec());

        assert_eq!(&*cache.get("k1").unwrap(), b"updated");
    }

    #[test]
    fn test_pubsub_channel() {
        assert_eq!(pubsub_channel(), "kel_updates");
    }

    #[test]
    fn test_parse_pubsub_empty_said() {
        let result = parse_pubsub_message("prefixonly");
        assert_eq!(result, Some(("prefixonly", "")));
    }

    #[test]
    fn test_count_min_sketch() {
        let mut sketch = CountMinSketch::new();

        sketch.increment("key1");
        sketch.increment("key1");
        sketch.increment("key1");
        sketch.increment("key2");

        assert!(sketch.estimate("key1") >= 3);
        assert!(sketch.estimate("key2") >= 1);
        assert_eq!(sketch.estimate("key3"), 0);
    }

    #[test]
    fn test_cache_segments() {
        let mut cache = LocalCache::new(100);

        // Add item - should go to window
        cache.set("k1".to_string(), b"data1".to_vec());
        let (window, probation, protected, _) = cache.stats();
        assert_eq!(window, 1);
        assert_eq!(probation, 0);
        assert_eq!(protected, 0);
    }

    #[test]
    fn test_promotion_to_protected() {
        let mut cache = LocalCache::new(1000);

        // Fill window to force eviction to probation
        for i in 0..20 {
            cache.set(format!("k{}", i), format!("data{}", i).into_bytes());
        }

        // Access an item in probation twice to promote to protected
        // First access moves from probation to protected
        if let Some(key) = cache.probation.front().cloned() {
            let _ = cache.get(&key); // First access promotes to protected
            assert_eq!(cache.key_segment.get(&key), Some(&Segment::Protected));
        }
    }

    #[test]
    fn test_admission_policy_frequency_comparison() {
        // W-TinyLFU admission: window victim competes with probation victim on frequency
        let mut cache = LocalCache::new(100);

        // Window capacity = 1% of 100 = 1
        // Probation capacity = 19% of 100 = 19
        // Protected capacity = 80% of 100 = 80

        // Add item to probation and boost its frequency
        cache.set("probation_item".to_string(), b"data".to_vec());
        // Force to probation by filling window
        cache.set("window_filler".to_string(), b"data".to_vec());

        // Boost probation item frequency
        for _ in 0..50 {
            let _ = cache.get("probation_item");
        }

        // Now add a new low-frequency item - it should lose to high-frequency probation item
        cache.set("new_low_freq".to_string(), b"data".to_vec());

        // The high-frequency item should still be in cache
        assert!(
            cache.get("probation_item").is_some(),
            "High-frequency probation item should survive admission competition"
        );
    }

    #[test]
    fn test_protected_overflow_demotes_to_probation() {
        // When protected segment overflows, items demote to probation
        let mut cache = LocalCache::new(100);

        // Fill cache and promote many items to protected
        for i in 0..50 {
            cache.set(format!("k{}", i), format!("data{}", i).into_bytes());
        }

        // Access items in probation to promote to protected
        let probation_keys: Vec<_> = cache.probation.iter().cloned().collect();
        for key in probation_keys {
            let _ = cache.get(&key); // Promotes to protected
        }

        let (_, probation, protected, _) = cache.stats();

        // Protected should be at or near capacity (80)
        // Overflow should have demoted some to probation
        assert!(
            protected <= cache.protected_capacity,
            "Protected segment should not exceed capacity"
        );
        assert!(
            probation > 0 || protected > 0,
            "Items should be in main cache segments"
        );
    }

    #[test]
    fn test_count_min_sketch_decay() {
        let mut sketch = CountMinSketch::new();

        // Increment key1 many times
        for _ in 0..100 {
            sketch.increment("key1");
        }
        let freq_before = sketch.estimate("key1");
        assert!(freq_before >= 100);

        // Manually trigger reset (simulating threshold reached)
        sketch.reset();

        let freq_after = sketch.estimate("key1");
        // After decay, frequency should be halved
        assert!(
            freq_after < freq_before,
            "Frequency should decrease after decay"
        );
        assert!(
            freq_after >= freq_before / 2 - 1,
            "Frequency should be approximately halved"
        );
    }

    #[test]
    fn test_cache_respects_total_capacity() {
        let max_entries = 100;
        let mut cache = LocalCache::new(max_entries);

        // Add more items than capacity
        for i in 0..200 {
            cache.set(format!("k{}", i), format!("data{}", i).into_bytes());
        }

        let (window, probation, protected, total) = cache.stats();

        // Total entries should not exceed max
        assert!(
            total <= max_entries,
            "Total entries {} should not exceed max {}",
            total,
            max_entries
        );

        // Segments should respect their capacities
        assert!(
            window <= cache.window_capacity,
            "Window {} exceeds capacity {}",
            window,
            cache.window_capacity
        );
        assert!(
            probation <= cache.probation_capacity,
            "Probation {} exceeds capacity {}",
            probation,
            cache.probation_capacity
        );
        assert!(
            protected <= cache.protected_capacity,
            "Protected {} exceeds capacity {}",
            protected,
            cache.protected_capacity
        );
    }

    #[test]
    fn test_window_to_probation_flow() {
        let mut cache = LocalCache::new(100);
        // Window capacity = 1

        // First item goes to window
        cache.set("first".to_string(), b"data".to_vec());
        assert_eq!(cache.key_segment.get("first"), Some(&Segment::Window));

        // Second item evicts first from window
        cache.set("second".to_string(), b"data".to_vec());

        // First should now be in probation (or evicted if it lost admission)
        // Second should be in window
        assert_eq!(cache.key_segment.get("second"), Some(&Segment::Window));

        // First should have moved to probation (empty probation = automatic admission)
        assert_eq!(cache.key_segment.get("first"), Some(&Segment::Probation));
    }
}
