//! File-based KEL storage (newline-delimited JSON)

use std::io::{BufRead, Write};

use async_trait::async_trait;

use super::KelStore;
use crate::{error::KelsError, types::SignedKeyEvent};

/// File-based KEL store for CLI and desktop apps.
/// Events are stored as newline-delimited JSON (one JSON object per line).
pub struct FileKelStore {
    kel_dir: std::path::PathBuf,
    owner_prefix: std::sync::RwLock<Option<cesr::Digest256>>,
}

impl FileKelStore {
    pub fn new(kel_dir: impl Into<std::path::PathBuf>) -> Result<Self, KelsError> {
        let kel_dir = kel_dir.into();
        std::fs::create_dir_all(&kel_dir).map_err(|e| KelsError::StorageError(e.to_string()))?;
        Ok(Self {
            kel_dir,
            owner_prefix: std::sync::RwLock::new(None),
        })
    }

    /// Owner prefix protects authoritative KEL from being overwritten by server-fetched data.
    pub fn with_owner(
        kel_dir: impl Into<std::path::PathBuf>,
        owner_prefix: cesr::Digest256,
    ) -> Result<Self, KelsError> {
        let kel_dir = kel_dir.into();
        std::fs::create_dir_all(&kel_dir).map_err(|e| KelsError::StorageError(e.to_string()))?;
        Ok(Self {
            kel_dir,
            owner_prefix: std::sync::RwLock::new(Some(owner_prefix)),
        })
    }

    fn kel_path(&self, prefix: &str) -> std::path::PathBuf {
        self.kel_dir.join(format!("{}.kel.jsonl", prefix))
    }
}

#[async_trait]
impl KelStore for FileKelStore {
    fn owner_prefix(&self) -> Option<cesr::Digest256> {
        self.owner_prefix.read().ok().and_then(|g| *g)
    }
    fn set_owner_prefix(&self, prefix: Option<&cesr::Digest256>) {
        if let Ok(mut guard) = self.owner_prefix.write() {
            *guard = prefix.cloned();
        }
    }

    async fn load(
        &self,
        prefix: &cesr::Digest256,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<SignedKeyEvent>, bool), KelsError> {
        let path = self.kel_path(prefix.as_ref());
        if !path.exists() {
            return Ok((vec![], false));
        }
        let file =
            std::fs::File::open(&path).map_err(|e| KelsError::StorageError(e.to_string()))?;
        let reader = std::io::BufReader::new(file);

        let start = offset as usize;
        let limit = limit as usize;
        let mut events = Vec::new();
        let mut count = 0;

        for line in reader.lines() {
            let line = line.map_err(|e| KelsError::StorageError(e.to_string()))?;
            if line.is_empty() {
                continue;
            }
            if count < start {
                count += 1;
                continue;
            }
            if events.len() >= limit {
                return Ok((events, true));
            }
            let event: SignedKeyEvent = serde_json::from_str(&line)?;
            events.push(event);
            count += 1;
        }

        Ok((events, false))
    }

    async fn load_tail(
        &self,
        prefix: &cesr::Digest256,
        limit: u64,
    ) -> Result<Vec<SignedKeyEvent>, KelsError> {
        let path = self.kel_path(prefix.as_ref());
        if !path.exists() {
            return Ok(vec![]);
        }
        let file =
            std::fs::File::open(&path).map_err(|e| KelsError::StorageError(e.to_string()))?;
        let reader = std::io::BufReader::new(file);
        let limit = limit as usize;

        // Collect all lines, keeping only the last `limit` in a ring buffer.
        let mut ring: std::collections::VecDeque<String> =
            std::collections::VecDeque::with_capacity(limit);
        for line in reader.lines() {
            let line = line.map_err(|e| KelsError::StorageError(e.to_string()))?;
            if line.is_empty() {
                continue;
            }
            if ring.len() == limit {
                ring.pop_front();
            }
            ring.push_back(line);
        }

        ring.iter()
            .map(|line| serde_json::from_str(line).map_err(Into::into))
            .collect()
    }

    async fn append(
        &self,
        prefix: &cesr::Digest256,
        events: &[SignedKeyEvent],
    ) -> Result<(), KelsError> {
        let path = self.kel_path(prefix.as_ref());
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| KelsError::StorageError(e.to_string()))?;

        for event in events {
            let line = serde_json::to_string(event)?;
            file.write_all(line.as_bytes())
                .map_err(|e| KelsError::StorageError(e.to_string()))?;
            file.write_all(b"\n")
                .map_err(|e| KelsError::StorageError(e.to_string()))?;
        }
        file.sync_all()
            .map_err(|e| KelsError::StorageError(e.to_string()))?;
        Ok(())
    }

    async fn overwrite(
        &self,
        prefix: &cesr::Digest256,
        events: &[SignedKeyEvent],
    ) -> Result<(), KelsError> {
        let path = self.kel_path(prefix.as_ref());
        let mut file =
            std::fs::File::create(&path).map_err(|e| KelsError::StorageError(e.to_string()))?;
        for event in events {
            let line = serde_json::to_string(event)?;
            file.write_all(line.as_bytes())
                .map_err(|e| KelsError::StorageError(e.to_string()))?;
            file.write_all(b"\n")
                .map_err(|e| KelsError::StorageError(e.to_string()))?;
        }
        file.sync_all()
            .map_err(|e| KelsError::StorageError(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use cesr::test_digest;
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn test_new_creates_directory() {
        let temp = TempDir::new().unwrap();
        let subdir = temp.path().join("kels");
        assert!(!subdir.exists());

        let _store = FileKelStore::new(&subdir).unwrap();
        assert!(subdir.exists());
    }

    #[test]
    fn test_new_with_existing_directory() {
        let temp = TempDir::new().unwrap();
        let _store = FileKelStore::new(temp.path()).unwrap();
        assert!(temp.path().exists());
    }

    #[test]
    fn test_with_owner_sets_prefix() {
        let temp = TempDir::new().unwrap();
        let d = test_digest("my-prefix");
        let store = FileKelStore::with_owner(temp.path(), d).unwrap();
        assert_eq!(store.owner_prefix(), Some(d));
    }

    #[test]
    fn test_owner_prefix_initially_none() {
        let temp = TempDir::new().unwrap();
        let store = FileKelStore::new(temp.path()).unwrap();
        assert_eq!(store.owner_prefix(), None);
    }

    #[test]
    fn test_set_owner_prefix() {
        let temp = TempDir::new().unwrap();
        let store = FileKelStore::new(temp.path()).unwrap();

        let d = test_digest("new-owner");
        store.set_owner_prefix(Some(&d));
        assert_eq!(store.owner_prefix(), Some(d));

        store.set_owner_prefix(None);
        assert_eq!(store.owner_prefix(), None);
    }

    #[tokio::test]
    async fn test_load_nonexistent_returns_empty() {
        let temp = TempDir::new().unwrap();
        let store = FileKelStore::new(temp.path()).unwrap();

        let nonexistent = test_digest("nonexistent");
        let (events, has_more) = store.load(&nonexistent, crate::LOAD_ALL, 0).await.unwrap();
        assert!(events.is_empty());
        assert!(!has_more);
    }

    #[tokio::test]
    async fn test_overwrite_and_load_roundtrip() {
        let temp = TempDir::new().unwrap();
        let store = FileKelStore::new(temp.path()).unwrap();

        let (prefix, events) = crate::store::create_test_events().await;
        let event_count = events.len();

        store.overwrite(&prefix, &events).await.unwrap();

        let (loaded, _) = store.load(&prefix, crate::LOAD_ALL, 0).await.unwrap();
        assert_eq!(loaded.len(), event_count);
    }

    #[tokio::test]
    async fn test_overwrite_creates_jsonl_file() {
        let temp = TempDir::new().unwrap();
        let store = FileKelStore::new(temp.path()).unwrap();

        let (prefix, events) = crate::store::create_test_events().await;

        store.overwrite(&prefix, &events).await.unwrap();

        let expected_path = temp.path().join(format!("{}.kel.jsonl", prefix));
        assert!(expected_path.exists());

        // Verify each line is valid JSON
        let contents = std::fs::read_to_string(&expected_path).unwrap();
        for line in contents.lines() {
            let _: SignedKeyEvent = serde_json::from_str(line).unwrap();
        }
    }

    #[tokio::test]
    async fn test_append_creates_and_extends() {
        let temp = TempDir::new().unwrap();
        let store = FileKelStore::new(temp.path()).unwrap();

        let (prefix, events) = crate::store::create_test_events().await;

        // Append first event
        store.append(&prefix, &events[..1]).await.unwrap();
        let (loaded, _) = store.load(&prefix, crate::LOAD_ALL, 0).await.unwrap();
        assert_eq!(loaded.len(), 1);

        // Append remaining events
        store.append(&prefix, &events[1..]).await.unwrap();
        let (loaded, _) = store.load(&prefix, crate::LOAD_ALL, 0).await.unwrap();
        assert_eq!(loaded.len(), events.len());
    }

    #[tokio::test]
    async fn test_load_invalid_json_returns_error() {
        let temp = TempDir::new().unwrap();
        let store = FileKelStore::new(temp.path()).unwrap();

        // Write invalid JSONL — use a known digest and its string form for the filename
        let bad_prefix = test_digest("bad");
        let path = temp.path().join(format!("{}.kel.jsonl", bad_prefix));
        std::fs::write(&path, "not valid json\n").unwrap();

        let result = store.load(&bad_prefix, crate::LOAD_ALL, 0).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_path_isolation_between_prefixes() {
        let temp = TempDir::new().unwrap();
        let store = FileKelStore::new(temp.path()).unwrap();

        let (prefix1, events1) = crate::store::create_test_events().await;
        let (prefix2, events2) = crate::store::create_test_events().await;

        store.overwrite(&prefix1, &events1).await.unwrap();
        store.overwrite(&prefix2, &events2).await.unwrap();

        // Both should be loadable independently
        let (loaded1, _) = store.load(&prefix1, crate::LOAD_ALL, 0).await.unwrap();
        let (loaded2, _) = store.load(&prefix2, crate::LOAD_ALL, 0).await.unwrap();

        assert!(!loaded1.is_empty());
        assert!(!loaded2.is_empty());
    }

    #[tokio::test]
    async fn test_cache_skips_owner_prefix() {
        let temp = TempDir::new().unwrap();
        let store = FileKelStore::new(temp.path()).unwrap();

        let (prefix, events) = crate::store::create_test_events().await;

        // Set this KEL's prefix as the owner
        store.set_owner_prefix(Some(&prefix));

        // Cache should skip saving because it's the owner's KEL
        store.cache(&prefix, &events).await.unwrap();

        // KEL should NOT be saved
        let (loaded, _) = store.load(&prefix, crate::LOAD_ALL, 0).await.unwrap();
        assert!(loaded.is_empty());
    }

    #[tokio::test]
    async fn test_cache_saves_non_owner_kel() {
        let temp = TempDir::new().unwrap();
        let store = FileKelStore::new(temp.path()).unwrap();

        let (prefix, events) = crate::store::create_test_events().await;

        // Set a different owner prefix
        store.set_owner_prefix(Some(&test_digest("different-prefix")));

        // Cache should save because it's not the owner's KEL
        store.cache(&prefix, &events).await.unwrap();

        // KEL should be saved
        let (loaded, _) = store.load(&prefix, crate::LOAD_ALL, 0).await.unwrap();
        assert!(!loaded.is_empty());
    }
}
