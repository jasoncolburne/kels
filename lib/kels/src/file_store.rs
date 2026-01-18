//! File-based KEL storage

use async_trait::async_trait;

use crate::error::KelsError;
use crate::kel::Kel;
use crate::store::KelStore;
use crate::types::SignedKeyEvent;

/// File-based KEL store for CLI and desktop apps
pub struct FileKelStore {
    kel_dir: std::path::PathBuf,
    owner_prefix: std::sync::RwLock<Option<String>>,
}

impl FileKelStore {
    pub fn new(kel_dir: impl Into<std::path::PathBuf>) -> Result<Self, KelsError> {
        let kel_dir = kel_dir.into();
        std::fs::create_dir_all(&kel_dir).map_err(|e| KelsError::StorageError(e.to_string()))?;
        Ok(Self { kel_dir, owner_prefix: std::sync::RwLock::new(None) })
    }

    /// Owner prefix protects authoritative KEL from being overwritten by server-fetched data.
    pub fn with_owner(kel_dir: impl Into<std::path::PathBuf>, owner_prefix: String) -> Result<Self, KelsError> {
        let kel_dir = kel_dir.into();
        std::fs::create_dir_all(&kel_dir).map_err(|e| KelsError::StorageError(e.to_string()))?;
        Ok(Self { kel_dir, owner_prefix: std::sync::RwLock::new(Some(owner_prefix)) })
    }

    fn kel_path(&self, prefix: &str) -> std::path::PathBuf { self.kel_dir.join(format!("{}.kel.json", prefix)) }
    fn owner_tail_path(&self, prefix: &str) -> std::path::PathBuf { self.kel_dir.join(format!("{}.owner_tail", prefix)) }
}

#[async_trait]
impl KelStore for FileKelStore {
    fn owner_prefix(&self) -> Option<String> { self.owner_prefix.read().ok().and_then(|g| g.clone()) }
    fn set_owner_prefix(&self, prefix: Option<&str>) {
        if let Ok(mut guard) = self.owner_prefix.write() { *guard = prefix.map(|s| s.to_string()); }
    }

    async fn load(&self, prefix: &str) -> Result<Option<Kel>, KelsError> {
        let path = self.kel_path(prefix);
        if !path.exists() { return Ok(None); }
        let contents = std::fs::read_to_string(&path).map_err(|e| KelsError::StorageError(e.to_string()))?;
        let events: Vec<SignedKeyEvent> = serde_json::from_str(&contents)?;
        Ok(Some(Kel::from_events(events, true)?))
    }

    async fn save(&self, kel: &Kel) -> Result<(), KelsError> {
        use std::io::Write;
        let prefix = kel.prefix().ok_or_else(|| KelsError::InvalidKel("KEL has no prefix".to_string()))?;
        let path = self.kel_path(prefix);
        let contents = serde_json::to_string_pretty(kel.events())?;
        let mut file = std::fs::File::create(&path).map_err(|e| KelsError::StorageError(e.to_string()))?;
        file.write_all(contents.as_bytes()).map_err(|e| KelsError::StorageError(e.to_string()))?;
        file.sync_all().map_err(|e| KelsError::StorageError(e.to_string()))?;
        Ok(())
    }

    async fn delete(&self, prefix: &str) -> Result<(), KelsError> {
        let path = self.kel_path(prefix);
        if path.exists() { std::fs::remove_file(&path).map_err(|e| KelsError::StorageError(e.to_string()))?; }
        let tail_path = self.owner_tail_path(prefix);
        if tail_path.exists() { let _ = std::fs::remove_file(&tail_path); }
        Ok(())
    }

    async fn save_owner_tail(&self, prefix: &str, said: &str) -> Result<(), KelsError> {
        use std::io::Write;
        let path = self.owner_tail_path(prefix);
        let mut file = std::fs::File::create(&path).map_err(|e| KelsError::StorageError(e.to_string()))?;
        file.write_all(said.as_bytes()).map_err(|e| KelsError::StorageError(e.to_string()))?;
        file.sync_all().map_err(|e| KelsError::StorageError(e.to_string()))?;
        Ok(())
    }

    async fn load_owner_tail(&self, prefix: &str) -> Result<Option<String>, KelsError> {
        let path = self.owner_tail_path(prefix);
        if !path.exists() { return Ok(None); }
        let contents = std::fs::read_to_string(&path).map_err(|e| KelsError::StorageError(e.to_string()))?;
        Ok(Some(contents.trim().to_string()))
    }
}
