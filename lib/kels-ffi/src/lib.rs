//! KELS FFI - C bindings for iOS/macOS applications
//!
//! This module provides C-compatible functions for interacting with KELS servers.
//! It wraps the KeyEventBuilder and related types for use from Swift/Objective-C.

#![allow(clippy::missing_safety_doc)]

use kels::{
    FileKelStore, KelStore, KelsClient, KelsError, KelsRegistryClient, KeyEventBuilder,
    KeyProvider, NodeStatus, PeersResponse,
};
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use tokio::runtime::Runtime;
use verifiable_storage::Versioned;

// ==================== Key State Persistence ====================

/// Persisted key state for restoring Secure Enclave keys
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct KeyState {
    current_label: Option<String>,
    next_label: Option<String>,
    recovery_label: Option<String>,
    next_label_generation: u64,
}

impl KeyState {
    #[allow(dead_code)] // Used only on macos/ios with secure-enclave feature
    fn load(state_dir: &Path, prefix: &str) -> Option<Self> {
        let path = state_dir.join(format!("{}.keys.json", prefix));
        let data = std::fs::read_to_string(&path).ok()?;
        serde_json::from_str(&data).ok()
    }

    fn save(&self, state_dir: &Path, prefix: &str) -> Result<(), KelsError> {
        let path = state_dir.join(format!("{}.keys.json", prefix));
        let data = serde_json::to_string_pretty(self)
            .map_err(|e| KelsError::StorageError(e.to_string()))?;
        std::fs::write(&path, data).map_err(|e| KelsError::StorageError(e.to_string()))?;
        Ok(())
    }

    #[allow(dead_code)]
    fn delete(state_dir: &Path, prefix: &str) {
        let path = state_dir.join(format!("{}.keys.json", prefix));
        let _ = std::fs::remove_file(&path);
    }
}

// ==================== Error Handling ====================

thread_local! {
    static LAST_ERROR: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

fn set_last_error(err: &str) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = Some(err.to_string());
    });
}

fn clear_last_error() {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = None;
    });
}

// ==================== Status Enums ====================

/// Status codes returned by KELS FFI functions
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KelsStatus {
    /// Operation completed successfully
    Ok = 0,
    /// Context not initialized or invalid
    NotInitialized = 1,
    /// Divergence detected - recovery may be needed
    DivergenceDetected = 2,
    /// KEL not found for the given prefix
    KelNotFound = 3,
    /// KEL is frozen (contested or decommissioned)
    KelFrozen = 4,
    /// Network or server error
    NetworkError = 5,
    /// KEL has not been incepted yet
    NotIncepted = 6,
    /// Recovery protected - adversary used recovery key, contest required
    RecoveryProtected = 7,
    /// Generic error - check kels_last_error() for details
    Error = 8,
}

/// Outcome of a recovery operation
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KelsRecoveryOutcome {
    /// Successfully recovered with new keys
    Recovered = 0,
    /// KEL contested and frozen
    Contested = 1,
    /// Recovery failed - check error
    Failed = 2,
}

// ==================== Result Structs ====================

/// Result from event operations (incept, rotate, interact, etc.)
#[repr(C)]
pub struct KelsEventResult {
    pub status: KelsStatus,
    /// KEL prefix (owned, must be freed with kels_free_string)
    pub prefix: *mut c_char,
    /// Event SAID (owned, must be freed with kels_free_string)
    pub said: *mut c_char,
    /// Event version number
    pub version: u64,
    /// Error message if status != Ok (owned, must be freed with kels_free_string)
    pub error: *mut c_char,
}

impl Default for KelsEventResult {
    fn default() -> Self {
        Self {
            status: KelsStatus::Error,
            prefix: std::ptr::null_mut(),
            said: std::ptr::null_mut(),
            version: 0,
            error: std::ptr::null_mut(),
        }
    }
}

/// Result from status query
#[repr(C)]
pub struct KelsStatusResult {
    pub status: KelsStatus,
    /// KEL prefix (owned, must be freed with kels_free_string)
    pub prefix: *mut c_char,
    /// Total number of events in KEL
    pub event_count: u32,
    /// SAID of latest event (owned, must be freed with kels_free_string)
    pub latest_said: *mut c_char,
    /// Whether divergence has been detected
    pub is_divergent: bool,
    /// Whether the KEL is contested
    pub is_contested: bool,
    /// Whether the KEL is decommissioned
    pub is_decommissioned: bool,
    /// Whether hardware (Secure Enclave) keys are in use
    pub use_hardware: bool,
    /// Error message if status != Ok (owned, must be freed with kels_free_string)
    pub error: *mut c_char,
}

impl Default for KelsStatusResult {
    fn default() -> Self {
        Self {
            status: KelsStatus::Error,
            prefix: std::ptr::null_mut(),
            event_count: 0,
            latest_said: std::ptr::null_mut(),
            is_divergent: false,
            is_contested: false,
            is_decommissioned: false,
            use_hardware: false,
            error: std::ptr::null_mut(),
        }
    }
}

/// Result from list operation
#[repr(C)]
pub struct KelsListResult {
    pub status: KelsStatus,
    /// JSON array of prefix strings (owned, must be freed with kels_free_string)
    pub prefixes_json: *mut c_char,
    /// Number of prefixes
    pub count: u32,
    /// Error message if status != Ok (owned, must be freed with kels_free_string)
    pub error: *mut c_char,
}

impl Default for KelsListResult {
    fn default() -> Self {
        Self {
            status: KelsStatus::Error,
            prefixes_json: std::ptr::null_mut(),
            count: 0,
            error: std::ptr::null_mut(),
        }
    }
}

/// Result from recovery operation
#[repr(C)]
pub struct KelsRecoveryResult {
    pub outcome: KelsRecoveryOutcome,
    pub status: KelsStatus,
    /// KEL prefix (owned, must be freed with kels_free_string)
    pub prefix: *mut c_char,
    /// Event SAID (owned, must be freed with kels_free_string)
    pub said: *mut c_char,
    /// Event version number
    pub version: u64,
    /// Error message if outcome == Failed (owned, must be freed with kels_free_string)
    pub error: *mut c_char,
}

impl Default for KelsRecoveryResult {
    fn default() -> Self {
        Self {
            outcome: KelsRecoveryOutcome::Failed,
            status: KelsStatus::Error,
            prefix: std::ptr::null_mut(),
            said: std::ptr::null_mut(),
            version: 0,
            error: std::ptr::null_mut(),
        }
    }
}

// ==================== Context ====================

/// Opaque context for KELS operations
pub struct KelsContext {
    builder: Arc<Mutex<KeyEventBuilder>>,
    store: Arc<FileKelStore>,
    runtime: Runtime,
    kels_url: RwLock<String>,
    state_dir: PathBuf,
    #[cfg(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "secure-enclave"
    ))]
    use_hardware: bool,
}

// ==================== Helper Functions ====================

fn to_c_string(s: &str) -> *mut c_char {
    CString::new(s)
        .map(|cs| cs.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

fn from_c_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr).to_str().ok().map(|s| s.to_string()) }
}

fn map_error_to_status(err: &KelsError) -> KelsStatus {
    match err {
        KelsError::KeyNotFound(_) => KelsStatus::KelNotFound,
        KelsError::NotIncepted => KelsStatus::NotIncepted,
        KelsError::KelDecommissioned => KelsStatus::KelFrozen,
        KelsError::ContestedKel(_) => KelsStatus::KelFrozen,
        KelsError::DivergenceDetected { .. } => KelsStatus::DivergenceDetected,
        KelsError::RecoveryProtected => KelsStatus::RecoveryProtected,
        KelsError::HttpError(_) | KelsError::ServerError(_) => KelsStatus::NetworkError,
        _ => KelsStatus::Error,
    }
}

/// Save key state from the builder's key provider
async fn save_key_state(
    builder: &KeyEventBuilder,
    state_dir: &Path,
    prefix: &str,
) -> Result<(), KelsError> {
    let key_provider = builder.key_provider();
    let key_state = KeyState {
        current_label: key_provider.current_handle().await,
        next_label: key_provider.next_handle().await,
        recovery_label: key_provider.recovery_handle().await,
        next_label_generation: key_provider.next_label_generation().await,
    };
    key_state.save(state_dir, prefix)
}

// ==================== Context Management ====================

/// Initialize a new KELS context
///
/// # Arguments
/// * `kels_url` - URL of the KELS server (e.g., "http://kels.example.com")
/// * `state_dir` - Directory for storing local state (KELs, keys)
/// * `prefix` - Optional existing KEL prefix to load (NULL for new)
///
/// # Returns
/// Pointer to context, or NULL on error. Check kels_last_error() for details.
#[unsafe(no_mangle)]
pub extern "C" fn kels_init(
    kels_url: *const c_char,
    state_dir: *const c_char,
    prefix: *const c_char,
) -> *mut KelsContext {
    clear_last_error();

    let Some(url) = from_c_string(kels_url) else {
        set_last_error("Invalid KELS URL");
        return std::ptr::null_mut();
    };

    let Some(state_dir_str) = from_c_string(state_dir) else {
        set_last_error("Invalid state directory");
        return std::ptr::null_mut();
    };

    let prefix_opt = from_c_string(prefix);
    let state_path = PathBuf::from(&state_dir_str);

    // Create runtime
    let Ok(runtime) = Runtime::new() else {
        set_last_error("Failed to create async runtime");
        return std::ptr::null_mut();
    };

    // Create store
    let store = match FileKelStore::new(&state_path) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            set_last_error(&format!("Failed to create store: {}", e));
            return std::ptr::null_mut();
        }
    };

    // Create key provider (prefer Secure Enclave on iOS/macOS)
    // If we have a saved prefix, try to load existing key state
    #[cfg(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "secure-enclave"
    ))]
    let (key_provider, use_hardware) = {
        let namespace = prefix_opt.as_deref().unwrap_or("kels-client").to_string();

        // Try to load existing key state for this prefix
        let key_state = prefix_opt
            .as_deref()
            .and_then(|p| KeyState::load(&state_path, p));

        if let Some(ks) = key_state {
            // Restore key provider with saved handles
            match KeyProvider::with_hardware_handles(
                &namespace,
                ks.current_label,
                ks.next_label,
                ks.recovery_label,
                ks.next_label_generation,
            ) {
                Some(p) => (p, true),
                None => {
                    // Fall back to fresh hardware provider
                    match KeyProvider::hardware(&namespace) {
                        Some(p) => (p, true),
                        None => (KeyProvider::software(), false),
                    }
                }
            }
        } else {
            // No saved state, create fresh provider
            match KeyProvider::hardware(&namespace) {
                Some(p) => (p, true),
                None => (KeyProvider::software(), false),
            }
        }
    };

    #[cfg(not(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "secure-enclave"
    )))]
    let (key_provider, _use_hardware) = (KeyProvider::software(), false);

    // Create KELS client
    let client = KelsClient::with_caching(&url);

    // Create builder
    let builder = runtime.block_on(async {
        KeyEventBuilder::with_dependencies(
            key_provider,
            Some(client),
            Some(store.clone()),
            prefix_opt.as_deref(),
        )
        .await
    });

    let builder = match builder {
        Ok(b) => b,
        Err(e) => {
            set_last_error(&format!("Failed to create builder: {}", e));
            return std::ptr::null_mut();
        }
    };

    let ctx = Box::new(KelsContext {
        builder: Arc::new(Mutex::new(builder)),
        store,
        runtime,
        kels_url: RwLock::new(url),
        state_dir: state_path,
        #[cfg(all(
            any(target_os = "macos", target_os = "ios"),
            feature = "secure-enclave"
        ))]
        use_hardware,
    });

    Box::into_raw(ctx)
}

/// Free a KELS context
///
/// # Safety
/// The context pointer must have been returned by kels_init() and not already freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_free(ctx: *mut KelsContext) {
    if !ctx.is_null() {
        unsafe {
            drop(Box::from_raw(ctx));
        }
    }
}

/// Change the KELS server URL at runtime
///
/// # Returns
/// 0 on success, -1 on error
///
/// # Safety
/// - `ctx` must be a valid context pointer
/// - `kels_url` must be a valid C string
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_set_url(ctx: *mut KelsContext, kels_url: *const c_char) -> i32 {
    clear_last_error();

    if ctx.is_null() {
        set_last_error("Context is null");
        return -1;
    }

    let Some(url) = from_c_string(kels_url) else {
        set_last_error("Invalid KELS URL");
        return -1;
    };

    let ctx = unsafe { &*ctx };

    // Update stored URL
    if let Ok(mut url_guard) = ctx.kels_url.write() {
        *url_guard = url.clone();
    } else {
        set_last_error("Failed to acquire URL lock");
        return -1;
    }

    // Create new client and update builder
    let client = KelsClient::with_caching(&url);

    let Ok(mut builder_guard) = ctx.builder.lock() else {
        set_last_error("Failed to acquire builder lock");
        return -1;
    };

    // Get current state from builder
    let prefix = builder_guard.prefix().map(|s| s.to_string());
    let kel = builder_guard.kel().clone();

    // Try to clone the key provider
    let key_provider_opt = ctx
        .runtime
        .block_on(async { builder_guard.key_provider().try_clone().await });

    let Some(key_provider) = key_provider_opt else {
        set_last_error("Cannot clone key provider");
        return -1;
    };

    // Create new builder with same state but new client, preserving store
    let new_builder =
        KeyEventBuilder::with_kel(key_provider, Some(client), Some(ctx.store.clone()), kel);
    *builder_guard = new_builder;

    // Preserve store owner prefix
    if let Some(p) = prefix {
        ctx.store.set_owner_prefix(Some(&p));
    }

    0
}

// ==================== KEL Operations ====================

/// Create an inception event (start a new KEL)
///
/// # Safety
/// - `ctx` must be a valid context pointer
/// - `result` must be a valid pointer to a KelsEventResult
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_incept(ctx: *mut KelsContext, result: *mut KelsEventResult) {
    clear_last_error();

    if ctx.is_null() || result.is_null() {
        if !result.is_null() {
            unsafe {
                (*result).status = KelsStatus::NotInitialized;
                (*result).error = to_c_string("Context or result is null");
            }
        }
        return;
    }

    let ctx = unsafe { &*ctx };
    let result = unsafe { &mut *result };
    *result = KelsEventResult::default();

    let Ok(mut builder_guard) = ctx.builder.lock() else {
        result.status = KelsStatus::Error;
        result.error = to_c_string("Failed to acquire builder lock");
        return;
    };

    let incept_result = ctx.runtime.block_on(async { builder_guard.incept().await });

    match incept_result {
        Ok((event, _sig)) => {
            // Set owner prefix after successful inception
            ctx.store.set_owner_prefix(Some(&event.prefix));

            // Save key state for future restarts
            let save_result = ctx.runtime.block_on(save_key_state(
                &builder_guard,
                &ctx.state_dir,
                &event.prefix,
            ));
            if let Err(e) = save_result {
                // Log but don't fail - the event was created successfully
                set_last_error(&format!("Warning: Failed to save key state: {}", e));
            }

            result.status = KelsStatus::Ok;
            result.prefix = to_c_string(&event.prefix);
            result.said = to_c_string(&event.said);
            result.version = event.version;
        }
        Err(e) => {
            result.status = map_error_to_status(&e);
            result.error = to_c_string(&e.to_string());
            set_last_error(&e.to_string());
        }
    }
}

/// Rotate the signing key
///
/// # Safety
/// - `ctx` must be a valid context pointer
/// - `result` must be a valid pointer to a KelsEventResult
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_rotate(ctx: *mut KelsContext, result: *mut KelsEventResult) {
    clear_last_error();

    if ctx.is_null() || result.is_null() {
        if !result.is_null() {
            unsafe {
                (*result).status = KelsStatus::NotInitialized;
                (*result).error = to_c_string("Context or result is null");
            }
        }
        return;
    }

    let ctx = unsafe { &*ctx };
    let result = unsafe { &mut *result };
    *result = KelsEventResult::default();

    let Ok(mut builder_guard) = ctx.builder.lock() else {
        result.status = KelsStatus::Error;
        result.error = to_c_string("Failed to acquire builder lock");
        return;
    };

    let rotate_result = ctx.runtime.block_on(async { builder_guard.rotate().await });

    match rotate_result {
        Ok((event, _sig)) => {
            // Save key state after rotation
            let save_result = ctx.runtime.block_on(save_key_state(
                &builder_guard,
                &ctx.state_dir,
                &event.prefix,
            ));
            if let Err(e) = save_result {
                set_last_error(&format!("Warning: Failed to save key state: {}", e));
            }

            result.status = KelsStatus::Ok;
            result.prefix = to_c_string(&event.prefix);
            result.said = to_c_string(&event.said);
            result.version = event.version;
        }
        Err(e) => {
            result.status = map_error_to_status(&e);
            result.error = to_c_string(&e.to_string());
            set_last_error(&e.to_string());
        }
    }
}

/// Rotate the recovery key (requires dual signature)
///
/// # Safety
/// - `ctx` must be a valid context pointer
/// - `result` must be a valid pointer to a KelsEventResult
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_rotate_recovery(ctx: *mut KelsContext, result: *mut KelsEventResult) {
    clear_last_error();

    if ctx.is_null() || result.is_null() {
        if !result.is_null() {
            unsafe {
                (*result).status = KelsStatus::NotInitialized;
                (*result).error = to_c_string("Context or result is null");
            }
        }
        return;
    }

    let ctx = unsafe { &*ctx };
    let result = unsafe { &mut *result };
    *result = KelsEventResult::default();

    let Ok(mut builder_guard) = ctx.builder.lock() else {
        result.status = KelsStatus::Error;
        result.error = to_c_string("Failed to acquire builder lock");
        return;
    };

    let rotate_result = ctx
        .runtime
        .block_on(async { builder_guard.rotate_recovery().await });

    match rotate_result {
        Ok((event, _sig)) => {
            // Save key state after recovery rotation
            let save_result = ctx.runtime.block_on(save_key_state(
                &builder_guard,
                &ctx.state_dir,
                &event.prefix,
            ));
            if let Err(e) = save_result {
                set_last_error(&format!("Warning: Failed to save key state: {}", e));
            }

            result.status = KelsStatus::Ok;
            result.prefix = to_c_string(&event.prefix);
            result.said = to_c_string(&event.said);
            result.version = event.version;
        }
        Err(e) => {
            result.status = map_error_to_status(&e);
            result.error = to_c_string(&e.to_string());
            set_last_error(&e.to_string());
        }
    }
}

/// Create an interaction event (anchor data to KEL)
///
/// # Arguments
/// * `anchor` - The data to anchor (e.g., a hash or identifier)
///
/// # Safety
/// - `ctx` must be a valid context pointer
/// - `anchor` must be a valid C string
/// - `result` must be a valid pointer to a KelsEventResult
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_interact(
    ctx: *mut KelsContext,
    anchor: *const c_char,
    result: *mut KelsEventResult,
) {
    clear_last_error();

    if ctx.is_null() || result.is_null() {
        if !result.is_null() {
            unsafe {
                (*result).status = KelsStatus::NotInitialized;
                (*result).error = to_c_string("Context or result is null");
            }
        }
        return;
    }

    let ctx = unsafe { &*ctx };
    let result = unsafe { &mut *result };
    *result = KelsEventResult::default();

    let Some(anchor_str) = from_c_string(anchor) else {
        result.status = KelsStatus::Error;
        result.error = to_c_string("Invalid anchor string");
        return;
    };

    let Ok(mut builder_guard) = ctx.builder.lock() else {
        result.status = KelsStatus::Error;
        result.error = to_c_string("Failed to acquire builder lock");
        return;
    };

    let interact_result = ctx
        .runtime
        .block_on(async { builder_guard.interact(&anchor_str).await });

    match interact_result {
        Ok((event, _sig)) => {
            result.status = KelsStatus::Ok;
            result.prefix = to_c_string(&event.prefix);
            result.said = to_c_string(&event.said);
            result.version = event.version;
        }
        Err(e) => {
            result.status = map_error_to_status(&e);
            result.error = to_c_string(&e.to_string());
            set_last_error(&e.to_string());
        }
    }
}

/// Attempt recovery from divergence or adversary attack
///
/// # Safety
/// - `ctx` must be a valid context pointer
/// - `result` must be a valid pointer to a KelsRecoveryResult
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_recover(ctx: *mut KelsContext, result: *mut KelsRecoveryResult) {
    clear_last_error();

    if ctx.is_null() || result.is_null() {
        if !result.is_null() {
            unsafe {
                (*result).status = KelsStatus::NotInitialized;
                (*result).outcome = KelsRecoveryOutcome::Failed;
                (*result).error = to_c_string("Context or result is null");
            }
        }
        return;
    }

    let ctx = unsafe { &*ctx };
    let result = unsafe { &mut *result };
    *result = KelsRecoveryResult::default();

    let Ok(mut builder_guard) = ctx.builder.lock() else {
        result.status = KelsStatus::Error;
        result.outcome = KelsRecoveryOutcome::Failed;
        result.error = to_c_string("Failed to acquire builder lock");
        return;
    };

    let recover_result = ctx
        .runtime
        .block_on(async { builder_guard.recover().await });

    match recover_result {
        Ok((event, _sig)) => {
            // Save key state after recovery
            let save_result = ctx.runtime.block_on(save_key_state(
                &builder_guard,
                &ctx.state_dir,
                &event.prefix,
            ));
            if let Err(e) = save_result {
                set_last_error(&format!("Warning: Failed to save key state: {}", e));
            }

            result.status = KelsStatus::Ok;
            result.outcome = KelsRecoveryOutcome::Recovered;
            result.prefix = to_c_string(&event.prefix);
            result.said = to_c_string(&event.said);
            result.version = event.version;
        }
        Err(e) => {
            result.status = map_error_to_status(&e);
            result.outcome = KelsRecoveryOutcome::Failed;
            result.error = to_c_string(&e.to_string());
            set_last_error(&e.to_string());
        }
    }
}

/// Contest a malicious recovery by submitting a contest event (cnt)
///
/// Use this when an adversary has revealed your recovery key.
/// The KEL will be permanently frozen after contesting.
///
/// # Safety
/// - `ctx` must be a valid context pointer
/// - `result` must be a valid pointer to a KelsEventResult
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_contest(ctx: *mut KelsContext, result: *mut KelsEventResult) {
    clear_last_error();

    if ctx.is_null() || result.is_null() {
        if !result.is_null() {
            unsafe {
                (*result).status = KelsStatus::NotInitialized;
                (*result).error = to_c_string("Context or result is null");
            }
        }
        return;
    }

    let ctx = unsafe { &*ctx };
    let result = unsafe { &mut *result };
    *result = KelsEventResult::default();

    let Ok(mut builder_guard) = ctx.builder.lock() else {
        result.status = KelsStatus::Error;
        result.error = to_c_string("Failed to acquire builder lock");
        return;
    };

    let contest_result = ctx
        .runtime
        .block_on(async { builder_guard.contest().await });

    match contest_result {
        Ok((event, _sig)) => {
            // Save key state after contest (keys rotated during contest)
            let save_result = ctx.runtime.block_on(save_key_state(
                &builder_guard,
                &ctx.state_dir,
                &event.prefix,
            ));
            if let Err(e) = save_result {
                set_last_error(&format!("Warning: Failed to save key state: {}", e));
            }

            result.status = KelsStatus::Ok;
            result.prefix = to_c_string(&event.prefix);
            result.said = to_c_string(&event.said);
            result.version = event.version;
        }
        Err(e) => {
            result.status = map_error_to_status(&e);
            result.error = to_c_string(&e.to_string());
            set_last_error(&e.to_string());
        }
    }
}

/// Decommission a KEL (permanently disable it)
///
/// # Safety
/// - `ctx` must be a valid context pointer
/// - `result` must be a valid pointer to a KelsEventResult
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_decommission(ctx: *mut KelsContext, result: *mut KelsEventResult) {
    clear_last_error();

    if ctx.is_null() || result.is_null() {
        if !result.is_null() {
            unsafe {
                (*result).status = KelsStatus::NotInitialized;
                (*result).error = to_c_string("Context or result is null");
            }
        }
        return;
    }

    let ctx = unsafe { &*ctx };
    let result = unsafe { &mut *result };
    *result = KelsEventResult::default();

    let Ok(mut builder_guard) = ctx.builder.lock() else {
        result.status = KelsStatus::Error;
        result.error = to_c_string("Failed to acquire builder lock");
        return;
    };

    let decommission_result = ctx
        .runtime
        .block_on(async { builder_guard.decommission().await });

    match decommission_result {
        Ok((event, _sig)) => {
            result.status = KelsStatus::Ok;
            result.prefix = to_c_string(&event.prefix);
            result.said = to_c_string(&event.said);
            result.version = event.version;
        }
        Err(e) => {
            result.status = map_error_to_status(&e);
            result.error = to_c_string(&e.to_string());
            set_last_error(&e.to_string());
        }
    }
}

// ==================== Query Operations ====================

/// Get the status of the current KEL
///
/// # Arguments
/// * `prefix` - Optional prefix to query (NULL for current context's KEL)
///
/// # Safety
/// - `ctx` must be a valid context pointer
/// - `result` must be a valid pointer to a KelsStatusResult
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_status(
    ctx: *mut KelsContext,
    _prefix: *const c_char,
    result: *mut KelsStatusResult,
) {
    clear_last_error();

    if ctx.is_null() || result.is_null() {
        if !result.is_null() {
            unsafe {
                (*result).status = KelsStatus::NotInitialized;
                (*result).error = to_c_string("Context or result is null");
            }
        }
        return;
    }

    let ctx = unsafe { &*ctx };
    let result = unsafe { &mut *result };
    *result = KelsStatusResult::default();

    let Ok(builder_guard) = ctx.builder.lock() else {
        result.status = KelsStatus::Error;
        result.error = to_c_string("Failed to acquire builder lock");
        return;
    };

    let kel = builder_guard.kel();
    let events = kel.events();

    result.status = KelsStatus::Ok;

    if let Some(prefix) = builder_guard.prefix() {
        result.prefix = to_c_string(prefix);
    }

    result.event_count = events.len() as u32;

    if let Some(said) = builder_guard.last_said() {
        result.latest_said = to_c_string(said);
    }

    result.is_divergent = kel.find_divergence().is_some();
    result.is_contested = kel.is_contested();
    result.is_decommissioned = builder_guard.is_decommissioned();

    #[cfg(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "secure-enclave"
    ))]
    {
        result.use_hardware = ctx.use_hardware;
    }

    #[cfg(not(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "secure-enclave"
    )))]
    {
        result.use_hardware = false;
    }
}

/// Get the full KEL as JSON
///
/// # Arguments
/// * `prefix` - The KEL prefix to fetch
///
/// # Returns
/// JSON string of events, or NULL on error. Must be freed with kels_free_string().
///
/// # Safety
/// - `ctx` must be a valid context pointer
/// - `prefix` must be a valid C string
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_get_kel(ctx: *mut KelsContext, prefix: *const c_char) -> *mut c_char {
    clear_last_error();

    if ctx.is_null() {
        set_last_error("Context is null");
        return std::ptr::null_mut();
    }

    let ctx = unsafe { &*ctx };

    let prefix_str = from_c_string(prefix);

    let Ok(builder_guard) = ctx.builder.lock() else {
        set_last_error("Failed to acquire builder lock");
        return std::ptr::null_mut();
    };

    // If no prefix specified, use the current KEL
    let kel_to_serialize =
        if prefix_str.is_none() || prefix_str.as_deref() == builder_guard.prefix() {
            builder_guard.kel()
        } else {
            set_last_error("Can only get current KEL from context");
            return std::ptr::null_mut();
        };

    match serde_json::to_string(kel_to_serialize.events()) {
        Ok(json) => to_c_string(&json),
        Err(e) => {
            set_last_error(&format!("Failed to serialize KEL: {}", e));
            std::ptr::null_mut()
        }
    }
}

/// List all local KEL prefixes
///
/// # Safety
/// - `ctx` must be a valid context pointer
/// - `result` must be a valid pointer to a KelsListResult
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_list(ctx: *mut KelsContext, result: *mut KelsListResult) {
    clear_last_error();

    if ctx.is_null() || result.is_null() {
        if !result.is_null() {
            unsafe {
                (*result).status = KelsStatus::NotInitialized;
                (*result).error = to_c_string("Context or result is null");
            }
        }
        return;
    }

    let ctx = unsafe { &*ctx };
    let result = unsafe { &mut *result };
    *result = KelsListResult::default();

    // List all .kel.json files in the state directory
    let prefixes: Vec<String> = match std::fs::read_dir(&ctx.state_dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                if name.ends_with(".kel.json") {
                    Some(name.trim_end_matches(".kel.json").to_string())
                } else {
                    None
                }
            })
            .collect(),
        Err(e) => {
            result.status = KelsStatus::Error;
            result.error = to_c_string(&format!("Failed to read state directory: {}", e));
            return;
        }
    };

    result.count = prefixes.len() as u32;

    match serde_json::to_string(&prefixes) {
        Ok(json) => {
            result.status = KelsStatus::Ok;
            result.prefixes_json = to_c_string(&json);
        }
        Err(e) => {
            result.status = KelsStatus::Error;
            result.error = to_c_string(&format!("Failed to serialize prefixes: {}", e));
        }
    }
}

// ==================== Memory Management ====================

/// Free a KelsEventResult's allocated strings
///
/// # Safety
/// The result must have been populated by a KELS function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_event_result_free(result: *mut KelsEventResult) {
    if result.is_null() {
        return;
    }

    let result = unsafe { &mut *result };

    if !result.prefix.is_null() {
        unsafe {
            drop(CString::from_raw(result.prefix));
        }
        result.prefix = std::ptr::null_mut();
    }

    if !result.said.is_null() {
        unsafe {
            drop(CString::from_raw(result.said));
        }
        result.said = std::ptr::null_mut();
    }

    if !result.error.is_null() {
        unsafe {
            drop(CString::from_raw(result.error));
        }
        result.error = std::ptr::null_mut();
    }
}

/// Free a KelsStatusResult's allocated strings
///
/// # Safety
/// The result must have been populated by a KELS function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_status_result_free(result: *mut KelsStatusResult) {
    if result.is_null() {
        return;
    }

    let result = unsafe { &mut *result };

    if !result.prefix.is_null() {
        unsafe {
            drop(CString::from_raw(result.prefix));
        }
        result.prefix = std::ptr::null_mut();
    }

    if !result.latest_said.is_null() {
        unsafe {
            drop(CString::from_raw(result.latest_said));
        }
        result.latest_said = std::ptr::null_mut();
    }

    if !result.error.is_null() {
        unsafe {
            drop(CString::from_raw(result.error));
        }
        result.error = std::ptr::null_mut();
    }
}

/// Free a KelsListResult's allocated strings
///
/// # Safety
/// The result must have been populated by a KELS function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_list_result_free(result: *mut KelsListResult) {
    if result.is_null() {
        return;
    }

    let result = unsafe { &mut *result };

    if !result.prefixes_json.is_null() {
        unsafe {
            drop(CString::from_raw(result.prefixes_json));
        }
        result.prefixes_json = std::ptr::null_mut();
    }

    if !result.error.is_null() {
        unsafe {
            drop(CString::from_raw(result.error));
        }
        result.error = std::ptr::null_mut();
    }
}

/// Free a KelsRecoveryResult's allocated strings
///
/// # Safety
/// The result must have been populated by a KELS function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_recovery_result_free(result: *mut KelsRecoveryResult) {
    if result.is_null() {
        return;
    }

    let result = unsafe { &mut *result };

    if !result.prefix.is_null() {
        unsafe {
            drop(CString::from_raw(result.prefix));
        }
        result.prefix = std::ptr::null_mut();
    }

    if !result.said.is_null() {
        unsafe {
            drop(CString::from_raw(result.said));
        }
        result.said = std::ptr::null_mut();
    }

    if !result.error.is_null() {
        unsafe {
            drop(CString::from_raw(result.error));
        }
        result.error = std::ptr::null_mut();
    }
}

/// Free a string returned by KELS functions
///
/// # Safety
/// The string must have been returned by a KELS function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            drop(CString::from_raw(s));
        }
    }
}

/// Get the last error message
///
/// # Returns
/// Error string or NULL if no error. String is valid until next KELS call.
/// Do NOT free this string.
#[unsafe(no_mangle)]
pub extern "C" fn kels_last_error() -> *const c_char {
    thread_local! {
        static ERROR_CSTRING: std::cell::RefCell<Option<CString>> = const { std::cell::RefCell::new(None) };
    }

    LAST_ERROR.with(|e| {
        let error = e.borrow();
        match error.as_ref() {
            Some(s) => ERROR_CSTRING.with(|cs| {
                *cs.borrow_mut() = CString::new(s.as_str()).ok();
                cs.borrow()
                    .as_ref()
                    .map(|c| c.as_ptr())
                    .unwrap_or(std::ptr::null())
            }),
            None => std::ptr::null(),
        }
    })
}

// ==================== Dev Tools (Feature-Gated) ====================

/// Inject adversary events for testing divergence scenarios
///
/// # Arguments
/// * `event_types` - Comma-separated event types to inject (e.g., "rot,ixn")
///
/// # Returns
/// 0 on success, -1 on error
///
/// # Safety
/// - `ctx` must be a valid context pointer
/// - `event_types` must be a valid C string
#[cfg(feature = "dev-tools")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_adversary_inject_events(
    ctx: *mut KelsContext,
    event_types: *const c_char,
) -> i32 {
    clear_last_error();

    if ctx.is_null() {
        set_last_error("Context is null");
        return -1;
    }

    if event_types.is_null() {
        set_last_error("Event types is null");
        return -1;
    }

    let ctx = unsafe { &*ctx };

    let event_types_str = match unsafe { CStr::from_ptr(event_types) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("Invalid event types string");
            return -1;
        }
    };

    // Parse event types
    let types: Vec<&str> = event_types_str.split(',').map(|s| s.trim()).collect();

    // Get KELS URL for adversary client
    let kels_url = match ctx.kels_url.read() {
        Ok(guard) => guard.clone(),
        Err(_) => {
            set_last_error("Failed to read KELS URL");
            return -1;
        }
    };

    // Inject events
    #[allow(clippy::await_holding_lock)]
    ctx.runtime.block_on(async {
        // Get key provider and KEL from builder (need to clone for adversary)
        let Ok(builder_guard) = ctx.builder.lock() else {
            set_last_error("Failed to acquire builder lock");
            return -1;
        };

        if builder_guard.prefix().is_none() {
            set_last_error("No KEL incepted - cannot inject adversary events");
            return -1;
        }

        // Clone key provider for adversary builder
        // Note: We hold the lock during try_clone().await, but this is safe because
        // we drop the guard immediately after and don't hold it during adversary operations
        let Some(adversary_keys) = builder_guard.key_provider().try_clone().await else {
            set_last_error(
                "Cannot clone key provider - adversary injection requires cloneable keys",
            );
            return -1;
        };

        let kel = builder_guard.kel().clone();
        drop(builder_guard);

        // Create adversary builder WITH KELS client but NO kel_store
        // Events submit to KELS but don't save locally (simulating adversary)
        let client = KelsClient::new(&kels_url);
        let mut adversary_builder =
            KeyEventBuilder::with_kel(adversary_keys, Some(client), None, kel);

        let mut counter = 0u32;

        for event_type in types {
            let result = match event_type {
                "ixn" => {
                    let anchor = format!(
                        "EAdversaryAnchor{}{}_",
                        counter,
                        "_".repeat(44 - 17 - counter.to_string().len())
                    );
                    counter += 1;
                    adversary_builder.interact(&anchor).await
                }
                "rot" => adversary_builder.rotate().await,
                "rec" | "ror" => adversary_builder.rotate_recovery().await,
                "dec" => adversary_builder.decommission().await,
                other => {
                    set_last_error(&format!(
                        "Unsupported event type: {}. Valid: ixn, rot, rec, ror, dec",
                        other
                    ));
                    return -1;
                }
            };

            if let Err(e) = result {
                set_last_error(&format!("Failed to inject {} event: {}", event_type, e));
                return -1;
            }
        }

        0
    })
}

/// Truncate the local KEL, keeping only the first N events
///
/// # Arguments
/// * `keep_events` - Number of events to keep
///
/// # Returns
/// 0 on success, -1 on error
///
/// # Safety
/// - `ctx` must be a valid context pointer
#[cfg(feature = "dev-tools")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_truncate_local_kel(ctx: *mut KelsContext, keep_events: u32) -> i32 {
    clear_last_error();

    if ctx.is_null() {
        set_last_error("Context is null");
        return -1;
    }

    let ctx = unsafe { &*ctx };

    // Get prefix from builder
    let Ok(builder_guard) = ctx.builder.lock() else {
        set_last_error("Failed to acquire builder lock");
        return -1;
    };

    let Some(prefix) = builder_guard.prefix().map(|s| s.to_string()) else {
        set_last_error("No KEL incepted - cannot truncate");
        return -1;
    };

    drop(builder_guard);

    // Load KEL from store, truncate, and save
    ctx.runtime.block_on(async {
        // Load current KEL
        let kel_result = ctx.store.load(&prefix).await;
        let mut kel = match kel_result {
            Ok(Some(k)) => k,
            Ok(None) => {
                set_last_error("KEL not found in local store");
                return -1;
            }
            Err(e) => {
                set_last_error(&format!("Failed to load KEL: {}", e));
                return -1;
            }
        };

        let current_len = kel.len();
        let keep = keep_events as usize;

        if keep >= current_len {
            // Nothing to truncate
            return 0;
        }

        // Truncate
        kel.truncate(keep);

        // Save back to store
        if let Err(e) = ctx.store.save(&kel).await {
            set_last_error(&format!("Failed to save truncated KEL: {}", e));
            return -1;
        }

        0
    })
}

/// Dump the local KEL for debugging
///
/// # Returns
/// JSON string of the KEL, or NULL on error. Must be freed with kels_free_string().
///
/// # Safety
/// - `ctx` must be a valid context pointer
#[cfg(feature = "dev-tools")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_dump_local_kel(ctx: *mut KelsContext) -> *mut c_char {
    clear_last_error();

    if ctx.is_null() {
        set_last_error("Context is null");
        return std::ptr::null_mut();
    }

    let ctx = unsafe { &*ctx };

    let Ok(builder_guard) = ctx.builder.lock() else {
        set_last_error("Failed to acquire builder lock");
        return std::ptr::null_mut();
    };

    let kel = builder_guard.kel();

    match serde_json::to_string_pretty(kel.events()) {
        Ok(json) => to_c_string(&json),
        Err(e) => {
            set_last_error(&format!("Failed to serialize KEL: {}", e));
            std::ptr::null_mut()
        }
    }
}

// ==================== Reset/Clear Operations ====================

/// Reset all local state (KELs, keys, owner tails)
///
/// This removes all local KEL data and key state files from the state directory.
/// After calling this, you must create a new context and incept a new KEL.
///
/// # Arguments
/// * `state_dir` - Directory containing local state to clear
///
/// # Returns
/// 0 on success, -1 on error
///
/// # Safety
/// - `state_dir` must be a valid C string
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_reset(state_dir: *const c_char) -> i32 {
    clear_last_error();

    let Some(state_dir_str) = from_c_string(state_dir) else {
        set_last_error("Invalid state directory");
        return -1;
    };

    let state_path = PathBuf::from(&state_dir_str);

    if !state_path.exists() {
        // Nothing to reset
        return 0;
    }

    // Read directory entries
    let entries = match std::fs::read_dir(&state_path) {
        Ok(e) => e,
        Err(e) => {
            set_last_error(&format!("Failed to read state directory: {}", e));
            return -1;
        }
    };

    let mut error_count = 0;

    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        // Delete .kel.json, .keys.json, and .owner_tail files
        let should_delete = file_name.ends_with(".kel.json")
            || file_name.ends_with(".keys.json")
            || file_name.ends_with(".owner_tail");

        if should_delete && std::fs::remove_file(&path).is_err() {
            set_last_error(&format!("Failed to delete {}", file_name));
            error_count += 1;
        }
    }

    if error_count > 0 { -1 } else { 0 }
}

// ==================== Registry Operations ====================

/// Node status for FFI
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KelsNodeStatus {
    Bootstrapping = 0,
    Ready = 1,
    Unhealthy = 2,
}

impl From<NodeStatus> for KelsNodeStatus {
    fn from(status: NodeStatus) -> Self {
        match status {
            NodeStatus::Bootstrapping => KelsNodeStatus::Bootstrapping,
            NodeStatus::Ready => KelsNodeStatus::Ready,
            NodeStatus::Unhealthy => KelsNodeStatus::Unhealthy,
        }
    }
}

/// Result from discover nodes operation
#[repr(C)]
pub struct KelsNodesResult {
    pub status: KelsStatus,
    /// JSON array of node objects (owned, must be freed with kels_free_string)
    pub nodes_json: *mut c_char,
    /// Number of nodes
    pub count: u32,
    /// Error message if status != Ok (owned, must be freed with kels_free_string)
    pub error: *mut c_char,
}

impl Default for KelsNodesResult {
    fn default() -> Self {
        Self {
            status: KelsStatus::Error,
            nodes_json: std::ptr::null_mut(),
            count: 0,
            error: std::ptr::null_mut(),
        }
    }
}

/// Node info for JSON serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeInfoJson {
    node_id: String,
    kels_url: String,
    status: String,
    latency_ms: Option<u64>,
}

/// Discover nodes from the registry and test latency
///
/// Returns a JSON array of node objects with status and latency info.
/// Nodes are sorted by latency (fastest first), with Ready nodes prioritized.
///
/// This function performs cryptographic verification:
/// 1. Fetches the registry's KEL and verifies its integrity
/// 2. Checks that the registry prefix matches the expected trust anchor
/// 3. Verifies each peer's SAID is anchored in the registry's KEL
///
/// # Arguments
/// * `registry_url` - URL of the kels-registry service
/// * `registry_prefix` - Expected registry prefix (trust anchor) - can be NULL to skip verification
///
/// # Safety
/// - `registry_url` must be a valid C string
/// - `registry_prefix` must be a valid C string or NULL
/// - `result` must be a valid pointer to a KelsNodesResult
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_discover_nodes(
    registry_url: *const c_char,
    registry_prefix: *const c_char,
    result: *mut KelsNodesResult,
) {
    clear_last_error();

    if result.is_null() {
        return;
    }

    let result = unsafe { &mut *result };
    *result = KelsNodesResult::default();

    let Some(url) = from_c_string(registry_url) else {
        result.status = KelsStatus::Error;
        result.error = to_c_string("Invalid registry URL");
        return;
    };

    // registry_prefix is optional - if provided, we verify against it
    let expected_prefix = from_c_string(registry_prefix);

    // Create runtime for async operations
    let Ok(runtime) = Runtime::new() else {
        result.status = KelsStatus::Error;
        result.error = to_c_string("Failed to create async runtime");
        return;
    };

    let discover_result = runtime.block_on(async {
        let client = KelsRegistryClient::new(&url);

        // Build set of verified node_ids from peer records
        let verified_node_ids: std::collections::HashSet<String> =
            if let Some(ref expected) = expected_prefix {
                // Verify registry and get the KEL for peer anchoring checks
                let registry_kel = client.verify_registry(expected).await?;

                // Fetch and verify peers, collecting verified node_ids
                let peers_response: PeersResponse = client.fetch_peers().await?;

                let mut verified = std::collections::HashSet::new();
                for history in &peers_response.peers {
                    if let Some(latest) = history.records.last() {
                        // Skip peers with invalid SAID
                        if latest.verify().is_err() {
                            continue;
                        }

                        // Skip peers not anchored in registry's KEL
                        if !registry_kel.contains_anchor(&latest.said) {
                            continue;
                        }

                        // This peer is verified - trust its node_id
                        if latest.active {
                            verified.insert(latest.node_id.clone());
                        }
                    }
                }
                verified
            } else {
                // No verification - empty set means accept all nodes
                std::collections::HashSet::new()
            };

        // Fetch all nodes (paginated)
        let nodes = client.list_all_nodes().await?;

        // Test latency to each Ready node, filtering to verified nodes if verification was performed
        let mut node_infos: Vec<NodeInfoJson> = Vec::with_capacity(nodes.len());

        for node in nodes {
            // If we have verified node_ids, only include nodes that passed verification
            if !verified_node_ids.is_empty() && !verified_node_ids.contains(&node.node_id) {
                continue;
            }
            let latency_ms = if node.status == NodeStatus::Ready {
                // Test latency with short timeout
                let kels_client =
                    KelsClient::with_timeout(&node.kels_url, std::time::Duration::from_millis(500));
                kels_client
                    .test_latency()
                    .await
                    .ok()
                    .map(|d| d.as_millis() as u64)
            } else {
                None
            };

            node_infos.push(NodeInfoJson {
                node_id: node.node_id,
                kels_url: node.kels_url,
                status: match node.status {
                    NodeStatus::Bootstrapping => "bootstrapping".to_string(),
                    NodeStatus::Ready => "ready".to_string(),
                    NodeStatus::Unhealthy => "unhealthy".to_string(),
                },
                latency_ms,
            });
        }

        // Sort: Ready nodes with latency first (by latency), then Ready without latency, then others
        node_infos.sort_by(|a, b| {
            let a_ready = a.status == "ready";
            let b_ready = b.status == "ready";

            match (a_ready, b_ready) {
                (true, true) => match (&a.latency_ms, &b.latency_ms) {
                    (Some(a_lat), Some(b_lat)) => a_lat.cmp(b_lat),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => std::cmp::Ordering::Equal,
                },
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                (false, false) => std::cmp::Ordering::Equal,
            }
        });

        Ok::<Vec<NodeInfoJson>, KelsError>(node_infos)
    });

    match discover_result {
        Ok(nodes) => {
            result.count = nodes.len() as u32;
            match serde_json::to_string(&nodes) {
                Ok(json) => {
                    result.status = KelsStatus::Ok;
                    result.nodes_json = to_c_string(&json);
                }
                Err(e) => {
                    result.status = KelsStatus::Error;
                    result.error = to_c_string(&format!("Failed to serialize nodes: {}", e));
                }
            }
        }
        Err(e) => {
            result.status = map_error_to_status(&e);
            result.error = to_c_string(&e.to_string());
            set_last_error(&e.to_string());
        }
    }
}

/// Free a KelsNodesResult's allocated strings
///
/// # Safety
/// The result must have been populated by kels_discover_nodes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_nodes_result_free(result: *mut KelsNodesResult) {
    if result.is_null() {
        return;
    }

    let result = unsafe { &mut *result };

    if !result.nodes_json.is_null() {
        unsafe {
            drop(CString::from_raw(result.nodes_json));
        }
        result.nodes_json = std::ptr::null_mut();
    }

    if !result.error.is_null() {
        unsafe {
            drop(CString::from_raw(result.error));
        }
        result.error = std::ptr::null_mut();
    }
}
