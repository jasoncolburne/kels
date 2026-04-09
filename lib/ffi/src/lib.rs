//! KELS FFI - C bindings for iOS/macOS applications
//!
//! This module provides C-compatible functions for interacting with KELS servers.
//! It wraps the KeyEventBuilder and related types for use from Swift/Objective-C.

#![allow(clippy::missing_safety_doc)]

use std::{
    ffi::{CStr, CString},
    os::raw::c_char,
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
};
use tokio::runtime::Runtime;

use cesr::Matter;

#[cfg(all(
    any(target_os = "macos", target_os = "ios"),
    feature = "secure-enclave"
))]
use kels_core::HardwareKeyProvider;
#[cfg(not(all(
    any(target_os = "macos", target_os = "ios"),
    feature = "secure-enclave"
)))]
use kels_core::SoftwareKeyProvider;
use kels_core::{
    FileKelStore, FileKeyStateStore, KelStore, KelsClient, KelsError, KeyEventBuilder, KeyProvider,
    VerificationKeyCode,
};

// ==================== Modules ====================

mod credential;
#[cfg(feature = "dev-tools")]
mod dev;
mod exchange;
mod kel;
mod registry;
mod sad;

// ==================== Re-exports for cbindgen visibility ====================

// KEL operations
pub use kel::{
    kels_contest, kels_decommission, kels_get_kel, kels_incept, kels_interact, kels_list,
    kels_recover, kels_rotate, kels_rotate_recovery, kels_status,
};

// Exchange operations
pub use exchange::{
    KelsEssrOpenResult, KelsKemKeyResult, kels_compute_blob_digest, kels_encap_key_kind,
    kels_encap_key_publication_create, kels_essr_open, kels_essr_open_result_free, kels_essr_seal,
    kels_generate_kem_keypair, kels_kem_key_result_free,
};

// Credential operations
pub use credential::{
    kels_credential_build, kels_credential_compact, kels_credential_disclose,
    kels_credential_validate, kels_poison_hash, kels_schema_validate,
};

// SAD operations
pub use sad::{
    kels_compute_sad_pointer_prefix, kels_sad_fetch_pointer, kels_sad_get_object,
    kels_sad_post_object, kels_sad_submit_pointer,
};

// Registry operations
pub use registry::{
    KelsNodesResult, KelsPrefixResult, kels_discover_nodes, kels_fetch_registry_prefix,
    kels_nodes_result_free, kels_prefix_result_free,
};

// Dev tools (feature-gated)
#[cfg(feature = "dev-tools")]
pub use dev::{kels_adversary_inject_events, kels_dump_local_kel, kels_truncate_local_kel};

// ==================== Error Handling ====================

thread_local! {
    static LAST_ERROR: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

pub(crate) fn set_last_error(err: &str) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = Some(err.to_string());
    });
}

pub(crate) fn clear_last_error() {
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
    /// Contest required - recovery key revealed, submit contest to freeze
    ContestRequired = 7,
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
    /// Error message if status != Ok (owned, must be freed with kels_free_string)
    pub error: *mut c_char,
}

impl Default for KelsEventResult {
    fn default() -> Self {
        Self {
            status: KelsStatus::Error,
            prefix: std::ptr::null_mut(),
            said: std::ptr::null_mut(),
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

/// Opaque context for KELS operations (Secure Enclave variant)
#[cfg(all(
    any(target_os = "macos", target_os = "ios"),
    feature = "secure-enclave"
))]
pub struct KelsContext {
    pub(crate) builder: Arc<Mutex<KeyEventBuilder<HardwareKeyProvider>>>,
    pub(crate) store: Arc<FileKelStore>,
    pub(crate) key_state_store: FileKeyStateStore,
    pub(crate) runtime: Runtime,
    pub(crate) kels_url: RwLock<String>,
    pub(crate) state_dir: PathBuf,
}

/// Opaque context for KELS operations (Software variant)
#[cfg(not(all(
    any(target_os = "macos", target_os = "ios"),
    feature = "secure-enclave"
)))]
pub struct KelsContext {
    pub(crate) builder: Arc<Mutex<KeyEventBuilder<SoftwareKeyProvider>>>,
    pub(crate) store: Arc<FileKelStore>,
    pub(crate) key_state_store: FileKeyStateStore,
    pub(crate) runtime: Runtime,
    pub(crate) kels_url: RwLock<String>,
    pub(crate) state_dir: PathBuf,
}

// ==================== Helper Functions ====================

pub(crate) fn to_c_string(s: &str) -> *mut c_char {
    CString::new(s)
        .map(|cs| cs.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

pub(crate) fn from_c_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr).to_str().ok().map(|s| s.to_string()) }
}

pub(crate) fn parse_algorithm_option(algo: *const c_char) -> Option<VerificationKeyCode> {
    match from_c_string(algo).as_deref() {
        Some("ml-dsa-65") | Some("ML-DSA-65") => Some(VerificationKeyCode::MlDsa65),
        Some("ml-dsa-87") | Some("ML-DSA-87") => Some(VerificationKeyCode::MlDsa87),
        Some("secp256r1") | Some("p256") => Some(VerificationKeyCode::Secp256r1),
        _ => None, // null, empty, or unrecognized = invalid
    }
}

pub(crate) fn map_error_to_status(err: &KelsError) -> KelsStatus {
    match err {
        KelsError::NotFound(_) => KelsStatus::KelNotFound,
        KelsError::HsmKeyNotFound(_) => KelsStatus::Error,
        KelsError::NotIncepted => KelsStatus::NotIncepted,
        KelsError::KelDecommissioned => KelsStatus::KelFrozen,
        KelsError::ContestedKel(_) => KelsStatus::KelFrozen,
        KelsError::DivergenceDetected { .. } => KelsStatus::DivergenceDetected,
        KelsError::ContestRequired => KelsStatus::ContestRequired,
        KelsError::HttpError(_) | KelsError::ServerError(..) => KelsStatus::NetworkError,
        _ => KelsStatus::Error,
    }
}

/// Save key state from the builder's key provider
pub(crate) async fn save_key_state<K: KeyProvider + Clone>(
    builder: &KeyEventBuilder<K>,
    key_state_store: &FileKeyStateStore,
    prefix: &cesr::Digest256,
) -> Result<(), KelsError> {
    builder
        .key_provider()
        .save_state(key_state_store, prefix)
        .await
}

// ==================== Context Management ====================

/// Initialize a new KELS context
///
/// # Arguments
/// * `kels_url` - URL of the KELS server (e.g., "http://kels.example.com")
/// * `state_dir` - Directory for storing local state (KELs, keys)
/// * `key_namespace` - Namespace for Secure Enclave key labels (e.g., "com.myapp.kels")
/// * `prefix` - Optional existing KEL prefix to load (NULL for new)
/// * `signing_algorithm` - Signing algorithm (e.g., "secp256r1" or "ml-dsa-65"). Required.
///   Returns NULL on error if absent or unrecognized.
/// * `recovery_algorithm` - Recovery key algorithm. Required.
///   Returns NULL on error if absent or unrecognized.
///
/// # Returns
/// Pointer to context, or NULL on error. Check kels_last_error() for details.
#[unsafe(no_mangle)]
pub extern "C" fn kels_init(
    kels_url: *const c_char,
    state_dir: *const c_char,
    key_namespace: *const c_char,
    prefix: *const c_char,
    signing_algorithm: *const c_char,
    recovery_algorithm: *const c_char,
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

    #[cfg(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "secure-enclave"
    ))]
    let namespace = match from_c_string(key_namespace) {
        Some(ns) => ns,
        None => {
            set_last_error("Invalid key namespace");
            return std::ptr::null_mut();
        }
    };

    #[cfg(not(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "secure-enclave"
    )))]
    let _ = key_namespace; // Unused in software-only builds

    let Some(signing_algo) = parse_algorithm_option(signing_algorithm) else {
        set_last_error("Invalid or missing signing algorithm");
        return std::ptr::null_mut();
    };
    let Some(recovery_algo) = parse_algorithm_option(recovery_algorithm) else {
        set_last_error("Invalid or missing recovery algorithm");
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

    // Create key state store and key provider
    let key_state_store = FileKeyStateStore::new(&state_path);

    #[cfg(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "secure-enclave"
    ))]
    let key_provider = {
        let mut provider = match HardwareKeyProvider::new(&namespace, signing_algo, recovery_algo) {
            Some(p) => p,
            None => {
                set_last_error("Secure Enclave not available");
                return std::ptr::null_mut();
            }
        };

        // Restore persisted state if a prefix exists
        if let Some(ref pfx) = prefix_opt
            && let Ok(pfx_digest) = cesr::Digest256::from_qb64(pfx)
        {
            match runtime.block_on(provider.restore_state(&key_state_store, &pfx_digest)) {
                Ok(true) => {}  // State restored
                Ok(false) => {} // No saved state, fresh provider
                Err(e) => {
                    set_last_error(&format!("Failed to restore key state: {}", e));
                    return std::ptr::null_mut();
                }
            }
        }

        provider
    };

    #[cfg(not(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "secure-enclave"
    )))]
    let key_provider = {
        let mut provider = SoftwareKeyProvider::new(signing_algo, recovery_algo);

        // Restore persisted state if a prefix exists
        if let Some(ref pfx) = prefix_opt
            && let Ok(pfx_digest) = cesr::Digest256::from_qb64(pfx)
        {
            match runtime.block_on(provider.restore_state(&key_state_store, &pfx_digest)) {
                Ok(true) => {}  // State restored
                Ok(false) => {} // No saved state, fresh provider
                Err(e) => {
                    set_last_error(&format!("Failed to restore key state: {}", e));
                    return std::ptr::null_mut();
                }
            }
        }

        provider
    };

    // Create KELS client
    let client = match KelsClient::new(&url) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(&format!("Failed to build HTTP client: {}", e));
            return std::ptr::null_mut();
        }
    };

    // Create builder
    let prefix_digest = match prefix_opt
        .as_deref()
        .map(cesr::Digest256::from_qb64)
        .transpose()
    {
        Ok(d) => d,
        Err(e) => {
            set_last_error(&format!("Invalid prefix CESR: {}", e));
            return std::ptr::null_mut();
        }
    };
    let builder = runtime.block_on(async {
        KeyEventBuilder::with_dependencies(
            key_provider,
            Some(client),
            Some(store.clone()),
            prefix_digest.as_ref(),
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
        key_state_store,
        runtime,
        kels_url: RwLock::new(url),
        state_dir: state_path,
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
    let client = match KelsClient::new(&url) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(&format!("Failed to build HTTP client: {}", e));
            return -1;
        }
    };

    let Ok(mut builder_guard) = ctx.builder.lock() else {
        set_last_error("Failed to acquire builder lock");
        return -1;
    };

    // Get current state from builder
    let prefix = builder_guard.prefix().cloned();

    // Clone the key provider
    #[cfg(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "secure-enclave"
    ))]
    let key_provider = ctx
        .runtime
        .block_on(async { builder_guard.key_provider().clone_async().await });

    #[cfg(not(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "secure-enclave"
    )))]
    let key_provider = builder_guard.key_provider().clone();

    // Rebuild from store with new client
    let new_builder = ctx.runtime.block_on(async {
        KeyEventBuilder::with_dependencies(
            key_provider,
            Some(client),
            Some(ctx.store.clone()),
            prefix.as_ref(),
        )
        .await
    });

    match new_builder {
        Ok(b) => {
            *builder_guard = b;
        }
        Err(e) => {
            set_last_error(&format!("Failed to rebuild builder: {}", e));
            return -1;
        }
    }

    // Preserve store owner prefix
    if let Some(p) = prefix {
        ctx.store.set_owner_prefix(Some(&p));
    }

    0
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

/// Free a byte buffer returned by KELS functions.
///
/// # Safety
/// The pointer must have been returned by a KELS function (e.g., payload from kels_essr_open).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_free_bytes(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        unsafe {
            drop(Vec::from_raw_parts(ptr, len, len));
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

    // Delete all SE keys from the app's Keychain before removing state files
    #[cfg(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "secure-enclave"
    ))]
    {
        let _ = kels_core::se_delete_all_keys();
    }

    let mut error_count = 0;

    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        // Delete .kel.jsonl files (NDJSON KEL storage)
        let should_delete = file_name.ends_with(".kel.jsonl");

        if should_delete && std::fs::remove_file(&path).is_err() {
            set_last_error(&format!("Failed to delete {}", file_name));
            error_count += 1;
        }
    }

    if error_count > 0 { -1 } else { 0 }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    // ==================== Helper Function Tests ====================

    #[test]
    fn test_to_c_string_valid() {
        let ptr = to_c_string("hello");
        assert!(!ptr.is_null());

        // Clean up
        unsafe {
            drop(CString::from_raw(ptr));
        }
    }

    #[test]
    fn test_to_c_string_empty() {
        let ptr = to_c_string("");
        assert!(!ptr.is_null());

        unsafe {
            let cstr = CStr::from_ptr(ptr);
            assert_eq!(cstr.to_str().expect("valid utf8"), "");
            drop(CString::from_raw(ptr));
        }
    }

    #[test]
    fn test_from_c_string_null() {
        let result = from_c_string(std::ptr::null());
        assert!(result.is_none());
    }

    #[test]
    fn test_from_c_string_valid() {
        let original = "test string";
        let cstring = CString::new(original).expect("valid cstring");
        let ptr = cstring.as_ptr();

        let result = from_c_string(ptr);
        assert!(result.is_some());
        assert_eq!(result.expect("should have value"), original);
    }

    #[test]
    fn test_to_from_c_string_roundtrip() {
        let original = "roundtrip test \u{1f389}";
        let ptr = to_c_string(original);
        assert!(!ptr.is_null());

        let recovered = from_c_string(ptr);
        assert_eq!(recovered, Some(original.to_string()));

        unsafe {
            drop(CString::from_raw(ptr));
        }
    }

    // ==================== Error Mapping Tests ====================

    #[test]
    fn test_map_error_to_status_key_not_found() {
        let err = KelsError::NotFound("test".to_string());
        assert_eq!(map_error_to_status(&err), KelsStatus::KelNotFound);
    }

    #[test]
    fn test_map_error_to_status_not_incepted() {
        let err = KelsError::NotIncepted;
        assert_eq!(map_error_to_status(&err), KelsStatus::NotIncepted);
    }

    #[test]
    fn test_map_error_to_status_decommissioned() {
        let err = KelsError::KelDecommissioned;
        assert_eq!(map_error_to_status(&err), KelsStatus::KelFrozen);
    }

    #[test]
    fn test_map_error_to_status_contested() {
        let err = KelsError::ContestedKel("test".to_string());
        assert_eq!(map_error_to_status(&err), KelsStatus::KelFrozen);
    }

    #[test]
    fn test_map_error_to_status_divergence() {
        let err = KelsError::DivergenceDetected {
            diverged_at: 5,
            submission_accepted: false,
        };
        assert_eq!(map_error_to_status(&err), KelsStatus::DivergenceDetected);
    }

    #[test]
    fn test_map_error_to_status_contest_required() {
        let err = KelsError::ContestRequired;
        assert_eq!(map_error_to_status(&err), KelsStatus::ContestRequired);
    }

    #[test]
    fn test_map_error_to_status_server_error() {
        let err = KelsError::ServerError(
            "server failed".to_string(),
            kels_core::ErrorCode::InternalError,
        );
        assert_eq!(map_error_to_status(&err), KelsStatus::NetworkError);
    }

    #[test]
    fn test_map_error_to_status_generic() {
        let err = KelsError::InvalidSignature("bad sig".to_string());
        assert_eq!(map_error_to_status(&err), KelsStatus::Error);
    }

    // ==================== Thread-Local Error Tests ====================

    #[test]
    fn test_set_and_clear_last_error() {
        clear_last_error();

        // Initially no error
        LAST_ERROR.with(|e| {
            assert!(e.borrow().is_none());
        });

        // Set an error
        set_last_error("test error message");
        LAST_ERROR.with(|e| {
            assert!(e.borrow().is_some());
            assert_eq!(e.borrow().as_deref(), Some("test error message"));
        });

        // Clear it
        clear_last_error();
        LAST_ERROR.with(|e| {
            assert!(e.borrow().is_none());
        });
    }

    #[test]
    fn test_set_last_error_overwrites() {
        clear_last_error();

        set_last_error("first error");
        set_last_error("second error");

        LAST_ERROR.with(|e| {
            assert_eq!(e.borrow().as_deref(), Some("second error"));
        });

        clear_last_error();
    }

    // ==================== kels_last_error Tests ====================

    #[test]
    fn test_kels_last_error_when_none() {
        clear_last_error();
        let ptr = kels_last_error();
        assert!(ptr.is_null());
    }

    #[test]
    fn test_kels_last_error_when_set() {
        clear_last_error();
        set_last_error("FFI error test");

        let ptr = kels_last_error();
        assert!(!ptr.is_null());

        let error_str = from_c_string(ptr);
        assert_eq!(error_str, Some("FFI error test".to_string()));

        clear_last_error();
    }

    // ==================== kels_free_string Tests ====================

    #[test]
    fn test_kels_free_string_null() {
        // Should not crash when freeing null
        unsafe {
            kels_free_string(std::ptr::null_mut());
        }
    }

    #[test]
    fn test_kels_free_string_valid() {
        let ptr = to_c_string("string to free");
        assert!(!ptr.is_null());

        // Free it
        unsafe {
            kels_free_string(ptr);
        }
        // Should not crash
    }
}
