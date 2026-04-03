//! KELS FFI - C bindings for iOS/macOS applications
//!
//! This module provides C-compatible functions for interacting with KELS servers.
//! It wraps the KeyEventBuilder and related types for use from Swift/Objective-C.

#![allow(clippy::missing_safety_doc)]

use serde::{Deserialize, Serialize};
use std::{
    ffi::{CStr, CString},
    os::raw::c_char,
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
};
use tokio::runtime::Runtime;

use base64::Engine;
use cesr::Matter;

use kels_creds::SADStore;
use kels_exchange::{EssrInner, ExchangeError};
use verifiable_storage::SelfAddressed;

#[cfg(feature = "dev-tools")]
use kels_core::EventKind;
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
    builder: Arc<Mutex<KeyEventBuilder<HardwareKeyProvider>>>,
    store: Arc<FileKelStore>,
    key_state_store: FileKeyStateStore,
    runtime: Runtime,
    kels_url: RwLock<String>,
    state_dir: PathBuf,
}

/// Opaque context for KELS operations (Software variant)
#[cfg(not(all(
    any(target_os = "macos", target_os = "ios"),
    feature = "secure-enclave"
)))]
pub struct KelsContext {
    builder: Arc<Mutex<KeyEventBuilder<SoftwareKeyProvider>>>,
    store: Arc<FileKelStore>,
    key_state_store: FileKeyStateStore,
    runtime: Runtime,
    kels_url: RwLock<String>,
    state_dir: PathBuf,
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

fn parse_algorithm_option(algo: *const c_char) -> Option<VerificationKeyCode> {
    match from_c_string(algo).as_deref() {
        Some("ml-dsa-65") | Some("ML-DSA-65") => Some(VerificationKeyCode::MlDsa65),
        Some("ml-dsa-87") | Some("ML-DSA-87") => Some(VerificationKeyCode::MlDsa87),
        Some("secp256r1") | Some("p256") => Some(VerificationKeyCode::Secp256r1),
        _ => None, // null, empty, or unrecognized = keep current
    }
}

fn parse_algorithm(algo: *const c_char) -> VerificationKeyCode {
    parse_algorithm_option(algo).unwrap_or(VerificationKeyCode::MlDsa65)
}

fn map_error_to_status(err: &KelsError) -> KelsStatus {
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
async fn save_key_state<K: KeyProvider + Clone>(
    builder: &KeyEventBuilder<K>,
    key_state_store: &FileKeyStateStore,
    prefix: &str,
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
/// * `signing_algorithm` - Signing algorithm (e.g., "secp256r1" or "ml-dsa-65"). NULL defaults to "secp256r1".
///   Supported on all platforms including Secure Enclave.
/// * `recovery_algorithm` - Recovery key algorithm. NULL defaults to "secp256r1".
///   Supported on all platforms including Secure Enclave.
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

    let signing_algo = parse_algorithm(signing_algorithm);
    let recovery_algo = parse_algorithm(recovery_algorithm);

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
        if let Some(ref pfx) = prefix_opt {
            match runtime.block_on(provider.restore_state(&key_state_store, pfx)) {
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
        if let Some(ref pfx) = prefix_opt {
            match runtime.block_on(provider.restore_state(&key_state_store, pfx)) {
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
    let prefix = builder_guard.prefix().map(|s| s.to_string());

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
            prefix.as_deref(),
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

// ==================== KEL Operations ====================

/// Create an inception event (start a new KEL)
///
/// # Arguments
/// * `signing_algorithm` - Signing algorithm for this inception (NULL = keep current).
///   Supported on all platforms including Secure Enclave.
/// * `recovery_algorithm` - Recovery algorithm for this inception (NULL = keep current).
///   Supported on all platforms including Secure Enclave.
///
/// # Safety
/// - `ctx` must be a valid context pointer
/// - `result` must be a valid pointer to a KelsEventResult
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_incept(
    ctx: *mut KelsContext,
    signing_algorithm: *const c_char,
    recovery_algorithm: *const c_char,
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

    let Ok(mut builder_guard) = ctx.builder.lock() else {
        result.status = KelsStatus::Error;
        result.error = to_c_string("Failed to acquire builder lock");
        return;
    };

    let incept_result = ctx.runtime.block_on(async {
        if let Some(algo) = parse_algorithm_option(signing_algorithm) {
            builder_guard
                .key_provider_mut()
                .set_signing_algorithm(algo)
                .await?;
        }
        if let Some(algo) = parse_algorithm_option(recovery_algorithm) {
            builder_guard
                .key_provider_mut()
                .set_recovery_algorithm(algo)
                .await?;
        }

        builder_guard.incept().await
    });

    match incept_result {
        Ok(icp) => {
            // Set owner prefix after successful inception
            ctx.store.set_owner_prefix(Some(&icp.event.prefix));

            // Save key state for future restarts
            let save_result = ctx.runtime.block_on(save_key_state(
                &builder_guard,
                &ctx.key_state_store,
                &icp.event.prefix,
            ));
            if let Err(e) = save_result {
                // Log but don't fail - the event was created successfully
                set_last_error(&format!("Warning: Failed to save key state: {}", e));
            }

            result.status = KelsStatus::Ok;
            result.prefix = to_c_string(&icp.event.prefix);
            result.said = to_c_string(&icp.event.said);
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
/// # Arguments
/// * `signing_algorithm` - Algorithm for the new signing key (NULL = keep current).
///   Supported on all platforms including Secure Enclave.
///
/// # Safety
/// - `ctx` must be a valid context pointer
/// - `result` must be a valid pointer to a KelsEventResult
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_rotate(
    ctx: *mut KelsContext,
    signing_algorithm: *const c_char,
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

    let Ok(mut builder_guard) = ctx.builder.lock() else {
        result.status = KelsStatus::Error;
        result.error = to_c_string("Failed to acquire builder lock");
        return;
    };

    let rotate_result = ctx.runtime.block_on(async {
        if let Some(algo) = parse_algorithm_option(signing_algorithm) {
            builder_guard
                .key_provider_mut()
                .set_signing_algorithm(algo)
                .await?;
        }

        builder_guard.rotate().await
    });

    match rotate_result {
        Ok(rot) => {
            // Save key state after rotation
            let save_result = ctx.runtime.block_on(save_key_state(
                &builder_guard,
                &ctx.key_state_store,
                &rot.event.prefix,
            ));
            if let Err(e) = save_result {
                set_last_error(&format!("Warning: Failed to save key state: {}", e));
            }

            result.status = KelsStatus::Ok;
            result.prefix = to_c_string(&rot.event.prefix);
            result.said = to_c_string(&rot.event.said);
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
/// # Arguments
/// * `signing_algorithm` - Algorithm for the new signing key (NULL = keep current).
///   Supported on all platforms including Secure Enclave.
/// * `recovery_algorithm` - Algorithm for the new recovery key (NULL = keep current).
///   Supported on all platforms including Secure Enclave.
///
/// # Safety
/// - `ctx` must be a valid context pointer
/// - `result` must be a valid pointer to a KelsEventResult
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_rotate_recovery(
    ctx: *mut KelsContext,
    signing_algorithm: *const c_char,
    recovery_algorithm: *const c_char,
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

    let Ok(mut builder_guard) = ctx.builder.lock() else {
        result.status = KelsStatus::Error;
        result.error = to_c_string("Failed to acquire builder lock");
        return;
    };

    let rotate_result = ctx.runtime.block_on(async {
        if let Some(algo) = parse_algorithm_option(signing_algorithm) {
            builder_guard
                .key_provider_mut()
                .set_signing_algorithm(algo)
                .await?;
        }
        if let Some(algo) = parse_algorithm_option(recovery_algorithm) {
            builder_guard
                .key_provider_mut()
                .set_recovery_algorithm(algo)
                .await?;
        }

        builder_guard.rotate_recovery().await
    });

    match rotate_result {
        Ok(ror) => {
            // Save key state after recovery rotation
            let save_result = ctx.runtime.block_on(save_key_state(
                &builder_guard,
                &ctx.key_state_store,
                &ror.event.prefix,
            ));
            if let Err(e) = save_result {
                set_last_error(&format!("Warning: Failed to save key state: {}", e));
            }

            result.status = KelsStatus::Ok;
            result.prefix = to_c_string(&ror.event.prefix);
            result.said = to_c_string(&ror.event.said);
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
        Ok(ixn) => {
            result.status = KelsStatus::Ok;
            result.prefix = to_c_string(&ixn.event.prefix);
            result.said = to_c_string(&ixn.event.said);
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
/// # Arguments
/// * `signing_algorithm` - Algorithm for the new signing key (NULL = keep current).
///   Supported on all platforms including Secure Enclave.
/// * `recovery_algorithm` - Algorithm for the new recovery key (NULL = keep current).
///   Supported on all platforms including Secure Enclave.
///
/// # Safety
/// - `ctx` must be a valid context pointer
/// - `result` must be a valid pointer to a KelsRecoveryResult
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_recover(
    ctx: *mut KelsContext,
    signing_algorithm: *const c_char,
    recovery_algorithm: *const c_char,
    result: *mut KelsRecoveryResult,
) {
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

    let recover_result = ctx.runtime.block_on(async {
        if let Some(algo) = parse_algorithm_option(signing_algorithm) {
            builder_guard
                .key_provider_mut()
                .set_signing_algorithm(algo)
                .await?;
        }
        if let Some(algo) = parse_algorithm_option(recovery_algorithm) {
            builder_guard
                .key_provider_mut()
                .set_recovery_algorithm(algo)
                .await?;
        }

        // Verify server KEL to detect if adversary revealed the rotation key
        let add_rot = if let Some(prefix) = builder_guard.prefix() {
            let kels_url = match ctx.kels_url.read() {
                Ok(url) => url.clone(),
                Err(_) => {
                    return Err(kels_core::KelsError::StorageError(
                        "kels_url lock poisoned".to_string(),
                    ));
                }
            };
            let source = kels_core::HttpKelSource::new(&kels_url, "/api/v1/kels/kel/{prefix}")?;
            match kels_core::verify_key_events(
                prefix,
                &source,
                kels_core::KelVerifier::new(prefix),
                kels_core::page_size(),
                kels_core::max_pages(),
            )
            .await
            {
                Ok(server_verification) => {
                    let owner_last_est_serial = builder_guard
                        .last_establishment_event()
                        .map(|e| e.serial)
                        .unwrap_or(0);
                    kels_core::should_rotate_with_recovery(
                        &server_verification,
                        builder_guard.rotation_count(),
                        owner_last_est_serial,
                    )
                }
                Err(_) => true, // Fail secure
            }
        } else {
            // Fail secure: no prefix = assume rotation needed
            true
        };
        builder_guard.recover(add_rot).await
    });

    match recover_result {
        Ok(rec) => {
            // Save key state after recovery
            let save_result = ctx.runtime.block_on(save_key_state(
                &builder_guard,
                &ctx.key_state_store,
                &rec.event.prefix,
            ));
            if let Err(e) = save_result {
                set_last_error(&format!("Warning: Failed to save key state: {}", e));
            }

            result.status = KelsStatus::Ok;
            result.outcome = KelsRecoveryOutcome::Recovered;
            result.prefix = to_c_string(&rec.event.prefix);
            result.said = to_c_string(&rec.event.said);
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
/// # Arguments
/// * `signing_algorithm` - Algorithm for the new signing key (NULL = keep current).
///   Supported on all platforms including Secure Enclave.
/// * `recovery_algorithm` - Algorithm for the new recovery key (NULL = keep current).
///   Supported on all platforms including Secure Enclave.
///
/// # Safety
/// - `ctx` must be a valid context pointer
/// - `result` must be a valid pointer to a KelsEventResult
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_contest(
    ctx: *mut KelsContext,
    signing_algorithm: *const c_char,
    recovery_algorithm: *const c_char,
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

    let Ok(mut builder_guard) = ctx.builder.lock() else {
        result.status = KelsStatus::Error;
        result.error = to_c_string("Failed to acquire builder lock");
        return;
    };

    let contest_result = ctx.runtime.block_on(async {
        if let Some(algo) = parse_algorithm_option(signing_algorithm) {
            builder_guard
                .key_provider_mut()
                .set_signing_algorithm(algo)
                .await?;
        }
        if let Some(algo) = parse_algorithm_option(recovery_algorithm) {
            builder_guard
                .key_provider_mut()
                .set_recovery_algorithm(algo)
                .await?;
        }

        builder_guard.contest().await
    });

    match contest_result {
        Ok(cnt) => {
            // Save key state after contest (keys rotated during contest)
            let save_result = ctx.runtime.block_on(save_key_state(
                &builder_guard,
                &ctx.key_state_store,
                &cnt.event.prefix,
            ));
            if let Err(e) = save_result {
                set_last_error(&format!("Warning: Failed to save key state: {}", e));
            }

            result.status = KelsStatus::Ok;
            result.prefix = to_c_string(&cnt.event.prefix);
            result.said = to_c_string(&cnt.event.said);
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
/// # Arguments
/// * `signing_algorithm` - Algorithm for the new signing key (NULL = keep current).
///   Supported on all platforms including Secure Enclave.
/// * `recovery_algorithm` - Algorithm for the new recovery key (NULL = keep current).
///   Supported on all platforms including Secure Enclave.
///
/// # Safety
/// - `ctx` must be a valid context pointer
/// - `result` must be a valid pointer to a KelsEventResult
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_decommission(
    ctx: *mut KelsContext,
    signing_algorithm: *const c_char,
    recovery_algorithm: *const c_char,
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

    let Ok(mut builder_guard) = ctx.builder.lock() else {
        result.status = KelsStatus::Error;
        result.error = to_c_string("Failed to acquire builder lock");
        return;
    };

    let decommission_result = ctx.runtime.block_on(async {
        if let Some(algo) = parse_algorithm_option(signing_algorithm) {
            builder_guard
                .key_provider_mut()
                .set_signing_algorithm(algo)
                .await?;
        }
        if let Some(algo) = parse_algorithm_option(recovery_algorithm) {
            builder_guard
                .key_provider_mut()
                .set_recovery_algorithm(algo)
                .await?;
        }

        builder_guard.decommission().await
    });

    match decommission_result {
        Ok(dec) => {
            result.status = KelsStatus::Ok;
            result.prefix = to_c_string(&dec.event.prefix);
            result.said = to_c_string(&dec.event.said);
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

    result.status = KelsStatus::Ok;

    if let Some(prefix) = builder_guard.prefix() {
        result.prefix = to_c_string(prefix);
    }

    result.event_count = builder_guard.confirmed_count() as u32;

    if let Some(said) = builder_guard.last_said() {
        result.latest_said = to_c_string(said);
    }

    if let Some(v) = builder_guard.kel_verification() {
        result.is_divergent = v.is_divergent();
        result.is_contested = v.is_contested();
    }
    result.is_decommissioned = builder_guard.is_decommissioned();

    #[cfg(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "secure-enclave"
    ))]
    {
        result.use_hardware = kels_core::se_is_available();
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
/// JSON string `{"events": [...], "has_more": bool}`, or NULL on error.
/// Must be freed with kels_free_string().
///
/// # Safety
/// - `ctx` must be a valid context pointer
/// - `prefix` must be a valid C string (or NULL for current KEL)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_get_kel(
    ctx: *mut KelsContext,
    prefix: *const c_char,
    limit: u64,
    offset: u64,
) -> *mut c_char {
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
    let target_prefix = if prefix_str.is_none() || prefix_str.as_deref() == builder_guard.prefix() {
        match builder_guard.prefix() {
            Some(p) => p.to_string(),
            None => {
                set_last_error("No KEL prefix available");
                return std::ptr::null_mut();
            }
        }
    } else {
        set_last_error("Can only get current KEL from context");
        return std::ptr::null_mut();
    };

    // Clamp limit to configured page size
    let limit = limit.min(kels_core::page_size() as u64);

    // Load a page of events from store
    let result = ctx
        .runtime
        .block_on(ctx.store.load(&target_prefix, limit, offset));

    match result {
        Ok((events, has_more)) => {
            match serde_json::to_string(&serde_json::json!({
                "events": events,
                "has_more": has_more,
            })) {
                Ok(json) => to_c_string(&json),
                Err(e) => {
                    set_last_error(&format!("Failed to serialize KEL: {}", e));
                    std::ptr::null_mut()
                }
            }
        }
        Err(e) => {
            set_last_error(&format!("Failed to load KEL: {}", e));
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
        #[cfg(all(
            any(target_os = "macos", target_os = "ios"),
            feature = "secure-enclave"
        ))]
        let adversary_keys = builder_guard.key_provider().clone_async().await;

        #[cfg(not(all(
            any(target_os = "macos", target_os = "ios"),
            feature = "secure-enclave"
        )))]
        let adversary_keys = builder_guard.key_provider().clone();

        let prefix = match builder_guard.prefix() {
            Some(p) => p.to_string(),
            None => {
                set_last_error("No KEL incepted");
                return -1;
            }
        };
        drop(builder_guard);

        // Load events from store for the adversary builder
        let source = kels_core::StoreKelSource::new(ctx.store.as_ref());
        let events = match kels_core::resolve_key_events(
            &prefix,
            &source,
            kels_core::page_size(),
            kels_core::max_pages(),
            None,
        )
        .await
        {
            Ok(e) => e,
            Err(e) => {
                set_last_error(&format!("Failed to load KEL for adversary: {}", e));
                return -1;
            }
        };

        // Create adversary builder WITH KELS client but NO kel_store
        // Events submit to KELS but don't save locally (simulating adversary)
        let client = match KelsClient::new(&kels_url) {
            Ok(c) => c,
            Err(e) => {
                set_last_error(&format!("Failed to build HTTP client: {}", e));
                return -1;
            }
        };
        let mut adversary_builder =
            KeyEventBuilder::with_events(adversary_keys, Some(client), None, events);

        let mut counter = 0u32;

        let algo_from_digit = |d: char| -> Option<VerificationKeyCode> {
            match d {
                '0' => Some(VerificationKeyCode::Secp256r1),
                '1' => Some(VerificationKeyCode::MlDsa65),
                '2' => Some(VerificationKeyCode::MlDsa87),
                _ => None,
            }
        };

        for token in types {
            // Parse: "ixn", "rot1", "ror02", "dec", "rec"
            let kind_str = token.trim_end_matches(|c: char| c.is_ascii_digit());
            let algo_suffix = &token[kind_str.len()..];

            let kind = match EventKind::from_short_name(kind_str) {
                Ok(k) => k,
                Err(e) => {
                    set_last_error(&format!("{}", e));
                    return -1;
                }
            };

            let result = match kind {
                EventKind::Ixn => {
                    let anchor = format!(
                        "KAdversaryAnchor{}{}_",
                        counter,
                        "_".repeat(44 - 17 - counter.to_string().len())
                    );
                    counter += 1;
                    adversary_builder.interact(&anchor).await
                }
                EventKind::Rot | EventKind::Ror | EventKind::Rec => {
                    let chars: Vec<char> = algo_suffix.chars().collect();
                    if let Some(&d) = chars.first()
                        && let Some(algo) = algo_from_digit(d)
                        && let Err(e) = adversary_builder
                            .key_provider_mut()
                            .set_signing_algorithm(algo)
                            .await
                    {
                        set_last_error(&format!("Failed to set algorithm: {}", e));
                        return -1;
                    }
                    if let Some(&d) = chars.get(1)
                        && let Some(algo) = algo_from_digit(d)
                        && let Err(e) = adversary_builder
                            .key_provider_mut()
                            .set_recovery_algorithm(algo)
                            .await
                    {
                        set_last_error(&format!("Failed to set algorithm: {}", e));
                        return -1;
                    }
                    match kind {
                        EventKind::Rot => adversary_builder.rotate().await,
                        EventKind::Ror => adversary_builder.rotate_recovery().await,
                        EventKind::Rec => adversary_builder.recover(false).await,
                        _ => unreachable!(),
                    }
                }
                EventKind::Dec => adversary_builder.decommission().await,
                other => {
                    set_last_error(&format!(
                        "Unsupported event type: {}. Valid: ixn, rot[0-2], rec[0-2][0-2], ror[0-2][0-2], dec",
                        other
                    ));
                    return -1;
                }
            };

            if let Err(e) = result {
                set_last_error(&format!("Failed to inject {} event: {}", token, e));
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
        let (events, _has_more) = match ctx.store.load(&prefix, kels_core::LOAD_ALL, 0).await {
            Ok(result) => result,
            Err(e) => {
                set_last_error(&format!("Failed to load KEL: {}", e));
                return -1;
            }
        };

        if events.is_empty() {
            set_last_error("KEL not found in local store");
            return -1;
        }

        let mut events = events;
        let current_len = events.len();
        let keep = keep_events as usize;

        if keep >= current_len {
            // Nothing to truncate
            return 0;
        }

        // Truncate
        events.truncate(keep);

        // Save back to store
        if let Err(e) = ctx.store.overwrite(&prefix, &events).await {
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

    let prefix = match builder_guard.prefix() {
        Some(p) => p.to_string(),
        None => {
            set_last_error("No KEL prefix available");
            return std::ptr::null_mut();
        }
    };

    // Load events from store
    let events = ctx.runtime.block_on(async {
        let source = kels_core::StoreKelSource::new(ctx.store.as_ref());
        kels_core::resolve_key_events(
            &prefix,
            &source,
            kels_core::page_size(),
            kels_core::max_pages(),
            None,
        )
        .await
    });

    match events {
        Ok(evts) => match serde_json::to_string_pretty(&evts) {
            Ok(json) => to_c_string(&json),
            Err(e) => {
                set_last_error(&format!("Failed to serialize KEL: {}", e));
                std::ptr::null_mut()
            }
        },
        Err(e) => {
            set_last_error(&format!("Failed to load KEL: {}", e));
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

// ==================== Registry Operations ====================

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

/// Peer info for JSON serialization in FFI
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PeerInfoJson {
    node_id: String,
    base_domain: String,
    gossip_addr: String,
    peer_prefix: String,
}

/// Discover verified, ready peers from the registry, sorted by latency.
///
/// Returns a JSON array of peer objects (nodeId, baseDomain, gossipAddr, peerPrefix).
/// All returned peers are verified (anchored + voted) and ready. Sorted fastest first.
///
/// This function performs cryptographic verification:
/// 1. Fetches the registry's KEL and verifies its integrity
/// 2. Checks that the registry prefix matches the expected trust anchor
/// 3. Verifies each peer's SAID is anchored in the registry's KEL
///
/// # Arguments
/// * `registry_url` - Comma-separated URLs of registry services
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

    let Some(urls_str) = from_c_string(registry_url) else {
        result.status = KelsStatus::Error;
        result.error = to_c_string("Invalid registry URL");
        return;
    };

    let urls: Vec<String> = urls_str
        .split(',')
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
        .collect();

    if urls.is_empty() {
        result.status = KelsStatus::Error;
        result.error = to_c_string("No registry URLs provided");
        return;
    }

    // registry_prefix is accepted for API compatibility but no longer used
    if from_c_string(registry_prefix).is_none() {
        result.status = KelsStatus::Error;
        result.error = to_c_string("Invalid registry prefix");
        return;
    };

    // Create runtime for async operations
    let Ok(runtime) = Runtime::new() else {
        result.status = KelsStatus::Error;
        result.error = to_c_string("Failed to create async runtime");
        return;
    };

    let discover_result = runtime.block_on(async {
        // Use a fresh temp directory for each discovery to avoid stale data
        let store_dir = std::env::temp_dir().join("kels-ffi-discovery");
        let _ = std::fs::remove_dir_all(&store_dir);
        let store = FileKelStore::new(&store_dir)?;

        let peers =
            kels_core::peers_sorted_by_latency(&urls, std::time::Duration::from_secs(2), &store)
                .await?;

        let peer_infos: Vec<PeerInfoJson> = peers
            .into_iter()
            .map(|peer| PeerInfoJson {
                node_id: peer.node_id,
                base_domain: peer.base_domain,
                gossip_addr: peer.gossip_addr,
                peer_prefix: peer.peer_prefix,
            })
            .collect();

        Ok(peer_infos)
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

/// Result of fetching registry prefix
#[repr(C)]
pub struct KelsPrefixResult {
    pub status: KelsStatus,
    pub prefix: *mut c_char,
    pub error: *mut c_char,
}

impl Default for KelsPrefixResult {
    fn default() -> Self {
        Self {
            status: KelsStatus::Error,
            prefix: std::ptr::null_mut(),
            error: std::ptr::null_mut(),
        }
    }
}

/// Fetch and verify the registry's KEL, returning its prefix.
///
/// This function:
/// 1. Fetches the registry's KEL from the given URL
/// 2. Verifies the KEL's cryptographic integrity
/// 3. Returns the registry's prefix
///
/// The caller should verify the returned prefix is in their trusted set.
///
/// # Arguments
/// * `registry_url` - URL of the registry service
///
/// # Safety
/// - `registry_url` must be a valid C string
/// - `result` must be a valid pointer to a KelsPrefixResult
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_fetch_registry_prefix(
    registry_url: *const c_char,
    result: *mut KelsPrefixResult,
) {
    clear_last_error();

    if result.is_null() {
        return;
    }

    let result = unsafe { &mut *result };
    *result = KelsPrefixResult::default();

    let Some(url) = from_c_string(registry_url) else {
        result.status = KelsStatus::Error;
        result.error = to_c_string("Invalid registry URL");
        return;
    };

    // Create runtime for async operations
    let Ok(runtime) = Runtime::new() else {
        result.status = KelsStatus::Error;
        result.error = to_c_string("Failed to create async runtime");
        return;
    };

    let fetch_result = runtime.block_on(async {
        let client = kels_core::KelsRegistryClient::new(&url)?;
        client.fetch_registry_prefix().await
    });

    match fetch_result {
        Ok(prefix) => {
            result.status = KelsStatus::Ok;
            result.prefix = to_c_string(&prefix);
        }
        Err(e) => {
            result.status = map_error_to_status(&e);
            result.error = to_c_string(&e.to_string());
            set_last_error(&e.to_string());
        }
    }
}

/// Free a KelsPrefixResult's allocated strings
///
/// # Safety
/// The result must have been populated by kels_fetch_registry_prefix.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_prefix_result_free(result: *mut KelsPrefixResult) {
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

    if !result.error.is_null() {
        unsafe {
            drop(CString::from_raw(result.error));
        }
        result.error = std::ptr::null_mut();
    }
}

// ==================== Exchange Operations ====================

/// Result from ML-KEM key generation
#[repr(C)]
pub struct KelsKemKeyResult {
    pub status: KelsStatus,
    /// CESR-encoded (qb64) encapsulation key (owned, must be freed with kels_free_string)
    pub encapsulation_key: *mut c_char,
    /// Decapsulation key in "algorithm:base64(raw)" format (owned, must be freed with kels_free_string)
    pub decapsulation_key: *mut c_char,
    /// Algorithm name: "ML-KEM-768" or "ML-KEM-1024" (owned, must be freed with kels_free_string)
    pub algorithm: *mut c_char,
    /// Error message if status != Ok (owned, must be freed with kels_free_string)
    pub error: *mut c_char,
}

impl Default for KelsKemKeyResult {
    fn default() -> Self {
        Self {
            status: KelsStatus::Error,
            encapsulation_key: std::ptr::null_mut(),
            decapsulation_key: std::ptr::null_mut(),
            algorithm: std::ptr::null_mut(),
            error: std::ptr::null_mut(),
        }
    }
}

/// Encode a DecapsulationKey in the portable "algorithm:base64(raw)" format.
fn encode_decap_key(dk: &cesr::DecapsulationKey) -> String {
    let (algo, raw) = match dk {
        cesr::DecapsulationKey::MlKem768(bytes) => ("ml-kem-768", bytes.as_slice()),
        cesr::DecapsulationKey::MlKem1024(bytes) => ("ml-kem-1024", bytes.as_slice()),
    };
    format!(
        "{}:{}",
        algo,
        base64::engine::general_purpose::STANDARD.encode(raw)
    )
}

/// Decode a DecapsulationKey from the "algorithm:base64(raw)" format.
fn decode_decap_key(encoded: &str) -> Result<cesr::DecapsulationKey, String> {
    let (algo, b64) = encoded
        .split_once(':')
        .ok_or_else(|| "Invalid decapsulation key format".to_string())?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| format!("Invalid base64: {e}"))?;
    match algo {
        "ml-kem-768" => Ok(cesr::DecapsulationKey::MlKem768(raw)),
        "ml-kem-1024" => Ok(cesr::DecapsulationKey::MlKem1024(raw)),
        _ => Err(format!("Unknown KEM algorithm: {algo}")),
    }
}

fn exchange_error_message(err: &ExchangeError) -> String {
    err.to_string()
}

/// Generate an ML-KEM keypair.
///
/// The algorithm defaults to match the signing algorithm strength:
/// - ML-DSA-65 / secp256r1 / NULL → ML-KEM-768
/// - ML-DSA-87 → ML-KEM-1024
///
/// You can override with `algorithm`: "ML-KEM-768" or "ML-KEM-1024".
///
/// # Arguments
/// * `signing_algorithm` - Signing algorithm to match (NULL = default to ML-KEM-768)
/// * `algorithm` - Explicit KEM algorithm override (NULL = auto-match)
///
/// # Safety
/// - `result` must be a valid pointer to a KelsKemKeyResult
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_generate_kem_keypair(
    signing_algorithm: *const c_char,
    algorithm: *const c_char,
    result: *mut KelsKemKeyResult,
) {
    clear_last_error();

    if result.is_null() {
        return;
    }

    let result = unsafe { &mut *result };
    *result = KelsKemKeyResult::default();

    // Determine algorithm
    let kem_algo = match from_c_string(algorithm).as_deref() {
        Some("ML-KEM-768") | Some("ml-kem-768") => kels_exchange::ML_KEM_768,
        Some("ML-KEM-1024") | Some("ml-kem-1024") => kels_exchange::ML_KEM_1024,
        Some(other) => {
            result.error = to_c_string(&format!("Unknown KEM algorithm: {other}"));
            return;
        }
        None => {
            // Auto-match from signing algorithm
            match from_c_string(signing_algorithm).as_deref() {
                Some("ml-dsa-87") | Some("ML-DSA-87") => kels_exchange::ML_KEM_1024,
                _ => kels_exchange::ML_KEM_768,
            }
        }
    };

    let keygen_result = if kem_algo == kels_exchange::ML_KEM_1024 {
        cesr::generate_ml_kem_1024()
    } else {
        cesr::generate_ml_kem_768()
    };

    match keygen_result {
        Ok((encap_key, decap_key)) => {
            result.status = KelsStatus::Ok;
            result.encapsulation_key = to_c_string(&encap_key.qb64());
            result.decapsulation_key = to_c_string(&encode_decap_key(&decap_key));
            result.algorithm = to_c_string(kem_algo);
        }
        Err(e) => {
            result.error = to_c_string(&format!("Key generation failed: {e}"));
            set_last_error(&format!("Key generation failed: {e}"));
        }
    }
}

/// Free a KelsKemKeyResult's allocated strings
///
/// # Safety
/// The result must have been populated by kels_generate_kem_keypair.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_kem_key_result_free(result: *mut KelsKemKeyResult) {
    if result.is_null() {
        return;
    }

    let result = unsafe { &mut *result };

    for ptr in [
        &mut result.encapsulation_key,
        &mut result.decapsulation_key,
        &mut result.algorithm,
        &mut result.error,
    ] {
        if !ptr.is_null() {
            unsafe {
                drop(CString::from_raw(*ptr));
            }
            *ptr = std::ptr::null_mut();
        }
    }
}

/// Create an EncapsulationKeyPublication SAD object with a derived SAID.
///
/// # Arguments
/// * `algorithm` - "ML-KEM-768" or "ML-KEM-1024"
/// * `encapsulation_key` - CESR-encoded (qb64) encapsulation key
///
/// # Returns
/// JSON string of the publication (with SAID), or NULL on error.
/// Must be freed with kels_free_string().
///
/// # Safety
/// - `algorithm` and `encapsulation_key` must be valid C strings
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_encap_key_publication_create(
    algorithm: *const c_char,
    encapsulation_key: *const c_char,
) -> *mut c_char {
    clear_last_error();

    let Some(algo) = from_c_string(algorithm) else {
        set_last_error("Invalid algorithm");
        return std::ptr::null_mut();
    };

    let Some(encap_key) = from_c_string(encapsulation_key) else {
        set_last_error("Invalid encapsulation key");
        return std::ptr::null_mut();
    };

    let mut publication = kels_exchange::EncapsulationKeyPublication {
        said: String::new(),
        algorithm: algo,
        encapsulation_key: encap_key,
    };

    if let Err(e) = publication.derive_said() {
        set_last_error(&format!("SAID derivation failed: {e}"));
        return std::ptr::null_mut();
    }

    match serde_json::to_string(&publication) {
        Ok(json) => to_c_string(&json),
        Err(e) => {
            set_last_error(&format!("Serialization failed: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// ESSR seal: encrypt and sign a message for a recipient.
///
/// # Arguments
/// * `sender_prefix` - Sender's KEL prefix
/// * `sender_serial` - Sender's latest establishment event serial
/// * `recipient_prefix` - Recipient's KEL prefix
/// * `topic` - Message topic (e.g., "kels/v1/exchange")
/// * `payload` - Raw payload bytes
/// * `payload_len` - Length of payload
/// * `recipient_encap_key_qb64` - Recipient's CESR-encoded encapsulation key
/// * `sender_signing_key_qb64` - Sender's CESR-encoded signing key
///
/// # Returns
/// JSON string of the SignedEssrEnvelope, or NULL on error.
/// Must be freed with kels_free_string().
///
/// # Safety
/// - All string arguments must be valid C strings
/// - `payload` must point to `payload_len` bytes
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_essr_seal(
    sender_prefix: *const c_char,
    sender_serial: u64,
    recipient_prefix: *const c_char,
    topic: *const c_char,
    payload: *const u8,
    payload_len: usize,
    recipient_encap_key_qb64: *const c_char,
    sender_signing_key_qb64: *const c_char,
) -> *mut c_char {
    clear_last_error();

    let Some(sender) = from_c_string(sender_prefix) else {
        set_last_error("Invalid sender prefix");
        return std::ptr::null_mut();
    };

    let Some(recipient) = from_c_string(recipient_prefix) else {
        set_last_error("Invalid recipient prefix");
        return std::ptr::null_mut();
    };

    let Some(topic_str) = from_c_string(topic) else {
        set_last_error("Invalid topic");
        return std::ptr::null_mut();
    };

    if payload.is_null() {
        set_last_error("Payload is null");
        return std::ptr::null_mut();
    }

    let payload_bytes = unsafe { std::slice::from_raw_parts(payload, payload_len) };

    let Some(encap_key_str) = from_c_string(recipient_encap_key_qb64) else {
        set_last_error("Invalid encapsulation key");
        return std::ptr::null_mut();
    };

    let Some(signing_key_str) = from_c_string(sender_signing_key_qb64) else {
        set_last_error("Invalid signing key");
        return std::ptr::null_mut();
    };

    // Parse cryptographic keys
    let encap_key = match cesr::EncapsulationKey::from_qb64(&encap_key_str) {
        Ok(k) => k,
        Err(e) => {
            set_last_error(&format!("Invalid encapsulation key: {e}"));
            return std::ptr::null_mut();
        }
    };

    let signing_key = match cesr::SigningKey::from_qb64(&signing_key_str) {
        Ok(k) => k,
        Err(e) => {
            set_last_error(&format!("Invalid signing key: {e}"));
            return std::ptr::null_mut();
        }
    };

    let inner = EssrInner {
        sender,
        topic: topic_str,
        payload: payload_bytes.to_vec(),
    };

    match kels_exchange::seal(&inner, sender_serial, &recipient, &encap_key, &signing_key) {
        Ok(signed_envelope) => match serde_json::to_string(&signed_envelope) {
            Ok(json) => to_c_string(&json),
            Err(e) => {
                set_last_error(&format!("Serialization failed: {e}"));
                std::ptr::null_mut()
            }
        },
        Err(e) => {
            set_last_error(&exchange_error_message(&e));
            std::ptr::null_mut()
        }
    }
}

/// Result from ESSR open
#[repr(C)]
pub struct KelsEssrOpenResult {
    pub status: KelsStatus,
    /// Sender's KEL prefix from inside the envelope (owned, must be freed with kels_free_string)
    pub sender: *mut c_char,
    /// Message topic (owned, must be freed with kels_free_string)
    pub topic: *mut c_char,
    /// Decrypted payload bytes (owned, must be freed with kels_free_bytes)
    pub payload: *mut u8,
    /// Length of the payload
    pub payload_len: usize,
    /// Error message if status != Ok (owned, must be freed with kels_free_string)
    pub error: *mut c_char,
}

impl Default for KelsEssrOpenResult {
    fn default() -> Self {
        Self {
            status: KelsStatus::Error,
            sender: std::ptr::null_mut(),
            topic: std::ptr::null_mut(),
            payload: std::ptr::null_mut(),
            payload_len: 0,
            error: std::ptr::null_mut(),
        }
    }
}

/// ESSR open: verify and decrypt a received ESSR envelope.
///
/// # Arguments
/// * `signed_envelope_json` - JSON string of the SignedEssrEnvelope
/// * `recipient_decap_key` - Recipient's decapsulation key in "algorithm:base64(raw)" format
/// * `sender_verification_key_qb64` - Sender's CESR-encoded verification key
///
/// # Safety
/// - All string arguments must be valid C strings
/// - `result` must be a valid pointer to a KelsEssrOpenResult
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_essr_open(
    signed_envelope_json: *const c_char,
    recipient_decap_key: *const c_char,
    sender_verification_key_qb64: *const c_char,
    result: *mut KelsEssrOpenResult,
) {
    clear_last_error();

    if result.is_null() {
        return;
    }

    let result = unsafe { &mut *result };
    *result = KelsEssrOpenResult::default();

    let Some(envelope_json) = from_c_string(signed_envelope_json) else {
        result.error = to_c_string("Invalid envelope JSON");
        return;
    };

    let Some(decap_key_str) = from_c_string(recipient_decap_key) else {
        result.error = to_c_string("Invalid decapsulation key");
        return;
    };

    let Some(vk_str) = from_c_string(sender_verification_key_qb64) else {
        result.error = to_c_string("Invalid verification key");
        return;
    };

    // Parse inputs
    let signed_envelope: kels_exchange::SignedEssrEnvelope =
        match serde_json::from_str(&envelope_json) {
            Ok(e) => e,
            Err(e) => {
                result.error = to_c_string(&format!("Invalid envelope JSON: {e}"));
                set_last_error(&format!("Invalid envelope JSON: {e}"));
                return;
            }
        };

    let decap_key = match decode_decap_key(&decap_key_str) {
        Ok(k) => k,
        Err(e) => {
            result.error = to_c_string(&format!("Invalid decapsulation key: {e}"));
            set_last_error(&format!("Invalid decapsulation key: {e}"));
            return;
        }
    };

    let verification_key = match cesr::VerificationKey::from_qb64(&vk_str) {
        Ok(k) => k,
        Err(e) => {
            result.error = to_c_string(&format!("Invalid verification key: {e}"));
            set_last_error(&format!("Invalid verification key: {e}"));
            return;
        }
    };

    match kels_exchange::open(&signed_envelope, &decap_key, &verification_key) {
        Ok(inner) => {
            result.status = KelsStatus::Ok;
            result.sender = to_c_string(&inner.sender);
            result.topic = to_c_string(&inner.topic);

            // Allocate payload bytes on the heap
            let mut payload = inner.payload.into_boxed_slice();
            result.payload_len = payload.len();
            result.payload = payload.as_mut_ptr();
            std::mem::forget(payload);
        }
        Err(e) => {
            let msg = exchange_error_message(&e);
            result.error = to_c_string(&msg);
            set_last_error(&msg);
        }
    }
}

/// Free a KelsEssrOpenResult's allocated strings and bytes
///
/// # Safety
/// The result must have been populated by kels_essr_open.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_essr_open_result_free(result: *mut KelsEssrOpenResult) {
    if result.is_null() {
        return;
    }

    let result = unsafe { &mut *result };

    for ptr in [&mut result.sender, &mut result.topic, &mut result.error] {
        if !ptr.is_null() {
            unsafe {
                drop(CString::from_raw(*ptr));
            }
            *ptr = std::ptr::null_mut();
        }
    }

    if !result.payload.is_null() {
        unsafe {
            drop(Vec::from_raw_parts(
                result.payload,
                result.payload_len,
                result.payload_len,
            ));
        }
        result.payload = std::ptr::null_mut();
        result.payload_len = 0;
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

/// Return the ENCAP_KEY_KIND constant for SADStore pointer chain lookups.
///
/// # Returns
/// Static string "kels/v1/mlkem-encap-key". Do NOT free this string.
#[unsafe(no_mangle)]
pub extern "C" fn kels_encap_key_kind() -> *const c_char {
    // Static CString to ensure null-terminated lifetime
    static KIND: std::sync::LazyLock<CString> = std::sync::LazyLock::new(|| {
        CString::new(kels_exchange::ENCAP_KEY_KIND)
            .unwrap_or_else(|_| CString::new("kels/v1/mlkem-encap-key").unwrap_or_default())
    });
    KIND.as_ptr()
}

/// Compute the blob digest (qb64 Blake3) for a byte buffer.
///
/// Used to verify mail message integrity.
///
/// # Arguments
/// * `data` - Byte buffer to digest
/// * `data_len` - Length of the buffer
///
/// # Returns
/// qb64-encoded Blake3 digest string. Must be freed with kels_free_string().
///
/// # Safety
/// - `data` must point to `data_len` bytes
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_compute_blob_digest(data: *const u8, data_len: usize) -> *mut c_char {
    clear_last_error();

    if data.is_null() {
        set_last_error("Data is null");
        return std::ptr::null_mut();
    }

    let bytes = unsafe { std::slice::from_raw_parts(data, data_len) };
    to_c_string(&kels_exchange::compute_blob_digest(bytes))
}

// ==================== Credential Operations ====================

/// Build a credential from JSON inputs.
///
/// Validates against schema, derives all inner SAIDs, and returns the expanded
/// credential JSON. The canonical SAID (for KEL anchoring) is returned separately.
///
/// # Arguments
/// * `json_claims` - JSON string of claims (must include "said" field)
/// * `json_schema` - JSON string of the schema
/// * `json_policy` - JSON string of the policy
/// * `subject` - Optional subject prefix (NULL for no subject)
/// * `unique` - If true, add a random nonce for uniqueness
/// * `json_edges` - Optional JSON string of edges (NULL for none)
/// * `json_rules` - Optional JSON string of rules (NULL for none)
/// * `json_expires_at` - Optional JSON datetime string (NULL for no expiry)
///
/// # Returns
/// JSON object `{"credential": <json>, "canonicalSaid": "<said>"}`, or NULL on error.
/// Must be freed with kels_free_string().
///
/// # Safety
/// - All non-NULL string arguments must be valid C strings
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_credential_build(
    json_claims: *const c_char,
    json_schema: *const c_char,
    json_policy: *const c_char,
    subject: *const c_char,
    unique: bool,
    json_edges: *const c_char,
    json_rules: *const c_char,
    json_expires_at: *const c_char,
) -> *mut c_char {
    clear_last_error();

    let Some(claims) = from_c_string(json_claims) else {
        set_last_error("Invalid claims JSON");
        return std::ptr::null_mut();
    };

    let Some(schema) = from_c_string(json_schema) else {
        set_last_error("Invalid schema JSON");
        return std::ptr::null_mut();
    };

    let Some(policy) = from_c_string(json_policy) else {
        set_last_error("Invalid policy JSON");
        return std::ptr::null_mut();
    };

    let subject_opt = from_c_string(subject);
    let edges_opt = from_c_string(json_edges);
    let rules_opt = from_c_string(json_rules);
    let expires_opt = from_c_string(json_expires_at);

    let Ok(runtime) = Runtime::new() else {
        set_last_error("Failed to create async runtime");
        return std::ptr::null_mut();
    };

    let result = runtime.block_on(kels_creds::json_api::build(
        &claims,
        &schema,
        &policy,
        subject_opt.as_deref(),
        unique,
        edges_opt.as_deref(),
        rules_opt.as_deref(),
        expires_opt.as_deref(),
    ));

    match result {
        Ok((credential_json, canonical_said)) => {
            match serde_json::to_string(&serde_json::json!({
                "credential": serde_json::from_str::<serde_json::Value>(&credential_json)
                    .unwrap_or(serde_json::Value::Null),
                "canonicalSaid": canonical_said,
            })) {
                Ok(json) => to_c_string(&json),
                Err(e) => {
                    set_last_error(&format!("Serialization failed: {e}"));
                    std::ptr::null_mut()
                }
            }
        }
        Err(e) => {
            set_last_error(&format!("Credential build failed: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Validate a credential against a schema.
///
/// # Arguments
/// * `json_credential` - JSON string of the credential
/// * `json_schema` - JSON string of the schema
///
/// # Returns
/// JSON string of the validation report, or NULL on error.
/// Must be freed with kels_free_string().
///
/// # Safety
/// - All arguments must be valid C strings
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_credential_validate(
    json_credential: *const c_char,
    json_schema: *const c_char,
) -> *mut c_char {
    clear_last_error();

    let Some(credential) = from_c_string(json_credential) else {
        set_last_error("Invalid credential JSON");
        return std::ptr::null_mut();
    };

    let Some(schema) = from_c_string(json_schema) else {
        set_last_error("Invalid schema JSON");
        return std::ptr::null_mut();
    };

    match kels_creds::json_api::validate(&credential, &schema) {
        Ok(report) => match serde_json::to_string(&report) {
            Ok(json) => to_c_string(&json),
            Err(e) => {
                set_last_error(&format!("Serialization failed: {e}"));
                std::ptr::null_mut()
            }
        },
        Err(e) => {
            set_last_error(&format!("Validation failed: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Compact a credential using schema-aware compaction.
///
/// Returns all chunks keyed by SAID, plus the canonical compacted SAID.
/// This is a local operation — the caller is responsible for persisting
/// the chunks (e.g., to a file-based store or uploading to a remote SADStore).
///
/// # Arguments
/// * `json_credential` - JSON string of the credential
/// * `json_schema` - JSON string of the schema
///
/// # Returns
/// JSON object `{"compactedSaid": "<said>", "chunks": {<said>: <value>, ...}}`,
/// or NULL on error. Must be freed with kels_free_string().
///
/// # Safety
/// - All arguments must be valid C strings
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_credential_compact(
    json_credential: *const c_char,
    json_schema: *const c_char,
) -> *mut c_char {
    clear_last_error();

    let Some(credential_str) = from_c_string(json_credential) else {
        set_last_error("Invalid credential JSON");
        return std::ptr::null_mut();
    };

    let Some(schema_str) = from_c_string(json_schema) else {
        set_last_error("Invalid schema JSON");
        return std::ptr::null_mut();
    };

    let credential: kels_creds::Credential<serde_json::Value> =
        match std::str::FromStr::from_str(&credential_str) {
            Ok(c) => c,
            Err(e) => {
                set_last_error(&format!("Invalid credential: {e}"));
                return std::ptr::null_mut();
            }
        };

    let schema: kels_creds::Schema = match serde_json::from_str(&schema_str) {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("Invalid schema: {e}"));
            return std::ptr::null_mut();
        }
    };

    match credential.compact(&schema) {
        Ok((compacted_said, chunks)) => {
            match serde_json::to_string(&serde_json::json!({
                "compactedSaid": compacted_said,
                "chunks": chunks,
            })) {
                Ok(json) => to_c_string(&json),
                Err(e) => {
                    set_last_error(&format!("Serialization failed: {e}"));
                    std::ptr::null_mut()
                }
            }
        }
        Err(e) => {
            set_last_error(&format!("Compaction failed: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Apply disclosure to a credential.
///
/// Takes a JSON object of SAD chunks (as returned by kels_credential_compact),
/// a disclosure statement, and a schema. Expands the credential per the disclosure
/// statement and returns the resulting JSON view.
///
/// # Arguments
/// * `compacted_said` - The compacted credential SAID
/// * `disclosure_statement` - Disclosure DSL expression (e.g., "claims", ".*", "claims -secrets.*")
/// * `json_chunks` - JSON object mapping SAIDs to values (the chunk store)
/// * `json_schema` - JSON string of the schema
///
/// # Returns
/// JSON string of the disclosed credential view, or NULL on error.
/// Must be freed with kels_free_string().
///
/// # Safety
/// - All arguments must be valid C strings
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_credential_disclose(
    compacted_said: *const c_char,
    disclosure_statement: *const c_char,
    json_chunks: *const c_char,
    json_schema: *const c_char,
) -> *mut c_char {
    clear_last_error();

    let Some(said) = from_c_string(compacted_said) else {
        set_last_error("Invalid compacted SAID");
        return std::ptr::null_mut();
    };

    let Some(disclosure) = from_c_string(disclosure_statement) else {
        set_last_error("Invalid disclosure statement");
        return std::ptr::null_mut();
    };

    let Some(chunks_str) = from_c_string(json_chunks) else {
        set_last_error("Invalid chunks JSON");
        return std::ptr::null_mut();
    };

    let Some(schema_str) = from_c_string(json_schema) else {
        set_last_error("Invalid schema JSON");
        return std::ptr::null_mut();
    };

    // Load chunks into InMemorySADStore
    let chunks: std::collections::HashMap<String, serde_json::Value> =
        match serde_json::from_str(&chunks_str) {
            Ok(c) => c,
            Err(e) => {
                set_last_error(&format!("Invalid chunks JSON: {e}"));
                return std::ptr::null_mut();
            }
        };

    let Ok(runtime) = Runtime::new() else {
        set_last_error("Failed to create async runtime");
        return std::ptr::null_mut();
    };

    let sad_store = kels_creds::InMemorySADStore::new();
    let store_result = runtime.block_on(sad_store.store_chunks(&chunks));
    if let Err(e) = store_result {
        set_last_error(&format!("Failed to load chunks: {e}"));
        return std::ptr::null_mut();
    }

    let result = runtime.block_on(kels_creds::json_api::disclose(
        &said,
        &disclosure,
        &sad_store,
        &schema_str,
    ));

    match result {
        Ok(json) => to_c_string(&json),
        Err(e) => {
            set_last_error(&format!("Disclosure failed: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Compute the poison hash for a credential SAID.
///
/// The poison hash is anchored in the issuer's KEL to revoke a credential.
/// Anchor via `kels_interact(ctx, poison_hash, &result)`.
///
/// # Arguments
/// * `credential_said` - The credential's SAID to poison
///
/// # Returns
/// The poison hash string. Must be freed with kels_free_string().
///
/// # Safety
/// - `credential_said` must be a valid C string
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_poison_hash(credential_said: *const c_char) -> *mut c_char {
    clear_last_error();

    let Some(said) = from_c_string(credential_said) else {
        set_last_error("Invalid credential SAID");
        return std::ptr::null_mut();
    };

    to_c_string(&kels_policy::poison_hash(&said))
}

// ==================== SAD Operations ====================

/// Compute the deterministic SAD pointer prefix for a given KEL prefix and kind.
///
/// This is an offline operation — no network access needed.
///
/// # Arguments
/// * `kel_prefix` - The KEL prefix (owner of the pointer chain)
/// * `kind` - The pointer kind (e.g., "kels/v1/mlkem-encap-key")
///
/// # Returns
/// The computed pointer prefix string, or NULL on error.
/// Must be freed with kels_free_string().
///
/// # Safety
/// - Both arguments must be valid C strings
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_compute_sad_pointer_prefix(
    kel_prefix: *const c_char,
    kind: *const c_char,
) -> *mut c_char {
    clear_last_error();

    let Some(prefix) = from_c_string(kel_prefix) else {
        set_last_error("Invalid KEL prefix");
        return std::ptr::null_mut();
    };

    let Some(kind_str) = from_c_string(kind) else {
        set_last_error("Invalid kind");
        return std::ptr::null_mut();
    };

    match kels_core::compute_sad_pointer_prefix(&prefix, &kind_str) {
        Ok(pointer_prefix) => to_c_string(&pointer_prefix),
        Err(e) => {
            set_last_error(&format!("Prefix computation failed: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Validate a schema's structure and compliance.
///
/// # Arguments
/// * `json_schema` - JSON string of the schema
///
/// # Returns
/// JSON string `{"valid": true}` on success, or `{"valid": false, "errors": [...]}` on failure.
/// Must be freed with kels_free_string().
///
/// # Safety
/// - `json_schema` must be a valid C string
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_schema_validate(json_schema: *const c_char) -> *mut c_char {
    clear_last_error();

    let Some(schema_str) = from_c_string(json_schema) else {
        set_last_error("Invalid schema JSON");
        return std::ptr::null_mut();
    };

    let schema: kels_creds::Schema = match serde_json::from_str(&schema_str) {
        Ok(s) => s,
        Err(e) => {
            let result =
                serde_json::json!({"valid": false, "errors": [format!("Invalid JSON: {e}")]});
            return to_c_string(&result.to_string());
        }
    };

    let mut errors = Vec::new();

    if let Err(e) = kels_creds::validate_schema_structure(&schema) {
        errors.push(format!("Structure: {e}"));
    }
    if let Err(e) = kels_creds::validate_schema_compliance(&schema) {
        errors.push(format!("Compliance: {e}"));
    }

    let result = if errors.is_empty() {
        serde_json::json!({"valid": true})
    } else {
        serde_json::json!({"valid": false, "errors": errors})
    };

    to_c_string(&result.to_string())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    // ==================== KelsStatus Tests ====================

    #[test]
    fn test_kels_status_values() {
        assert_eq!(KelsStatus::Ok as i32, 0);
        assert_eq!(KelsStatus::NotInitialized as i32, 1);
        assert_eq!(KelsStatus::DivergenceDetected as i32, 2);
        assert_eq!(KelsStatus::KelNotFound as i32, 3);
        assert_eq!(KelsStatus::KelFrozen as i32, 4);
        assert_eq!(KelsStatus::NetworkError as i32, 5);
        assert_eq!(KelsStatus::NotIncepted as i32, 6);
        assert_eq!(KelsStatus::ContestRequired as i32, 7);
        assert_eq!(KelsStatus::Error as i32, 8);
    }

    // ==================== KelsRecoveryOutcome Tests ====================

    #[test]
    fn test_kels_recovery_outcome_values() {
        assert_eq!(KelsRecoveryOutcome::Recovered as i32, 0);
        assert_eq!(KelsRecoveryOutcome::Contested as i32, 1);
        assert_eq!(KelsRecoveryOutcome::Failed as i32, 2);
    }

    // ==================== Default Implementations Tests ====================

    #[test]
    fn test_kels_event_result_default() {
        let result = KelsEventResult::default();
        assert_eq!(result.status, KelsStatus::Error);
        assert!(result.prefix.is_null());
        assert!(result.said.is_null());
        assert!(result.error.is_null());
    }

    #[test]
    fn test_kels_status_result_default() {
        let result = KelsStatusResult::default();
        assert_eq!(result.status, KelsStatus::Error);
        assert!(result.prefix.is_null());
        assert_eq!(result.event_count, 0);
        assert!(result.latest_said.is_null());
        assert!(!result.is_divergent);
        assert!(!result.is_contested);
        assert!(!result.is_decommissioned);
        assert!(!result.use_hardware);
        assert!(result.error.is_null());
    }

    #[test]
    fn test_kels_list_result_default() {
        let result = KelsListResult::default();
        assert_eq!(result.status, KelsStatus::Error);
        assert!(result.prefixes_json.is_null());
        assert_eq!(result.count, 0);
        assert!(result.error.is_null());
    }

    #[test]
    fn test_kels_recovery_result_default() {
        let result = KelsRecoveryResult::default();
        assert_eq!(result.outcome, KelsRecoveryOutcome::Failed);
        assert_eq!(result.status, KelsStatus::Error);
        assert!(result.prefix.is_null());
        assert!(result.said.is_null());
        assert_eq!(result.version, 0);
        assert!(result.error.is_null());
    }

    #[test]
    fn test_kels_nodes_result_default() {
        let result = KelsNodesResult::default();
        assert_eq!(result.status, KelsStatus::Error);
        assert!(result.nodes_json.is_null());
        assert_eq!(result.count, 0);
        assert!(result.error.is_null());
    }

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
        let original = "roundtrip test 🎉";
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

    // ==================== KeyState Tests ====================

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

    // ==================== Exchange FFI Tests ====================

    #[test]
    fn test_kem_key_result_default() {
        let result = KelsKemKeyResult::default();
        assert_eq!(result.status, KelsStatus::Error);
        assert!(result.encapsulation_key.is_null());
        assert!(result.decapsulation_key.is_null());
        assert!(result.algorithm.is_null());
        assert!(result.error.is_null());
    }

    #[test]
    fn test_essr_open_result_default() {
        let result = KelsEssrOpenResult::default();
        assert_eq!(result.status, KelsStatus::Error);
        assert!(result.sender.is_null());
        assert!(result.topic.is_null());
        assert!(result.payload.is_null());
        assert_eq!(result.payload_len, 0);
        assert!(result.error.is_null());
    }

    #[test]
    fn test_generate_kem_keypair_768() {
        let mut result = KelsKemKeyResult::default();
        unsafe {
            kels_generate_kem_keypair(std::ptr::null(), std::ptr::null(), &mut result);
        }
        assert_eq!(result.status, KelsStatus::Ok);
        assert!(!result.encapsulation_key.is_null());
        assert!(!result.decapsulation_key.is_null());
        assert!(!result.algorithm.is_null());

        let algo = from_c_string(result.algorithm);
        assert_eq!(algo, Some("ML-KEM-768".to_string()));

        unsafe {
            kels_kem_key_result_free(&mut result);
        }
    }

    #[test]
    fn test_generate_kem_keypair_1024_from_signing_algo() {
        let signing_algo = CString::new("ml-dsa-87").expect("valid cstring");
        let mut result = KelsKemKeyResult::default();
        unsafe {
            kels_generate_kem_keypair(signing_algo.as_ptr(), std::ptr::null(), &mut result);
        }
        assert_eq!(result.status, KelsStatus::Ok);

        let algo = from_c_string(result.algorithm);
        assert_eq!(algo, Some("ML-KEM-1024".to_string()));

        unsafe {
            kels_kem_key_result_free(&mut result);
        }
    }

    #[test]
    fn test_generate_kem_keypair_explicit_override() {
        let algo = CString::new("ML-KEM-1024").expect("valid cstring");
        let mut result = KelsKemKeyResult::default();
        unsafe {
            kels_generate_kem_keypair(std::ptr::null(), algo.as_ptr(), &mut result);
        }
        assert_eq!(result.status, KelsStatus::Ok);

        let result_algo = from_c_string(result.algorithm);
        assert_eq!(result_algo, Some("ML-KEM-1024".to_string()));

        unsafe {
            kels_kem_key_result_free(&mut result);
        }
    }

    #[test]
    fn test_generate_kem_keypair_invalid_algo() {
        let algo = CString::new("invalid-algo").expect("valid cstring");
        let mut result = KelsKemKeyResult::default();
        unsafe {
            kels_generate_kem_keypair(std::ptr::null(), algo.as_ptr(), &mut result);
        }
        assert_eq!(result.status, KelsStatus::Error);
        assert!(!result.error.is_null());

        unsafe {
            kels_kem_key_result_free(&mut result);
        }
    }

    #[test]
    fn test_encap_key_publication_create() {
        // First generate a keypair to get a valid encapsulation key
        let mut key_result = KelsKemKeyResult::default();
        unsafe {
            kels_generate_kem_keypair(std::ptr::null(), std::ptr::null(), &mut key_result);
        }
        assert_eq!(key_result.status, KelsStatus::Ok);

        let algo = CString::new("ML-KEM-768").expect("valid cstring");
        let encap_key_str = from_c_string(key_result.encapsulation_key).expect("valid string");
        let encap_key_cstr = CString::new(encap_key_str).expect("valid cstring");

        let pub_json =
            unsafe { kels_encap_key_publication_create(algo.as_ptr(), encap_key_cstr.as_ptr()) };

        assert!(!pub_json.is_null());
        let json_str = from_c_string(pub_json).expect("valid json");
        let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("valid JSON");
        assert!(parsed.get("said").is_some());
        assert_eq!(parsed["algorithm"], "ML-KEM-768");

        unsafe {
            kels_free_string(pub_json);
            kels_kem_key_result_free(&mut key_result);
        }
    }

    #[test]
    fn test_essr_seal_open_roundtrip() {
        // Generate sender signing keys
        let (sender_vk, sender_sk) = cesr::generate_ml_dsa_65().expect("keygen");
        // Generate recipient KEM keys
        let (recipient_ek, recipient_dk) = cesr::generate_ml_kem_768().expect("keygen");

        let sender_prefix = CString::new("sender-prefix-ffi").expect("cstring");
        let recipient_prefix = CString::new("recipient-prefix-ffi").expect("cstring");
        let topic = CString::new("test/v1/roundtrip").expect("cstring");
        let payload = b"hello from FFI";
        let encap_key_qb64 = CString::new(recipient_ek.qb64()).expect("cstring");
        let signing_key_qb64 = CString::new(sender_sk.qb64()).expect("cstring");

        // Seal
        let sealed_json = unsafe {
            kels_essr_seal(
                sender_prefix.as_ptr(),
                0,
                recipient_prefix.as_ptr(),
                topic.as_ptr(),
                payload.as_ptr(),
                payload.len(),
                encap_key_qb64.as_ptr(),
                signing_key_qb64.as_ptr(),
            )
        };

        assert!(!sealed_json.is_null());

        // Open
        let decap_key_encoded = encode_decap_key(&recipient_dk);
        let decap_key_cstr = CString::new(decap_key_encoded).expect("cstring");
        let vk_qb64 = CString::new(sender_vk.qb64()).expect("cstring");

        let mut open_result = KelsEssrOpenResult::default();
        unsafe {
            kels_essr_open(
                sealed_json,
                decap_key_cstr.as_ptr(),
                vk_qb64.as_ptr(),
                &mut open_result,
            );
        }

        assert_eq!(open_result.status, KelsStatus::Ok);
        assert_eq!(
            from_c_string(open_result.sender),
            Some("sender-prefix-ffi".to_string())
        );
        assert_eq!(
            from_c_string(open_result.topic),
            Some("test/v1/roundtrip".to_string())
        );
        assert_eq!(open_result.payload_len, payload.len());

        let opened_payload =
            unsafe { std::slice::from_raw_parts(open_result.payload, open_result.payload_len) };
        assert_eq!(opened_payload, payload);

        unsafe {
            kels_free_string(sealed_json);
            kels_essr_open_result_free(&mut open_result);
        }
    }

    #[test]
    fn test_essr_open_wrong_key_fails() {
        let (_, sender_sk) = cesr::generate_ml_dsa_65().expect("keygen");
        let (recipient_ek, _) = cesr::generate_ml_kem_768().expect("keygen");
        let (_, wrong_dk) = cesr::generate_ml_kem_768().expect("keygen");
        let (wrong_vk, _) = cesr::generate_ml_dsa_65().expect("keygen");

        let sender_prefix = CString::new("sender").expect("cstring");
        let recipient_prefix = CString::new("recipient").expect("cstring");
        let topic = CString::new("test").expect("cstring");
        let payload = b"secret";
        let encap_key_qb64 = CString::new(recipient_ek.qb64()).expect("cstring");
        let signing_key_qb64 = CString::new(sender_sk.qb64()).expect("cstring");

        let sealed_json = unsafe {
            kels_essr_seal(
                sender_prefix.as_ptr(),
                0,
                recipient_prefix.as_ptr(),
                topic.as_ptr(),
                payload.as_ptr(),
                payload.len(),
                encap_key_qb64.as_ptr(),
                signing_key_qb64.as_ptr(),
            )
        };
        assert!(!sealed_json.is_null());

        // Try opening with wrong decapsulation key
        let decap_key_encoded = encode_decap_key(&wrong_dk);
        let decap_key_cstr = CString::new(decap_key_encoded).expect("cstring");
        let vk_qb64 = CString::new(wrong_vk.qb64()).expect("cstring");

        let mut open_result = KelsEssrOpenResult::default();
        unsafe {
            kels_essr_open(
                sealed_json,
                decap_key_cstr.as_ptr(),
                vk_qb64.as_ptr(),
                &mut open_result,
            );
        }

        assert_eq!(open_result.status, KelsStatus::Error);
        assert!(!open_result.error.is_null());

        unsafe {
            kels_free_string(sealed_json);
            kels_essr_open_result_free(&mut open_result);
        }
    }

    #[test]
    fn test_compute_blob_digest() {
        let data = b"test data for digest";
        let digest = unsafe { kels_compute_blob_digest(data.as_ptr(), data.len()) };
        assert!(!digest.is_null());

        let digest_str = from_c_string(digest).expect("valid string");
        assert!(!digest_str.is_empty());
        // Should start with 'K' (CESR Blake3 prefix)
        assert!(digest_str.starts_with('K'));

        unsafe {
            kels_free_string(digest);
        }
    }

    #[test]
    fn test_encap_key_kind() {
        let kind = kels_encap_key_kind();
        assert!(!kind.is_null());

        let kind_str = from_c_string(kind);
        assert_eq!(kind_str, Some("kels/v1/mlkem-encap-key".to_string()));
        // Do NOT free — it's a static string
    }

    #[test]
    fn test_decap_key_encode_decode_roundtrip() {
        let (_, dk) = cesr::generate_ml_kem_768().expect("keygen");
        let encoded = encode_decap_key(&dk);
        assert!(encoded.starts_with("ml-kem-768:"));

        let decoded = decode_decap_key(&encoded).expect("decode");
        // Re-encode to compare
        assert_eq!(encode_decap_key(&decoded), encoded);
    }

    // ==================== Credential FFI Tests ====================

    fn test_schema_and_policy() -> (String, String) {
        // Minimal schema with all required credential envelope fields
        let schema_json = r#"{
            "said": "",
            "name": "test/v1/ffi",
            "description": "FFI test schema",
            "version": "1.0.0",
            "fields": {
                "schema": { "type": "said" },
                "policy": { "type": "said" },
                "issuedAt": { "type": "datetime" },
                "claims": {
                    "type": "object",
                    "compactable": true,
                    "fields": {
                        "name": { "type": "string" },
                        "age": { "type": "integer" }
                    }
                },
                "subject": { "type": "prefix", "optional": true },
                "nonce": { "type": "string", "optional": true },
                "expiresAt": { "type": "datetime", "optional": true },
                "edges": { "type": "object", "compactable": true, "optional": true },
                "rules": { "type": "object", "compactable": true, "optional": true }
            }
        }"#;
        // Derive SAID for the schema
        let mut schema_value: serde_json::Value = serde_json::from_str(schema_json).expect("valid");
        schema_value.derive_said().expect("derive said");
        let schema = serde_json::to_string(&schema_value).expect("serialize");

        let policy_json = r#"{
            "said": "",
            "expression": "endorse(KTestPrefix1234567890123456789012345678901)"
        }"#;
        let mut policy_value: serde_json::Value = serde_json::from_str(policy_json).expect("valid");
        policy_value.derive_said().expect("derive said");
        let policy = serde_json::to_string(&policy_value).expect("serialize");

        (schema, policy)
    }

    #[test]
    fn test_credential_build() {
        let (schema, policy) = test_schema_and_policy();

        let claims = r#"{"said": "", "name": "Alice", "age": 30}"#;

        let schema_cstr = CString::new(schema).expect("cstring");
        let policy_cstr = CString::new(policy).expect("cstring");
        let claims_cstr = CString::new(claims).expect("cstring");

        let result = unsafe {
            kels_credential_build(
                claims_cstr.as_ptr(),
                schema_cstr.as_ptr(),
                policy_cstr.as_ptr(),
                std::ptr::null(), // no subject
                false,            // not unique
                std::ptr::null(), // no edges
                std::ptr::null(), // no rules
                std::ptr::null(), // no expiry
            )
        };

        assert!(!result.is_null(), "build returned null: {:?}", unsafe {
            CStr::from_ptr(kels_last_error()).to_str()
        });

        let json_str = from_c_string(result).expect("valid json");
        let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("valid JSON");
        assert!(parsed.get("credential").is_some());
        assert!(parsed.get("canonicalSaid").is_some());
        let canonical = parsed["canonicalSaid"].as_str().expect("string");
        assert_eq!(canonical.len(), 44);

        unsafe {
            kels_free_string(result);
        }
    }

    #[test]
    fn test_credential_build_invalid_claims() {
        let (schema, policy) = test_schema_and_policy();

        let claims = r#"{"said": "", "wrong_field": true}"#;
        let schema_cstr = CString::new(schema).expect("cstring");
        let policy_cstr = CString::new(policy).expect("cstring");
        let claims_cstr = CString::new(claims).expect("cstring");

        let result = unsafe {
            kels_credential_build(
                claims_cstr.as_ptr(),
                schema_cstr.as_ptr(),
                policy_cstr.as_ptr(),
                std::ptr::null(),
                false,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };

        assert!(result.is_null());
        let err_ptr = kels_last_error();
        assert!(!err_ptr.is_null());
    }

    #[test]
    fn test_credential_validate() {
        let (schema, policy) = test_schema_and_policy();
        let claims = r#"{"said": "", "name": "Alice", "age": 30}"#;

        let schema_cstr = CString::new(schema.clone()).expect("cstring");
        let policy_cstr = CString::new(policy).expect("cstring");
        let claims_cstr = CString::new(claims).expect("cstring");

        // First build a credential
        let build_result = unsafe {
            kels_credential_build(
                claims_cstr.as_ptr(),
                schema_cstr.as_ptr(),
                policy_cstr.as_ptr(),
                std::ptr::null(),
                false,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert!(!build_result.is_null());

        let build_json = from_c_string(build_result).expect("valid json");
        let parsed: serde_json::Value = serde_json::from_str(&build_json).expect("valid JSON");
        let credential_json = serde_json::to_string(&parsed["credential"]).expect("serialize");

        let cred_cstr = CString::new(credential_json).expect("cstring");

        // Validate
        let validate_result =
            unsafe { kels_credential_validate(cred_cstr.as_ptr(), schema_cstr.as_ptr()) };

        assert!(!validate_result.is_null());
        let report_str = from_c_string(validate_result).expect("valid json");
        let report: serde_json::Value = serde_json::from_str(&report_str).expect("valid JSON");
        assert_eq!(report["valid"], true);

        unsafe {
            kels_free_string(build_result);
            kels_free_string(validate_result);
        }
    }

    #[test]
    fn test_credential_compact_and_disclose() {
        let (schema, policy) = test_schema_and_policy();
        let claims = r#"{"said": "", "name": "Bob", "age": 25}"#;

        let schema_cstr = CString::new(schema.clone()).expect("cstring");
        let policy_cstr = CString::new(policy).expect("cstring");
        let claims_cstr = CString::new(claims).expect("cstring");

        // Build
        let build_result = unsafe {
            kels_credential_build(
                claims_cstr.as_ptr(),
                schema_cstr.as_ptr(),
                policy_cstr.as_ptr(),
                std::ptr::null(),
                false,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert!(!build_result.is_null());

        let build_json = from_c_string(build_result).expect("valid json");
        let parsed: serde_json::Value = serde_json::from_str(&build_json).expect("valid JSON");
        let credential_json = serde_json::to_string(&parsed["credential"]).expect("serialize");
        let cred_cstr = CString::new(credential_json).expect("cstring");

        // Compact
        let compact_result =
            unsafe { kels_credential_compact(cred_cstr.as_ptr(), schema_cstr.as_ptr()) };
        assert!(
            !compact_result.is_null(),
            "compact returned null: {:?}",
            unsafe { CStr::from_ptr(kels_last_error()).to_str() }
        );

        let compact_json = from_c_string(compact_result).expect("valid json");
        let compact_parsed: serde_json::Value =
            serde_json::from_str(&compact_json).expect("valid JSON");
        let compacted_said = compact_parsed["compactedSaid"].as_str().expect("string");
        assert_eq!(compacted_said.len(), 44);
        let chunks = &compact_parsed["chunks"];
        assert!(chunks.is_object());
        assert!(!chunks.as_object().expect("obj").is_empty());

        // Disclose everything
        let said_cstr = CString::new(compacted_said).expect("cstring");
        let disclosure_cstr = CString::new(".*").expect("cstring");
        let chunks_json = serde_json::to_string(chunks).expect("serialize");
        let chunks_cstr = CString::new(chunks_json).expect("cstring");

        let disclose_result = unsafe {
            kels_credential_disclose(
                said_cstr.as_ptr(),
                disclosure_cstr.as_ptr(),
                chunks_cstr.as_ptr(),
                schema_cstr.as_ptr(),
            )
        };

        assert!(
            !disclose_result.is_null(),
            "disclose returned null: {:?}",
            unsafe { CStr::from_ptr(kels_last_error()).to_str() }
        );

        let disclosed = from_c_string(disclose_result).expect("valid json");
        let disclosed_value: serde_json::Value =
            serde_json::from_str(&disclosed).expect("valid JSON");
        assert!(disclosed_value.get("claims").is_some());

        unsafe {
            kels_free_string(build_result);
            kels_free_string(compact_result);
            kels_free_string(disclose_result);
        }
    }

    #[test]
    fn test_poison_hash() {
        let said = CString::new("KTestSaid0000000000000000000000000000000000").expect("cstring");
        let hash = unsafe { kels_poison_hash(said.as_ptr()) };
        assert!(!hash.is_null());

        let hash_str = from_c_string(hash).expect("valid string");
        assert!(!hash_str.is_empty());
        // Poison hash should start with 'K' (CESR Blake3)
        assert!(hash_str.starts_with('K'));

        // Same input should produce same hash
        let hash2 = unsafe { kels_poison_hash(said.as_ptr()) };
        let hash2_str = from_c_string(hash2).expect("valid string");
        assert_eq!(hash_str, hash2_str);

        unsafe {
            kels_free_string(hash);
            kels_free_string(hash2);
        }
    }

    // ==================== SAD FFI Tests ====================

    #[test]
    fn test_compute_sad_pointer_prefix() {
        let prefix = CString::new("KMyPrefix0000000000000000000000000000000000").expect("cstring");
        let kind = CString::new("kels/v1/mlkem-encap-key").expect("cstring");

        let result = unsafe { kels_compute_sad_pointer_prefix(prefix.as_ptr(), kind.as_ptr()) };

        assert!(!result.is_null());
        let prefix_str = from_c_string(result).expect("valid string");
        assert_eq!(prefix_str.len(), 44);

        // Same inputs should produce same prefix (deterministic)
        let result2 = unsafe { kels_compute_sad_pointer_prefix(prefix.as_ptr(), kind.as_ptr()) };
        let prefix_str2 = from_c_string(result2).expect("valid string");
        assert_eq!(prefix_str, prefix_str2);

        unsafe {
            kels_free_string(result);
            kels_free_string(result2);
        }
    }

    #[test]
    fn test_schema_validate_valid() {
        let (schema, _) = test_schema_and_policy();
        let schema_cstr = CString::new(schema).expect("cstring");

        let result = unsafe { kels_schema_validate(schema_cstr.as_ptr()) };
        assert!(!result.is_null());

        let json_str = from_c_string(result).expect("valid json");
        let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("valid JSON");
        assert_eq!(parsed["valid"], true);

        unsafe {
            kels_free_string(result);
        }
    }

    #[test]
    fn test_schema_validate_invalid_json() {
        let bad = CString::new("not json").expect("cstring");
        let result = unsafe { kels_schema_validate(bad.as_ptr()) };
        assert!(!result.is_null());

        let json_str = from_c_string(result).expect("valid json");
        let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("valid JSON");
        assert_eq!(parsed["valid"], false);

        unsafe {
            kels_free_string(result);
        }
    }
}
