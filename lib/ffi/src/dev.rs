//! Dev Tools (Feature-Gated)
//!
//! All functions in this module require the `dev-tools` feature.

use std::ffi::CStr;
use std::os::raw::c_char;

use kels_core::{EventKind, KelStore, KeyProvider};

use crate::{KelsContext, clear_last_error, set_last_error, to_c_string};

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
        let client = match kels_core::KelsClient::new(&kels_url) {
            Ok(c) => c,
            Err(e) => {
                set_last_error(&format!("Failed to build HTTP client: {}", e));
                return -1;
            }
        };
        let mut adversary_builder =
            kels_core::KeyEventBuilder::with_events(adversary_keys, Some(client), None, events);

        let mut counter = 0u32;

        let algo_from_digit = |d: char| -> Option<kels_core::VerificationKeyCode> {
            match d {
                '0' => Some(kels_core::VerificationKeyCode::Secp256r1),
                '1' => Some(kels_core::VerificationKeyCode::MlDsa65),
                '2' => Some(kels_core::VerificationKeyCode::MlDsa87),
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
