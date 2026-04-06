//! KEL Operations and Query Operations

use std::os::raw::c_char;

use cesr::Matter;
use kels_core::{KelStore, KeyProvider};

use crate::{
    KelsContext, KelsEventResult, KelsListResult, KelsRecoveryOutcome, KelsRecoveryResult,
    KelsStatus, KelsStatusResult, clear_last_error, from_c_string, map_error_to_status,
    parse_algorithm_option, save_key_state, to_c_string,
};

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
                crate::set_last_error(&format!("Warning: Failed to save key state: {}", e));
            }

            result.status = KelsStatus::Ok;
            result.prefix = to_c_string(icp.event.prefix.as_ref());
            result.said = to_c_string(icp.event.said.as_ref());
        }
        Err(e) => {
            result.status = map_error_to_status(&e);
            result.error = to_c_string(&e.to_string());
            crate::set_last_error(&e.to_string());
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
                crate::set_last_error(&format!("Warning: Failed to save key state: {}", e));
            }

            result.status = KelsStatus::Ok;
            result.prefix = to_c_string(rot.event.prefix.as_ref());
            result.said = to_c_string(rot.event.said.as_ref());
        }
        Err(e) => {
            result.status = map_error_to_status(&e);
            result.error = to_c_string(&e.to_string());
            crate::set_last_error(&e.to_string());
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
                crate::set_last_error(&format!("Warning: Failed to save key state: {}", e));
            }

            result.status = KelsStatus::Ok;
            result.prefix = to_c_string(ror.event.prefix.as_ref());
            result.said = to_c_string(ror.event.said.as_ref());
        }
        Err(e) => {
            result.status = map_error_to_status(&e);
            result.error = to_c_string(&e.to_string());
            crate::set_last_error(&e.to_string());
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

    let anchor_digest = match cesr::Digest::from_qb64(&anchor_str) {
        Ok(d) => d,
        Err(e) => {
            result.status = KelsStatus::Error;
            result.error = to_c_string(&format!("Invalid anchor CESR: {}", e));
            return;
        }
    };

    let interact_result = ctx
        .runtime
        .block_on(async { builder_guard.interact(&anchor_digest).await });

    match interact_result {
        Ok(ixn) => {
            result.status = KelsStatus::Ok;
            result.prefix = to_c_string(ixn.event.prefix.as_ref());
            result.said = to_c_string(ixn.event.said.as_ref());
        }
        Err(e) => {
            result.status = map_error_to_status(&e);
            result.error = to_c_string(&e.to_string());
            crate::set_last_error(&e.to_string());
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
                crate::set_last_error(&format!("Warning: Failed to save key state: {}", e));
            }

            result.status = KelsStatus::Ok;
            result.outcome = KelsRecoveryOutcome::Recovered;
            result.prefix = to_c_string(rec.event.prefix.as_ref());
            result.said = to_c_string(rec.event.said.as_ref());
        }
        Err(e) => {
            result.status = map_error_to_status(&e);
            result.outcome = KelsRecoveryOutcome::Failed;
            result.error = to_c_string(&e.to_string());
            crate::set_last_error(&e.to_string());
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
                crate::set_last_error(&format!("Warning: Failed to save key state: {}", e));
            }

            result.status = KelsStatus::Ok;
            result.prefix = to_c_string(cnt.event.prefix.as_ref());
            result.said = to_c_string(cnt.event.said.as_ref());
        }
        Err(e) => {
            result.status = map_error_to_status(&e);
            result.error = to_c_string(&e.to_string());
            crate::set_last_error(&e.to_string());
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
            result.prefix = to_c_string(dec.event.prefix.as_ref());
            result.said = to_c_string(dec.event.said.as_ref());
        }
        Err(e) => {
            result.status = map_error_to_status(&e);
            result.error = to_c_string(&e.to_string());
            crate::set_last_error(&e.to_string());
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
        result.prefix = to_c_string(prefix.as_ref());
    }

    result.event_count = builder_guard.confirmed_count() as u32;

    if let Some(said) = builder_guard.last_said() {
        result.latest_said = to_c_string(said.as_ref());
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
        crate::set_last_error("Context is null");
        return std::ptr::null_mut();
    }

    let ctx = unsafe { &*ctx };

    let prefix_str = from_c_string(prefix);

    let Ok(builder_guard) = ctx.builder.lock() else {
        crate::set_last_error("Failed to acquire builder lock");
        return std::ptr::null_mut();
    };

    // If no prefix specified, use the current KEL
    let target_prefix = if prefix_str.is_none()
        || prefix_str.as_deref() == builder_guard.prefix().map(|p| p.as_ref())
    {
        match builder_guard.prefix() {
            Some(p) => p.clone(),
            None => {
                crate::set_last_error("No KEL prefix available");
                return std::ptr::null_mut();
            }
        }
    } else {
        crate::set_last_error("Can only get current KEL from context");
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
                    crate::set_last_error(&format!("Failed to serialize KEL: {}", e));
                    std::ptr::null_mut()
                }
            }
        }
        Err(e) => {
            crate::set_last_error(&format!("Failed to load KEL: {}", e));
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{KelsRecoveryOutcome, KelsStatus};

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
}
