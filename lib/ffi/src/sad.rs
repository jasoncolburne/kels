//! SAD Operations (pointer prefix computation, SAD object and pointer CRUD)

use std::os::raw::c_char;

use cesr::Matter;
use tokio::runtime::Runtime;

use crate::{
    KelsStatus, clear_last_error, from_c_string, map_error_to_status, set_last_error, to_c_string,
};

// ==================== FFI Functions ====================

/// Compute the deterministic SAD pointer prefix for a given write policy SAID and topic.
///
/// This is an offline operation -- no network access needed.
///
/// # Arguments
/// * `write_policy` - The write policy SAID
/// * `topic` - The pointer topic (e.g., "kels/exchange/v1/keys/mlkem")
///
/// # Returns
/// The computed pointer prefix string, or NULL on error.
/// Must be freed with kels_free_string().
///
/// # Safety
/// - Both arguments must be valid C strings
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_compute_sad_pointer_prefix(
    write_policy: *const c_char,
    topic: *const c_char,
) -> *mut c_char {
    clear_last_error();

    let Some(policy_str) = from_c_string(write_policy) else {
        set_last_error("Invalid write policy");
        return std::ptr::null_mut();
    };

    let Some(topic_str) = from_c_string(topic) else {
        set_last_error("Invalid topic");
        return std::ptr::null_mut();
    };

    let policy_digest = match cesr::Digest256::from_qb64(&policy_str) {
        Ok(d) => d,
        Err(e) => {
            set_last_error(&format!("Invalid write policy CESR: {e}"));
            return std::ptr::null_mut();
        }
    };

    match kels_core::compute_sad_pointer_prefix(policy_digest, &topic_str) {
        Ok(pointer_prefix) => to_c_string(pointer_prefix.as_ref()),
        Err(e) => {
            set_last_error(&format!("Prefix computation failed: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Store a self-addressed JSON object in a SADStore. Returns the SAID.
///
/// The object must already have a valid derived `said` field.
///
/// # Arguments
/// * `sadstore_url` - URL of the SADStore service
/// * `json_object` - JSON string of the object to store
///
/// # Returns
/// The SAID string, or NULL on error. Must be freed with kels_free_string().
///
/// # Safety
/// - Both arguments must be valid C strings
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_sad_post_object(
    sadstore_url: *const c_char,
    json_object: *const c_char,
) -> *mut c_char {
    clear_last_error();

    let Some(url) = from_c_string(sadstore_url) else {
        set_last_error("Invalid SADStore URL");
        return std::ptr::null_mut();
    };

    let Some(object_str) = from_c_string(json_object) else {
        set_last_error("Invalid JSON object");
        return std::ptr::null_mut();
    };

    let object: serde_json::Value = match serde_json::from_str(&object_str) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(&format!("Invalid JSON: {e}"));
            return std::ptr::null_mut();
        }
    };

    let Ok(runtime) = Runtime::new() else {
        set_last_error("Failed to create async runtime");
        return std::ptr::null_mut();
    };

    let client = match kels_core::SadStoreClient::new(&url) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(&format!("Failed to create SADStore client: {e}"));
            return std::ptr::null_mut();
        }
    };

    match runtime.block_on(client.post_sad_object(&object)) {
        Ok(said) => to_c_string(said.as_ref()),
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Retrieve a self-addressed JSON object from a SADStore by SAID.
///
/// # Arguments
/// * `sadstore_url` - URL of the SADStore service
/// * `said` - The SAID of the object to retrieve
///
/// # Returns
/// JSON string of the object, or NULL on error. Must be freed with kels_free_string().
///
/// # Safety
/// - Both arguments must be valid C strings
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_sad_get_object(
    sadstore_url: *const c_char,
    said: *const c_char,
) -> *mut c_char {
    clear_last_error();

    let Some(url) = from_c_string(sadstore_url) else {
        set_last_error("Invalid SADStore URL");
        return std::ptr::null_mut();
    };

    let Some(said_str) = from_c_string(said) else {
        set_last_error("Invalid SAID");
        return std::ptr::null_mut();
    };
    let said_digest = match cesr::Digest256::from_qb64(&said_str) {
        Ok(d) => d,
        Err(e) => {
            set_last_error(&format!("Invalid SAID CESR: {e}"));
            return std::ptr::null_mut();
        }
    };

    let Ok(runtime) = Runtime::new() else {
        set_last_error("Failed to create async runtime");
        return std::ptr::null_mut();
    };

    let client = match kels_core::SadStoreClient::new(&url) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(&format!("Failed to create SADStore client: {e}"));
            return std::ptr::null_mut();
        }
    };

    match runtime.block_on(client.get_sad_object(&said_digest)) {
        Ok(value) => match serde_json::to_string(&value) {
            Ok(json) => to_c_string(&json),
            Err(e) => {
                set_last_error(&format!("Serialization failed: {e}"));
                std::ptr::null_mut()
            }
        },
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Submit SAD pointer records to a SADStore.
///
/// # Arguments
/// * `sadstore_url` - URL of the SADStore service
/// * `json_signed_records` - JSON string of `Vec<SadPointer>`
///
/// # Returns
/// 0 on success, -1 on error
///
/// # Safety
/// - Both arguments must be valid C strings
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_sad_submit_pointer(
    sadstore_url: *const c_char,
    json_signed_records: *const c_char,
) -> KelsStatus {
    clear_last_error();

    let Some(url) = from_c_string(sadstore_url) else {
        set_last_error("Invalid SADStore URL");
        return KelsStatus::Error;
    };

    let Some(records_str) = from_c_string(json_signed_records) else {
        set_last_error("Invalid records JSON");
        return KelsStatus::Error;
    };

    let records: Vec<kels_core::SadPointer> = match serde_json::from_str(&records_str) {
        Ok(r) => r,
        Err(e) => {
            set_last_error(&format!("Invalid records JSON: {e}"));
            return KelsStatus::Error;
        }
    };

    let Ok(runtime) = Runtime::new() else {
        set_last_error("Failed to create async runtime");
        return KelsStatus::Error;
    };

    let client = match kels_core::SadStoreClient::new(&url) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(&format!("Failed to create SADStore client: {e}"));
            return KelsStatus::Error;
        }
    };

    match runtime.block_on(client.submit_sad_pointer(&records)) {
        Ok(()) => KelsStatus::Ok,
        Err(e) => {
            set_last_error(&e.to_string());
            map_error_to_status(&e)
        }
    }
}

/// Fetch a page of SAD pointer records from a SADStore.
///
/// # Arguments
/// * `sadstore_url` - URL of the SADStore service
/// * `pointer_prefix` - The pointer chain prefix
/// * `since` - Optional effective SAID cursor (NULL for first page)
///
/// # Returns
/// JSON string of the SadPointerPage, or NULL on error.
/// Must be freed with kels_free_string().
///
/// # Safety
/// - `sadstore_url` and `pointer_prefix` must be valid C strings
/// - `since` may be NULL
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kels_sad_fetch_pointer(
    sadstore_url: *const c_char,
    pointer_prefix: *const c_char,
    since: *const c_char,
) -> *mut c_char {
    clear_last_error();

    let Some(url) = from_c_string(sadstore_url) else {
        set_last_error("Invalid SADStore URL");
        return std::ptr::null_mut();
    };

    let Some(prefix_str) = from_c_string(pointer_prefix) else {
        set_last_error("Invalid pointer prefix");
        return std::ptr::null_mut();
    };

    let prefix = match cesr::Digest256::from_qb64(&prefix_str) {
        Ok(d) => d,
        Err(e) => {
            set_last_error(&format!("Invalid prefix CESR: {e}"));
            return std::ptr::null_mut();
        }
    };

    let since_digest = match from_c_string(since) {
        Some(s) if !s.is_empty() => match cesr::Digest256::from_qb64(&s) {
            Ok(d) => Some(d),
            Err(e) => {
                set_last_error(&format!("Invalid since CESR: {e}"));
                return std::ptr::null_mut();
            }
        },
        _ => None,
    };

    let Ok(runtime) = Runtime::new() else {
        set_last_error("Failed to create async runtime");
        return std::ptr::null_mut();
    };

    let client = match kels_core::SadStoreClient::new(&url) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(&format!("Failed to create SADStore client: {e}"));
            return std::ptr::null_mut();
        }
    };

    match runtime.block_on(client.fetch_sad_pointer(&prefix, since_digest.as_ref())) {
        Ok(page) => match serde_json::to_string(&page) {
            Ok(json) => to_c_string(&json),
            Err(e) => {
                set_last_error(&format!("Serialization failed: {e}"));
                std::ptr::null_mut()
            }
        },
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use cesr::test_digest;

    use super::*;
    use crate::kels_free_string;

    use std::ffi::CString;

    #[test]
    fn test_compute_sad_pointer_prefix() {
        let digest = test_digest("test-prefix");
        let prefix = CString::new(digest.as_ref()).expect("cstring");
        let kind = CString::new("kels/exchange/v1/keys/mlkem").expect("cstring");

        let result = unsafe { kels_compute_sad_pointer_prefix(prefix.as_ptr(), kind.as_ptr()) };

        assert!(!result.is_null());
        let prefix_str = crate::from_c_string(result).expect("valid string");
        assert_eq!(prefix_str.len(), 44);

        // Same inputs should produce same prefix (deterministic)
        let result2 = unsafe { kels_compute_sad_pointer_prefix(prefix.as_ptr(), kind.as_ptr()) };
        let prefix_str2 = crate::from_c_string(result2).expect("valid string");
        assert_eq!(prefix_str, prefix_str2);

        unsafe {
            kels_free_string(result);
            kels_free_string(result2);
        }
    }

    #[test]
    fn test_sad_post_object_null_url() {
        let obj = CString::new(r#"{"said": "test"}"#).expect("cstring");
        let result = unsafe { kels_sad_post_object(std::ptr::null(), obj.as_ptr()) };
        assert!(result.is_null());
    }

    #[test]
    fn test_sad_post_object_invalid_json() {
        let url = CString::new("http://localhost:9999").expect("cstring");
        let obj = CString::new("not json").expect("cstring");
        let result = unsafe { kels_sad_post_object(url.as_ptr(), obj.as_ptr()) };
        assert!(result.is_null());
    }

    #[test]
    fn test_sad_get_object_null_url() {
        let said = CString::new("KTestSaid000000000000000000000000000000000").expect("cstring");
        let result = unsafe { kels_sad_get_object(std::ptr::null(), said.as_ptr()) };
        assert!(result.is_null());
    }

    #[test]
    fn test_sad_submit_pointer_null_url() {
        let records = CString::new("[]").expect("cstring");
        let result = unsafe { kels_sad_submit_pointer(std::ptr::null(), records.as_ptr()) };
        assert_eq!(result, KelsStatus::Error);
    }

    #[test]
    fn test_sad_submit_pointer_invalid_json() {
        let url = CString::new("http://localhost:9999").expect("cstring");
        let records = CString::new("not json").expect("cstring");
        let result = unsafe { kels_sad_submit_pointer(url.as_ptr(), records.as_ptr()) };
        assert_eq!(result, KelsStatus::Error);
    }

    #[test]
    fn test_sad_fetch_pointer_null_url() {
        let prefix = CString::new("KTestPrefix0000000000000000000000000000000").expect("cstring");
        let result =
            unsafe { kels_sad_fetch_pointer(std::ptr::null(), prefix.as_ptr(), std::ptr::null()) };
        assert!(result.is_null());
    }

    #[test]
    fn test_sad_fetch_pointer_null_prefix() {
        let url = CString::new("http://localhost:9999").expect("cstring");
        let result =
            unsafe { kels_sad_fetch_pointer(url.as_ptr(), std::ptr::null(), std::ptr::null()) };
        assert!(result.is_null());
    }
}
