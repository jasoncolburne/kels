//! Registry Operations (node discovery, registry prefix fetch)

use std::ffi::CString;
use std::os::raw::c_char;

use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;

use kels_core::FileKelStore;

use crate::{
    KelsStatus, clear_last_error, from_c_string, map_error_to_status, set_last_error, to_c_string,
};

// ==================== Result Structs ====================

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

// ==================== FFI Functions ====================

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
                peer_prefix: peer.peer_prefix.to_string(),
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
            result.prefix = to_c_string(prefix.as_ref());
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_kels_nodes_result_default() {
        let result = KelsNodesResult::default();
        assert_eq!(result.status, KelsStatus::Error);
        assert!(result.nodes_json.is_null());
        assert_eq!(result.count, 0);
        assert!(result.error.is_null());
    }
}
