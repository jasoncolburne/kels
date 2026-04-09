//! Credential Operations (build, validate, compact, disclose, poison, schema validate)

use std::os::raw::c_char;

use cesr::Matter;
use kels_core::SadStore;
use tokio::runtime::Runtime;

use crate::{clear_last_error, from_c_string, set_last_error, to_c_string};

// ==================== FFI Functions ====================

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
            let credential_value = match serde_json::from_str::<serde_json::Value>(&credential_json)
            {
                Ok(v) => v,
                Err(e) => {
                    set_last_error(&format!("Failed to parse credential JSON: {e}"));
                    return std::ptr::null_mut();
                }
            };
            match serde_json::to_string(&serde_json::json!({
                "credential": credential_value,
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
/// This is a local operation -- the caller is responsible for persisting
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

    // Load chunks into InMemorySadStore — JSON keys are qb64 SAIDs
    let string_chunks: std::collections::HashMap<String, serde_json::Value> =
        match serde_json::from_str(&chunks_str) {
            Ok(c) => c,
            Err(e) => {
                set_last_error(&format!("Invalid chunks JSON: {e}"));
                return std::ptr::null_mut();
            }
        };
    let mut chunks = std::collections::HashMap::new();
    for (key, value) in string_chunks {
        match cesr::Digest256::from_qb64(&key) {
            Ok(digest) => {
                chunks.insert(digest, value);
            }
            Err(e) => {
                set_last_error(&format!("Invalid SAID key '{key}': {e}"));
                return std::ptr::null_mut();
            }
        }
    }

    let Ok(runtime) = Runtime::new() else {
        set_last_error("Failed to create async runtime");
        return std::ptr::null_mut();
    };

    let sad_store = kels_core::InMemorySadStore::new();
    let store_result = runtime.block_on(sad_store.store_batch(&chunks));
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

    to_c_string(kels_policy::poison_hash(&said).as_ref())
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
    use verifiable_storage::SelfAddressed;

    use crate::{kels_free_string, kels_last_error};

    use std::ffi::{CStr, CString};

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

        let json_str = crate::from_c_string(result).expect("valid json");
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

        let build_json = crate::from_c_string(build_result).expect("valid json");
        let parsed: serde_json::Value = serde_json::from_str(&build_json).expect("valid JSON");
        let credential_json = serde_json::to_string(&parsed["credential"]).expect("serialize");

        let cred_cstr = CString::new(credential_json).expect("cstring");

        // Validate
        let validate_result =
            unsafe { kels_credential_validate(cred_cstr.as_ptr(), schema_cstr.as_ptr()) };

        assert!(!validate_result.is_null());
        let report_str = crate::from_c_string(validate_result).expect("valid json");
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

        let build_json = crate::from_c_string(build_result).expect("valid json");
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

        let compact_json = crate::from_c_string(compact_result).expect("valid json");
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

        let disclosed = crate::from_c_string(disclose_result).expect("valid json");
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

        let hash_str = crate::from_c_string(hash).expect("valid string");
        assert!(!hash_str.is_empty());
        // Poison hash should start with 'K' (CESR Blake3)
        assert!(hash_str.starts_with('K'));

        // Same input should produce same hash
        let hash2 = unsafe { kels_poison_hash(said.as_ptr()) };
        let hash2_str = crate::from_c_string(hash2).expect("valid string");
        assert_eq!(hash_str, hash2_str);

        unsafe {
            kels_free_string(hash);
            kels_free_string(hash2);
        }
    }

    #[test]
    fn test_schema_validate_valid() {
        let (schema, _) = test_schema_and_policy();
        let schema_cstr = CString::new(schema).expect("cstring");

        let result = unsafe { kels_schema_validate(schema_cstr.as_ptr()) };
        assert!(!result.is_null());

        let json_str = crate::from_c_string(result).expect("valid json");
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

        let json_str = crate::from_c_string(result).expect("valid json");
        let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("valid JSON");
        assert_eq!(parsed["valid"], false);

        unsafe {
            kels_free_string(result);
        }
    }
}
