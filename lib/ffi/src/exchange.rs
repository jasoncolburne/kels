//! Exchange Operations (KEM keypairs, ESSR seal/open, encap key publications)

use std::ffi::CString;
use std::os::raw::c_char;

use cesr::Matter;

use kels_exchange::{EssrInner, ExchangeError};
use verifiable_storage::SelfAddressed;

use crate::{KelsStatus, clear_last_error, from_c_string, set_last_error, to_c_string};

// ==================== Result Structs ====================

/// Result from ML-KEM key generation
#[repr(C)]
pub struct KelsKemKeyResult {
    pub status: KelsStatus,
    /// CESR-encoded (qb64) encapsulation key (owned, must be freed with kels_free_string)
    pub encapsulation_key: *mut c_char,
    /// Decapsulation key in CESR qb64 format (owned, must be freed with kels_free_string)
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

// ==================== Helper Functions ====================

/// Encode a DecapsulationKey as a CESR qb64 string.
pub(crate) fn encode_decap_key(dk: &cesr::DecapsulationKey) -> String {
    dk.qb64()
}

/// Decode a DecapsulationKey from a CESR qb64 string.
pub(crate) fn decode_decap_key(encoded: &str) -> Result<cesr::DecapsulationKey, String> {
    cesr::DecapsulationKey::from_qb64(encoded.trim()).map_err(|e| e.to_string())
}

fn exchange_error_message(err: &ExchangeError) -> String {
    err.to_string()
}

// ==================== FFI Functions ====================

/// Generate an ML-KEM keypair.
///
/// The algorithm defaults to match the signing algorithm strength:
/// - ML-DSA-65 / secp256r1 / NULL -> ML-KEM-768
/// - ML-DSA-87 -> ML-KEM-1024
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

    let encap_key = match cesr::EncapsulationKey::from_qb64(&encap_key) {
        Ok(k) => k,
        Err(e) => {
            set_last_error(&format!("Invalid encapsulation key CESR: {e}"));
            return std::ptr::null_mut();
        }
    };

    let mut publication = kels_exchange::EncapsulationKeyPublication {
        said: cesr::Digest::blake3_256(b"placeholder"),
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

    let Some(sender_str) = from_c_string(sender_prefix) else {
        set_last_error("Invalid sender prefix");
        return std::ptr::null_mut();
    };
    let sender = match cesr::Digest::from_qb64(&sender_str) {
        Ok(d) => d,
        Err(e) => {
            set_last_error(&format!("Invalid sender prefix CESR: {e}"));
            return std::ptr::null_mut();
        }
    };

    let Some(recipient_str) = from_c_string(recipient_prefix) else {
        set_last_error("Invalid recipient prefix");
        return std::ptr::null_mut();
    };
    let recipient = match cesr::Digest::from_qb64(&recipient_str) {
        Ok(d) => d,
        Err(e) => {
            set_last_error(&format!("Invalid recipient prefix CESR: {e}"));
            return std::ptr::null_mut();
        }
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

/// ESSR open: verify and decrypt a received ESSR envelope.
///
/// # Arguments
/// * `signed_envelope_json` - JSON string of the SignedEssrEnvelope
/// * `recipient_decap_key` - Recipient's decapsulation key in CESR qb64 format
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
            result.sender = to_c_string(inner.sender.as_ref());
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
    to_c_string(kels_exchange::compute_blob_digest(bytes).as_ref())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{KelsStatus, kels_free_string};

    use std::ffi::CString;

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

        let algo = crate::from_c_string(result.algorithm);
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

        let algo = crate::from_c_string(result.algorithm);
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

        let result_algo = crate::from_c_string(result.algorithm);
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
        let encap_key_str =
            crate::from_c_string(key_result.encapsulation_key).expect("valid string");
        let encap_key_cstr = CString::new(encap_key_str).expect("valid cstring");

        let pub_json =
            unsafe { kels_encap_key_publication_create(algo.as_ptr(), encap_key_cstr.as_ptr()) };

        assert!(!pub_json.is_null());
        let json_str = crate::from_c_string(pub_json).expect("valid json");
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

        let sender_digest = cesr::Digest::blake3_256(b"sender-prefix-ffi");
        let recipient_digest = cesr::Digest::blake3_256(b"recipient-prefix-ffi");
        let sender_prefix = CString::new(sender_digest.as_ref()).expect("cstring");
        let recipient_prefix = CString::new(recipient_digest.as_ref()).expect("cstring");
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
            crate::from_c_string(open_result.sender),
            Some(sender_digest.as_ref().to_string())
        );
        assert_eq!(
            crate::from_c_string(open_result.topic),
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

        let sender_digest = cesr::Digest::blake3_256(b"sender");
        let recipient_digest = cesr::Digest::blake3_256(b"recipient");
        let sender_prefix = CString::new(sender_digest.as_ref()).expect("cstring");
        let recipient_prefix = CString::new(recipient_digest.as_ref()).expect("cstring");
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

        let digest_str = crate::from_c_string(digest).expect("valid string");
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

        let kind_str = crate::from_c_string(kind);
        assert_eq!(kind_str, Some("kels/v1/mlkem-encap-key".to_string()));
        // Do NOT free -- it's a static string
    }

    #[test]
    fn test_decap_key_encode_decode_roundtrip() {
        let (_, dk) = cesr::generate_ml_kem_768().expect("keygen");
        let encoded = encode_decap_key(&dk);
        assert!(encoded.starts_with("0m"));

        let decoded = decode_decap_key(&encoded).expect("decode");
        assert_eq!(encode_decap_key(&decoded), encoded);
    }
}
