//! Mock PKCS#11 provider with ML-DSA-65 and ML-DSA-87 support
//!
//! Implements a minimal subset of PKCS#11 3.2 for use as a development HSM.
//! Keys are stored in memory and do not persist across restarts.
//!
//! Supports:
//! - ML-DSA-65 key generation and signing (`CKM_ML_DSA_KEY_PAIR_GEN` / `CKM_ML_DSA`)
//! - ML-DSA-87 key generation and signing (`CKM_ML_DSA_KEY_PAIR_GEN` / `CKM_ML_DSA`)
//!
//! The parameter set (ML-DSA-65 vs ML-DSA-87) is selected via `CKA_PARAMETER_SET`
//! in the public key template during key generation.
//!
//! In production, swap the library path to a real HSM's PKCS#11 `.so`.

// All PKCS#11 C ABI functions share the same safety contract: callers must provide
// valid pointers and buffer sizes per the PKCS#11 specification. Each function validates
// null pointers and returns CKR_ARGUMENTS_BAD for invalid inputs.
#![allow(clippy::missing_safety_doc)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::unwrap_in_result,
        unsafe_code
    )
)]

use std::collections::HashMap;
use std::sync::Mutex;

use fips204::traits::{KeyGen, SerDes, Signer};
use fips204::{ml_dsa_65, ml_dsa_87};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

// ==================== PKCS#11 Type Definitions ====================

type CkRv = u64;
type CkSlotId = u64;
type CkSessionHandle = u64;
type CkObjectHandle = u64;
type CkMechanismType = u64;
type CkAttributeType = u64;
type CkObjectClass = u64;
type CkKeyType = u64;
type CkFlags = u64;
type CkUserType = u64;
type CkBbool = u8;
type CkByte = u8;
type CkUlong = u64;
type CkVoidPtr = *mut std::ffi::c_void;
type CkNotifyFn = Option<unsafe extern "C" fn(CkSessionHandle, CkUlong, CkVoidPtr) -> CkRv>;

// Return values
const CKR_OK: CkRv = 0x00000000;
const CKR_ARGUMENTS_BAD: CkRv = 0x00000007;
const CKR_ATTRIBUTE_TYPE_INVALID: CkRv = 0x00000012;
const CKR_DEVICE_ERROR: CkRv = 0x00000030;
const CKR_FUNCTION_NOT_SUPPORTED: CkRv = 0x00000054;
const CKR_KEY_HANDLE_INVALID: CkRv = 0x00000060;
const CKR_MECHANISM_INVALID: CkRv = 0x00000068;
const CKR_OPERATION_NOT_INITIALIZED: CkRv = 0x00000091;
const CKR_SESSION_HANDLE_INVALID: CkRv = 0x000000B3;
const CKR_TOKEN_NOT_PRESENT: CkRv = 0x000000E0;
const CKR_CRYPTOKI_ALREADY_INITIALIZED: CkRv = 0x00000191;
const CKR_CRYPTOKI_NOT_INITIALIZED: CkRv = 0x00000190;
const CKR_BUFFER_TOO_SMALL: CkRv = 0x00000150;

// Object classes
const CKO_PUBLIC_KEY: CkObjectClass = 0x00000002;
const CKO_PRIVATE_KEY: CkObjectClass = 0x00000003;

// Key types (PKCS#11 3.2)
const CKK_ML_DSA: CkKeyType = 0x0000004A;

// Mechanisms (PKCS#11 3.2)
const CKM_ML_DSA_KEY_PAIR_GEN: CkMechanismType = 0x0000001C;
const CKM_ML_DSA: CkMechanismType = 0x0000001D;

// Attributes
const CKA_CLASS: CkAttributeType = 0x00000000;
const CKA_TOKEN: CkAttributeType = 0x00000001;
const CKA_LABEL: CkAttributeType = 0x00000003;
const CKA_VALUE: CkAttributeType = 0x00000011;
const CKA_KEY_TYPE: CkAttributeType = 0x00000100;
const CKA_SIGN: CkAttributeType = 0x00000108;
const CKA_VERIFY: CkAttributeType = 0x0000010A;
const CKA_PRIVATE: CkAttributeType = 0x00000002;
const CKA_SENSITIVE: CkAttributeType = 0x00000103;
const CKA_PARAMETER_SET: CkAttributeType = 0x0000061D;

// Flags
const CKF_SERIAL_SESSION: CkFlags = 0x00000004;
const CKF_RW_SESSION: CkFlags = 0x00000002;
const CKF_TOKEN_PRESENT: CkFlags = 0x00000001;
const CKF_LOGIN_REQUIRED: CkFlags = 0x00000004;
const CKF_TOKEN_INITIALIZED: CkFlags = 0x00000400;

// Booleans
const CK_TRUE: CkBbool = 1;

// ML-DSA parameter set values
const CKP_ML_DSA_65: CkUlong = 2;
const CKP_ML_DSA_87: CkUlong = 3;

// Session magic value
const SESSION_HANDLE: CkSessionHandle = 0x0001;

// ==================== C Structs ====================

#[repr(C)]
pub struct CkVersion {
    major: u8,
    minor: u8,
}

#[repr(C)]
pub struct CkInfo {
    cryptoki_version: CkVersion,
    manufacturer_id: [u8; 32],
    flags: CkFlags,
    library_description: [u8; 32],
    library_version: CkVersion,
}

#[repr(C)]
pub struct CkSlotInfo {
    slot_description: [u8; 64],
    manufacturer_id: [u8; 32],
    flags: CkFlags,
    hardware_version: CkVersion,
    firmware_version: CkVersion,
}

#[repr(C)]
pub struct CkTokenInfo {
    label: [u8; 32],
    manufacturer_id: [u8; 32],
    model: [u8; 16],
    serial_number: [u8; 16],
    flags: CkFlags,
    max_session_count: CkUlong,
    session_count: CkUlong,
    max_rw_session_count: CkUlong,
    rw_session_count: CkUlong,
    max_pin_len: CkUlong,
    min_pin_len: CkUlong,
    total_public_memory: CkUlong,
    free_public_memory: CkUlong,
    total_private_memory: CkUlong,
    free_private_memory: CkUlong,
    hardware_version: CkVersion,
    firmware_version: CkVersion,
    utc_time: [u8; 16],
}

#[repr(C)]
pub struct CkMechanism {
    mechanism: CkMechanismType,
    p_parameter: *const u8,
    ul_parameter_len: CkUlong,
}

#[repr(C)]
pub struct CkAttribute {
    r#type: CkAttributeType,
    p_value: *mut u8,
    ul_value_len: CkUlong,
}

#[repr(C)]
pub struct CkSessionInfo {
    slot_id: CkSlotId,
    state: CkUlong,
    flags: CkFlags,
    device_error: CkUlong,
}

// ==================== Internal State ====================

struct StoredObject {
    class: CkObjectClass,
    key_type: CkKeyType,
    label: String,
    value: Vec<u8>, // public key bytes or private key seed
    parameter_set: CkUlong,
}

/// Serializable representation of a stored object for disk persistence.
#[derive(Serialize, Deserialize)]
struct PersistedObject {
    class: u64,
    key_type: u64,
    value: String, // hex-encoded
    #[serde(default = "default_parameter_set")]
    parameter_set: u64,
}

fn default_parameter_set() -> u64 {
    CKP_ML_DSA_65
}

/// Serializable state for all objects keyed by label+class.
#[derive(Serialize, Deserialize)]
struct PersistedState {
    objects: HashMap<String, PersistedObject>,
    next_handle: u64,
}

fn persistence_key(label: &str, class: CkObjectClass) -> String {
    format!("{}:{}", label, class)
}

fn save_state(state: &HsmState) {
    let data_dir = match state.data_dir.as_ref() {
        Some(d) => d,
        None => return,
    };

    let mut persisted = PersistedState {
        objects: HashMap::new(),
        next_handle: state.next_handle,
    };

    for obj in state.objects.values() {
        let key = persistence_key(&obj.label, obj.class);
        persisted.objects.insert(
            key,
            PersistedObject {
                class: obj.class,
                key_type: obj.key_type,
                value: hex::encode(&obj.value),
                parameter_set: obj.parameter_set,
            },
        );
    }

    let path = format!("{}/keys.json", data_dir);
    if let Ok(json) = serde_json::to_string_pretty(&persisted) {
        let _ = std::fs::write(&path, json);
    }
}

fn load_state(state: &mut HsmState) {
    let data_dir = match state.data_dir.as_ref() {
        Some(d) => d,
        None => return,
    };

    let path = format!("{}/keys.json", data_dir);
    let Ok(json) = std::fs::read_to_string(&path) else {
        return;
    };
    let Ok(persisted) = serde_json::from_str::<PersistedState>(&json) else {
        return;
    };

    state.next_handle = persisted.next_handle;

    for (key, pobj) in persisted.objects {
        // Extract label from persistence key (label:class)
        let label = key
            .rsplit_once(':')
            .map(|(l, _)| l.to_string())
            .unwrap_or(key);
        let Ok(value) = hex::decode(&pobj.value) else {
            continue;
        };
        let handle = state.alloc_handle();
        state.objects.insert(
            handle,
            StoredObject {
                class: pobj.class,
                key_type: pobj.key_type,
                label,
                value,
                parameter_set: pobj.parameter_set,
            },
        );
    }
}

struct FindState {
    results: Vec<CkObjectHandle>,
    position: usize,
}

struct SignState {
    key_handle: CkObjectHandle,
}

struct HsmState {
    initialized: bool,
    session_open: bool,
    logged_in: bool,
    objects: HashMap<CkObjectHandle, StoredObject>,
    next_handle: CkObjectHandle,
    find_state: Option<FindState>,
    sign_state: Option<SignState>,
    data_dir: Option<String>,
}

impl HsmState {
    fn new() -> Self {
        Self {
            initialized: false,
            session_open: false,
            logged_in: false,
            objects: HashMap::new(),
            next_handle: 1,
            find_state: None,
            sign_state: None,
            data_dir: None,
        }
    }

    fn alloc_handle(&mut self) -> CkObjectHandle {
        let handle = self.next_handle;
        self.next_handle += 1;
        handle
    }
}

static STATE: Mutex<Option<HsmState>> = Mutex::new(None);

fn with_state<F, T>(f: F) -> Result<T, CkRv>
where
    F: FnOnce(&mut HsmState) -> Result<T, CkRv>,
{
    let mut guard = STATE.lock().map_err(|_| CKR_DEVICE_ERROR)?;
    let state = guard.as_mut().ok_or(CKR_CRYPTOKI_NOT_INITIALIZED)?;
    f(state)
}

// ==================== PKCS#11 Function Implementations ====================

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Initialize(_p_init_args: CkVoidPtr) -> CkRv {
    let Ok(mut guard) = STATE.lock() else {
        return CKR_DEVICE_ERROR;
    };
    if guard.is_some() {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    *guard = Some(HsmState::new());
    drop(guard);

    let result = with_state(|state| {
        state.initialized = true;
        state.data_dir = std::env::var("KELS_HSM_DATA_DIR")
            .ok()
            .filter(|d| !d.is_empty());
        load_state(state);
        Ok(())
    });
    match result {
        Ok(()) => CKR_OK,
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Finalize(_p_reserved: CkVoidPtr) -> CkRv {
    let Ok(mut guard) = STATE.lock() else {
        return CKR_DEVICE_ERROR;
    };
    if guard.is_none() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    *guard = None;
    CKR_OK
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetInfo(p_info: *mut CkInfo) -> CkRv {
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut info = CkInfo {
        cryptoki_version: CkVersion { major: 3, minor: 2 },
        manufacturer_id: [b' '; 32],
        flags: 0,
        library_description: [b' '; 32],
        library_version: CkVersion { major: 0, minor: 1 },
    };
    copy_padded(&mut info.manufacturer_id, b"KELS");
    copy_padded(&mut info.library_description, b"KELS Mock HSM");
    unsafe { *p_info = info };
    CKR_OK
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetSlotList(
    _token_present: CkBbool,
    p_slot_list: *mut CkSlotId,
    pul_count: *mut CkUlong,
) -> CkRv {
    if pul_count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if p_slot_list.is_null() {
        unsafe { *pul_count = 1 };
        return CKR_OK;
    }
    let count = unsafe { *pul_count };
    if count < 1 {
        unsafe { *pul_count = 1 };
        return CKR_BUFFER_TOO_SMALL;
    }
    unsafe {
        *p_slot_list = 0; // slot 0
        *pul_count = 1;
    };
    CKR_OK
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetSlotInfo(slot_id: CkSlotId, p_info: *mut CkSlotInfo) -> CkRv {
    if slot_id != 0 || p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut info = CkSlotInfo {
        slot_description: [b' '; 64],
        manufacturer_id: [b' '; 32],
        flags: CKF_TOKEN_PRESENT,
        hardware_version: CkVersion { major: 0, minor: 1 },
        firmware_version: CkVersion { major: 0, minor: 1 },
    };
    copy_padded(&mut info.slot_description[..], b"KELS Mock HSM Slot");
    copy_padded(&mut info.manufacturer_id, b"KELS");
    unsafe { *p_info = info };
    CKR_OK
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetTokenInfo(slot_id: CkSlotId, p_info: *mut CkTokenInfo) -> CkRv {
    if slot_id != 0 || p_info.is_null() {
        return CKR_TOKEN_NOT_PRESENT;
    }
    let mut info = CkTokenInfo {
        label: [b' '; 32],
        manufacturer_id: [b' '; 32],
        model: [b' '; 16],
        serial_number: [b' '; 16],
        flags: CKF_TOKEN_INITIALIZED | CKF_LOGIN_REQUIRED,
        max_session_count: 1,
        session_count: 0,
        max_rw_session_count: 1,
        rw_session_count: 0,
        max_pin_len: 128,
        min_pin_len: 4,
        total_public_memory: u64::MAX,
        free_public_memory: u64::MAX,
        total_private_memory: u64::MAX,
        free_private_memory: u64::MAX,
        hardware_version: CkVersion { major: 0, minor: 1 },
        firmware_version: CkVersion { major: 0, minor: 1 },
        utc_time: [b' '; 16],
    };
    copy_padded(&mut info.label, b"KELS Mock Token");
    copy_padded(&mut info.manufacturer_id, b"KELS");
    copy_padded(&mut info.model, b"MockHSM");
    copy_padded(&mut info.serial_number, b"0001");
    unsafe { *p_info = info };
    CKR_OK
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_OpenSession(
    slot_id: CkSlotId,
    flags: CkFlags,
    _p_application: CkVoidPtr,
    _notify: CkNotifyFn,
    ph_session: *mut CkSessionHandle,
) -> CkRv {
    if slot_id != 0 || ph_session.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if flags & CKF_SERIAL_SESSION == 0 {
        return CKR_ARGUMENTS_BAD;
    }
    let result = with_state(|state| {
        state.session_open = true;
        Ok(SESSION_HANDLE)
    });
    match result {
        Ok(handle) => {
            unsafe { *ph_session = handle };
            CKR_OK
        }
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_CloseSession(h_session: CkSessionHandle) -> CkRv {
    if h_session != SESSION_HANDLE {
        return CKR_SESSION_HANDLE_INVALID;
    }
    let result = with_state(|state| {
        state.session_open = false;
        state.logged_in = false;
        Ok(())
    });
    match result {
        Ok(()) => CKR_OK,
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_CloseAllSessions(_slot_id: CkSlotId) -> CkRv {
    let result = with_state(|state| {
        state.session_open = false;
        state.logged_in = false;
        Ok(())
    });
    match result {
        Ok(()) => CKR_OK,
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetSessionInfo(
    h_session: CkSessionHandle,
    p_info: *mut CkSessionInfo,
) -> CkRv {
    if h_session != SESSION_HANDLE || p_info.is_null() {
        return CKR_SESSION_HANDLE_INVALID;
    }
    let info = CkSessionInfo {
        slot_id: 0,
        state: 3, // CKS_RW_USER_FUNCTIONS
        flags: CKF_SERIAL_SESSION | CKF_RW_SESSION,
        device_error: 0,
    };
    unsafe { *p_info = info };
    CKR_OK
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Login(
    h_session: CkSessionHandle,
    _user_type: CkUserType,
    _p_pin: *const CkByte,
    _ul_pin_len: CkUlong,
) -> CkRv {
    if h_session != SESSION_HANDLE {
        return CKR_SESSION_HANDLE_INVALID;
    }
    let result = with_state(|state| {
        state.logged_in = true;
        Ok(())
    });
    match result {
        Ok(()) => CKR_OK,
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Logout(h_session: CkSessionHandle) -> CkRv {
    if h_session != SESSION_HANDLE {
        return CKR_SESSION_HANDLE_INVALID;
    }
    let result = with_state(|state| {
        state.logged_in = false;
        Ok(())
    });
    match result {
        Ok(()) => CKR_OK,
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GenerateKeyPair(
    h_session: CkSessionHandle,
    p_mechanism: *const CkMechanism,
    p_public_key_template: *const CkAttribute,
    ul_public_key_attribute_count: CkUlong,
    _p_private_key_template: *const CkAttribute,
    _ul_private_key_attribute_count: CkUlong,
    ph_public_key: *mut CkObjectHandle,
    ph_private_key: *mut CkObjectHandle,
) -> CkRv {
    if h_session != SESSION_HANDLE
        || p_mechanism.is_null()
        || ph_public_key.is_null()
        || ph_private_key.is_null()
    {
        return CKR_ARGUMENTS_BAD;
    }

    let mechanism = unsafe { &*p_mechanism };
    if mechanism.mechanism != CKM_ML_DSA_KEY_PAIR_GEN {
        return CKR_MECHANISM_INVALID;
    }

    // Extract label and parameter set from public key template
    let label = extract_label(p_public_key_template, ul_public_key_attribute_count);
    let parameter_set = extract_parameter_set(p_public_key_template, ul_public_key_attribute_count);

    let result = with_state(|state| {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);

        let pk_bytes = match parameter_set {
            CKP_ML_DSA_87 => {
                let (pk, _sk) = ml_dsa_87::KG::keygen_from_seed(&seed);
                pk.into_bytes().to_vec()
            }
            _ => {
                // CKP_ML_DSA_65 or default
                let (pk, _sk) = ml_dsa_65::KG::keygen_from_seed(&seed);
                pk.into_bytes().to_vec()
            }
        };

        let pub_handle = state.alloc_handle();
        let priv_handle = state.alloc_handle();

        state.objects.insert(
            pub_handle,
            StoredObject {
                class: CKO_PUBLIC_KEY,
                key_type: CKK_ML_DSA,
                label: label.clone(),
                value: pk_bytes,
                parameter_set,
            },
        );
        state.objects.insert(
            priv_handle,
            StoredObject {
                class: CKO_PRIVATE_KEY,
                key_type: CKK_ML_DSA,
                label,
                value: seed.to_vec(),
                parameter_set,
            },
        );

        save_state(state);

        Ok((pub_handle, priv_handle))
    });

    match result {
        Ok((pub_h, priv_h)) => {
            unsafe {
                *ph_public_key = pub_h;
                *ph_private_key = priv_h;
            };
            CKR_OK
        }
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_FindObjectsInit(
    h_session: CkSessionHandle,
    p_template: *const CkAttribute,
    ul_count: CkUlong,
) -> CkRv {
    if h_session != SESSION_HANDLE {
        return CKR_SESSION_HANDLE_INVALID;
    }

    // Extract search criteria
    let mut search_class: Option<CkObjectClass> = None;
    let mut search_label: Option<String> = None;

    for i in 0..ul_count as usize {
        let attr = unsafe { &*p_template.add(i) };
        match attr.r#type {
            CKA_CLASS if !attr.p_value.is_null() && attr.ul_value_len >= 8 => {
                search_class = Some(unsafe { *(attr.p_value as *const CkObjectClass) });
            }
            CKA_LABEL if !attr.p_value.is_null() => {
                let slice =
                    unsafe { std::slice::from_raw_parts(attr.p_value, attr.ul_value_len as usize) };
                search_label = String::from_utf8(slice.to_vec()).ok();
            }
            _ => {}
        }
    }

    let result = with_state(|state| {
        let results: Vec<CkObjectHandle> = state
            .objects
            .iter()
            .filter(|(_, obj)| {
                if let Some(class) = search_class
                    && obj.class != class
                {
                    return false;
                }
                if let Some(ref label) = search_label
                    && &obj.label != label
                {
                    return false;
                }
                true
            })
            .map(|(handle, _)| *handle)
            .collect();

        state.find_state = Some(FindState {
            results,
            position: 0,
        });
        Ok(())
    });
    match result {
        Ok(()) => CKR_OK,
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_FindObjects(
    h_session: CkSessionHandle,
    ph_object: *mut CkObjectHandle,
    ul_max_object_count: CkUlong,
    pul_object_count: *mut CkUlong,
) -> CkRv {
    if h_session != SESSION_HANDLE || ph_object.is_null() || pul_object_count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let result = with_state(|state| {
        let find = state
            .find_state
            .as_mut()
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        let remaining = &find.results[find.position..];
        let count = remaining.len().min(ul_max_object_count as usize);

        for (i, &handle) in remaining[..count].iter().enumerate() {
            unsafe { *ph_object.add(i) = handle };
        }
        find.position += count;

        Ok(count as CkUlong)
    });

    match result {
        Ok(count) => {
            unsafe { *pul_object_count = count };
            CKR_OK
        }
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_FindObjectsFinal(h_session: CkSessionHandle) -> CkRv {
    if h_session != SESSION_HANDLE {
        return CKR_SESSION_HANDLE_INVALID;
    }
    let result = with_state(|state| {
        state.find_state = None;
        Ok(())
    });
    match result {
        Ok(()) => CKR_OK,
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetAttributeValue(
    h_session: CkSessionHandle,
    h_object: CkObjectHandle,
    p_template: *mut CkAttribute,
    ul_count: CkUlong,
) -> CkRv {
    if h_session != SESSION_HANDLE || p_template.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let result = with_state(|state| {
        let obj = state.objects.get(&h_object).ok_or(CKR_KEY_HANDLE_INVALID)?;

        for i in 0..ul_count as usize {
            let attr = unsafe { &mut *p_template.add(i) };
            match attr.r#type {
                CKA_CLASS => {
                    write_attr_value(attr, &obj.class.to_ne_bytes());
                }
                CKA_KEY_TYPE => {
                    write_attr_value(attr, &obj.key_type.to_ne_bytes());
                }
                CKA_LABEL => {
                    write_attr_value(attr, obj.label.as_bytes());
                }
                CKA_VALUE => {
                    write_attr_value(attr, &obj.value);
                }
                CKA_PARAMETER_SET => {
                    write_attr_value(attr, &obj.parameter_set.to_ne_bytes());
                }
                CKA_TOKEN => {
                    write_attr_value(attr, &[CK_TRUE]);
                }
                CKA_SIGN => {
                    let val = if obj.class == CKO_PRIVATE_KEY {
                        CK_TRUE
                    } else {
                        0
                    };
                    write_attr_value(attr, &[val]);
                }
                CKA_VERIFY => {
                    let val = if obj.class == CKO_PUBLIC_KEY {
                        CK_TRUE
                    } else {
                        0
                    };
                    write_attr_value(attr, &[val]);
                }
                CKA_PRIVATE => {
                    let val = if obj.class == CKO_PRIVATE_KEY {
                        CK_TRUE
                    } else {
                        0
                    };
                    write_attr_value(attr, &[val]);
                }
                CKA_SENSITIVE => {
                    let val = if obj.class == CKO_PRIVATE_KEY {
                        CK_TRUE
                    } else {
                        0
                    };
                    write_attr_value(attr, &[val]);
                }
                _ => {
                    attr.ul_value_len = CkUlong::MAX; // CK_UNAVAILABLE_INFORMATION
                    return Err(CKR_ATTRIBUTE_TYPE_INVALID);
                }
            }
        }
        Ok(())
    });
    match result {
        Ok(()) => CKR_OK,
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_SignInit(
    h_session: CkSessionHandle,
    p_mechanism: *const CkMechanism,
    h_key: CkObjectHandle,
) -> CkRv {
    if h_session != SESSION_HANDLE || p_mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let mechanism = unsafe { &*p_mechanism };
    if mechanism.mechanism != CKM_ML_DSA {
        return CKR_MECHANISM_INVALID;
    }

    let result = with_state(|state| {
        if !state.objects.contains_key(&h_key) {
            return Err(CKR_KEY_HANDLE_INVALID);
        }
        state.sign_state = Some(SignState { key_handle: h_key });
        Ok(())
    });
    match result {
        Ok(()) => CKR_OK,
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Sign(
    h_session: CkSessionHandle,
    p_data: *const CkByte,
    ul_data_len: CkUlong,
    p_signature: *mut CkByte,
    pul_signature_len: *mut CkUlong,
) -> CkRv {
    if h_session != SESSION_HANDLE || p_data.is_null() || pul_signature_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    // Determine signature length from the key's parameter set
    let sig_len_result = with_state(|state| {
        let sign = state
            .sign_state
            .as_ref()
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        let obj = state
            .objects
            .get(&sign.key_handle)
            .ok_or(CKR_KEY_HANDLE_INVALID)?;
        match obj.parameter_set {
            CKP_ML_DSA_87 => Ok(4627u64),
            _ => Ok(3309u64),
        }
    });

    let sig_len: CkUlong = match sig_len_result {
        Ok(len) => len,
        Err(rv) => return rv,
    };

    // Size query
    if p_signature.is_null() {
        unsafe { *pul_signature_len = sig_len };
        return CKR_OK;
    }

    if unsafe { *pul_signature_len } < sig_len {
        unsafe { *pul_signature_len = sig_len };
        return CKR_BUFFER_TOO_SMALL;
    }

    let data = unsafe { std::slice::from_raw_parts(p_data, ul_data_len as usize) };

    let result = with_state(|state| {
        let sign = state
            .sign_state
            .take()
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;

        let obj = state
            .objects
            .get(&sign.key_handle)
            .ok_or(CKR_KEY_HANDLE_INVALID)?;

        let mut seed = [0u8; 32];
        if obj.value.len() < 32 {
            return Err(CKR_DEVICE_ERROR);
        }
        seed.copy_from_slice(&obj.value[..32]);

        let sig_bytes = match obj.parameter_set {
            CKP_ML_DSA_87 => {
                let (_pk, sk) = ml_dsa_87::KG::keygen_from_seed(&seed);
                let sig = sk.try_sign(data, &[]).map_err(|_| CKR_DEVICE_ERROR)?;
                sig.to_vec()
            }
            _ => {
                let (_pk, sk) = ml_dsa_65::KG::keygen_from_seed(&seed);
                let sig = sk.try_sign(data, &[]).map_err(|_| CKR_DEVICE_ERROR)?;
                sig.to_vec()
            }
        };

        Ok(sig_bytes)
    });

    match result {
        Ok(sig_bytes) => {
            unsafe {
                std::ptr::copy_nonoverlapping(sig_bytes.as_ptr(), p_signature, sig_bytes.len());
                *pul_signature_len = sig_bytes.len() as CkUlong;
            };
            CKR_OK
        }
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_DestroyObject(
    h_session: CkSessionHandle,
    h_object: CkObjectHandle,
) -> CkRv {
    if h_session != SESSION_HANDLE {
        return CKR_SESSION_HANDLE_INVALID;
    }
    let result = with_state(|state| {
        state
            .objects
            .remove(&h_object)
            .ok_or(CKR_KEY_HANDLE_INVALID)?;
        Ok(())
    });
    match result {
        Ok(()) => CKR_OK,
        Err(rv) => rv,
    }
}

// ==================== Helpers ====================

fn copy_padded(dest: &mut [u8], src: &[u8]) {
    let len = src.len().min(dest.len());
    dest[..len].copy_from_slice(&src[..len]);
}

fn extract_parameter_set(template: *const CkAttribute, count: CkUlong) -> CkUlong {
    for i in 0..count as usize {
        let attr = unsafe { &*template.add(i) };
        if attr.r#type == CKA_PARAMETER_SET && !attr.p_value.is_null() && attr.ul_value_len >= 8 {
            return unsafe { *(attr.p_value as *const CkUlong) };
        }
    }
    CKP_ML_DSA_65 // default
}

fn extract_label(template: *const CkAttribute, count: CkUlong) -> String {
    for i in 0..count as usize {
        let attr = unsafe { &*template.add(i) };
        if attr.r#type == CKA_LABEL && !attr.p_value.is_null() {
            let slice =
                unsafe { std::slice::from_raw_parts(attr.p_value, attr.ul_value_len as usize) };
            if let Ok(s) = String::from_utf8(slice.to_vec()) {
                return s;
            }
        }
    }
    String::new()
}

fn write_attr_value(attr: &mut CkAttribute, data: &[u8]) {
    if attr.p_value.is_null() {
        // Size query only
        attr.ul_value_len = data.len() as CkUlong;
    } else if (attr.ul_value_len as usize) < data.len() {
        attr.ul_value_len = data.len() as CkUlong;
        // Note: should return CKR_BUFFER_TOO_SMALL but we're in a per-attribute loop
    } else {
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), attr.p_value, data.len());
        };
        attr.ul_value_len = data.len() as CkUlong;
    }
}

// ==================== Stub Functions ====================

macro_rules! stub {
    ($name:ident $(, $arg:ident : $ty:ty)*) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name($(_: $ty),*) -> CkRv {
            CKR_FUNCTION_NOT_SUPPORTED
        }
    };
}

stub!(C_GetMechanismList, _a: CkSlotId, _b: *mut CkMechanismType, _c: *mut CkUlong);
stub!(C_GetMechanismInfo, _a: CkSlotId, _b: CkMechanismType, _c: CkVoidPtr);
stub!(C_InitToken, _a: CkSlotId, _b: *const CkByte, _c: CkUlong, _d: *const CkByte);
stub!(C_InitPIN, _a: CkSessionHandle, _b: *const CkByte, _c: CkUlong);
stub!(C_SetPIN, _a: CkSessionHandle, _b: *const CkByte, _c: CkUlong, _d: *const CkByte, _e: CkUlong);
stub!(C_GetOperationState, _a: CkSessionHandle, _b: *mut CkByte, _c: *mut CkUlong);
stub!(C_SetOperationState, _a: CkSessionHandle, _b: *const CkByte, _c: CkUlong, _d: CkObjectHandle, _e: CkObjectHandle);
stub!(C_CreateObject, _a: CkSessionHandle, _b: *const CkAttribute, _c: CkUlong, _d: *mut CkObjectHandle);
stub!(C_CopyObject, _a: CkSessionHandle, _b: CkObjectHandle, _c: *const CkAttribute, _d: CkUlong, _e: *mut CkObjectHandle);
stub!(C_SetAttributeValue, _a: CkSessionHandle, _b: CkObjectHandle, _c: *const CkAttribute, _d: CkUlong);
stub!(C_GetObjectSize, _a: CkSessionHandle, _b: CkObjectHandle, _c: *mut CkUlong);
stub!(C_EncryptInit, _a: CkSessionHandle, _b: *const CkMechanism, _c: CkObjectHandle);
stub!(C_Encrypt, _a: CkSessionHandle, _b: *const CkByte, _c: CkUlong, _d: *mut CkByte, _e: *mut CkUlong);
stub!(C_EncryptUpdate, _a: CkSessionHandle, _b: *const CkByte, _c: CkUlong, _d: *mut CkByte, _e: *mut CkUlong);
stub!(C_EncryptFinal, _a: CkSessionHandle, _b: *mut CkByte, _c: *mut CkUlong);
stub!(C_DecryptInit, _a: CkSessionHandle, _b: *const CkMechanism, _c: CkObjectHandle);
stub!(C_Decrypt, _a: CkSessionHandle, _b: *const CkByte, _c: CkUlong, _d: *mut CkByte, _e: *mut CkUlong);
stub!(C_DecryptUpdate, _a: CkSessionHandle, _b: *const CkByte, _c: CkUlong, _d: *mut CkByte, _e: *mut CkUlong);
stub!(C_DecryptFinal, _a: CkSessionHandle, _b: *mut CkByte, _c: *mut CkUlong);
stub!(C_DigestInit, _a: CkSessionHandle, _b: *const CkMechanism);
stub!(C_Digest, _a: CkSessionHandle, _b: *const CkByte, _c: CkUlong, _d: *mut CkByte, _e: *mut CkUlong);
stub!(C_DigestUpdate, _a: CkSessionHandle, _b: *const CkByte, _c: CkUlong);
stub!(C_DigestKey, _a: CkSessionHandle, _b: CkObjectHandle);
stub!(C_DigestFinal, _a: CkSessionHandle, _b: *mut CkByte, _c: *mut CkUlong);
stub!(C_SignUpdate, _a: CkSessionHandle, _b: *const CkByte, _c: CkUlong);
stub!(C_SignFinal, _a: CkSessionHandle, _b: *mut CkByte, _c: *mut CkUlong);
stub!(C_SignRecoverInit, _a: CkSessionHandle, _b: *const CkMechanism, _c: CkObjectHandle);
stub!(C_SignRecover, _a: CkSessionHandle, _b: *const CkByte, _c: CkUlong, _d: *mut CkByte, _e: *mut CkUlong);
stub!(C_VerifyInit, _a: CkSessionHandle, _b: *const CkMechanism, _c: CkObjectHandle);
stub!(C_Verify, _a: CkSessionHandle, _b: *const CkByte, _c: CkUlong, _d: *const CkByte, _e: CkUlong);
stub!(C_VerifyUpdate, _a: CkSessionHandle, _b: *const CkByte, _c: CkUlong);
stub!(C_VerifyFinal, _a: CkSessionHandle, _b: *const CkByte, _c: CkUlong);
stub!(C_VerifyRecoverInit, _a: CkSessionHandle, _b: *const CkMechanism, _c: CkObjectHandle);
stub!(C_VerifyRecover, _a: CkSessionHandle, _b: *const CkByte, _c: CkUlong, _d: *mut CkByte, _e: *mut CkUlong);
stub!(C_DigestEncryptUpdate, _a: CkSessionHandle, _b: *const CkByte, _c: CkUlong, _d: *mut CkByte, _e: *mut CkUlong);
stub!(C_DecryptDigestUpdate, _a: CkSessionHandle, _b: *const CkByte, _c: CkUlong, _d: *mut CkByte, _e: *mut CkUlong);
stub!(C_SignEncryptUpdate, _a: CkSessionHandle, _b: *const CkByte, _c: CkUlong, _d: *mut CkByte, _e: *mut CkUlong);
stub!(C_DecryptVerifyUpdate, _a: CkSessionHandle, _b: *const CkByte, _c: CkUlong, _d: *mut CkByte, _e: *mut CkUlong);
stub!(C_GenerateKey, _a: CkSessionHandle, _b: *const CkMechanism, _c: *const CkAttribute, _d: CkUlong, _e: *mut CkObjectHandle);
stub!(C_WrapKey, _a: CkSessionHandle, _b: *const CkMechanism, _c: CkObjectHandle, _d: CkObjectHandle, _e: *mut CkByte, _f: *mut CkUlong);
stub!(C_UnwrapKey, _a: CkSessionHandle, _b: *const CkMechanism, _c: CkObjectHandle, _d: *const CkByte, _e: CkUlong, _f: *const CkAttribute, _g: CkUlong, _h: *mut CkObjectHandle);
stub!(C_DeriveKey, _a: CkSessionHandle, _b: *const CkMechanism, _c: CkObjectHandle, _d: *const CkAttribute, _e: CkUlong, _f: *mut CkObjectHandle);
stub!(C_SeedRandom, _a: CkSessionHandle, _b: *const CkByte, _c: CkUlong);
stub!(C_GenerateRandom, _a: CkSessionHandle, _b: *mut CkByte, _c: CkUlong);
stub!(C_WaitForSlotEvent, _a: CkFlags, _b: *mut CkSlotId, _c: CkVoidPtr);
stub!(C_GetFunctionStatus, _a: CkSessionHandle);
stub!(C_CancelFunction, _a: CkSessionHandle);

// ==================== Function List ====================

// Function pointer type matching PKCS#11 C_GetFunctionList signature
type GetFunctionListFn = unsafe extern "C" fn(*mut *const CkFunctionList) -> CkRv;

#[repr(C)]
pub struct CkFunctionList {
    pub version: CkVersion,
    pub c_initialize: unsafe extern "C" fn(CkVoidPtr) -> CkRv,
    pub c_finalize: unsafe extern "C" fn(CkVoidPtr) -> CkRv,
    pub c_get_info: unsafe extern "C" fn(*mut CkInfo) -> CkRv,
    pub c_get_function_list: GetFunctionListFn,
    pub c_get_slot_list: unsafe extern "C" fn(CkBbool, *mut CkSlotId, *mut CkUlong) -> CkRv,
    pub c_get_slot_info: unsafe extern "C" fn(CkSlotId, *mut CkSlotInfo) -> CkRv,
    pub c_get_token_info: unsafe extern "C" fn(CkSlotId, *mut CkTokenInfo) -> CkRv,
    pub c_get_mechanism_list:
        unsafe extern "C" fn(CkSlotId, *mut CkMechanismType, *mut CkUlong) -> CkRv,
    pub c_get_mechanism_info: unsafe extern "C" fn(CkSlotId, CkMechanismType, CkVoidPtr) -> CkRv,
    pub c_init_token: unsafe extern "C" fn(CkSlotId, *const CkByte, CkUlong, *const CkByte) -> CkRv,
    pub c_init_pin: unsafe extern "C" fn(CkSessionHandle, *const CkByte, CkUlong) -> CkRv,
    pub c_set_pin: unsafe extern "C" fn(
        CkSessionHandle,
        *const CkByte,
        CkUlong,
        *const CkByte,
        CkUlong,
    ) -> CkRv,
    pub c_open_session: unsafe extern "C" fn(
        CkSlotId,
        CkFlags,
        CkVoidPtr,
        CkNotifyFn,
        *mut CkSessionHandle,
    ) -> CkRv,
    pub c_close_session: unsafe extern "C" fn(CkSessionHandle) -> CkRv,
    pub c_close_all_sessions: unsafe extern "C" fn(CkSlotId) -> CkRv,
    pub c_get_session_info: unsafe extern "C" fn(CkSessionHandle, *mut CkSessionInfo) -> CkRv,
    pub c_get_operation_state:
        unsafe extern "C" fn(CkSessionHandle, *mut CkByte, *mut CkUlong) -> CkRv,
    pub c_set_operation_state: unsafe extern "C" fn(
        CkSessionHandle,
        *const CkByte,
        CkUlong,
        CkObjectHandle,
        CkObjectHandle,
    ) -> CkRv,
    pub c_login: unsafe extern "C" fn(CkSessionHandle, CkUserType, *const CkByte, CkUlong) -> CkRv,
    pub c_logout: unsafe extern "C" fn(CkSessionHandle) -> CkRv,
    pub c_create_object: unsafe extern "C" fn(
        CkSessionHandle,
        *const CkAttribute,
        CkUlong,
        *mut CkObjectHandle,
    ) -> CkRv,
    pub c_copy_object: unsafe extern "C" fn(
        CkSessionHandle,
        CkObjectHandle,
        *const CkAttribute,
        CkUlong,
        *mut CkObjectHandle,
    ) -> CkRv,
    pub c_destroy_object: unsafe extern "C" fn(CkSessionHandle, CkObjectHandle) -> CkRv,
    pub c_get_object_size:
        unsafe extern "C" fn(CkSessionHandle, CkObjectHandle, *mut CkUlong) -> CkRv,
    pub c_get_attribute_value:
        unsafe extern "C" fn(CkSessionHandle, CkObjectHandle, *mut CkAttribute, CkUlong) -> CkRv,
    pub c_set_attribute_value:
        unsafe extern "C" fn(CkSessionHandle, CkObjectHandle, *const CkAttribute, CkUlong) -> CkRv,
    pub c_find_objects_init:
        unsafe extern "C" fn(CkSessionHandle, *const CkAttribute, CkUlong) -> CkRv,
    pub c_find_objects:
        unsafe extern "C" fn(CkSessionHandle, *mut CkObjectHandle, CkUlong, *mut CkUlong) -> CkRv,
    pub c_find_objects_final: unsafe extern "C" fn(CkSessionHandle) -> CkRv,
    pub c_encrypt_init:
        unsafe extern "C" fn(CkSessionHandle, *const CkMechanism, CkObjectHandle) -> CkRv,
    pub c_encrypt: unsafe extern "C" fn(
        CkSessionHandle,
        *const CkByte,
        CkUlong,
        *mut CkByte,
        *mut CkUlong,
    ) -> CkRv,
    pub c_encrypt_update: unsafe extern "C" fn(
        CkSessionHandle,
        *const CkByte,
        CkUlong,
        *mut CkByte,
        *mut CkUlong,
    ) -> CkRv,
    pub c_encrypt_final: unsafe extern "C" fn(CkSessionHandle, *mut CkByte, *mut CkUlong) -> CkRv,
    pub c_decrypt_init:
        unsafe extern "C" fn(CkSessionHandle, *const CkMechanism, CkObjectHandle) -> CkRv,
    pub c_decrypt: unsafe extern "C" fn(
        CkSessionHandle,
        *const CkByte,
        CkUlong,
        *mut CkByte,
        *mut CkUlong,
    ) -> CkRv,
    pub c_decrypt_update: unsafe extern "C" fn(
        CkSessionHandle,
        *const CkByte,
        CkUlong,
        *mut CkByte,
        *mut CkUlong,
    ) -> CkRv,
    pub c_decrypt_final: unsafe extern "C" fn(CkSessionHandle, *mut CkByte, *mut CkUlong) -> CkRv,
    pub c_digest_init: unsafe extern "C" fn(CkSessionHandle, *const CkMechanism) -> CkRv,
    pub c_digest: unsafe extern "C" fn(
        CkSessionHandle,
        *const CkByte,
        CkUlong,
        *mut CkByte,
        *mut CkUlong,
    ) -> CkRv,
    pub c_digest_update: unsafe extern "C" fn(CkSessionHandle, *const CkByte, CkUlong) -> CkRv,
    pub c_digest_key: unsafe extern "C" fn(CkSessionHandle, CkObjectHandle) -> CkRv,
    pub c_digest_final: unsafe extern "C" fn(CkSessionHandle, *mut CkByte, *mut CkUlong) -> CkRv,
    pub c_sign_init:
        unsafe extern "C" fn(CkSessionHandle, *const CkMechanism, CkObjectHandle) -> CkRv,
    pub c_sign: unsafe extern "C" fn(
        CkSessionHandle,
        *const CkByte,
        CkUlong,
        *mut CkByte,
        *mut CkUlong,
    ) -> CkRv,
    pub c_sign_update: unsafe extern "C" fn(CkSessionHandle, *const CkByte, CkUlong) -> CkRv,
    pub c_sign_final: unsafe extern "C" fn(CkSessionHandle, *mut CkByte, *mut CkUlong) -> CkRv,
    pub c_sign_recover_init:
        unsafe extern "C" fn(CkSessionHandle, *const CkMechanism, CkObjectHandle) -> CkRv,
    pub c_sign_recover: unsafe extern "C" fn(
        CkSessionHandle,
        *const CkByte,
        CkUlong,
        *mut CkByte,
        *mut CkUlong,
    ) -> CkRv,
    pub c_verify_init:
        unsafe extern "C" fn(CkSessionHandle, *const CkMechanism, CkObjectHandle) -> CkRv,
    pub c_verify: unsafe extern "C" fn(
        CkSessionHandle,
        *const CkByte,
        CkUlong,
        *const CkByte,
        CkUlong,
    ) -> CkRv,
    pub c_verify_update: unsafe extern "C" fn(CkSessionHandle, *const CkByte, CkUlong) -> CkRv,
    pub c_verify_final: unsafe extern "C" fn(CkSessionHandle, *const CkByte, CkUlong) -> CkRv,
    pub c_verify_recover_init:
        unsafe extern "C" fn(CkSessionHandle, *const CkMechanism, CkObjectHandle) -> CkRv,
    pub c_verify_recover: unsafe extern "C" fn(
        CkSessionHandle,
        *const CkByte,
        CkUlong,
        *mut CkByte,
        *mut CkUlong,
    ) -> CkRv,
    pub c_digest_encrypt_update: unsafe extern "C" fn(
        CkSessionHandle,
        *const CkByte,
        CkUlong,
        *mut CkByte,
        *mut CkUlong,
    ) -> CkRv,
    pub c_decrypt_digest_update: unsafe extern "C" fn(
        CkSessionHandle,
        *const CkByte,
        CkUlong,
        *mut CkByte,
        *mut CkUlong,
    ) -> CkRv,
    pub c_sign_encrypt_update: unsafe extern "C" fn(
        CkSessionHandle,
        *const CkByte,
        CkUlong,
        *mut CkByte,
        *mut CkUlong,
    ) -> CkRv,
    pub c_decrypt_verify_update: unsafe extern "C" fn(
        CkSessionHandle,
        *const CkByte,
        CkUlong,
        *mut CkByte,
        *mut CkUlong,
    ) -> CkRv,
    pub c_generate_key: unsafe extern "C" fn(
        CkSessionHandle,
        *const CkMechanism,
        *const CkAttribute,
        CkUlong,
        *mut CkObjectHandle,
    ) -> CkRv,
    pub c_generate_key_pair: unsafe extern "C" fn(
        CkSessionHandle,
        *const CkMechanism,
        *const CkAttribute,
        CkUlong,
        *const CkAttribute,
        CkUlong,
        *mut CkObjectHandle,
        *mut CkObjectHandle,
    ) -> CkRv,
    pub c_wrap_key: unsafe extern "C" fn(
        CkSessionHandle,
        *const CkMechanism,
        CkObjectHandle,
        CkObjectHandle,
        *mut CkByte,
        *mut CkUlong,
    ) -> CkRv,
    pub c_unwrap_key: unsafe extern "C" fn(
        CkSessionHandle,
        *const CkMechanism,
        CkObjectHandle,
        *const CkByte,
        CkUlong,
        *const CkAttribute,
        CkUlong,
        *mut CkObjectHandle,
    ) -> CkRv,
    pub c_derive_key: unsafe extern "C" fn(
        CkSessionHandle,
        *const CkMechanism,
        CkObjectHandle,
        *const CkAttribute,
        CkUlong,
        *mut CkObjectHandle,
    ) -> CkRv,
    pub c_seed_random: unsafe extern "C" fn(CkSessionHandle, *const CkByte, CkUlong) -> CkRv,
    pub c_generate_random: unsafe extern "C" fn(CkSessionHandle, *mut CkByte, CkUlong) -> CkRv,
    pub c_get_function_status: unsafe extern "C" fn(CkSessionHandle) -> CkRv,
    pub c_cancel_function: unsafe extern "C" fn(CkSessionHandle) -> CkRv,
    pub c_wait_for_slot_event: unsafe extern "C" fn(CkFlags, *mut CkSlotId, CkVoidPtr) -> CkRv,
}

static FUNCTION_LIST: CkFunctionList = CkFunctionList {
    version: CkVersion { major: 3, minor: 2 },
    c_initialize: C_Initialize,
    c_finalize: C_Finalize,
    c_get_info: C_GetInfo,
    c_get_function_list: C_GetFunctionList,
    c_get_slot_list: C_GetSlotList,
    c_get_slot_info: C_GetSlotInfo,
    c_get_token_info: C_GetTokenInfo,
    c_get_mechanism_list: C_GetMechanismList,
    c_get_mechanism_info: C_GetMechanismInfo,
    c_init_token: C_InitToken,
    c_init_pin: C_InitPIN,
    c_set_pin: C_SetPIN,
    c_open_session: C_OpenSession,
    c_close_session: C_CloseSession,
    c_close_all_sessions: C_CloseAllSessions,
    c_get_session_info: C_GetSessionInfo,
    c_get_operation_state: C_GetOperationState,
    c_set_operation_state: C_SetOperationState,
    c_login: C_Login,
    c_logout: C_Logout,
    c_create_object: C_CreateObject,
    c_copy_object: C_CopyObject,
    c_destroy_object: C_DestroyObject,
    c_get_object_size: C_GetObjectSize,
    c_get_attribute_value: C_GetAttributeValue,
    c_set_attribute_value: C_SetAttributeValue,
    c_find_objects_init: C_FindObjectsInit,
    c_find_objects: C_FindObjects,
    c_find_objects_final: C_FindObjectsFinal,
    c_encrypt_init: C_EncryptInit,
    c_encrypt: C_Encrypt,
    c_encrypt_update: C_EncryptUpdate,
    c_encrypt_final: C_EncryptFinal,
    c_decrypt_init: C_DecryptInit,
    c_decrypt: C_Decrypt,
    c_decrypt_update: C_DecryptUpdate,
    c_decrypt_final: C_DecryptFinal,
    c_digest_init: C_DigestInit,
    c_digest: C_Digest,
    c_digest_update: C_DigestUpdate,
    c_digest_key: C_DigestKey,
    c_digest_final: C_DigestFinal,
    c_sign_init: C_SignInit,
    c_sign: C_Sign,
    c_sign_update: C_SignUpdate,
    c_sign_final: C_SignFinal,
    c_sign_recover_init: C_SignRecoverInit,
    c_sign_recover: C_SignRecover,
    c_verify_init: C_VerifyInit,
    c_verify: C_Verify,
    c_verify_update: C_VerifyUpdate,
    c_verify_final: C_VerifyFinal,
    c_verify_recover_init: C_VerifyRecoverInit,
    c_verify_recover: C_VerifyRecover,
    c_digest_encrypt_update: C_DigestEncryptUpdate,
    c_decrypt_digest_update: C_DecryptDigestUpdate,
    c_sign_encrypt_update: C_SignEncryptUpdate,
    c_decrypt_verify_update: C_DecryptVerifyUpdate,
    c_generate_key: C_GenerateKey,
    c_generate_key_pair: C_GenerateKeyPair,
    c_wrap_key: C_WrapKey,
    c_unwrap_key: C_UnwrapKey,
    c_derive_key: C_DeriveKey,
    c_seed_random: C_SeedRandom,
    c_generate_random: C_GenerateRandom,
    c_get_function_status: C_GetFunctionStatus,
    c_cancel_function: C_CancelFunction,
    c_wait_for_slot_event: C_WaitForSlotEvent,
};

/// PKCS#11 entry point — returns the function list
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetFunctionList(pp_function_list: *mut *const CkFunctionList) -> CkRv {
    if pp_function_list.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe { *pp_function_list = &FUNCTION_LIST };
    CKR_OK
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use serial_test::serial;

    use super::*;

    fn init_and_login() {
        unsafe {
            C_Initialize(std::ptr::null_mut());
            let mut session: CkSessionHandle = 0;
            C_OpenSession(
                0,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                std::ptr::null_mut(),
                None,
                &mut session,
            );
            C_Login(session, 1, b"1234".as_ptr(), 4);
        }
    }

    fn cleanup() {
        unsafe { C_Finalize(std::ptr::null_mut()) };
    }

    #[test]
    #[serial]
    fn test_initialize_finalize() {
        unsafe {
            assert_eq!(C_Initialize(std::ptr::null_mut()), CKR_OK);
            assert_eq!(
                C_Initialize(std::ptr::null_mut()),
                CKR_CRYPTOKI_ALREADY_INITIALIZED
            );
            assert_eq!(C_Finalize(std::ptr::null_mut()), CKR_OK);
        }
    }

    #[test]
    #[serial]
    fn test_get_function_list() {
        unsafe {
            let mut fl: *const CkFunctionList = std::ptr::null();
            assert_eq!(C_GetFunctionList(&mut fl), CKR_OK);
            assert!(!fl.is_null());
        }
    }

    #[test]
    #[serial]
    fn test_get_slot_list() {
        init_and_login();
        unsafe {
            let mut count: CkUlong = 0;
            assert_eq!(C_GetSlotList(0, std::ptr::null_mut(), &mut count), CKR_OK);
            assert_eq!(count, 1);

            let mut slot: CkSlotId = 99;
            count = 1;
            assert_eq!(C_GetSlotList(0, &mut slot, &mut count), CKR_OK);
            assert_eq!(slot, 0);
        }
        cleanup();
    }

    #[test]
    #[serial]
    fn test_generate_keypair_and_sign() {
        init_and_login();
        unsafe {
            let mechanism = CkMechanism {
                mechanism: CKM_ML_DSA_KEY_PAIR_GEN,
                p_parameter: std::ptr::null(),
                ul_parameter_len: 0,
            };

            let label = b"test-key";
            let label_attr = CkAttribute {
                r#type: CKA_LABEL,
                p_value: label.as_ptr() as *mut u8,
                ul_value_len: label.len() as CkUlong,
            };

            let mut pub_handle: CkObjectHandle = 0;
            let mut priv_handle: CkObjectHandle = 0;
            assert_eq!(
                C_GenerateKeyPair(
                    SESSION_HANDLE,
                    &mechanism,
                    &label_attr,
                    1,
                    std::ptr::null(),
                    0,
                    &mut pub_handle,
                    &mut priv_handle,
                ),
                CKR_OK
            );
            assert_ne!(pub_handle, 0);
            assert_ne!(priv_handle, 0);

            // Get public key value
            let mut value_buf = vec![0u8; 2048];
            let mut attr = CkAttribute {
                r#type: CKA_VALUE,
                p_value: value_buf.as_mut_ptr(),
                ul_value_len: value_buf.len() as CkUlong,
            };
            assert_eq!(
                C_GetAttributeValue(SESSION_HANDLE, pub_handle, &mut attr, 1),
                CKR_OK
            );
            assert_eq!(attr.ul_value_len, 1952); // ML-DSA-65 public key

            // Sign
            let sign_mechanism = CkMechanism {
                mechanism: CKM_ML_DSA,
                p_parameter: std::ptr::null(),
                ul_parameter_len: 0,
            };
            assert_eq!(
                C_SignInit(SESSION_HANDLE, &sign_mechanism, priv_handle),
                CKR_OK
            );

            let data = b"test message";
            let mut sig_buf = vec![0u8; 4096];
            let mut sig_len: CkUlong = sig_buf.len() as CkUlong;
            assert_eq!(
                C_Sign(
                    SESSION_HANDLE,
                    data.as_ptr(),
                    data.len() as CkUlong,
                    sig_buf.as_mut_ptr(),
                    &mut sig_len,
                ),
                CKR_OK
            );
            assert_eq!(sig_len, 3309); // ML-DSA-65 signature
        }
        cleanup();
    }

    #[test]
    #[serial]
    fn test_find_objects() {
        init_and_login();
        unsafe {
            let mechanism = CkMechanism {
                mechanism: CKM_ML_DSA_KEY_PAIR_GEN,
                p_parameter: std::ptr::null(),
                ul_parameter_len: 0,
            };

            let label = b"find-me";
            let label_attr = CkAttribute {
                r#type: CKA_LABEL,
                p_value: label.as_ptr() as *mut u8,
                ul_value_len: label.len() as CkUlong,
            };

            let mut pub_handle: CkObjectHandle = 0;
            let mut priv_handle: CkObjectHandle = 0;
            C_GenerateKeyPair(
                SESSION_HANDLE,
                &mechanism,
                &label_attr,
                1,
                std::ptr::null(),
                0,
                &mut pub_handle,
                &mut priv_handle,
            );

            // Find private key by label
            let mut class_val: CkObjectClass = CKO_PRIVATE_KEY;
            let search_template = [
                CkAttribute {
                    r#type: CKA_CLASS,
                    p_value: &mut class_val as *mut _ as *mut u8,
                    ul_value_len: std::mem::size_of::<CkObjectClass>() as CkUlong,
                },
                CkAttribute {
                    r#type: CKA_LABEL,
                    p_value: label.as_ptr() as *mut u8,
                    ul_value_len: label.len() as CkUlong,
                },
            ];

            assert_eq!(
                C_FindObjectsInit(SESSION_HANDLE, search_template.as_ptr(), 2),
                CKR_OK
            );

            let mut found: CkObjectHandle = 0;
            let mut found_count: CkUlong = 0;
            assert_eq!(
                C_FindObjects(SESSION_HANDLE, &mut found, 1, &mut found_count),
                CKR_OK
            );
            assert_eq!(found_count, 1);
            assert_eq!(found, priv_handle);

            assert_eq!(C_FindObjectsFinal(SESSION_HANDLE), CKR_OK);
        }
        cleanup();
    }
}
