//! HSM Service REST API Handlers

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::Engine;
use cesr::{KeyCode, Matter, PublicKey, Signature, SignatureCode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::pkcs11::{HsmContext, HsmError};

/// Compress an uncompressed secp256r1 public key (65 bytes) to compressed format (33 bytes).
/// The PKCS#11 EC_POINT attribute may include a DER OCTET STRING wrapper.
fn compress_public_key(ec_point: &[u8]) -> Result<Vec<u8>, String> {
    // PKCS#11 EC_POINT is typically wrapped in DER OCTET STRING: 04 <len> <point>
    // Strip the wrapper if present
    let point = if ec_point.len() == 67 && ec_point[0] == 0x04 && ec_point[1] == 0x41 {
        // DER wrapper: OCTET STRING of 65 bytes
        &ec_point[2..]
    } else if ec_point.len() == 65 && ec_point[0] == 0x04 {
        // Raw uncompressed point
        ec_point
    } else {
        return Err(format!(
            "Unexpected EC point format: {} bytes, first byte 0x{:02x}",
            ec_point.len(),
            ec_point.first().copied().unwrap_or(0)
        ));
    };

    // point[0] = 0x04 (uncompressed marker)
    // point[1..33] = X coordinate
    // point[33..65] = Y coordinate
    if point.len() != 65 || point[0] != 0x04 {
        return Err(format!("Invalid uncompressed point: {} bytes", point.len()));
    }

    let x = &point[1..33];
    let y = &point[33..65];

    // Compressed format: 0x02 if Y is even, 0x03 if Y is odd, followed by X
    let prefix = if y[31] & 1 == 0 { 0x02 } else { 0x03 };

    let mut compressed = Vec::with_capacity(33);
    compressed.push(prefix);
    compressed.extend_from_slice(x);

    Ok(compressed)
}

/// Convert raw PKCS#11 public key bytes to CESR qb64 format.
/// Handles compression and CESR encoding in one step.
fn bytes_to_cesr_public_key(ec_point: &[u8]) -> Result<PublicKey, ApiError> {
    let compressed = compress_public_key(ec_point)
        .map_err(|e| ApiError::internal(format!("Failed to compress public key: {}", e)))?;
    PublicKey::from_raw(KeyCode::Secp256r1, compressed)
        .map_err(|e| ApiError::internal(format!("Failed to create CESR public key: {}", e)))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateKeyRequest {
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateKeyResponse {
    pub label: String,
    pub public_key: String,
    pub created: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyResponse {
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignRequest {
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignResponse {
    pub signature: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListKeysResponse {
    pub keys: Vec<String>,
}

pub struct ApiError(pub StatusCode, pub Json<ErrorResponse>);

impl ApiError {
    pub fn not_found(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::NOT_FOUND,
            Json(ErrorResponse { error: msg.into() }),
        )
    }

    pub fn bad_request(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: msg.into() }),
        )
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: msg.into() }),
        )
    }
}

impl From<HsmError> for ApiError {
    fn from(e: HsmError) -> Self {
        match &e {
            HsmError::KeyNotFound(_) => ApiError::not_found(e.to_string()),
            _ => ApiError::internal(e.to_string()),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, self.1).into_response()
    }
}

pub async fn health() -> StatusCode {
    StatusCode::OK
}

/// Maximum allowed length for key labels
const MAX_LABEL_LENGTH: usize = 128;

/// Validate a key label for safety and compatibility
fn validate_label(label: &str) -> Result<(), ApiError> {
    if label.is_empty() {
        return Err(ApiError::bad_request("Label cannot be empty"));
    }

    if label.len() > MAX_LABEL_LENGTH {
        return Err(ApiError::bad_request(format!(
            "Label too long: {} chars (max {})",
            label.len(),
            MAX_LABEL_LENGTH
        )));
    }

    // Allow alphanumeric, hyphens, underscores, and dots
    if !label
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(ApiError::bad_request(
            "Label contains invalid characters (only alphanumeric, hyphen, underscore, dot allowed)",
        ));
    }

    Ok(())
}

pub async fn generate_key(
    State(hsm): State<Arc<HsmContext>>,
    Json(request): Json<GenerateKeyRequest>,
) -> Result<Json<GenerateKeyResponse>, ApiError> {
    validate_label(&request.label)?;

    // Check if key already exists - if so, return it (get-or-create semantic)
    let (public_key_bytes, created) = if hsm.key_exists(&request.label) {
        (hsm.get_public_key(&request.label)?, false)
    } else {
        (hsm.generate_keypair(&request.label)?, true)
    };

    let public_key = bytes_to_cesr_public_key(&public_key_bytes)?;

    Ok(Json(GenerateKeyResponse {
        label: request.label,
        public_key: public_key.qb64(),
        created,
    }))
}

pub async fn get_public_key(
    State(hsm): State<Arc<HsmContext>>,
    Path(label): Path<String>,
) -> Result<Json<PublicKeyResponse>, ApiError> {
    validate_label(&label)?;
    let public_key_bytes = hsm.get_public_key(&label)?;
    let public_key = bytes_to_cesr_public_key(&public_key_bytes)?;

    Ok(Json(PublicKeyResponse {
        public_key: public_key.qb64(),
    }))
}

pub async fn sign(
    State(hsm): State<Arc<HsmContext>>,
    Path(label): Path<String>,
    Json(request): Json<SignRequest>,
) -> Result<Json<SignResponse>, ApiError> {
    validate_label(&label)?;
    let data = base64::engine::general_purpose::URL_SAFE
        .decode(&request.data)
        .map_err(|e| ApiError::bad_request(format!("Invalid base64 data: {}", e)))?;

    let signature_bytes = hsm.sign(&label, &data)?;

    // Convert signature to CESR qb64 format
    let signature = Signature::from_raw(SignatureCode::Secp256r1, signature_bytes)
        .map_err(|e| ApiError::internal(format!("Failed to create CESR signature: {}", e)))?;

    // Get public key and convert to CESR qb64 format
    let public_key_bytes = hsm.get_public_key(&label)?;
    let public_key = bytes_to_cesr_public_key(&public_key_bytes)?;

    Ok(Json(SignResponse {
        signature: signature.qb64(),
        public_key: public_key.qb64(),
    }))
}

pub async fn list_keys(
    State(hsm): State<Arc<HsmContext>>,
) -> Result<Json<ListKeysResponse>, ApiError> {
    let keys = hsm.list_keys()?;
    Ok(Json(ListKeysResponse { keys }))
}
