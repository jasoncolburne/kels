//! Registry KEL HTTP handlers
//!
//! Provides endpoints for clients to fetch the registry's KEL
//! for verification purposes.

use axum::{Json, extract::State};
use kels::Kel;
use std::sync::Arc;

use crate::handlers::ApiError;
use crate::identity_client::IdentityClient;

/// Shared state for registry KEL handlers
pub struct RegistryKelState {
    pub identity_client: Arc<IdentityClient>,
    pub prefix: String,
}

/// Get the registry's full KEL
///
/// This is a public endpoint - no authentication required.
/// Clients use this to verify peer records are anchored in the registry's KEL.
/// Fetches from the identity service which is the authoritative source.
pub async fn get_registry_kel(
    State(state): State<Arc<RegistryKelState>>,
) -> Result<Json<Kel>, ApiError> {
    let kel = state
        .identity_client
        .get_kel()
        .await
        .map_err(|e| ApiError::internal_error(format!("Failed to fetch KEL: {}", e)))?;

    Ok(Json(kel))
}
