//! Registry KEL HTTP handlers

use axum::{Json, extract::State};
use kels::Kel;
use std::sync::Arc;

use crate::handlers::ApiError;
use crate::identity_client::IdentityClient;

pub struct RegistryKelState {
    pub identity_client: Arc<IdentityClient>,
    pub prefix: String,
}

/// Public endpoint for clients to verify peer records are anchored in the registry's KEL.
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
