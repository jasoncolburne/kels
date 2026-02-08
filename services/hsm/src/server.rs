//! HSM Service HTTP Server

use std::{net::SocketAddr, sync::Arc};
use tracing::{error, info};

use axum::{
    Router,
    routing::{get, post},
};

use crate::{handlers, pkcs11::HsmContext};

/// Create and configure the Axum router
pub fn create_router(hsm: Arc<HsmContext>) -> Router {
    Router::new()
        // Health
        .route("/health", get(handlers::health))
        // Key operations
        .route("/api/hsm/keys", post(handlers::generate_key))
        .route("/api/hsm/keys", get(handlers::list_keys))
        .route("/api/hsm/keys/:label/public", get(handlers::get_public_key))
        .route("/api/hsm/keys/:label/sign", post(handlers::sign))
        .with_state(hsm)
}

/// Run the HTTP server
pub async fn run(listener: tokio::net::TcpListener) -> Result<(), Box<dyn std::error::Error>> {
    // Get SoftHSM2 configuration from environment
    let library_path = std::env::var("SOFTHSM2_LIBRARY")
        .unwrap_or_else(|_| "/usr/lib/softhsm/libsofthsm2.so".to_string());
    let slot_index: usize = std::env::var("HSM_SLOT")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .map_err(|e| format!("HSM_SLOT must be a valid number: {}", e))?;
    let pin = std::env::var("HSM_PIN").unwrap_or_else(|_| "1234".to_string());

    // Initialize HSM context
    info!("Initializing SoftHSM2 from {}", library_path);
    let hsm = HsmContext::new(&library_path, slot_index, &pin)
        .map_err(|e| format!("Failed to initialize HSM: {}", e))?;
    info!("SoftHSM2 initialized successfully");

    let hsm = Arc::new(hsm);

    // Create router
    let app = create_router(hsm);

    info!(
        "HSM service listening on {}",
        listener
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/// Wait for SIGTERM or SIGINT signal
async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        match signal::ctrl_c().await {
            Ok(()) => info!("Received Ctrl+C signal"),
            Err(e) => error!("Failed to listen for Ctrl+C: {}", e),
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
                info!("Received SIGTERM signal");
            }
            Err(e) => {
                error!("Failed to install SIGTERM handler: {}", e);
                // Wait forever since we can't receive SIGTERM
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Starting graceful shutdown...");
}
