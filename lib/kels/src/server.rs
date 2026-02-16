//! Server utilities for KELS services

use tracing::{error, info};

/// Wait for shutdown signal (SIGTERM or Ctrl+C).
///
/// Returns when either signal is received. Use with axum's `with_graceful_shutdown`.
pub async fn shutdown_signal() {
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
