//! Identity Service HTTP Server

use axum::{
    Router,
    routing::{get, post},
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::handlers::{self, AppState};
use crate::hsm::HsmClient;
use crate::repository::{
    AUTHORITY_IDENTITY_NAME, AuthorityMapping, HsmKeyBinding, IdentityRepository,
};
use kels::{KelStore, RepositoryKelStore};
use verifiable_storage::{RepositoryConnection, VersionedRepository};

/// Create and configure the Axum router
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Health
        .route("/health", get(handlers::health))
        // Identity operations
        .route("/api/identity", get(handlers::get_identity))
        .route("/api/identity/kel", get(handlers::get_kel))
        .route("/api/identity/anchor", post(handlers::anchor))
        .with_state(state)
}

/// Run the HTTP server
pub async fn run(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    use crate::hsm::HsmKeyProvider;
    use kels::{KeyEventBuilder, KeyProvider};

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@database:5432/identity".to_string());
    let hsm_url = std::env::var("HSM_URL").unwrap_or_else(|_| "http://hsm:80".to_string());

    // Allows multiple identity services to share one HSM
    let key_handle_prefix =
        std::env::var("KEY_HANDLE_PREFIX").unwrap_or_else(|_| "kels-registry".to_string());

    tracing::info!("Connecting to database");
    let repo = IdentityRepository::connect(&database_url)
        .await
        .map_err(|e| format!("Failed to connect to database: {}", e))?;

    tracing::info!("Running migrations");
    repo.initialize()
        .await
        .map_err(|e| format!("Failed to run migrations: {}", e))?;
    tracing::info!("Database connected");

    tracing::info!("Connecting to HSM service at {}", hsm_url);
    let hsm = Arc::new(HsmClient::new(&hsm_url));

    let kel_repo = Arc::new(crate::repository::KeyEventRepository::new(
        repo.pool().clone(),
    ));
    let kel_store: Arc<dyn KelStore> = Arc::new(RepositoryKelStore::new(kel_repo.clone()));

    // Try to restore identity from authority marker + HSM binding, or auto-incept
    let builder = if let Some(mapping) = repo.authority.get_by_name(AUTHORITY_IDENTITY_NAME).await?
    {
        let prefix = mapping.kel_prefix.clone();
        tracing::info!("Found registry prefix: {}", prefix);

        let binding = repo
            .hsm_bindings
            .get_latest_by_kel_prefix(&prefix)
            .await?
            .ok_or_else(|| format!("HSM binding not found for KEL prefix: {}", prefix))?;

        tracing::info!(
            "Restored HSM binding: current={}, next={}",
            binding.current_key_handle,
            binding.next_key_handle
        );

        let provider = HsmKeyProvider::with_handles(
            hsm.clone(),
            &key_handle_prefix,
            binding.version + 2, // next generation
            binding.current_key_handle.into(),
            binding.next_key_handle.into(),
        );
        let key_provider = KeyProvider::external(Box::new(provider));

        // Create builder with store and prefix - auto-loads KEL
        // No KelsClient - identity service is authoritative for its own KEL
        KeyEventBuilder::with_dependencies(
            key_provider,
            None, // No KelsClient - we ARE the authority
            Some(kel_store.clone()),
            Some(&prefix),
        )
        .await
        .map_err(|e| format!("Failed to create builder: {}", e))?
    } else {
        tracing::info!("No existing identity - auto-incepting");

        // Create HSM key provider for inception (will generate keys 0 and 1)
        let provider = HsmKeyProvider::new(hsm.clone(), &key_handle_prefix, 0);
        let key_provider = KeyProvider::external(Box::new(provider));

        // Create builder with store, no prefix - ready for incept
        let mut builder = KeyEventBuilder::with_dependencies(
            key_provider,
            None, // No KelsClient - we ARE the authority
            Some(kel_store.clone()),
            None,
        )
        .await
        .map_err(|e| format!("Failed to create builder: {}", e))?;

        // Incept - generates keys, creates event, signs, saves locally
        let (event, _signature) = builder
            .incept()
            .await
            .map_err(|e| format!("Failed to incept: {}", e))?;

        tracing::info!("Generated registry prefix: {}", event.prefix);

        // Get key handles from the provider for HSM binding persistence
        let current_handle = builder
            .key_provider()
            .current_handle()
            .await
            .ok_or("No current handle after incept")?;
        let next_handle = builder
            .key_provider()
            .next_handle()
            .await
            .ok_or("No next handle after incept")?;

        let binding = HsmKeyBinding::new(
            event.prefix.clone(),
            current_handle.clone(),
            next_handle.clone(),
        );
        repo.hsm_bindings
            .create(binding)
            .await
            .map_err(|e| format!("Failed to create HSM binding: {}", e))?;

        repo.authority
            .create(AuthorityMapping::new(
                AUTHORITY_IDENTITY_NAME.to_string(),
                event.prefix.clone(),
                event.said.clone(),
            ))
            .await
            .map_err(|e| format!("Failed to set authority prefix: {}", e))?;

        builder
    };

    let state = Arc::new(AppState {
        repo: Arc::new(repo),
        builder: RwLock::new(builder),
        kel_repo,
    });

    let app = create_router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("Identity service listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;

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
            Ok(()) => tracing::info!("Received Ctrl+C signal"),
            Err(e) => tracing::error!("Failed to listen for Ctrl+C: {}", e),
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
                tracing::info!("Received SIGTERM signal");
            }
            Err(e) => {
                tracing::error!("Failed to install SIGTERM handler: {}", e);
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

    tracing::info!("Starting graceful shutdown...");
}
