//! Identity Service HTTP Server

use std::{net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;
use tracing::info;

use axum::{
    Router,
    routing::{get, post},
};
use kels::{KelStore, RepositoryKelStore, shutdown_signal};
use verifiable_storage::{ChainedRepository, RepositoryConnection};

use crate::{
    handlers::{self, AppState},
    hsm::HsmClient,
    repository::{AUTHORITY_IDENTITY_NAME, AuthorityMapping, HsmKeyBinding, IdentityRepository},
};

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(handlers::health))
        .route("/api/identity", get(handlers::get_identity))
        .route("/api/identity/kel", get(handlers::get_kel))
        .route("/api/identity/anchor", post(handlers::anchor))
        .route("/api/identity/sign", post(handlers::sign))
        .with_state(state)
}

pub async fn run(listener: tokio::net::TcpListener) -> Result<(), Box<dyn std::error::Error>> {
    use crate::hsm::HsmKeyProvider;
    use kels::{KeyEventBuilder, KeyProvider};

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@database:5432/identity".to_string());
    let hsm_url = std::env::var("HSM_URL").unwrap_or_else(|_| "http://hsm:80".to_string());
    let key_handle_prefix =
        std::env::var("KEY_HANDLE_PREFIX").unwrap_or_else(|_| "kels-registry".to_string());

    info!("Connecting to database");
    let repo = IdentityRepository::connect(&database_url)
        .await
        .map_err(|e| format!("Failed to connect to database: {}", e))?;

    info!("Running migrations");
    repo.initialize()
        .await
        .map_err(|e| format!("Failed to run migrations: {}", e))?;
    info!("Database connected");

    info!("Connecting to HSM service at {}", hsm_url);
    let hsm = Arc::new(HsmClient::new(&hsm_url));

    let kel_repo = Arc::new(crate::repository::KeyEventRepository::new(
        repo.pool().clone(),
    ));
    let kel_store: Arc<dyn KelStore> = Arc::new(RepositoryKelStore::new(kel_repo.clone()));

    let builder = if let Some(mapping) = repo.authority.get_by_name(AUTHORITY_IDENTITY_NAME).await?
    {
        let prefix = mapping.kel_prefix.clone();
        info!("Found registry prefix: {}", prefix);

        let binding = repo
            .hsm_bindings
            .get_latest_by_kel_prefix(&prefix)
            .await?
            .ok_or_else(|| format!("HSM binding not found for KEL prefix: {}", prefix))?;

        info!(
            "Restored HSM binding: current={}, next={}, recovery={}, signing_gen={}, recovery_gen={}",
            binding.current_key_handle,
            binding.next_key_handle,
            binding.recovery_key_handle,
            binding.signing_generation,
            binding.recovery_generation
        );

        let key_provider = HsmKeyProvider::with_handles(
            hsm.clone(),
            &key_handle_prefix,
            binding.signing_generation,
            binding.recovery_generation,
            binding.current_key_handle.into(),
            binding.next_key_handle.into(),
            binding.recovery_key_handle.into(),
        );

        KeyEventBuilder::with_dependencies(
            key_provider,
            None,
            Some(kel_store.clone()),
            Some(&prefix),
        )
        .await
        .map_err(|e| format!("Failed to create builder: {}", e))?
    } else {
        info!("No existing identity - auto-incepting");

        let key_provider = HsmKeyProvider::new(hsm.clone(), &key_handle_prefix, 0, 0);

        let mut builder =
            KeyEventBuilder::with_dependencies(key_provider, None, Some(kel_store.clone()), None)
                .await
                .map_err(|e| format!("Failed to create builder: {}", e))?;

        let icp = builder
            .incept()
            .await
            .map_err(|e| format!("Failed to incept: {}", e))?;

        info!("Generated registry prefix: {}", icp.event.prefix);

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
        let recovery_handle = builder
            .key_provider()
            .recovery_handle()
            .await
            .ok_or("No recovery handle after incept")?;

        // Get generation counters from the provider (2 signing keys and 1 recovery key were created)
        let signing_gen = builder.key_provider().signing_generation().await;
        let recovery_gen = builder.key_provider().recovery_generation().await;
        let binding = HsmKeyBinding::new(
            icp.event.prefix.clone(),
            current_handle.clone(),
            next_handle.clone(),
            recovery_handle.clone(),
            signing_gen,
            recovery_gen,
        );
        repo.hsm_bindings
            .create(binding)
            .await
            .map_err(|e| format!("Failed to create HSM binding: {}", e))?;

        repo.authority
            .create(AuthorityMapping::new(
                AUTHORITY_IDENTITY_NAME.to_string(),
                icp.event.prefix.clone(),
                icp.event.said.clone(),
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

    info!(
        "Identity service listening on {}",
        listener
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}
