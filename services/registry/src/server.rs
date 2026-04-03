//! KELS Registry HTTP Server

use std::{net::SocketAddr, sync::Arc};
use tracing::{error, info, warn};

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};
use kels_core::{IdentityClient, shutdown_signal};
use verifiable_storage::RepositoryConnection;

use crate::{
    federation::{FederationConfig, FederationNode},
    handlers::{self, FederationState},
    repository::RegistryRepository,
};

pub fn create_router(federation_state: Option<Arc<FederationState>>) -> Router {
    // Base router with health endpoint
    let base_router = Router::new().route("/health", get(handlers::health));

    // Federation mode routes (node management + peer management + admin)
    let federation_router = if let Some(fed_state) = federation_state {
        // Peer discovery and member KEL endpoints
        let discovery_router = Router::new()
            .route("/api/v1/peers", get(handlers::list_peers_federated))
            .route(
                "/api/v1/member-kels/events",
                post(handlers::submit_member_key_events),
            )
            .route(
                "/api/v1/member-kels/kel/:prefix",
                get(handlers::get_member_key_events),
            )
            .route(
                "/api/v1/member-kels/kel/:prefix/effective-said",
                get(handlers::get_member_effective_said),
            );

        // Federation protocol
        let federation_router = Router::new()
            .route("/api/v1/federation/rpc", post(handlers::federation_rpc))
            .route(
                "/api/v1/federation/status",
                get(handlers::federation_status),
            )
            .route(
                "/api/v1/federation/proposals",
                get(handlers::list_completed_proposals),
            )
            .route(
                "/api/v1/federation/proposals/:proposal_id",
                get(handlers::get_proposal),
            );

        // Admin API for proposal and peer management (requests must be anchored to be valid)
        let admin_router = Router::new()
            .route(
                "/api/v1/admin/addition-proposals",
                post(handlers::admin_submit_addition_proposal),
            )
            .route(
                "/api/v1/admin/removal-proposals",
                post(handlers::admin_submit_removal_proposal),
            )
            .route(
                "/api/v1/admin/proposals/:proposal_id/vote",
                post(handlers::admin_vote_proposal),
            );

        discovery_router
            .merge(federation_router)
            .merge(admin_router)
            .with_state(fed_state)
    } else {
        // Standalone mode: health only
        Router::new()
    };

    // Merge all routers
    base_router
        .merge(federation_router)
        .layer(DefaultBodyLimit::max(5 * 1024 * 1024)) // 5 MiB
}

pub async fn run(listener: tokio::net::TcpListener) -> Result<(), Box<dyn std::error::Error>> {
    let postgres_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@postgres:5432/kels".to_string());

    info!("Connecting to PostgreSQL");
    let repo = RegistryRepository::connect(&postgres_url)
        .await
        .map_err(|e| format!("Failed to connect to PostgreSQL: {}", e))?;

    info!("Running migrations");
    repo.initialize()
        .await
        .map_err(|e| format!("Failed to run migrations: {}", e))?;
    info!("Database initialized");

    // Connect to identity service to get the registry's prefix
    let identity_url =
        std::env::var("IDENTITY_URL").unwrap_or_else(|_| "http://identity:80".to_string());
    info!("Connecting to identity service at {}", identity_url);
    let identity_client = Arc::new(IdentityClient::new(&identity_url)?);

    // Fetch the registry prefix from the identity service
    let prefix = identity_client
        .get_prefix()
        .await
        .map_err(|e| format!("Failed to get registry prefix from identity service: {}", e))?;
    info!("Registry prefix from identity service: {}", prefix);

    // Initialize federation if configured
    let federation_state = match FederationConfig::from_env() {
        Ok(Some(config)) => {
            info!(
                "Federation configured with {} members",
                config.members.len()
            );
            // Sync all member KELs before Raft initialization.
            // Raft log replay re-verifies vote anchoring, which requires
            // member KELs to be present in the local DB.
            crate::federation::sync::sync_all_member_kels(&config, &repo.member_kels).await;

            match FederationNode::new(config.clone(), identity_client.clone(), &repo).await {
                Ok(node) => {
                    info!("Federation node initialized");
                    let node = Arc::new(node);

                    // Auto-initialize if this is node 0 (first member)
                    // This bootstraps the Raft cluster for leader election
                    if config.self_node_id().unwrap_or(u64::MAX) == 0 {
                        let init_node = node.clone();
                        tokio::spawn(async move {
                            // Wait for other members to start
                            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                            info!("Initializing federation cluster (this is node 0)...");
                            if let Err(e) = init_node.initialize().await {
                                warn!(
                                    "Federation initialization: {} (may already be initialized)",
                                    e
                                );
                            } else {
                                info!("Federation cluster initialized successfully");
                            }
                        });
                    }

                    // Membership sync loop — periodically checks if this node is the
                    // leader and if membership needs updating. Handles leadership changes
                    // and new members joining after initial startup.
                    {
                        let sync_node = node.clone();
                        tokio::spawn(async move {
                            let mut ticker =
                                tokio::time::interval(tokio::time::Duration::from_secs(10));
                            loop {
                                ticker.tick().await;

                                if !sync_node.is_leader().await {
                                    continue;
                                }

                                if let Err(e) = sync_node.sync_membership().await {
                                    warn!("Federation membership sync: {}", e);
                                }
                            }
                        });
                    }

                    // Spawn member KEL sync loop (runs on every node)
                    {
                        let sync_node = node.clone();
                        let sync_identity = identity_client.clone();
                        let sync_member_kel_repo = repo.member_kels.clone();
                        tokio::spawn(async move {
                            crate::federation::sync::run_member_kel_sync_loop(
                                sync_node,
                                sync_identity,
                                sync_member_kel_repo,
                                std::time::Duration::from_secs(30),
                            )
                            .await;
                        });
                    }

                    let fed_state = Arc::new(FederationState {
                        node,
                        identity_client: identity_client.clone(),
                        member_kel_repo: repo.member_kels.clone(),
                        member_kel_ip_rate_limits: dashmap::DashMap::new(),
                        member_kel_prefix_rate_limits: dashmap::DashMap::new(),
                    });
                    handlers::spawn_rate_limit_reaper(Arc::clone(&fed_state));
                    Some(fed_state)
                }
                Err(e) => {
                    error!("Failed to initialize federation node: {}", e);
                    return Err(format!("Federation initialization failed: {}", e).into());
                }
            }
        }
        Ok(None) => {
            info!("Federation not configured, running in standalone mode");
            None
        }
        Err(e) => {
            error!("Invalid federation configuration: {}", e);
            return Err(format!("Invalid federation configuration: {}", e).into());
        }
    };

    let app = create_router(federation_state).into_make_service_with_connect_info::<SocketAddr>();

    info!(
        "KELS Registry service listening on {}",
        listener
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}
