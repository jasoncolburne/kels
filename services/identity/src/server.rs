//! Identity Service HTTP Server

use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::RwLock;
use tracing::{info, warn};

use axum::{
    Router,
    routing::{get, post},
};
use kels::{KelStore, RepositoryKelStore, shutdown_signal};
use verifiable_storage::{
    Chained, ChainedRepository, RepositoryConnection, SelfAddressed, StorageDatetime,
};

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
        .route("/api/identity/ecdh", post(handlers::ecdh))
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
        let binding = HsmKeyBinding::create(
            icp.event.prefix.clone(),
            current_handle.clone(),
            next_handle.clone(),
            recovery_handle.clone(),
            signing_gen,
            recovery_gen,
        )
        .map_err(|e| format!("Failed to create HSM binding: {}", e))?;
        repo.hsm_bindings
            .insert(binding.clone())
            .await
            .map_err(|e| format!("Failed to store HSM binding: {}", e))?;

        // Anchor the binding SAID in the KEL so it can't be faked by DB-only attacker
        builder
            .interact(&binding.said)
            .await
            .map_err(|e| format!("Failed to anchor HSM binding: {}", e))?;

        let authority = AuthorityMapping::create(
            AUTHORITY_IDENTITY_NAME.to_string(),
            icp.event.prefix.clone(),
            icp.event.said.clone(),
        )
        .map_err(|e| format!("Failed to create authority mapping: {}", e))?;
        repo.authority
            .insert(authority)
            .await
            .map_err(|e| format!("Failed to store authority prefix: {}", e))?;

        builder
    };

    let state = Arc::new(AppState {
        repo: Arc::new(repo),
        builder: RwLock::new(builder),
        kel_repo,
    });

    let rotation_state = state.clone();
    tokio::spawn(async move {
        auto_rotation_loop(rotation_state).await;
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

const ROTATION_INTERVAL: Duration = Duration::from_secs(30 * 24 * 3600); // 30 days
const LOOP_PERIOD: Duration = Duration::from_secs(6 * 3600); // 6 hours

async fn auto_rotation_loop(state: Arc<AppState>) {
    // Stabilize on startup
    tokio::time::sleep(Duration::from_secs(10)).await;

    let mut interval = tokio::time::interval(LOOP_PERIOD);

    loop {
        interval.tick().await; // first tick is immediate, then every LOOP_PERIOD

        match check_and_rotate(&state).await {
            Ok(rotated) => {
                if rotated {
                    info!("Auto-rotation completed successfully");
                }
            }
            Err(e) => {
                warn!("Auto-rotation check failed: {}", e);
            }
        }
    }
}

async fn check_and_rotate(
    state: &Arc<AppState>,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let mapping = state
        .repo
        .authority
        .get_by_name(AUTHORITY_IDENTITY_NAME)
        .await?
        .ok_or("Identity not initialized")?;

    let prefix = &mapping.kel_prefix;

    let bindings = state
        .repo
        .hsm_bindings
        .get_all_by_kel_prefix(prefix)
        .await?;

    if bindings.is_empty() {
        return Err("No HSM bindings found".into());
    }

    let kel = state.kel_repo.get_kel(prefix).await?;

    // Verify KEL integrity
    kel.verify()?;

    // Verify binding chain integrity
    let should_rotate = match verify_binding_chain(&bindings, &kel) {
        Ok(needs_rotation) => needs_rotation,
        Err(e) => {
            warn!(
                "Binding chain verification failed ({}), rotating immediately",
                e
            );
            true
        }
    };

    if should_rotate {
        info!("Triggering scheduled rotation");
        let output = tokio::process::Command::new("/app/identity-admin")
            .args(["--json", "scheduled-rotate"])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("scheduled-rotate failed: {}", stderr).into());
        }

        // Reload the builder so the server picks up the new keys
        let mut builder = state.builder.write().await;
        builder
            .reload()
            .await
            .map_err(|e| format!("Failed to reload builder after rotation: {}", e))?;

        return Ok(true);
    }

    Ok(false)
}

fn verify_binding_chain(
    bindings: &[HsmKeyBinding],
    kel: &kels::Kel,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let max_gap = ROTATION_INTERVAL + LOOP_PERIOD;

    // Verify each binding's SAID
    for binding in bindings {
        binding.verify_said()?;
    }

    // Verify chain links: first has no previous, rest link correctly
    if bindings[0].get_previous().is_some() {
        return Err("First binding has unexpected previous pointer".into());
    }

    for i in 1..bindings.len() {
        let expected_prev = Some(bindings[i - 1].get_said());
        if bindings[i].get_previous() != expected_prev {
            return Err(
                format!("Binding {} has wrong previous pointer", bindings[i].version).into(),
            );
        }
    }

    // Verify versions increment by 1
    for i in 1..bindings.len() {
        if bindings[i].version != bindings[i - 1].version + 1 {
            return Err(format!(
                "Binding version gap: {} -> {}",
                bindings[i - 1].version,
                bindings[i].version
            )
            .into());
        }
    }

    // Verify the first binding's SAID is anchored in the KEL
    if !kel.contains_anchor(&bindings[0].said) {
        return Err("First binding SAID not anchored in KEL".into());
    }

    // Verify consecutive created_at gaps are within bounds
    for i in 1..bindings.len() {
        let prev_ts = bindings[i - 1]
            .get_created_at()
            .ok_or("Missing created_at")?;
        let curr_ts = bindings[i].get_created_at().ok_or("Missing created_at")?;
        let gap = (*curr_ts.inner() - *prev_ts.inner())
            .to_std()
            .unwrap_or(Duration::ZERO);
        if gap > max_gap {
            return Err(format!(
                "Binding created_at gap too large: {:?} between versions {} and {}",
                gap,
                bindings[i - 1].version,
                bindings[i].version
            )
            .into());
        }
    }

    // All checks passed — check if latest binding is older than rotation interval
    let latest = &bindings[bindings.len() - 1];
    let latest_ts = latest
        .get_created_at()
        .ok_or("Missing created_at on latest binding")?;
    let now = StorageDatetime::now();
    let age = (*now.inner() - *latest_ts.inner())
        .to_std()
        .unwrap_or(Duration::ZERO);

    Ok(age > ROTATION_INTERVAL)
}
