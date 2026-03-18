//! Identity Service HTTP Server

use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use axum::{
    Router,
    routing::{get, post},
};
use kels::{KelStore, KeyEventBuilder, KeyProvider, RepositoryKelStore, shutdown_signal};
use verifiable_storage::{
    Chained, ChainedRepository, RepositoryConnection, SelfAddressed, StorageDatetime,
};

use kels::{ManageKelOperation, ManageKelResponse, RotateMode};

use crate::{
    handlers::{self, AppState},
    hsm::{HsmKeyProvider, Pkcs11Client},
    repository::{AUTHORITY_IDENTITY_NAME, AuthorityMapping, HsmKeyBinding, IdentityRepository},
};

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(handlers::health))
        .route("/api/identity", get(handlers::get_identity))
        .route("/api/identity/status", get(handlers::get_status))
        .route("/api/identity/anchor", post(handlers::anchor))
        .route("/api/identity/kel", get(handlers::get_key_events))
        .route("/api/identity/kel/manage", post(handlers::manage_kel))
        .route("/api/identity/sign", post(handlers::sign))
        .with_state(state)
}

pub async fn run(listener: tokio::net::TcpListener) -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@database:5432/identity".to_string());
    let pkcs11_library = std::env::var("PKCS11_LIBRARY")
        .unwrap_or_else(|_| "/usr/lib/kels/libkels_mock_hsm.so".to_string());
    let hsm_slot: usize = std::env::var("HSM_SLOT")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .unwrap_or(0);
    let hsm_pin = std::env::var("HSM_PIN").unwrap_or_else(|_| "1234".to_string());
    let key_handle_prefix =
        std::env::var("KEY_HANDLE_PREFIX").unwrap_or_else(|_| "kels-registry".to_string());
    let forward_url = std::env::var("KEL_FORWARD_URL")
        .ok()
        .filter(|u| !u.is_empty());
    let forward_path_prefix =
        std::env::var("KEL_FORWARD_PATH_PREFIX").unwrap_or_else(|_| "/api/kels".to_string());
    let next_signing_algorithm =
        std::env::var("NEXT_SIGNING_ALGORITHM").unwrap_or_else(|_| "ml-dsa-65".to_string());
    let next_recovery_algorithm =
        std::env::var("NEXT_RECOVERY_ALGORITHM").unwrap_or_else(|_| "ml-dsa-65".to_string());
    let http_client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_default();

    info!("Connecting to database");
    let repo = IdentityRepository::connect(&database_url)
        .await
        .map_err(|e| format!("Failed to connect to database: {}", e))?;

    info!("Running migrations");
    repo.initialize()
        .await
        .map_err(|e| format!("Failed to run migrations: {}", e))?;
    info!("Database connected");

    info!("Connecting to PKCS#11 HSM at {}", pkcs11_library);
    let hsm = Arc::new(
        Pkcs11Client::new(&pkcs11_library, hsm_slot, &hsm_pin)
            .map_err(|e| format!("Failed to connect to PKCS#11 HSM: {}", e))?,
    );

    let kel_repo = Arc::new(crate::repository::KeyEventRepository::new(
        repo.pool().clone(),
    ));
    let kel_store: Arc<dyn KelStore> = Arc::new(RepositoryKelStore::new(kel_repo.clone()));

    let builder = if let Some(mapping) = repo.authority.get_by_name(AUTHORITY_IDENTITY_NAME).await?
    {
        let prefix = mapping.kel_prefix.clone();
        info!("Found identity prefix: {}", prefix);

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
            &next_signing_algorithm,
            &next_recovery_algorithm,
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
        // No eager push to registry needed — identity starts before registry,
        // and registry pulls all member KELs via sync_all_member_kels on startup.
        info!("No existing identity - auto-incepting");

        let key_provider = HsmKeyProvider::new(
            hsm.clone(),
            &key_handle_prefix,
            0,
            0,
            &next_signing_algorithm,
            &next_recovery_algorithm,
        );

        let mut builder =
            KeyEventBuilder::with_dependencies(key_provider, None, Some(kel_store.clone()), None)
                .await
                .map_err(|e| format!("Failed to create builder: {}", e))?;

        let icp = builder
            .incept()
            .await
            .map_err(|e| format!("Failed to incept: {}", e))?;

        info!("Generated identity prefix: {}", icp.event.prefix);

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
        forward_url,
        forward_path_prefix,
        http_client,
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
    let mut last_rotation: Option<tokio::time::Instant> = None;

    loop {
        interval.tick().await; // first tick is immediate, then every LOOP_PERIOD

        // Cooldown: skip if we rotated recently (keys are fresh for ROTATION_INTERVAL)
        if let Some(last) = last_rotation
            && last.elapsed() < ROTATION_INTERVAL
        {
            continue;
        }

        match check_and_rotate(&state).await {
            Ok(rotated) => {
                if rotated {
                    info!("Auto-rotation completed successfully");
                    last_rotation = Some(tokio::time::Instant::now());
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

    // Consuming: verify full KEL under advisory lock with inline anchor checking
    let binding_saids: Vec<String> = bindings.iter().map(|b| b.said.clone()).collect();
    let mut tx = state.kel_repo.begin_locked_transaction(prefix).await?;
    let kel_verification = kels::completed_verification(
        &mut tx,
        prefix,
        kels::MAX_EVENTS_PER_KEL_QUERY as u64,
        kels::max_verification_pages(),
        binding_saids,
    )
    .await?;

    if kel_verification.is_divergent() {
        return Err("SECURITY: Identity KEL has diverged".into());
    }

    // Audit full binding chain — alert on any tampering but don't rotate
    if let Err(e) = audit_binding_chain(&bindings, &kel_verification) {
        warn!("SECURITY: binding chain integrity check failed: {}", e);
    }

    // Only the latest binding's consistency determines rotation
    let should_rotate = match verify_latest_binding(&bindings, &kel_verification) {
        Ok(needs_rotation) => needs_rotation,
        Err(e) => {
            warn!(
                "SECURITY: latest binding verification failed ({}), rotating immediately",
                e
            );
            true
        }
    };

    // Release advisory lock. The brief gap before perform_kel_operation re-acquires
    // is safe: the verification result (rotation check, binding audit) doesn't go stale
    // because save_with_merge independently re-verifies new events against the current
    // KEL state. The builder's RwLock serializes callers, and this service is the sole
    // writer to its own prefix.
    tx.commit().await?;

    if should_rotate {
        info!("Triggering scheduled rotation");

        let op = ManageKelOperation::Rotate {
            mode: RotateMode::Scheduled,
        };
        perform_kel_operation(state, &op).await?;

        return Ok(true);
    }

    Ok(false)
}

/// Perform a KEL management operation and update the in-memory builder.
///
/// This is the single source of truth for all KEL operations — called by both
/// the HTTP handler and the auto-rotation loop. The builder's key provider is
/// updated in-place, so no rebuild is needed.
pub(crate) async fn perform_kel_operation(
    state: &Arc<AppState>,
    operation: &ManageKelOperation,
) -> Result<ManageKelResponse, Box<dyn std::error::Error + Send + Sync>> {
    let mut builder = state.builder.write().await;

    // Reload to pick up any external changes
    builder
        .reload()
        .await
        .map_err(|e| format!("Failed to reload KEL: {}", e))?;

    let prefix = builder.prefix().ok_or("Builder has no prefix")?.to_string();

    if builder.last_said().is_none() {
        return Err("KEL is empty".into());
    }

    let (event, event_kind, rotation_number, updates_signing_keys) = match operation {
        ManageKelOperation::Rotate { mode } => {
            let rotation_count = builder.rotation_count();

            let actual_mode = match mode {
                RotateMode::Scheduled => {
                    if rotation_count % 3 == 2 {
                        RotateMode::Recovery
                    } else {
                        RotateMode::Standard
                    }
                }
                other => other.clone(),
            };

            let event = match actual_mode {
                RotateMode::Standard => builder.rotate().await?,
                RotateMode::Recovery => builder.rotate_recovery().await?,
                RotateMode::Scheduled => unreachable!(),
            };

            let kind = if actual_mode == RotateMode::Recovery {
                "ror"
            } else {
                "rot"
            };

            (event, kind, Some(rotation_count + 1), true)
        }
        ManageKelOperation::Recover => {
            // Determine if adversary revealed rotation key by checking the server's
            // verification state. The identity service uses its forward_url to reach
            // the colocated KELS service.
            let add_rot = if let Some(ref forward_url) = state.forward_url
                && let Some(prefix) = builder.prefix()
            {
                let source = kels::HttpKelSource::new(
                    forward_url,
                    &format!("{}/kel/{{prefix}}", state.forward_path_prefix),
                );
                match kels::verify_key_events(
                    prefix,
                    &source,
                    kels::KelVerifier::new(prefix),
                    kels::MAX_EVENTS_PER_KEL_QUERY,
                    kels::max_verification_pages(),
                )
                .await
                {
                    Ok(server_verification) => {
                        let owner_last_est_serial = builder
                            .last_establishment_event()
                            .map(|e| e.serial)
                            .unwrap_or(0);
                        kels::should_rotate_with_recovery(
                            &server_verification,
                            builder.rotation_count(),
                            owner_last_est_serial,
                        )
                    }
                    Err(e) => {
                        warn!("Failed to verify server KEL for recovery decision: {}", e);
                        true // Fail secure
                    }
                }
            } else {
                true // Fail secure: no forward URL
            };
            let event = builder.recover(add_rot).await?;
            (event, "rec", None, true)
        }
        ManageKelOperation::Contest => {
            let event = builder.contest().await?;
            (event, "cnt", None, false)
        }
        ManageKelOperation::Decommission => {
            if builder.is_decommissioned() {
                return Err("Identity is already decommissioned".into());
            }
            let event = builder.decommission().await?;
            (event, "dec", None, false)
        }
    };

    // Get current handles
    let current_handle = builder
        .key_provider()
        .current_handle()
        .await
        .ok_or("No current handle")?;
    let next_handle = builder
        .key_provider()
        .next_handle()
        .await
        .ok_or("No next handle")?;

    // Update HSM binding if signing keys changed
    if updates_signing_keys {
        let mut binding = state
            .repo
            .hsm_bindings
            .get_latest_by_kel_prefix(&prefix)
            .await?
            .ok_or("HSM binding not found")?;

        binding.current_key_handle = current_handle.clone();
        binding.next_key_handle = next_handle.clone();
        binding.signing_generation = builder.key_provider().signing_generation().await;

        // Recovery key changes on ROR and REC
        if event_kind == "ror" || event_kind == "rec" {
            let recovery_handle = builder
                .key_provider()
                .recovery_handle()
                .await
                .ok_or("No recovery handle")?;
            binding.recovery_key_handle = recovery_handle;
            binding.recovery_generation = builder.key_provider().recovery_generation().await;
        }

        binding.increment()?;
        builder.interact(&binding.said).await?;
        state
            .repo
            .hsm_bindings
            .insert(binding)
            .await
            .map_err(|e| format!("Failed to insert binding: {}", e))?;
    }

    // Update authority
    let mut authority = state
        .repo
        .authority
        .get_by_name(AUTHORITY_IDENTITY_NAME)
        .await?
        .ok_or("Authority not found")?;
    authority.last_said = event.event.said.clone();
    state
        .repo
        .authority
        .update(authority)
        .await
        .map_err(|e| format!("Failed to update authority: {}", e))?;

    info!(
        "KEL operation completed: kind={}, said={}",
        event_kind, event.event.said
    );

    // Release write lock before forwarding
    drop(builder);

    // Best-effort forward KEL to colocated service if configured
    handlers::forward_kel(state, &prefix).await;

    Ok(ManageKelResponse {
        prefix,
        said: event.event.said,
        event_kind: event_kind.to_string(),
        rotation_number,
        current_key_handle: current_handle,
    })
}

/// Audit the full binding chain for tampering. Logs warnings but does not
/// influence the rotation decision — a corrupted historical binding cannot
/// be fixed by rotating, so triggering rotation here would loop forever.
fn audit_binding_chain(
    bindings: &[HsmKeyBinding],
    kel_verification: &kels::KelVerification,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if kel_verification.is_divergent() {
        error!("SECURITY: Identity KEL diverged — refusing to verify bindings");
        return Err("SECURITY: Identity KEL has diverged".into());
    }

    for binding in bindings {
        binding.verify()?;
    }

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

    if !kel_verification.anchors_all_saids() {
        return Err("Not all binding SAIDs are anchored in KEL".into());
    }

    Ok(())
}

/// Verify only the latest binding's integrity. If this fails, something is
/// actively wrong with the current key state and defensive rotation is warranted.
fn verify_latest_binding(
    bindings: &[HsmKeyBinding],
    kel_verification: &kels::KelVerification,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    if kel_verification.is_divergent() {
        error!("SECURITY: Identity KEL diverged — refusing to verify bindings");
        return Err("SECURITY: Identity KEL has diverged".into());
    }

    let latest = &bindings[bindings.len() - 1];

    latest.verify()?;

    if bindings.len() > 1 {
        let previous = &bindings[bindings.len() - 2];
        let expected_prev = Some(previous.get_said());
        if latest.get_previous() != expected_prev {
            return Err("Latest binding has wrong previous pointer".into());
        }
    }

    if !kel_verification.is_said_anchored(&latest.said) {
        return Err("Latest binding SAID not anchored in KEL".into());
    }

    let latest_ts = latest
        .get_created_at()
        .ok_or("Missing created_at on latest binding")?;
    let now = StorageDatetime::now();
    let age = (*now.inner() - *latest_ts.inner())
        .to_std()
        .unwrap_or(Duration::ZERO);

    Ok(age > ROTATION_INTERVAL)
}
