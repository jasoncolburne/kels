//! Identity Admin CLI
//!
//! Administrative commands for the KELS registry identity.

use clap::{Parser, Subcommand};
use colored::Colorize;
use identity::{
    handlers::{RotateMode, RotateRequest, RotateResponse, SignRequest, SignResponse},
    hsm::{HsmClient, HsmKeyProvider, KeyHandle},
    repository::{AUTHORITY_IDENTITY_NAME, IdentityRepository, KeyEventRepository},
};
use kels::{KelStore, KelsClient, KeyEventBuilder, KeyProvider, RepositoryKelStore};
use std::sync::Arc;
use verifiable_storage::{ChainedRepository, RepositoryConnection};

#[derive(Parser)]
#[command(name = "identity-admin")]
#[command(about = "KELS Registry Identity Administration")]
struct Cli {
    /// PostgreSQL database URL
    #[arg(
        long,
        env = "DATABASE_URL",
        default_value = "postgres://postgres:postgres@database:5432/identity"
    )]
    database_url: String,

    /// HSM service URL
    #[arg(long, env = "HSM_URL", default_value = "http://hsm:80")]
    hsm_url: String,

    /// HSM key handle prefix
    #[arg(long, env = "KEY_HANDLE_PREFIX", default_value = "kels-registry")]
    key_handle_prefix: String,

    /// Identity service URL (for rotation commands)
    #[arg(long, env = "IDENTITY_URL", default_value = "http://localhost:80")]
    identity_url: String,

    /// Output as JSON
    #[arg(short, long)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show current identity status
    Status,
    /// Rotate the registry's signing key
    Rotate,
    /// Rotate the registry's recovery key (requires both current and recovery signatures)
    RotateRecovery,
    /// Recover control using the recovery key (creates REC event from current tail)
    Recover,
    /// Contest a malicious recovery at a specific version (creates CNT event)
    Contest {
        /// The version number where the adversary's recovery event occurred
        #[arg(long)]
        at_version: u64,
    },
    /// Decommission the registry identity (permanent, cannot be undone)
    Decommission,
    /// Perform scheduled rotation (auto-selects ROT vs ROR based on rotation count)
    ScheduledRotate {
        /// KELS service URL (if set, submit updated KEL after rotation)
        #[arg(long, env = "KELS_URL")]
        kels_url: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let repo = IdentityRepository::connect(&cli.database_url).await?;
    repo.initialize().await?;

    let hsm = Arc::new(HsmClient::new(&cli.hsm_url));

    match cli.command {
        Commands::Status => {
            cmd_status(&repo, cli.json).await?;
        }
        Commands::Rotate => {
            cmd_rotate(&cli.identity_url, cli.json).await?;
        }
        Commands::RotateRecovery => {
            cmd_rotate_recovery(&cli.identity_url, cli.json).await?;
        }
        Commands::Recover => {
            cmd_recover(&repo, hsm, &cli.key_handle_prefix, cli.json).await?;
        }
        Commands::Contest { at_version } => {
            cmd_contest(&repo, hsm, at_version, &cli.key_handle_prefix, cli.json).await?;
        }
        Commands::Decommission => {
            cmd_decommission(&repo, hsm, &cli.key_handle_prefix, cli.json).await?;
        }
        Commands::ScheduledRotate { kels_url } => {
            cmd_scheduled_rotate(&cli.identity_url, kels_url, cli.json).await?;
        }
    }

    Ok(())
}

/// Call the identity server's rotate endpoint with a signed request.
async fn call_rotate(
    identity_url: &str,
    request: &RotateRequest,
) -> anyhow::Result<RotateResponse> {
    let client = reqwest::Client::new();

    // Get prefix
    let info_resp = client
        .get(format!("{}/api/identity", identity_url))
        .send()
        .await?;
    if !info_resp.status().is_success() {
        return Err(anyhow::anyhow!("Failed to get identity info"));
    }
    let info: identity::handlers::IdentityInfo = info_resp.json().await?;

    // Sign the request payload
    let payload_json = serde_json::to_string(request)?;
    let sign_resp = client
        .post(format!("{}/api/identity/sign", identity_url))
        .json(&SignRequest { data: payload_json })
        .send()
        .await?;
    if !sign_resp.status().is_success() {
        return Err(anyhow::anyhow!("Failed to sign rotation request"));
    }
    let sign_result: SignResponse = sign_resp.json().await?;

    // Wrap in SignedRequest
    let signed = kels::SignedRequest {
        payload: request.clone(),
        peer_prefix: info.prefix,
        signature: sign_result.signature,
    };

    let resp = client
        .post(format!("{}/api/identity/rotate", identity_url))
        .json(&signed)
        .send()
        .await?;

    if !resp.status().is_success() {
        let text = resp.text().await?;
        return Err(anyhow::anyhow!("Rotation failed: {}", text));
    }

    let response: RotateResponse = resp.json().await?;
    Ok(response)
}

async fn cmd_status(repo: &IdentityRepository, json: bool) -> anyhow::Result<()> {
    let authority = match repo.authority.get_by_name(AUTHORITY_IDENTITY_NAME).await? {
        Some(mapping) => mapping,
        None => {
            if json {
                println!("{}", serde_json::json!({"initialized": false}));
            } else {
                println!("{}", "Registry identity not initialized.".red());
                println!("The identity service will auto-incept on startup.");
            }
            return Ok(());
        }
    };

    let binding = repo
        .hsm_bindings
        .get_latest_by_kel_prefix(&authority.kel_prefix)
        .await?
        .ok_or_else(|| anyhow::anyhow!("HSM binding not found"))?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "initialized": true,
                "prefix": authority.kel_prefix,
                "last_said": authority.last_said,
                "current_key_handle": binding.current_key_handle,
                "next_key_handle": binding.next_key_handle,
            })
        );
    } else {
        println!("{}", "Registry Identity Status".cyan().bold());
        println!("{}", "=".repeat(60));
        println!("  {}: {}", "Prefix".cyan(), authority.kel_prefix.yellow());
        println!("  {}: {}", "Last SAID".cyan(), authority.last_said);
        println!("  {}: {}", "Current Key".cyan(), binding.current_key_handle);
        println!("  {}: {}", "Next Key".cyan(), binding.next_key_handle);
    }

    Ok(())
}

async fn cmd_rotate(identity_url: &str, json: bool) -> anyhow::Result<()> {
    if !json {
        println!("{}", "Rotating Registry Key...".cyan());
    }

    let request = RotateRequest {
        mode: RotateMode::Standard,
    };
    let response = call_rotate(identity_url, &request).await?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "prefix": response.prefix,
                "said": response.said,
                "current_key_handle": response.current_key_handle,
                "next_key_handle": response.next_key_handle,
            })
        );
    } else {
        println!("{}", "Key Rotation Successful!".green().bold());
        println!("{}", "=".repeat(60));
        println!("  {}: {}", "Prefix".cyan(), response.prefix);
        println!("  {}: {}", "New SAID".cyan(), response.said);
        println!(
            "  {}: {}",
            "New Current Key".cyan(),
            response.current_key_handle
        );
        println!("  {}: {}", "New Next Key".cyan(), response.next_key_handle);
    }

    Ok(())
}

async fn cmd_rotate_recovery(identity_url: &str, json: bool) -> anyhow::Result<()> {
    if !json {
        println!("{}", "Rotating Recovery Key...".cyan());
    }

    let request = RotateRequest {
        mode: RotateMode::Recovery,
    };
    let response = call_rotate(identity_url, &request).await?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "prefix": response.prefix,
                "said": response.said,
                "current_key_handle": response.current_key_handle,
                "next_key_handle": response.next_key_handle,
                "recovery_key_handle": response.recovery_key_handle,
            })
        );
    } else {
        println!("{}", "Recovery Key Rotation Successful!".green().bold());
        println!("{}", "=".repeat(60));
        println!("  {}: {}", "Prefix".cyan(), response.prefix);
        println!("  {}: {}", "New SAID".cyan(), response.said);
        println!(
            "  {}: {}",
            "New Current Key".cyan(),
            response.current_key_handle
        );
        println!("  {}: {}", "New Next Key".cyan(), response.next_key_handle);
        if let Some(ref recovery) = response.recovery_key_handle {
            println!("  {}: {}", "New Recovery Key".cyan(), recovery);
        }
    }

    Ok(())
}

async fn cmd_scheduled_rotate(
    identity_url: &str,
    kels_url: Option<String>,
    json: bool,
) -> anyhow::Result<()> {
    let request = RotateRequest {
        mode: RotateMode::Scheduled,
    };

    if !json {
        println!("{}", "Performing Scheduled Rotation...".cyan());
    }

    let response = call_rotate(identity_url, &request).await?;

    // Submit updated KEL to local KELS service if URL is configured
    let kels_url = kels_url.filter(|u| !u.is_empty());
    if let Some(url) = kels_url {
        let client = reqwest::Client::new();
        let kel_resp = client
            .get(format!("{}/api/identity/kel", identity_url))
            .send()
            .await?;

        if !kel_resp.status().is_success() {
            return Err(anyhow::anyhow!("Failed to fetch KEL after rotation"));
        }

        let page: kels::SignedKeyEventPage = kel_resp.json().await?;
        let kels_client = KelsClient::new(&url);
        let submit_resp = kels_client.submit_events(&page.events).await?;

        if !submit_resp.applied {
            return Err(anyhow::anyhow!("KELS service rejected the updated KEL"));
        }

        if !json {
            println!("{}", "Updated KEL submitted to KELS service.".green());
        }
    }

    if json {
        println!("{}", serde_json::to_string(&response)?);
    } else {
        println!("{}", "Scheduled Rotation Complete!".green().bold());
        println!("{}", "=".repeat(60));
        println!(
            "  {}: {} (rotation #{})",
            "Mode".cyan(),
            response.mode,
            response.rotation_number
        );
        println!("  {}: {}", "Prefix".cyan(), response.prefix);
        println!("  {}: {}", "New SAID".cyan(), response.said);
        println!(
            "  {}: {}",
            "New Current Key".cyan(),
            response.current_key_handle
        );
        println!("  {}: {}", "New Next Key".cyan(), response.next_key_handle);
        if let Some(ref recovery) = response.recovery_key_handle {
            println!("  {}: {}", "New Recovery Key".cyan(), recovery);
        }
    }

    Ok(())
}

async fn cmd_recover(
    repo: &IdentityRepository,
    hsm: Arc<HsmClient>,
    key_handle_prefix: &str,
    json: bool,
) -> anyhow::Result<()> {
    let mut authority = repo
        .authority
        .get_by_name(AUTHORITY_IDENTITY_NAME)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Identity not initialized"))?;

    let prefix = authority.kel_prefix.clone();

    let mut binding = repo
        .hsm_bindings
        .get_latest_by_kel_prefix(&prefix)
        .await?
        .ok_or_else(|| anyhow::anyhow!("HSM binding not found"))?;

    if !json {
        println!("{}", "Recovering Identity...".yellow().bold());
        println!(
            "{}",
            "This will create a recovery event using the recovery key.".yellow()
        );
        println!("  {}: {}", "Prefix".cyan(), prefix);
        println!("  {}: {}", "Current Version".cyan(), binding.version);
        println!();
    }

    let kel_store: Arc<dyn KelStore> = Arc::new(RepositoryKelStore::new(Arc::new(
        KeyEventRepository::new(repo.pool().clone()),
    )));

    let provider = HsmKeyProvider::with_handles(
        hsm.clone(),
        key_handle_prefix,
        binding.signing_generation,
        binding.recovery_generation,
        KeyHandle::from(binding.current_key_handle.as_str()),
        KeyHandle::from(binding.next_key_handle.as_str()),
        KeyHandle::from(binding.recovery_key_handle.as_str()),
    );
    let key_provider = provider;

    let mut builder =
        KeyEventBuilder::with_dependencies(key_provider, None, Some(kel_store), Some(&prefix))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create builder: {}", e))?;

    if builder.last_said().is_none() {
        return Err(anyhow::anyhow!("KEL is empty"));
    }

    // Recover using the builder (authoritative mode)
    let add_rot = builder.should_add_rot_with_recover().await?;
    let rec = builder.recover(add_rot).await?;

    // Get updated handles from key provider
    let new_current_handle = builder
        .key_provider()
        .current_handle()
        .await
        .ok_or_else(|| anyhow::anyhow!("No current handle after recover"))?;
    let new_next_handle = builder
        .key_provider()
        .next_handle()
        .await
        .ok_or_else(|| anyhow::anyhow!("No next handle after recover"))?;
    let new_recovery_handle = builder
        .key_provider()
        .recovery_handle()
        .await
        .ok_or_else(|| anyhow::anyhow!("No recovery handle after recover"))?;

    // Update HSM binding
    binding.current_key_handle = new_current_handle.clone();
    binding.next_key_handle = new_next_handle.clone();
    binding.recovery_key_handle = new_recovery_handle.clone();
    repo.hsm_bindings.update(binding).await?;

    // Update authority last_said
    authority.last_said = rec.event.said.clone();
    repo.authority.update(authority).await?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "prefix": prefix,
                "said": rec.event.said,
                "event_kind": "REC",
                "current_key_handle": new_current_handle,
                "next_key_handle": new_next_handle,
                "recovery_key_handle": new_recovery_handle,
            })
        );
    } else {
        println!("{}", "Recovery Successful!".green().bold());
        println!("{}", "=".repeat(60));
        println!("  {}: {}", "Prefix".cyan(), prefix);
        println!("  {}: REC (Recovery)", "Event Kind".cyan());
        println!("  {}: {}", "New SAID".cyan(), rec.event.said);
        println!("  {}: {}", "New Current Key".cyan(), new_current_handle);
        println!("  {}: {}", "New Next Key".cyan(), new_next_handle);
        println!("  {}: {}", "New Recovery Key".cyan(), new_recovery_handle);
        println!();
        println!(
            "{}",
            "Clients will accept this recovery and heal their KEL view.".green()
        );
    }

    Ok(())
}

async fn cmd_contest(
    repo: &IdentityRepository,
    hsm: Arc<HsmClient>,
    at_version: u64,
    key_handle_prefix: &str,
    json: bool,
) -> anyhow::Result<()> {
    let mut authority = repo
        .authority
        .get_by_name(AUTHORITY_IDENTITY_NAME)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Identity not initialized"))?;

    let prefix = authority.kel_prefix.clone();

    let binding = repo
        .hsm_bindings
        .get_latest_by_kel_prefix(&prefix)
        .await?
        .ok_or_else(|| anyhow::anyhow!("HSM binding not found"))?;

    if !json {
        println!("{}", "Contesting Malicious Recovery...".red().bold());
        println!(
            "{}",
            "This will create a contest event at the specified version.".yellow()
        );
        println!("  {}: {}", "Prefix".cyan(), prefix);
        println!("  {}: {}", "Contest at Version".cyan(), at_version);
        println!();
    }

    let kel_store: Arc<dyn KelStore> = Arc::new(RepositoryKelStore::new(Arc::new(
        KeyEventRepository::new(repo.pool().clone()),
    )));

    let provider = HsmKeyProvider::with_handles(
        hsm.clone(),
        key_handle_prefix,
        binding.signing_generation,
        binding.recovery_generation,
        KeyHandle::from(binding.current_key_handle.as_str()),
        KeyHandle::from(binding.next_key_handle.as_str()),
        KeyHandle::from(binding.recovery_key_handle.as_str()),
    );
    let key_provider = provider;

    let mut builder =
        KeyEventBuilder::with_dependencies(key_provider, None, Some(kel_store), Some(&prefix))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create builder: {}", e))?;

    if builder.last_said().is_none() {
        return Err(anyhow::anyhow!("KEL is empty"));
    }

    // Contest using the builder (authoritative mode)
    let cnt = builder.contest().await?;

    // Update authority last_said
    authority.last_said = cnt.event.said.clone();
    repo.authority.update(authority).await?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "prefix": prefix,
                "said": cnt.event.said,
                "event_kind": "CNT",
                "contested_at_version": at_version,
            })
        );
    } else {
        println!("{}", "Contest Successful!".green().bold());
        println!("{}", "=".repeat(60));
        println!("  {}: {}", "Prefix".cyan(), prefix);
        println!("  {}: CNT (Contest)", "Event Kind".cyan());
        println!("  {}: {}", "New SAID".cyan(), cnt.event.said);
        println!("  {}: {}", "Contested at Version".cyan(), at_version);
        println!();
        println!(
            "{}",
            "The adversary's recovery has been contested. KEL is now frozen.".yellow()
        );
    }

    Ok(())
}

async fn cmd_decommission(
    repo: &IdentityRepository,
    hsm: Arc<HsmClient>,
    key_handle_prefix: &str,
    json: bool,
) -> anyhow::Result<()> {
    let mut authority = repo
        .authority
        .get_by_name(AUTHORITY_IDENTITY_NAME)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Identity not initialized"))?;

    let prefix = authority.kel_prefix.clone();

    let binding = repo
        .hsm_bindings
        .get_latest_by_kel_prefix(&prefix)
        .await?
        .ok_or_else(|| anyhow::anyhow!("HSM binding not found"))?;

    if !json {
        println!("{}", "WARNING: Decommissioning is PERMANENT!".red().bold());
        println!("{}", "This identity will be permanently ended.".red());
        println!("  {}: {}", "Prefix".cyan(), prefix);
        println!("  {}: {}", "Current Version".cyan(), binding.version);
        println!();
        println!("Proceeding with decommission...");
    }

    let kel_store: Arc<dyn KelStore> = Arc::new(RepositoryKelStore::new(Arc::new(
        KeyEventRepository::new(repo.pool().clone()),
    )));

    let provider = HsmKeyProvider::with_handles(
        hsm.clone(),
        key_handle_prefix,
        binding.signing_generation,
        binding.recovery_generation,
        KeyHandle::from(binding.current_key_handle.as_str()),
        KeyHandle::from(binding.next_key_handle.as_str()),
        KeyHandle::from(binding.recovery_key_handle.as_str()),
    );
    let key_provider = provider;

    let mut builder =
        KeyEventBuilder::with_dependencies(key_provider, None, Some(kel_store), Some(&prefix))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create builder: {}", e))?;

    if builder.last_said().is_none() {
        return Err(anyhow::anyhow!("KEL is empty"));
    }

    if builder.is_decommissioned() {
        return Err(anyhow::anyhow!("Identity is already decommissioned"));
    }

    // Decommission using the builder
    let dec = builder.decommission().await?;

    // Update authority last_said
    authority.last_said = dec.event.said.clone();
    repo.authority.update(authority).await?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "prefix": prefix,
                "said": dec.event.said,
                "decommissioned": true,
            })
        );
    } else {
        println!("{}", "Identity Decommissioned!".red().bold());
        println!("{}", "=".repeat(60));
        println!("  {}: {}", "Prefix".cyan(), prefix);
        println!("  {}: {}", "Final SAID".cyan(), dec.event.said);
        println!();
        println!("{}", "This identity can no longer be used.".red());
    }

    Ok(())
}
