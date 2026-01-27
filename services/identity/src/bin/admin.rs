//! Identity Admin CLI
//!
//! Administrative commands for the KELS registry identity.

use clap::{Parser, Subcommand};
use colored::Colorize;
use identity::{
    hsm::{HsmClient, HsmKeyProvider, KeyHandle},
    repository::{AUTHORITY_IDENTITY_NAME, IdentityRepository, KeyEventRepository},
};
use kels::{KelStore, KeyEventBuilder, KeyProvider, RepositoryKelStore};
use std::sync::Arc;
use verifiable_storage::{RepositoryConnection, VersionedRepository};

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
            cmd_rotate(&repo, hsm, cli.json).await?;
        }
        Commands::RotateRecovery => {
            cmd_rotate_recovery(&repo, hsm, cli.json).await?;
        }
        Commands::Recover => {
            cmd_recover(&repo, hsm, cli.json).await?;
        }
        Commands::Contest { at_version } => {
            cmd_contest(&repo, hsm, at_version, cli.json).await?;
        }
        Commands::Decommission => {
            cmd_decommission(&repo, hsm, cli.json).await?;
        }
    }

    Ok(())
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

    let kel = repo.kel.get_kel(&authority.kel_prefix).await?;
    let latest_event = kel
        .last_event()
        .ok_or_else(|| anyhow::anyhow!("KEL is empty"))?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "initialized": true,
                "prefix": authority.kel_prefix,
                "kel_version": latest_event.event.version,
                "last_said": authority.last_said,
                "current_key_handle": binding.current_key_handle,
                "next_key_handle": binding.next_key_handle,
            })
        );
    } else {
        println!("{}", "Registry Identity Status".cyan().bold());
        println!("{}", "=".repeat(60));
        println!("  {}: {}", "Prefix".cyan(), authority.kel_prefix.yellow());
        println!("  {}: {}", "KEL Version".cyan(), latest_event.event.version);
        println!("  {}: {}", "Last SAID".cyan(), authority.last_said);
        println!("  {}: {}", "Current Key".cyan(), binding.current_key_handle);
        println!("  {}: {}", "Next Key".cyan(), binding.next_key_handle);
    }

    Ok(())
}

async fn cmd_rotate(
    repo: &IdentityRepository,
    hsm: Arc<HsmClient>,
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
        println!("{}", "Rotating Registry Key...".cyan());
        println!("  {}: {}", "Current Version".cyan(), binding.version);
    }

    // Create local KEL store for auto-save using RepositoryKelStore
    let kel_store: Arc<dyn KelStore> = Arc::new(RepositoryKelStore::new(Arc::new(
        KeyEventRepository::new(repo.pool().clone()),
    )));

    // Create HSM key provider with existing handles
    let provider = HsmKeyProvider::with_handles(
        hsm.clone(),
        "kels-registry",
        binding.signing_generation,
        binding.recovery_generation,
        KeyHandle::from(binding.current_key_handle.as_str()),
        KeyHandle::from(binding.next_key_handle.as_str()),
        KeyHandle::from(binding.recovery_key_handle.as_str()),
    );
    let key_provider = provider;

    // Create builder with auto-load from store and auto-save after operations
    let mut builder = KeyEventBuilder::with_dependencies(
        key_provider,
        None, // No KelsClient - identity service is authoritative
        Some(kel_store),
        Some(&prefix),
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to create builder: {}", e))?;

    // Verify KEL is not empty
    if builder.last_said().is_none() {
        return Err(anyhow::anyhow!("KEL is empty"));
    }

    // Rotate using the builder (handles key management, event creation, and local save)
    let (event, _signature) = builder.rotate().await?;

    // Get updated handles from key provider
    let new_current_handle = builder
        .key_provider()
        .current_handle()
        .await
        .ok_or_else(|| anyhow::anyhow!("No current handle after rotate"))?;
    let new_next_handle = builder
        .key_provider()
        .next_handle()
        .await
        .ok_or_else(|| anyhow::anyhow!("No next handle after rotate"))?;

    // Update HSM binding
    binding.current_key_handle = new_current_handle.clone();
    binding.next_key_handle = new_next_handle.clone();
    repo.hsm_bindings.update(binding).await?;

    // Update authority last_said
    authority.last_said = event.said.clone();
    repo.authority.update(authority).await?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "prefix": prefix,
                "kel_version": event.version,
                "said": event.said,
                "current_key_handle": new_current_handle,
                "next_key_handle": new_next_handle,
            })
        );
    } else {
        println!("{}", "Key Rotation Successful!".green().bold());
        println!("{}", "=".repeat(60));
        println!("  {}: {}", "Prefix".cyan(), prefix);
        println!("  {}: {}", "New KEL Version".cyan(), event.version);
        println!("  {}: {}", "New SAID".cyan(), event.said);
        println!("  {}: {}", "New Current Key".cyan(), new_current_handle);
        println!("  {}: {}", "New Next Key".cyan(), new_next_handle);
    }

    Ok(())
}

async fn cmd_rotate_recovery(
    repo: &IdentityRepository,
    hsm: Arc<HsmClient>,
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
        println!("{}", "Rotating Recovery Key...".cyan());
        println!("  {}: {}", "Current Version".cyan(), binding.version);
        println!(
            "  {}: {}",
            "Current Recovery Key".cyan(),
            binding.recovery_key_handle
        );
    }

    let kel_store: Arc<dyn KelStore> = Arc::new(RepositoryKelStore::new(Arc::new(
        KeyEventRepository::new(repo.pool().clone()),
    )));

    let provider = HsmKeyProvider::with_handles(
        hsm.clone(),
        "kels-registry",
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

    // Rotate recovery key using the builder
    let (event, _signature) = builder.rotate_recovery().await?;

    // Get updated handles from key provider
    let new_current_handle = builder
        .key_provider()
        .current_handle()
        .await
        .ok_or_else(|| anyhow::anyhow!("No current handle after rotate"))?;
    let new_next_handle = builder
        .key_provider()
        .next_handle()
        .await
        .ok_or_else(|| anyhow::anyhow!("No next handle after rotate"))?;
    let new_recovery_handle = builder
        .key_provider()
        .recovery_handle()
        .await
        .ok_or_else(|| anyhow::anyhow!("No recovery handle after rotate"))?;

    // Update HSM binding
    binding.current_key_handle = new_current_handle.clone();
    binding.next_key_handle = new_next_handle.clone();
    binding.recovery_key_handle = new_recovery_handle.clone();
    repo.hsm_bindings.update(binding).await?;

    // Update authority last_said
    authority.last_said = event.said.clone();
    repo.authority.update(authority).await?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "prefix": prefix,
                "kel_version": event.version,
                "said": event.said,
                "current_key_handle": new_current_handle,
                "next_key_handle": new_next_handle,
                "recovery_key_handle": new_recovery_handle,
            })
        );
    } else {
        println!("{}", "Recovery Key Rotation Successful!".green().bold());
        println!("{}", "=".repeat(60));
        println!("  {}: {}", "Prefix".cyan(), prefix);
        println!("  {}: {}", "New KEL Version".cyan(), event.version);
        println!("  {}: {}", "New SAID".cyan(), event.said);
        println!("  {}: {}", "New Current Key".cyan(), new_current_handle);
        println!("  {}: {}", "New Next Key".cyan(), new_next_handle);
        println!("  {}: {}", "New Recovery Key".cyan(), new_recovery_handle);
    }

    Ok(())
}

async fn cmd_recover(
    repo: &IdentityRepository,
    hsm: Arc<HsmClient>,
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
        "kels-registry",
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
    let (event, _signature) = builder.recover().await?;

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
    authority.last_said = event.said.clone();
    repo.authority.update(authority).await?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "prefix": prefix,
                "kel_version": event.version,
                "said": event.said,
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
        println!("  {}: {}", "New KEL Version".cyan(), event.version);
        println!("  {}: REC (Recovery)", "Event Kind".cyan());
        println!("  {}: {}", "New SAID".cyan(), event.said);
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
        "kels-registry",
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
    let (event, _signature) = builder.contest().await?;

    // Update authority last_said
    authority.last_said = event.said.clone();
    repo.authority.update(authority).await?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "prefix": prefix,
                "kel_version": event.version,
                "said": event.said,
                "event_kind": "CNT",
                "contested_at_version": at_version,
            })
        );
    } else {
        println!("{}", "Contest Successful!".green().bold());
        println!("{}", "=".repeat(60));
        println!("  {}: {}", "Prefix".cyan(), prefix);
        println!("  {}: {}", "New KEL Version".cyan(), event.version);
        println!("  {}: CNT (Contest)", "Event Kind".cyan());
        println!("  {}: {}", "New SAID".cyan(), event.said);
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
        "kels-registry",
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
    let (event, _signature) = builder.decommission().await?;

    // Update authority last_said
    authority.last_said = event.said.clone();
    repo.authority.update(authority).await?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "prefix": prefix,
                "kel_version": event.version,
                "said": event.said,
                "decommissioned": true,
            })
        );
    } else {
        println!("{}", "Identity Decommissioned!".red().bold());
        println!("{}", "=".repeat(60));
        println!("  {}: {}", "Prefix".cyan(), prefix);
        println!("  {}: {}", "Final KEL Version".cyan(), event.version);
        println!("  {}: {}", "Final SAID".cyan(), event.said);
        println!();
        println!("{}", "This identity can no longer be used.".red());
    }

    Ok(())
}
