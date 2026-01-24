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
    /// Initialize database schema (run migrations)
    Init,
    /// Show current identity status
    Status,
    /// Rotate the registry's signing key
    Rotate,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let repo = IdentityRepository::connect(&cli.database_url).await?;
    repo.initialize().await?;

    let hsm = Arc::new(HsmClient::new(&cli.hsm_url));

    match cli.command {
        Commands::Init => {
            // Just connect and initialize - migrations are run on connect
            if !cli.json {
                println!("Database initialized successfully.");
            }
        }
        Commands::Status => {
            cmd_status(&repo, cli.json).await?;
        }
        Commands::Rotate => {
            cmd_rotate(&repo, hsm, cli.json).await?;
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
    // next_label_generation is binding.version + 2 (we have keys 0..binding.version+1, next is binding.version+2)
    let provider = HsmKeyProvider::with_handles(
        hsm.clone(),
        "kels-registry",
        binding.version + 2,
        KeyHandle::from(binding.current_key_handle.as_str()),
        KeyHandle::from(binding.next_key_handle.as_str()),
    );
    let key_provider = KeyProvider::external(Box::new(provider));

    // Create builder with auto-load from store and auto-save after operations
    let mut builder = KeyEventBuilder::with_dependencies(
        key_provider,
        None, // No KelsClient - identity service is authoritative
        Some(kel_store),
        Some(&prefix),
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to create builder: {}", e))?;

    // Verify KEL state matches authority record
    if let Some(last_said) = builder.last_said() {
        if last_said != authority.last_said {
            return Err(anyhow::anyhow!(
                "KEL last_said mismatch: expected {}, got {}",
                authority.last_said,
                last_said
            ));
        }
    } else {
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
