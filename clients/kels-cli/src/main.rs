//! kels-cli - KELS Command Line Interface
//!
//! A command-line client for managing Key Event Logs (KELs) via the KELS service.
//!
//! # Usage
//!
//! ```bash
//! # Create a new KEL (inception)
//! kels-cli incept
//!
//! # Rotate signing key
//! kels-cli rotate --prefix <prefix>
//!
//! # Anchor a SAID in the KEL
//! kels-cli anchor --prefix <prefix> --said <said>
//!
//! # Fetch a KEL
//! kels-cli get <prefix>
//! ```

use std::path::PathBuf;

#[cfg(feature = "dev-tools")]
use anyhow::bail;
use anyhow::{Context, Result};
#[cfg(feature = "dev-tools")]
use cesr::Matter;
use cesr::PrivateKey;
use clap::{Parser, Subcommand};
use colored::Colorize;
use kels::{FileKelStore, KelStore, KelsClient, KeyEventBuilder, KeyProvider, RecoveryOutcome};
use serde::{Deserialize, Serialize};

const DEFAULT_KELS_URL: &str = "http://localhost:8091";

/// KELS Command Line Interface
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// KELS server URL
    #[arg(short, long, env = "KELS_URL", default_value = DEFAULT_KELS_URL)]
    url: String,

    /// Config directory (default: ~/.kels-cli)
    #[arg(long, env = "KELS_CLI_HOME")]
    config_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Create a new KEL (inception event)
    Incept,

    /// Rotate the signing key
    Rotate {
        /// KEL prefix to rotate
        #[arg(long)]
        prefix: String,
    },

    /// Rotate the recovery key (requires dual signatures)
    RotateRecovery {
        /// KEL prefix
        #[arg(long)]
        prefix: String,
    },

    /// Anchor a SAID in the KEL (interaction event)
    Anchor {
        /// KEL prefix
        #[arg(long)]
        prefix: String,

        /// SAID to anchor
        #[arg(long)]
        said: String,
    },

    /// Recover from divergence (submits rec or cnt event automatically).
    ///
    /// If adversary only has signing key: submits rec, KEL recovers.
    /// If adversary revealed recovery key: submits cnt, KEL is contested (frozen).
    Recover {
        /// KEL prefix to recover
        #[arg(long)]
        prefix: String,
    },

    /// Decommission the KEL (permanent, no further events allowed)
    Decommission {
        /// KEL prefix to decommission
        #[arg(long)]
        prefix: String,
    },

    /// Fetch and display a KEL
    Get {
        /// KEL prefix to fetch
        prefix: String,

        /// Include audit records in response
        #[arg(long)]
        audit: bool,

        /// Fetch events since timestamp (RFC3339 format)
        #[arg(long)]
        since: Option<String>,
    },

    /// List all local KELs
    List,

    /// Show status of a local KEL
    Status {
        /// KEL prefix
        #[arg(long)]
        prefix: String,
    },

    /// Development and testing commands
    #[cfg(feature = "dev-tools")]
    #[command(subcommand)]
    Dev(DevCommands),

    /// Adversary simulation commands (for testing divergence)
    #[cfg(feature = "dev-tools")]
    #[command(subcommand)]
    Adversary(AdversaryCommands),
}

/// Development commands (only available with dev-tools feature)
#[cfg(feature = "dev-tools")]
#[derive(Subcommand, Debug)]
enum DevCommands {
    /// Truncate local KEL to N events (simulates being behind server)
    Truncate {
        /// KEL prefix
        #[arg(long)]
        prefix: String,

        /// Number of events to keep
        #[arg(long)]
        count: usize,
    },

    /// Dump local KEL as JSON
    DumpKel {
        /// KEL prefix
        #[arg(long)]
        prefix: String,
    },
}

/// Adversary simulation commands (only available with dev-tools feature)
#[cfg(feature = "dev-tools")]
#[derive(Subcommand, Debug)]
enum AdversaryCommands {
    /// Inject events to server only (not local storage) - simulates adversary
    Inject {
        /// KEL prefix to attack
        #[arg(long)]
        prefix: String,

        /// Comma-separated list of event types to inject (e.g., "ixn,ixn,rot")
        #[arg(long)]
        events: String,
    },
}

/// CLI configuration stored in config.toml
#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize, Default)]
struct Config {
    /// Default KELS server URL
    default_url: Option<String>,
    /// Default prefix for commands that don't specify one
    default_prefix: Option<String>,
}

/// Get the config directory path
fn config_dir(cli: &Cli) -> Result<PathBuf> {
    if let Some(ref dir) = cli.config_dir {
        return Ok(dir.clone());
    }

    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(home.join(".kels-cli"))
}

/// Get the KEL storage directory for a prefix
fn kel_dir(cli: &Cli) -> Result<PathBuf> {
    Ok(config_dir(cli)?.join("kels"))
}

/// Load or create a KeyProvider for the given prefix
async fn load_key_provider(cli: &Cli, prefix: &str) -> Result<KeyProvider> {
    let key_dir = config_dir(cli)?.join("keys").join(prefix);
    std::fs::create_dir_all(&key_dir)?;

    let current_path = key_dir.join("current.key");
    let next_path = key_dir.join("next.key");
    let recovery_path = key_dir.join("recovery.key");

    if current_path.exists() && next_path.exists() {
        // Load existing keys from qb64 format
        let current_qb64 =
            std::fs::read_to_string(&current_path).context("Failed to read current key")?;
        let next_qb64 = std::fs::read_to_string(&next_path).context("Failed to read next key")?;

        let current = PrivateKey::from_qb64(current_qb64.trim())
            .map_err(|e| anyhow::anyhow!("Invalid current key: {}", e))?;
        let next = PrivateKey::from_qb64(next_qb64.trim())
            .map_err(|e| anyhow::anyhow!("Invalid next key: {}", e))?;

        let recovery = if recovery_path.exists() {
            let recovery_qb64 =
                std::fs::read_to_string(&recovery_path).context("Failed to read recovery key")?;
            Some(
                PrivateKey::from_qb64(recovery_qb64.trim())
                    .map_err(|e| anyhow::anyhow!("Invalid recovery key: {}", e))?,
            )
        } else {
            None
        };

        Ok(KeyProvider::with_all_software_keys(current, next, recovery))
    } else {
        // Create new key provider (keys will be saved after inception)
        Ok(KeyProvider::software())
    }
}

/// Save KeyProvider keys to files
fn save_key_provider(cli: &Cli, prefix: &str, provider: &KeyProvider) -> Result<()> {
    let key_dir = config_dir(cli)?.join("keys").join(prefix);
    std::fs::create_dir_all(&key_dir)?;

    let software = provider
        .as_software()
        .ok_or_else(|| anyhow::anyhow!("Cannot save non-software key provider"))?;

    let current_path = key_dir.join("current.key");
    let next_path = key_dir.join("next.key");
    let recovery_path = key_dir.join("recovery.key");

    if let Some(current) = software.current_private_key() {
        std::fs::write(&current_path, current.qb64()).context("Failed to write current key")?;
    }

    if let Some(next) = software.next_private_key() {
        std::fs::write(&next_path, next.qb64()).context("Failed to write next key")?;
    }

    if let Some(recovery) = software.recovery_private_key() {
        std::fs::write(&recovery_path, recovery.qb64()).context("Failed to write recovery key")?;
    }

    Ok(())
}

/// Create a KelsClient
fn create_client(cli: &Cli) -> KelsClient {
    KelsClient::new(&cli.url)
}

/// Create a FileKelStore for the given prefix
fn create_kel_store(cli: &Cli, prefix: Option<&str>) -> Result<FileKelStore> {
    let dir = kel_dir(cli)?;
    if let Some(p) = prefix {
        FileKelStore::with_owner(dir, p.to_string()).context("Failed to create KEL store")
    } else {
        FileKelStore::new(dir).context("Failed to create KEL store")
    }
}

// ==================== Command Handlers ====================

async fn cmd_incept(cli: &Cli) -> Result<()> {
    println!("{}", "Creating new KEL...".green());

    let client = create_client(cli);
    let key_provider = KeyProvider::software();
    let kel_store = create_kel_store(cli, None)?;

    let mut builder = KeyEventBuilder::with_dependencies(
        key_provider,
        Some(client),
        Some(std::sync::Arc::new(kel_store)),
        None,
    )
    .await?;

    let (event, _sig) = builder.incept().await.context("Inception failed")?;

    // Save the keys
    save_key_provider(cli, &event.prefix, builder.key_provider())?;

    // Update the store's owner prefix now that we know it
    let kel_store = create_kel_store(cli, Some(&event.prefix))?;
    kel_store.save(&builder.kel()).await?;

    println!("{}", "KEL created successfully!".green().bold());
    println!("  Prefix: {}", event.prefix.cyan());
    println!("  SAID:   {}", event.said);

    Ok(())
}

async fn cmd_rotate(cli: &Cli, prefix: &str) -> Result<()> {
    println!(
        "{}",
        format!("Rotating signing key for {}...", prefix).green()
    );

    let client = create_client(cli);
    let key_provider = load_key_provider(cli, prefix).await?;
    let kel_store = create_kel_store(cli, Some(prefix))?;

    let mut builder = KeyEventBuilder::with_dependencies(
        key_provider,
        Some(client),
        Some(std::sync::Arc::new(kel_store)),
        Some(prefix),
    )
    .await?;

    let (event, _sig) = builder.rotate().await.context("Rotation failed")?;

    // Save updated keys
    save_key_provider(cli, prefix, builder.key_provider())?;

    println!("{}", "Rotation successful!".green().bold());
    println!("  Event SAID: {}", event.said);

    Ok(())
}

async fn cmd_rotate_recovery(cli: &Cli, prefix: &str) -> Result<()> {
    println!(
        "{}",
        format!("Rotating recovery key for {}...", prefix).green()
    );

    let client = create_client(cli);
    let key_provider = load_key_provider(cli, prefix).await?;
    let kel_store = create_kel_store(cli, Some(prefix))?;

    let mut builder = KeyEventBuilder::with_dependencies(
        key_provider,
        Some(client),
        Some(std::sync::Arc::new(kel_store)),
        Some(prefix),
    )
    .await?;

    let (event, _sig) = builder
        .rotate_recovery()
        .await
        .context("Recovery rotation failed")?;

    // Save updated keys
    save_key_provider(cli, prefix, builder.key_provider())?;

    println!("{}", "Recovery rotation successful!".green().bold());
    println!("  Event SAID: {}", event.said);

    Ok(())
}

async fn cmd_anchor(cli: &Cli, prefix: &str, said: &str) -> Result<()> {
    println!("{}", format!("Anchoring SAID in {}...", prefix).green());

    let client = create_client(cli);
    let key_provider = load_key_provider(cli, prefix).await?;
    let kel_store = create_kel_store(cli, Some(prefix))?;

    let mut builder = KeyEventBuilder::with_dependencies(
        key_provider,
        Some(client),
        Some(std::sync::Arc::new(kel_store)),
        Some(prefix),
    )
    .await?;

    let (event, _sig) = builder.interact(said).await.context("Interaction failed")?;

    println!("{}", "Anchor successful!".green().bold());
    println!("  Event SAID: {}", event.said);
    println!("  Anchored:   {}", said);

    Ok(())
}

async fn cmd_recover(cli: &Cli, prefix: &str) -> Result<()> {
    println!("{}", format!("Recovering KEL {}...", prefix).yellow());

    let client = create_client(cli);
    let key_provider = load_key_provider(cli, prefix).await?;
    let kel_store = create_kel_store(cli, Some(prefix))?;

    let mut builder = KeyEventBuilder::with_dependencies(
        key_provider,
        Some(client),
        Some(std::sync::Arc::new(kel_store)),
        Some(prefix),
    )
    .await?;

    let (outcome, event, _sig) = builder.recover().await.context("Recovery failed")?;

    // Save updated keys
    save_key_provider(cli, prefix, builder.key_provider())?;

    match outcome {
        RecoveryOutcome::Recovered => {
            println!("{}", "Recovery successful!".green().bold());
            println!("  Event SAID: {}", event.said);
        }
        RecoveryOutcome::Contested => {
            println!(
                "{}",
                "KEL is now CONTESTED (adversary had recovery key)"
                    .red()
                    .bold()
            );
            println!("  The KEL is permanently frozen.");
            println!("  Event SAID: {}", event.said);
        }
    }

    Ok(())
}

async fn cmd_decommission(cli: &Cli, prefix: &str) -> Result<()> {
    println!(
        "{}",
        format!("Decommissioning KEL {}...", prefix).yellow().bold()
    );
    println!(
        "{}",
        "WARNING: This is permanent. No further events can be added.".red()
    );

    let client = create_client(cli);
    let key_provider = load_key_provider(cli, prefix).await?;
    let kel_store = create_kel_store(cli, Some(prefix))?;

    let mut builder = KeyEventBuilder::with_dependencies(
        key_provider,
        Some(client),
        Some(std::sync::Arc::new(kel_store)),
        Some(prefix),
    )
    .await?;

    let (event, _sig) = builder
        .decommission()
        .await
        .context("Decommission failed")?;

    println!("{}", "KEL decommissioned.".green().bold());
    println!("  Event SAID: {}", event.said);

    Ok(())
}

async fn cmd_get(cli: &Cli, prefix: &str, _audit: bool, since: Option<&str>) -> Result<()> {
    let client = create_client(cli);

    let kel = if let Some(since_ts) = since {
        // Incremental fetch - for now just fetch full KEL
        // TODO: implement since-based fetch when KelsClient supports it with timestamp
        println!(
            "{}",
            format!("Fetching KEL {} since {}...", prefix, since_ts).green()
        );
        client.fetch_full_kel(prefix).await?
    } else {
        println!("{}", format!("Fetching KEL {}...", prefix).green());
        client.fetch_full_kel(prefix).await?
    };

    println!();
    println!("{}", format!("KEL: {}", prefix).cyan().bold());
    println!("  Events: {}", kel.len());

    if let Some(last) = kel.last() {
        println!("  Latest SAID: {}", last.event.said);
        println!("  Latest Type: {}", last.event.kind);
    }

    if kel.is_decommissioned() {
        println!("  Status: {}", "DECOMMISSIONED".red());
    } else if kel.find_divergence().is_some() {
        println!("  Status: {}", "DIVERGENT".yellow());
    } else {
        println!("  Status: {}", "OK".green());
    }

    // Print events
    println!();
    println!("{}", "Events:".yellow().bold());
    for (i, signed_event) in kel.events().iter().enumerate() {
        let event = &signed_event.event;
        println!(
            "  [{}] {} - {} ({})",
            i,
            event.kind.as_str().to_uppercase(),
            &event.said[..16],
            event.created_at
        );
    }

    Ok(())
}

async fn cmd_list(cli: &Cli) -> Result<()> {
    let kel_dir = kel_dir(cli)?;

    if !kel_dir.exists() {
        println!("{}", "No KELs found.".yellow());
        return Ok(());
    }

    println!("{}", "Local KELs:".cyan().bold());

    let mut found = false;
    for entry in std::fs::read_dir(&kel_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().is_some_and(|e| e == "json")
            && let Some(stem) = path.file_stem()
            && let Some(prefix) = stem.to_str()
        {
            // Remove .kel suffix if present
            let prefix = prefix.strip_suffix(".kel").unwrap_or(prefix);
            println!("  {}", prefix);
            found = true;
        }
    }

    if !found {
        println!("{}", "  (none)".yellow());
    }

    Ok(())
}

async fn cmd_status(cli: &Cli, prefix: &str) -> Result<()> {
    let kel_store = create_kel_store(cli, Some(prefix))?;

    let kel = kel_store
        .load(prefix)
        .await?
        .ok_or_else(|| anyhow::anyhow!("KEL not found locally: {}", prefix))?;

    println!("{}", format!("KEL Status: {}", prefix).cyan().bold());
    println!("  Local Events: {}", kel.len());

    if let Some(last) = kel.last() {
        println!("  Latest SAID:  {}", last.event.said);
        println!("  Latest Type:  {}", last.event.kind);
        println!("  Created At:   {}", last.event.created_at);
    }

    if kel.is_decommissioned() {
        println!("  Status:       {}", "DECOMMISSIONED".red());
    } else if let Some(div) = kel.find_divergence() {
        println!("  Status:       {}", "DIVERGENT".yellow());
        println!("  Diverged At:  v{}", div.diverged_at_version);
    } else {
        println!("  Status:       {}", "OK".green());
    }

    // Check key files
    let key_dir = config_dir(cli)?.join("keys").join(prefix);
    let has_keys = key_dir.join("current.key").exists();
    println!(
        "  Keys:         {}",
        if has_keys {
            "present".green()
        } else {
            "missing".red()
        }
    );

    Ok(())
}

// ==================== Dev Commands ====================

#[cfg(feature = "dev-tools")]
async fn cmd_dev_truncate(cli: &Cli, prefix: &str, count: usize) -> Result<()> {
    println!(
        "{}",
        format!("Truncating local KEL {} to {} events...", prefix, count).yellow()
    );

    let kel_store = create_kel_store(cli, Some(prefix))?;

    let mut kel = kel_store
        .load(prefix)
        .await?
        .ok_or_else(|| anyhow::anyhow!("KEL not found locally: {}", prefix))?;

    if count >= kel.len() {
        println!("KEL already has {} events, nothing to truncate.", kel.len());
        return Ok(());
    }

    kel.truncate(count);
    kel_store.save(&kel).await?;

    println!(
        "{}",
        format!("Truncated to {} events.", count).green().bold()
    );

    Ok(())
}

#[cfg(feature = "dev-tools")]
async fn cmd_dev_dump_kel(cli: &Cli, prefix: &str) -> Result<()> {
    let kel_store = create_kel_store(cli, Some(prefix))?;

    let kel = kel_store
        .load(prefix)
        .await?
        .ok_or_else(|| anyhow::anyhow!("KEL not found locally: {}", prefix))?;

    let json = serde_json::to_string_pretty(kel.events())?;
    println!("{}", json);

    Ok(())
}

#[cfg(feature = "dev-tools")]
async fn cmd_adversary_inject(cli: &Cli, prefix: &str, events_str: &str) -> Result<()> {
    println!(
        "{}",
        format!("ADVERSARY: Injecting events to {} (server only)...", prefix)
            .yellow()
            .bold()
    );

    // Load the local KEL to get the chain state
    let kel_store = create_kel_store(cli, Some(prefix))?;
    let kel = kel_store
        .load(prefix)
        .await?
        .ok_or_else(|| anyhow::anyhow!("KEL not found locally: {}", prefix))?;

    // Create a separate key provider for the adversary (uses the same keys!)
    // In a real attack, adversary would have stolen/compromised these keys
    let key_provider = load_key_provider(cli, prefix).await?;

    // Parse event types
    let event_types: Vec<&str> = events_str.split(',').map(|s| s.trim()).collect();

    // Build events locally but DON'T save them
    let client = create_client(cli);
    let mut builder = KeyEventBuilder::with_kel(key_provider, None, &kel); // No client = offline

    let mut events_to_submit = Vec::new();

    for event_type in &event_types {
        match *event_type {
            "ixn" => {
                // Anchor must be a valid SAID (44 chars)
                // Dynamically pad based on version digit count
                let version_str = builder.version().to_string();
                let padding = 44 - 16 - version_str.len(); // 16 = "EAdversaryAnchor".len()
                let anchor = format!("EAdversaryAnchor{}{}", version_str, "_".repeat(padding));
                let (event, sig) = builder.interact(&anchor).await?;
                let public_key = builder.current_public_key().await?.qb64();
                events_to_submit.push(kels::SignedKeyEvent::new(event, public_key, sig.qb64()));
            }
            "rot" => {
                let (event, sig) = builder.rotate().await?;
                let public_key = builder.current_public_key().await?.qb64();
                events_to_submit.push(kels::SignedKeyEvent::new(event, public_key, sig.qb64()));
            }
            other => {
                bail!("Unsupported adversary event type: {}", other);
            }
        }
    }

    // Submit directly to server (bypassing local storage)
    let response = client.submit_events(&events_to_submit).await?;

    if response.accepted {
        println!(
            "{}",
            format!("Adversary injected {} events!", events_to_submit.len())
                .yellow()
                .bold()
        );
        for event in &events_to_submit {
            println!("  {} - {}", event.event.kind, event.event.said);
        }
    } else {
        println!("{}", "Injection rejected by server.".yellow());
        if let Some(diverged) = response.diverged_at {
            println!("  Diverged at: {}", diverged);
        }
    }

    Ok(())
}

// ==================== Main ====================

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Ensure config directory exists
    let config_dir = config_dir(&cli)?;
    std::fs::create_dir_all(&config_dir)?;

    match &cli.command {
        Commands::Incept => cmd_incept(&cli).await,
        Commands::Rotate { prefix } => cmd_rotate(&cli, prefix).await,
        Commands::RotateRecovery { prefix } => cmd_rotate_recovery(&cli, prefix).await,
        Commands::Anchor { prefix, said } => cmd_anchor(&cli, prefix, said).await,
        Commands::Recover { prefix } => cmd_recover(&cli, prefix).await,
        Commands::Decommission { prefix } => cmd_decommission(&cli, prefix).await,
        Commands::Get {
            prefix,
            audit,
            since,
        } => cmd_get(&cli, prefix, *audit, since.as_deref()).await,
        Commands::List => cmd_list(&cli).await,
        Commands::Status { prefix } => cmd_status(&cli, prefix).await,

        #[cfg(feature = "dev-tools")]
        Commands::Dev(dev_cmd) => match dev_cmd {
            DevCommands::Truncate { prefix, count } => cmd_dev_truncate(&cli, prefix, *count).await,
            DevCommands::DumpKel { prefix } => cmd_dev_dump_kel(&cli, prefix).await,
        },

        #[cfg(feature = "dev-tools")]
        Commands::Adversary(adv_cmd) => match adv_cmd {
            AdversaryCommands::Inject { prefix, events } => {
                cmd_adversary_inject(&cli, prefix, events).await
            }
        },
    }
}
