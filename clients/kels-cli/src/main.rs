//! kels-cli - KELS Command Line Interface

use std::path::PathBuf;

#[cfg(feature = "dev-tools")]
use anyhow::bail;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use kels::{
    FileKelStore, KelStore, KelsClient, KeyEventBuilder, NodeStatus, ProviderConfig,
    SoftwareProviderConfig,
};
use serde::{Deserialize, Serialize};

const DEFAULT_KELS_URL: &str = "http://kels.kels-node-a.local";
const DEFAULT_REGISTRY_URL: &str = "http://kels-registry.kels-registry.local";

/// Registry KEL prefix - trust anchor for verifying registry identity.
/// Must be set at compile time via REGISTRY_PREFIX environment variable.
const REGISTRY_PREFIX: &str = env!("REGISTRY_PREFIX");

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// KELS server URL (ignored if --auto-select is used)
    #[arg(short, long, env = "KELS_URL", default_value = DEFAULT_KELS_URL)]
    url: String,

    /// Registry URL for node discovery
    #[arg(long, env = "KELS_REGISTRY_URL", default_value = DEFAULT_REGISTRY_URL)]
    registry: String,

    /// Auto-select the fastest available node from registry (requires --registry)
    #[arg(long)]
    auto_select: bool,

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

    /// Recover from divergence by submitting a recovery event (rec).
    Recover {
        /// KEL prefix to recover
        #[arg(long)]
        prefix: String,
    },

    /// Contest a malicious recovery by submitting a contest event (cnt).
    /// Use this when an adversary has revealed your recovery key.
    /// The KEL will be permanently frozen after contesting.
    Contest {
        /// KEL prefix to contest
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
    },

    /// List all local KELs
    List,

    /// List registered nodes from registry
    ListNodes,

    /// Show status of a local KEL
    Status {
        /// KEL prefix
        #[arg(long)]
        prefix: String,
    },

    /// Reset local state (delete local KEL and keys)
    Reset {
        /// KEL prefix to reset (if omitted, resets all local state)
        #[arg(long)]
        prefix: Option<String>,

        /// Skip confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
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

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize, Default)]
struct Config {
    default_url: Option<String>,
    default_prefix: Option<String>,
}

fn config_dir(cli: &Cli) -> Result<PathBuf> {
    if let Some(ref dir) = cli.config_dir {
        return Ok(dir.clone());
    }

    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(home.join(".kels-cli"))
}

fn kel_dir(cli: &Cli) -> Result<PathBuf> {
    Ok(config_dir(cli)?.join("kels"))
}

fn provider_config(cli: &Cli, prefix: &str) -> Result<SoftwareProviderConfig> {
    let key_dir = config_dir(cli)?.join("keys").join(prefix);
    Ok(SoftwareProviderConfig::new(key_dir))
}

/// Verify the registry's KEL matches the expected prefix (trust anchor).
async fn verify_registry(registry_url: &str) -> Result<()> {
    use kels::KelsRegistryClient;

    let registry_client = KelsRegistryClient::new(registry_url);
    registry_client
        .verify_registry(REGISTRY_PREFIX)
        .await
        .context("Registry verification failed")?;

    Ok(())
}

async fn create_client(cli: &Cli) -> Result<KelsClient> {
    if cli.auto_select {
        // Verify registry identity before trusting node list
        verify_registry(&cli.registry).await?;

        let nodes = KelsClient::discover_nodes(&cli.registry)
            .await
            .context("Failed to discover nodes from registry")?;

        println!("{}", "Node Latencies:".cyan());
        for node in &nodes {
            let status_str = match node.status {
                NodeStatus::Ready => "READY".green(),
                NodeStatus::Bootstrapping => "BOOTSTRAPPING".yellow(),
                NodeStatus::Unhealthy => "UNHEALTHY".red(),
            };
            let latency_str = node
                .latency_ms
                .map(|ms| format!("{}ms", ms))
                .unwrap_or_else(|| "timeout".to_string());
            println!("  {} [{}] - {}", node.node_id, status_str, latency_str);
        }

        // Select best node (randomly among ties)
        use rand::seq::SliceRandom;

        // Filter to ready nodes with successful latency measurements
        let ready_nodes: Vec<_> = nodes
            .into_iter()
            .filter(|n| n.status == NodeStatus::Ready && n.latency_ms.is_some())
            .collect();

        if ready_nodes.is_empty() {
            return Err(anyhow::anyhow!(
                "No ready nodes with successful latency measurements available"
            ));
        }

        // Find minimum latency
        let min_latency = ready_nodes
            .iter()
            .filter_map(|n| n.latency_ms)
            .min()
            .context("No nodes with latency measurements")?;

        // Get all nodes with the minimum latency and pick randomly among ties
        let best_nodes: Vec<_> = ready_nodes
            .into_iter()
            .filter(|n| n.latency_ms == Some(min_latency))
            .collect();

        let best_node = best_nodes
            .choose(&mut rand::thread_rng())
            .context("No nodes available")?
            .clone();

        let latency = best_node
            .latency_ms
            .context("Selected node missing latency")?;

        println!(
            "{} {} ({}ms)",
            "Selected:".green().bold(),
            best_node.node_id,
            latency
        );
        println!();

        Ok(KelsClient::new(&best_node.kels_url))
    } else {
        Ok(KelsClient::new(&cli.url))
    }
}

fn create_kel_store(cli: &Cli, prefix: Option<&str>) -> Result<FileKelStore> {
    let dir = kel_dir(cli)?;
    if let Some(p) = prefix {
        FileKelStore::with_owner(dir, p.to_string()).context("Failed to create KEL store")
    } else {
        FileKelStore::new(dir).context("Failed to create KEL store")
    }
}

// ==================== Command Handlers ====================

async fn cmd_list_nodes(cli: &Cli) -> Result<()> {
    // Verify registry identity before trusting node list
    verify_registry(&cli.registry).await?;

    println!(
        "{}",
        format!("Discovering nodes from {}...", cli.registry).green()
    );

    let nodes = KelsClient::discover_nodes(&cli.registry).await?;

    if nodes.is_empty() {
        println!("{}", "No nodes registered.".yellow());
        return Ok(());
    }

    println!();
    println!("{}", "Registered Nodes:".cyan().bold());

    for node in &nodes {
        let status_str = match node.status {
            NodeStatus::Ready => "READY".green(),
            NodeStatus::Bootstrapping => "BOOTSTRAPPING".yellow(),
            NodeStatus::Unhealthy => "UNHEALTHY".red(),
        };

        let latency_str = node
            .latency_ms
            .map(|ms| format!("{}ms", ms))
            .unwrap_or_else(|| "-".to_string());

        println!(
            "  {} [{}] - {} (latency: {})",
            node.node_id, status_str, node.kels_url, latency_str
        );
    }

    Ok(())
}

async fn cmd_incept(cli: &Cli) -> Result<()> {
    println!("{}", "Creating new KEL...".green());

    let client = create_client(cli).await?;
    // Use a temporary config for init - we don't know the prefix yet
    let temp_config = SoftwareProviderConfig::new(config_dir(cli)?.join("keys").join("temp"));
    let key_provider = temp_config.load_provider().await?;
    let kel_store = create_kel_store(cli, None)?;

    let mut builder = KeyEventBuilder::with_dependencies(
        key_provider,
        Some(client),
        Some(std::sync::Arc::new(kel_store)),
        None,
    )
    .await?;

    let (event, _sig) = builder.incept().await.context("Inception failed")?;

    // Save to the correct prefix directory
    let config = provider_config(cli, &event.prefix)?;
    config.save_provider(builder.key_provider()).await?;
    let kel_store = create_kel_store(cli, Some(&event.prefix))?;
    kel_store.save(builder.kel()).await?;

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

    let config = provider_config(cli, prefix)?;
    let client = create_client(cli).await?;
    let key_provider = config.load_provider().await?;
    let kel_store = create_kel_store(cli, Some(prefix))?;

    let mut builder = KeyEventBuilder::with_dependencies(
        key_provider,
        Some(client),
        Some(std::sync::Arc::new(kel_store)),
        Some(prefix),
    )
    .await?;

    match builder.rotate().await {
        Ok((event, _sig)) => {
            config.save_provider(builder.key_provider()).await?;
            println!("{}", "Rotation successful!".green().bold());
            println!("  Event SAID: {}", event.said);
            Ok(())
        }
        Err(kels::KelsError::DivergenceDetected {
            submission_accepted: true,
            ref diverged_at,
        }) => {
            // Keys were committed internally - save them before returning error
            config.save_provider(builder.key_provider()).await?;
            Err(anyhow::anyhow!(
                "Divergence detected at: {}, submission_accepted: true",
                diverged_at
            ))
        }
        Err(e) => Err(e.into()),
    }
}

async fn cmd_rotate_recovery(cli: &Cli, prefix: &str) -> Result<()> {
    println!(
        "{}",
        format!("Rotating recovery key for {}...", prefix).green()
    );

    let config = provider_config(cli, prefix)?;
    let client = create_client(cli).await?;
    let key_provider = config.load_provider().await?;
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
    config.save_provider(builder.key_provider()).await?;

    println!("{}", "Recovery rotation successful!".green().bold());
    println!("  Event SAID: {}", event.said);

    Ok(())
}

async fn cmd_anchor(cli: &Cli, prefix: &str, said: &str) -> Result<()> {
    println!("{}", format!("Anchoring SAID in {}...", prefix).green());

    let client = create_client(cli).await?;
    let key_provider = provider_config(cli, prefix)?.load_provider().await?;
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

    let config = provider_config(cli, prefix)?;
    let client = create_client(cli).await?;
    let key_provider = config.load_provider().await?;
    let kel_store = create_kel_store(cli, Some(prefix))?;

    let mut builder = KeyEventBuilder::with_dependencies(
        key_provider,
        Some(client),
        Some(std::sync::Arc::new(kel_store)),
        Some(prefix),
    )
    .await?;

    let add_rot = builder.should_add_rot_with_recover().await?;
    let (event, _sig) = builder.recover(add_rot).await.context("Recovery failed")?;
    config.save_provider(builder.key_provider()).await?;

    println!("{}", "Recovery successful!".green().bold());
    println!("  Event SAID: {}", event.said);

    Ok(())
}

async fn cmd_contest(cli: &Cli, prefix: &str) -> Result<()> {
    println!("{}", format!("Contesting KEL {}...", prefix).red().bold());
    println!(
        "{}",
        "WARNING: This will permanently freeze the KEL.".yellow()
    );

    let client = create_client(cli).await?;
    let key_provider = provider_config(cli, prefix)?.load_provider().await?;
    let kel_store = create_kel_store(cli, Some(prefix))?;

    let mut builder = KeyEventBuilder::with_dependencies(
        key_provider,
        Some(client),
        Some(std::sync::Arc::new(kel_store)),
        Some(prefix),
    )
    .await?;

    let (event, _sig) = builder.contest().await.context("Contest failed")?;

    println!("{}", "KEL contested and permanently frozen.".red().bold());
    println!("  Event SAID: {}", event.said);

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

    let client = create_client(cli).await?;
    let key_provider = provider_config(cli, prefix)?.load_provider().await?;
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

async fn cmd_get(cli: &Cli, prefix: &str, audit: bool) -> Result<()> {
    let client = create_client(cli).await?;

    if audit {
        println!(
            "{}",
            format!("Fetching KEL {} with audit records...", prefix).green()
        );
        let response = client.fetch_kel_with_audit(prefix).await?;

        println!();
        println!("{}", format!("KEL: {}", prefix).cyan().bold());
        println!("  Events: {}", response.events.len());
        let kel = kels::Kel::from_events(response.events.clone(), true)?;

        if let Some(last) = kel.last() {
            println!("  Latest SAID: {}", last.event.said);
            println!("  Latest Type: {}", last.event.kind);
        }

        // Check contested/decommissioned first since they take precedence over divergent
        if kel.is_contested() {
            println!("  Status: {}", "CONTESTED".red());
        } else if kel.is_decommissioned() {
            println!("  Status: {}", "DECOMMISSIONED".red());
        } else if kel.find_divergence().is_some() {
            println!("  Status: {}", "DIVERGENT".yellow());
        } else {
            println!("  Status: {}", "OK".green());
        }

        println!();
        println!("{}", "Events:".yellow().bold());
        for (i, signed_event) in response.events.iter().enumerate() {
            let event = &signed_event.event;
            println!(
                "  [{}] {} - {}",
                i,
                event.kind.as_str().to_uppercase(),
                &event.said[..16]
            );
        }

        // Print audit records
        if let Some(audit_records) = &response.audit_records {
            println!();
            println!("{}", "Audit Records:".yellow().bold());
            for (i, record) in audit_records.iter().enumerate() {
                println!(
                    "  [{}] {} - {} ({})",
                    i,
                    record.kind.as_str().to_uppercase(),
                    &record.said[..16],
                    record.recorded_at
                );
                println!("      Data: {}", record.data_json);
            }
        } else {
            println!();
            println!("{}", "Audit Records: (none)".yellow());
        }

        return Ok(());
    }

    println!("{}", format!("Fetching KEL {}...", prefix).green());
    let kel = client.get_kel(prefix).await?;

    println!();
    println!("{}", format!("KEL: {}", prefix).cyan().bold());
    println!("  Events: {}", kel.len());

    if let Some(last) = kel.last() {
        println!("  Latest SAID: {}", last.event.said);
        println!("  Latest Type: {}", last.event.kind);
    }
    if kel.is_contested() {
        println!("  Status: {}", "CONTESTED".red());
    } else if kel.is_decommissioned() {
        println!("  Status: {}", "DECOMMISSIONED".red());
    } else if kel.find_divergence().is_some() {
        println!("  Status: {}", "DIVERGENT".yellow());
    } else {
        println!("  Status: {}", "OK".green());
    }
    println!();
    println!("{}", "Events:".yellow().bold());
    for (i, signed_event) in kel.events().iter().enumerate() {
        let event = &signed_event.event;
        println!(
            "  [{}] {} - {}",
            i,
            event.kind.as_str().to_uppercase(),
            &event.said[..16]
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
    }
    if kel.is_contested() {
        println!("  Status:       {}", "CONTESTED".red());
    } else if kel.is_decommissioned() {
        println!("  Status:       {}", "DECOMMISSIONED".red());
    } else if let Some(div) = kel.find_divergence() {
        println!("  Status:       {}", "DIVERGENT".yellow());
        println!("  Diverged At:  g{}", div.diverged_at_generation);
    } else {
        println!("  Status:       {}", "OK".green());
    }
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

async fn cmd_reset(cli: &Cli, prefix: Option<&str>, yes: bool) -> Result<()> {
    use std::io::{self, Write};

    let config = config_dir(cli)?;
    let kel_dir = kel_dir(cli)?;
    let keys_dir = config.join("keys");

    if let Some(p) = prefix {
        // Reset specific KEL
        let kel_file = kel_dir.join(format!("{}.kel.json", p));
        let key_dir = keys_dir.join(p);

        if !kel_file.exists() && !key_dir.exists() {
            println!("{}", format!("No local state found for {}", p).yellow());
            return Ok(());
        }

        if !yes {
            print!(
                "{}",
                format!(
                    "Reset local state for {}? This will delete local KEL and keys. [y/N] ",
                    p
                )
                .red()
            );
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                println!("Aborted.");
                return Ok(());
            }
        }

        if kel_file.exists() {
            std::fs::remove_file(&kel_file)?;
            println!("  Deleted KEL: {}", kel_file.display());
        }
        if key_dir.exists() {
            std::fs::remove_dir_all(&key_dir)?;
            println!("  Deleted keys: {}", key_dir.display());
        }

        println!("{}", format!("Reset complete for {}", p).green().bold());
    } else {
        // Reset all local state
        if !yes {
            print!(
                "{}",
                "Reset ALL local state? This will delete ALL local KELs and keys. [y/N] "
                    .red()
                    .bold()
            );
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                println!("Aborted.");
                return Ok(());
            }
        }

        let mut count = 0;
        if kel_dir.exists() {
            for entry in std::fs::read_dir(&kel_dir)? {
                let entry = entry?;
                std::fs::remove_file(entry.path())?;
                count += 1;
            }
            println!("  Deleted {} KEL file(s)", count);
        }

        if keys_dir.exists() {
            let key_count = std::fs::read_dir(&keys_dir)?.count();
            std::fs::remove_dir_all(&keys_dir)?;
            std::fs::create_dir_all(&keys_dir)?;
            println!("  Deleted {} key directory(ies)", key_count);
        }

        println!(
            "{}",
            "Reset complete - all local state cleared.".green().bold()
        );
    }

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

    // Load the key provider (adversary has the same keys as owner)
    let key_provider = provider_config(cli, prefix)?.load_provider().await?;

    // Parse event types
    let event_types: Vec<&str> = events_str.split(',').map(|s| s.trim()).collect();

    let has_recovery = event_types.iter().any(|e| matches!(*e, "rec" | "ror"));

    if has_recovery {
        println!(
            "{}",
            "(Includes recovery event - simulates true key compromise)".yellow()
        );
    }

    // Create adversary builder WITH KELS client but NO kel_store
    // Events submit to KELS but don't save locally (simulating adversary)
    let client = create_client(cli).await?;
    let mut builder = KeyEventBuilder::with_kel(key_provider, Some(client), None, kel)?;

    let mut saids = Vec::new();
    let mut counter = 0u32;

    for event_type in &event_types {
        let (event, _) = match *event_type {
            "ixn" => {
                // Generate a realistic 44-char SAID-like anchor
                let anchor = format!(
                    "EAdversaryAnchor{}{}",
                    counter,
                    "_".repeat(44 - 16 - counter.to_string().len())
                );
                counter += 1;
                builder.interact(&anchor).await?
            }
            "rot" => builder.rotate().await?,
            "rec" | "ror" => {
                // Both rec and ror prove the adversary has both signing and recovery keys.
                // Use rotate_recovery() which creates a ror event with dual signatures.
                builder.rotate_recovery().await?
            }
            "dec" => builder.decommission().await?,
            other => {
                bail!(
                    "Unsupported adversary event type: {}. Valid types: ixn, rot, rec, ror, dec",
                    other
                );
            }
        };
        saids.push(event.said.clone());
    }

    println!(
        "{}",
        format!("Adversary injected {} events!", saids.len())
            .yellow()
            .bold()
    );
    for (i, said) in saids.iter().enumerate() {
        println!("  Event {}: {}", i + 1, said);
    }
    println!(
        "{}",
        "Local state NOT updated (simulating adversary)".yellow()
    );

    Ok(())
}

// ==================== Main ====================

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config_dir = config_dir(&cli)?;
    std::fs::create_dir_all(&config_dir)?;

    match &cli.command {
        Commands::Incept => cmd_incept(&cli).await,
        Commands::Rotate { prefix } => cmd_rotate(&cli, prefix).await,
        Commands::RotateRecovery { prefix } => cmd_rotate_recovery(&cli, prefix).await,
        Commands::Anchor { prefix, said } => cmd_anchor(&cli, prefix, said).await,
        Commands::Recover { prefix } => cmd_recover(&cli, prefix).await,
        Commands::Contest { prefix } => cmd_contest(&cli, prefix).await,
        Commands::Decommission { prefix } => cmd_decommission(&cli, prefix).await,
        Commands::Get { prefix, audit } => cmd_get(&cli, prefix, *audit).await,
        Commands::List => cmd_list(&cli).await,
        Commands::ListNodes => cmd_list_nodes(&cli).await,
        Commands::Status { prefix } => cmd_status(&cli, prefix).await,
        Commands::Reset { prefix, yes } => cmd_reset(&cli, prefix.as_deref(), *yes).await,

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
