//! kels-cli - KELS Command Line Interface

use std::{iter, path::PathBuf};

#[cfg(feature = "dev-tools")]
use anyhow::bail;
use anyhow::{Context, Result, anyhow};
use cesr::Matter;
use clap::{Parser, Subcommand};
use colored::Colorize;
#[cfg(feature = "dev-tools")]
use kels::{EventKind, KelStore};
use kels::{
    FileKelStore, HttpKelSource, KelVerification, KelVerifier, KelsClient, KeyEventBuilder,
    KeyProvider, NodeStatus, ProviderConfig, SoftwareKeyProvider, SoftwareProviderConfig,
    VerificationKeyCode,
};

const DEFAULT_BASE_DOMAIN: &str = "kels-node-a.kels";
const DEFAULT_REGISTRY_URL: &str = "http://kels-registry.kels-registry-a.kels";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Base domain for service discovery (e.g., "kels-node-a.kels").
    /// KELS URL = http://kels.{domain}, SADStore URL = http://kels-sadstore.{domain}
    #[arg(short = 'd', long, env = "BASE_DOMAIN", default_value = DEFAULT_BASE_DOMAIN)]
    base_domain: String,

    /// Registry URLs for node discovery (comma-separated)
    #[arg(long, env = "KELS_REGISTRY_URLS", default_value = DEFAULT_REGISTRY_URL)]
    registry: String,

    /// Auto-select the fastest available node from registry (requires --registry)
    #[arg(long)]
    auto_select: bool,

    /// Override KELS URL (takes precedence over base_domain)
    #[arg(long, env = "KELS_URL")]
    kels_url: Option<String>,

    /// Override SADStore URL (takes precedence over base_domain)
    #[arg(long, env = "SADSTORE_URL")]
    sadstore_url: Option<String>,

    /// Config directory (default: ~/.kels-cli)
    #[arg(long, env = "KELS_CLI_HOME")]
    config_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Create a new KEL (inception event)
    Incept {
        /// Signing key algorithm (ml-dsa-65, ml-dsa-87, or secp256r1)
        #[arg(long, default_value = "ml-dsa-65")]
        signing_algorithm: String,

        /// Recovery key algorithm (defaults to signing algorithm)
        #[arg(long)]
        recovery_algorithm: Option<String>,
    },

    /// Rotate the signing key
    Rotate {
        /// KEL prefix to rotate
        #[arg(long)]
        prefix: String,

        /// Algorithm for the new signing key (defaults to current)
        #[arg(long)]
        algorithm: Option<String>,
    },

    /// Rotate both signing and recovery keys (requires dual signatures)
    RotateRecovery {
        /// KEL prefix
        #[arg(long)]
        prefix: String,

        /// Algorithm for the new signing key (defaults to current)
        #[arg(long)]
        signing_algorithm: Option<String>,

        /// Algorithm for the new recovery key (defaults to current)
        #[arg(long)]
        recovery_algorithm: Option<String>,
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

        /// Algorithm for the new signing key (defaults to current)
        #[arg(long)]
        signing_algorithm: Option<String>,

        /// Algorithm for the new recovery key (defaults to current)
        #[arg(long)]
        recovery_algorithm: Option<String>,
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

    /// Sign arbitrary data with the current signing key and print the CESR signature
    Sign {
        /// KEL prefix whose signing key to use
        #[arg(long)]
        prefix: String,

        /// Data to sign (raw string)
        data: String,
    },

    /// SAD store commands (self-addressed data)
    #[command(subcommand)]
    Sad(SadCommands),

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

#[derive(Subcommand, Debug)]
enum SadCommands {
    /// Store a self-addressed JSON object in the SAD store
    Put {
        /// Path to JSON file containing the self-addressed object
        file: PathBuf,
    },

    /// Retrieve a self-addressed object by SAID
    Get {
        /// The SAID of the object to retrieve
        said: String,
    },

    /// Submit a signed SAD record to a chain
    Submit {
        /// Path to JSON file containing SignedSadRecord(s)
        file: PathBuf,
    },

    /// Fetch and display a SAD record chain
    Chain {
        /// The chain prefix to fetch
        prefix: String,
    },

    /// Compute a SAD chain prefix from a KEL prefix and kind
    Prefix {
        /// The KEL prefix
        kel_prefix: String,

        /// The record kind (e.g., "kels/v1/mlkem-pubkey")
        kind: String,
    },
}

fn parse_algorithm(algorithm: &str) -> Result<VerificationKeyCode> {
    match algorithm {
        "secp256r1" => Ok(VerificationKeyCode::Secp256r1),
        "ml-dsa-65" => Ok(VerificationKeyCode::MlDsa65),
        "ml-dsa-87" => Ok(VerificationKeyCode::MlDsa87),
        _ => Err(anyhow!(
            "Unknown algorithm '{}'. Valid options: secp256r1, ml-dsa-65, ml-dsa-87",
            algorithm
        )),
    }
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
    Ok(SoftwareProviderConfig::new(
        key_dir,
        VerificationKeyCode::MlDsa65,
        VerificationKeyCode::MlDsa65,
    ))
}

/// Parse comma-separated registry URLs into a Vec.
fn parse_registry_urls(registry: &str) -> Vec<String> {
    registry
        .split(',')
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
        .collect()
}

async fn create_client(cli: &Cli) -> Result<KelsClient> {
    if cli.auto_select {
        let registry_urls = parse_registry_urls(&cli.registry);
        if registry_urls.is_empty() {
            return Err(anyhow!("No registry URLs provided"));
        }

        let store = create_kel_store(cli, "registry-discovery")?;
        let nodes = kels::nodes_sorted_by_latency(
            &registry_urls,
            std::time::Duration::from_secs(2),
            &store,
        )
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
        println!();

        let url = match nodes.first() {
            Some(n) => format!("http://kels.{}", n.base_domain),
            None => return Err(anyhow!("Failed to find kels url of fastest node")),
        };
        Ok(KelsClient::new(&url)?)
    } else {
        Ok(KelsClient::new(&cli.kels_url())?)
    }
}

impl Cli {
    fn kels_url(&self) -> String {
        self.kels_url
            .clone()
            .unwrap_or_else(|| format!("http://kels.{}", self.base_domain))
    }

    fn sadstore_url(&self) -> String {
        self.sadstore_url
            .clone()
            .unwrap_or_else(|| format!("http://kels-sadstore.{}", self.base_domain))
    }
}

fn create_kel_store(cli: &Cli, prefix: &str) -> Result<FileKelStore> {
    let dir = kel_dir(cli)?;
    FileKelStore::with_owner(dir, prefix.to_string()).context("Failed to create KEL store")
}

// ==================== Command Handlers ====================

async fn cmd_list_nodes(cli: &Cli) -> Result<()> {
    let registry_urls = parse_registry_urls(&cli.registry);
    if registry_urls.is_empty() {
        return Err(anyhow!("No registry URLs provided"));
    }

    println!(
        "{}",
        format!("Discovering nodes from {}...", cli.registry).green()
    );

    let store = create_kel_store(cli, "registry-discovery")?;
    let nodes =
        kels::nodes_sorted_by_latency(&registry_urls, std::time::Duration::from_secs(2), &store)
            .await?;

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
            node.node_id, status_str, node.base_domain, latency_str
        );
    }

    Ok(())
}

async fn cmd_incept(
    cli: &Cli,
    signing: VerificationKeyCode,
    recovery: VerificationKeyCode,
) -> Result<()> {
    println!("{}", "Creating new KEL...".green());

    let client = create_client(cli).await?;
    let key_provider = SoftwareKeyProvider::new(signing, recovery);

    // Pass a kel_store to the builder so add_and_flush saves automatically
    let kel_dir = kel_dir(cli)?;
    let kel_store = FileKelStore::new(&kel_dir).context("Failed to create KEL store")?;
    let mut builder = KeyEventBuilder::with_dependencies(
        key_provider,
        Some(client),
        Some(std::sync::Arc::new(kel_store)),
        None,
    )
    .await?;

    let icp = builder.incept().await.context("Inception failed")?;

    // Save keys to the correct prefix directory
    let config = provider_config(cli, &icp.event.prefix)?;
    config.save_provider(builder.key_provider()).await?;

    println!("{}", "KEL created successfully!".green().bold());
    println!("  Prefix: {}", icp.event.prefix.cyan());
    println!("  SAID:   {}", icp.event.said);

    Ok(())
}

async fn cmd_rotate(cli: &Cli, prefix: &str, algorithm: Option<VerificationKeyCode>) -> Result<()> {
    println!(
        "{}",
        format!("Rotating signing key for {}...", prefix).green()
    );

    let config = provider_config(cli, prefix)?;
    let client = create_client(cli).await?;
    let key_provider = config.load_provider().await?;
    let kel_store = create_kel_store(cli, prefix)?;

    let mut builder = KeyEventBuilder::with_dependencies(
        key_provider,
        Some(client),
        Some(std::sync::Arc::new(kel_store)),
        Some(prefix),
    )
    .await?;

    if let Some(algo) = algorithm {
        builder
            .key_provider_mut()
            .set_signing_algorithm(algo)
            .await?;
    }

    match builder.rotate().await {
        Ok(rot) => {
            config.save_provider(builder.key_provider()).await?;
            println!("{}", "Rotation successful!".green().bold());
            println!("  Event SAID: {}", rot.event.said);
            Ok(())
        }
        Err(kels::KelsError::DivergenceDetected {
            submission_accepted: true,
            ref diverged_at,
        }) => {
            // Keys were committed internally - save them before returning error
            config.save_provider(builder.key_provider()).await?;
            Err(anyhow!(
                "Divergence detected at: {}, submission_accepted: true",
                diverged_at
            ))
        }
        Err(e) => Err(e.into()),
    }
}

async fn cmd_rotate_recovery(
    cli: &Cli,
    prefix: &str,
    signing_algorithm: Option<VerificationKeyCode>,
    recovery_algorithm: Option<VerificationKeyCode>,
) -> Result<()> {
    println!(
        "{}",
        format!("Rotating signing and recovery keys for {}...", prefix).green()
    );

    let config = provider_config(cli, prefix)?;
    let client = create_client(cli).await?;
    let key_provider = config.load_provider().await?;
    let kel_store = create_kel_store(cli, prefix)?;

    let mut builder = KeyEventBuilder::with_dependencies(
        key_provider,
        Some(client),
        Some(std::sync::Arc::new(kel_store)),
        Some(prefix),
    )
    .await?;

    if let Some(algo) = signing_algorithm {
        builder
            .key_provider_mut()
            .set_signing_algorithm(algo)
            .await?;
    }
    if let Some(algo) = recovery_algorithm {
        builder
            .key_provider_mut()
            .set_recovery_algorithm(algo)
            .await?;
    }

    let ror = builder
        .rotate_recovery()
        .await
        .context("Recovery rotation failed")?;
    config.save_provider(builder.key_provider()).await?;

    println!("{}", "Recovery rotation successful!".green().bold());
    println!("  Event SAID: {}", ror.event.said);

    Ok(())
}

async fn cmd_sign(cli: &Cli, prefix: &str, data: &str) -> Result<()> {
    let key_provider = provider_config(cli, prefix)?.load_provider().await?;
    let sig = key_provider
        .sign(data.as_bytes())
        .await
        .context("Signing failed")?;
    println!("{}", sig.qb64());
    Ok(())
}

async fn cmd_anchor(cli: &Cli, prefix: &str, said: &str) -> Result<()> {
    println!("{}", format!("Anchoring SAID in {}...", prefix).green());

    let client = create_client(cli).await?;
    let key_provider = provider_config(cli, prefix)?.load_provider().await?;
    let kel_store = create_kel_store(cli, prefix)?;

    let mut builder = KeyEventBuilder::with_dependencies(
        key_provider,
        Some(client),
        Some(std::sync::Arc::new(kel_store)),
        Some(prefix),
    )
    .await?;

    let ixn = builder.interact(said).await.context("Interaction failed")?;

    println!("{}", "Anchor successful!".green().bold());
    println!("  Event SAID: {}", ixn.event.said);
    println!("  Anchored:   {}", said);

    Ok(())
}

async fn cmd_recover(
    cli: &Cli,
    prefix: &str,
    signing_algorithm: Option<&str>,
    recovery_algorithm: Option<&str>,
) -> Result<()> {
    println!("{}", format!("Recovering KEL {}...", prefix).yellow());

    let config = provider_config(cli, prefix)?;
    let client = create_client(cli).await?;
    let mut key_provider = config.load_provider().await?;

    if let Some(algo) = signing_algorithm {
        let algo = parse_algorithm(algo)?;
        key_provider.set_signing_algorithm(algo).await?;
    }
    if let Some(algo) = recovery_algorithm {
        let algo = parse_algorithm(algo)?;
        key_provider.set_recovery_algorithm(algo).await?;
    }

    let kel_store = create_kel_store(cli, prefix)?;

    let mut builder = KeyEventBuilder::with_dependencies(
        key_provider,
        Some(client.clone()),
        Some(std::sync::Arc::new(kel_store)),
        Some(prefix),
    )
    .await?;

    // Verify server KEL to detect if adversary revealed the rotation key
    let source = kels::HttpKelSource::new(client.base_url(), "/api/v1/kels/kel/{prefix}")?;
    let server_verification = kels::verify_key_events(
        prefix,
        &source,
        KelVerifier::new(prefix),
        kels::page_size(),
        kels::max_pages(),
    )
    .await
    .map_err(|e| anyhow!("{}", e))?;
    let owner_last_est_serial = builder
        .last_establishment_event()
        .map(|e| e.serial)
        .unwrap_or(0);
    let add_rot = kels::should_rotate_with_recovery(
        &server_verification,
        builder.rotation_count(),
        owner_last_est_serial,
    );
    let rec = builder.recover(add_rot).await.context("Recovery failed")?;
    config.save_provider(builder.key_provider()).await?;

    println!("{}", "Recovery successful!".green().bold());
    println!("  Event SAID: {}", rec.event.said);

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
    let kel_store = create_kel_store(cli, prefix)?;

    let mut builder = KeyEventBuilder::with_dependencies(
        key_provider,
        Some(client),
        Some(std::sync::Arc::new(kel_store)),
        Some(prefix),
    )
    .await?;

    let cnt = builder.contest().await.context("Contest failed")?;

    println!("{}", "KEL contested and permanently frozen.".red().bold());
    println!("  Event SAID: {}", cnt.event.said);

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
    let kel_store = create_kel_store(cli, prefix)?;

    let mut builder = KeyEventBuilder::with_dependencies(
        key_provider,
        Some(client),
        Some(std::sync::Arc::new(kel_store)),
        Some(prefix),
    )
    .await?;

    let dec = builder
        .decommission()
        .await
        .context("Decommission failed")?;

    println!("{}", "KEL decommissioned.".green().bold());
    println!("  Event SAID: {}", dec.event.said);

    Ok(())
}

fn print_kel_status(kel_verification: &KelVerification, verbose: bool) {
    if verbose {
        println!("  Verified: Yes");
    }
    if kel_verification.is_contested() {
        println!("  Status: {}", "CONTESTED".red());
    } else if kel_verification.is_decommissioned() {
        println!("  Status: {}", "DECOMMISSIONED".red());
    } else if kel_verification.is_divergent() {
        println!("  Status: {}", "DIVERGENT".yellow());
    } else {
        println!("  Status: {}", "OK".green());
    }
}

fn print_kel_summary(prefix: &str, kel_verification: &KelVerification) {
    println!();
    println!("{}", format!("KEL: {}", prefix).cyan().bold());
    println!("  Events: {}", kel_verification.event_count());

    if let Some(tip) = kel_verification.branch_tips().last() {
        println!("  Latest SAID: {}", tip.tip.event.said);
        println!("  Latest Type: {}", tip.tip.event.kind);
    }
}

async fn cmd_get(cli: &Cli, prefix: &str, audit: bool) -> Result<()> {
    let client = create_client(cli).await?;
    let source = HttpKelSource::new(client.base_url(), "/api/v1/kels/kel/{prefix}")?;

    let msg = if audit {
        format!("Fetching KEL {} with audit records...", prefix)
    } else {
        format!("Fetching KEL {}...", prefix)
    };
    println!("{}", msg.green());

    // Verify and print events in a single pass
    let kel_verification = kels::verify_key_events_with(
        prefix,
        &source,
        KelVerifier::new(prefix),
        kels::page_size(),
        kels::max_pages(),
        |events| {
            for signed_event in events {
                let event = &signed_event.event;
                println!(
                    "  [{}] {} - {}",
                    event.serial,
                    event.kind.as_str().to_uppercase(),
                    &event.said[..16]
                );
            }
        },
    )
    .await
    .map_err(|e| anyhow!("{}", e))?;

    print_kel_summary(prefix, &kel_verification);
    print_kel_status(&kel_verification, !audit);

    if audit {
        let mut all_records = Vec::new();
        let mut offset = 0u64;
        loop {
            let page = client
                .fetch_kel_audit(prefix, kels::page_size(), offset)
                .await?;
            all_records.extend(page.records);
            if !page.has_more {
                break;
            }
            offset += kels::page_size() as u64;
        }
        if !all_records.is_empty() {
            println!();
            println!("{}", "Recovery History:".yellow().bold());
            for (i, record) in all_records.iter().enumerate() {
                println!("  [{}] {} ({})", i, &record.said[..16], record.created_at);
                println!(
                    "      diverged_at={} recovery_serial={}",
                    record.diverged_at, record.recovery_serial
                );
            }
        } else {
            println!();
            println!("{}", "Recovery History: (none)".yellow());
        }
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

        if path.extension().is_some_and(|e| e == "jsonl")
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
    let kel_store = create_kel_store(cli, prefix)?;

    let kel_verification = kels::completed_verification(
        &mut kels::StorePageLoader::new(&kel_store),
        prefix,
        kels::page_size(),
        kels::max_pages(),
        iter::empty(),
    )
    .await?;

    if kel_verification.is_empty() {
        return Err(anyhow!("KEL not found locally: {}", prefix));
    }

    let event_count = kel_verification.event_count();

    println!("{}", format!("KEL Status: {}", prefix).cyan().bold());
    println!("  Local Events: {}", event_count);

    if let Some(bt) = kel_verification.branch_tips().first() {
        println!("  Latest SAID:  {}", bt.tip.event.said);
        println!("  Latest Type:  {}", bt.tip.event.kind);
    }
    if kel_verification.is_contested() {
        println!("  Status:       {}", "CONTESTED".red());
    } else if kel_verification.is_decommissioned() {
        println!("  Status:       {}", "DECOMMISSIONED".red());
    } else if kel_verification.is_divergent() {
        println!("  Status:       {}", "DIVERGENT".yellow());
        if let Some(serial) = kel_verification.diverged_at_serial() {
            println!("  Diverged At:  s{}", serial);
        }
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

    let kel_store = create_kel_store(cli, prefix)?;
    let source = kels::StoreKelSource::new(&kel_store);

    let mut events =
        kels::resolve_key_events(prefix, &source, kels::page_size(), kels::max_pages(), None)
            .await
            .map_err(|e| anyhow!("{}", e))?;
    if events.is_empty() {
        return Err(anyhow!("KEL not found locally: {}", prefix));
    }
    if count >= events.len() {
        println!(
            "KEL already has {} events, nothing to truncate.",
            events.len()
        );
        return Ok(());
    }

    events.truncate(count);
    kel_store.overwrite(prefix, &events).await?;

    println!(
        "{}",
        format!("Truncated to {} events.", count).green().bold()
    );

    Ok(())
}

#[cfg(feature = "dev-tools")]
async fn cmd_dev_dump_kel(cli: &Cli, prefix: &str) -> Result<()> {
    let kel_store = create_kel_store(cli, prefix)?;
    let source = kels::StoreKelSource::new(&kel_store);
    let all_events =
        kels::resolve_key_events(prefix, &source, kels::page_size(), kels::max_pages(), None)
            .await
            .map_err(|e| anyhow!("{}", e))?;

    if all_events.is_empty() {
        return Err(anyhow!("KEL not found locally: {}", prefix));
    }

    let json = serde_json::to_string_pretty(&all_events)?;
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

    // Load the local KEL to get the chain state (dev-tools, not production)
    let kel_store = create_kel_store(cli, prefix)?;
    let source = kels::StoreKelSource::new(&kel_store);
    let events =
        kels::resolve_key_events(prefix, &source, kels::page_size(), kels::max_pages(), None)
            .await
            .map_err(|e| anyhow!("{}", e))?;
    if events.is_empty() {
        return Err(anyhow!("KEL not found locally: {}", prefix));
    }

    // Load the key provider (adversary has the same keys as owner)
    let key_provider = provider_config(cli, prefix)?.load_provider().await?;

    // Parse event types
    let event_kinds: Vec<EventKind> = events_str
        .split(',')
        .map(|s| EventKind::from_short_name(s.trim()))
        .collect::<Result<_, _>>()?;

    let has_recovery = event_kinds.iter().any(|k| k.reveals_recovery_key());

    if has_recovery {
        println!(
            "{}",
            "(Includes recovery event - simulates true key compromise)".yellow()
        );
    }

    // Create adversary builder WITH KELS client but NO kel_store
    // Events submit to KELS but don't save locally (simulating adversary)
    let client = create_client(cli).await?;
    let mut builder = KeyEventBuilder::with_events(key_provider, Some(client), None, events);

    let mut saids = Vec::new();

    for kind in &event_kinds {
        let signed = match kind {
            EventKind::Ixn => {
                let anchor = kels::generate_nonce();
                builder.interact(&anchor).await?
            }
            EventKind::Rot => builder.rotate().await?,
            EventKind::Rec => builder.recover(false).await?,
            EventKind::Ror => builder.rotate_recovery().await?,
            EventKind::Dec => builder.decommission().await?,
            other => {
                bail!(
                    "Unsupported adversary event type: {}. Valid types: ixn, rot, rec, ror, dec",
                    other
                );
            }
        };
        saids.push(signed.event.said.clone());
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

// ==================== SAD Commands ====================

async fn cmd_sad_put(cli: &Cli, file: &PathBuf) -> Result<()> {
    use verifiable_storage::SelfAddressed;

    let data = std::fs::read_to_string(file)
        .with_context(|| format!("Failed to read file: {}", file.display()))?;
    let mut value: serde_json::Value =
        serde_json::from_str(&data).context("Failed to parse JSON file")?;

    // Compute the SAID if missing or placeholder
    let current_said = value.get_said();
    if current_said.is_empty() || current_said.chars().all(|c| c == '#') {
        value
            .derive_said()
            .context("Failed to compute SAID for object")?;
    }

    let client = kels::SadStoreClient::new(&cli.sadstore_url())?;
    let said = client
        .put_sad_object(&value)
        .await
        .context("Failed to store SAD object")?;

    println!("{}", said);
    Ok(())
}

async fn cmd_sad_get(cli: &Cli, said: &str) -> Result<()> {
    let client = kels::SadStoreClient::new(&cli.sadstore_url())?;
    let value = client
        .get_sad_object(said)
        .await
        .context("Failed to retrieve SAD object")?;

    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

async fn cmd_sad_submit(cli: &Cli, file: &PathBuf) -> Result<()> {
    let data = std::fs::read_to_string(file)
        .with_context(|| format!("Failed to read file: {}", file.display()))?;
    let records: Vec<kels::SignedSadRecord> =
        serde_json::from_str(&data).context("Failed to parse SignedSadRecord JSON")?;

    let client = kels::SadStoreClient::new(&cli.sadstore_url())?;
    client
        .submit_sad_records(&records)
        .await
        .context("Failed to submit SAD records")?;

    println!(
        "{}",
        format!("{} SAD record(s) submitted", records.len()).green()
    );
    Ok(())
}

async fn cmd_sad_chain(cli: &Cli, prefix: &str) -> Result<()> {
    let client = kels::SadStoreClient::new(&cli.sadstore_url())?;
    let page = client
        .fetch_sad_chain(prefix, None)
        .await
        .context("Failed to fetch SAD chain")?;

    println!("{}", serde_json::to_string_pretty(&page)?);
    Ok(())
}

fn cmd_sad_prefix(kel_prefix: &str, kind: &str) -> Result<()> {
    let prefix =
        kels::compute_sad_prefix(kel_prefix, kind).context("Failed to compute SAD prefix")?;
    println!("{}", prefix);
    Ok(())
}

// ==================== Main ====================

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config_dir = config_dir(&cli)?;
    std::fs::create_dir_all(&config_dir)?;

    match &cli.command {
        Commands::Incept {
            signing_algorithm,
            recovery_algorithm,
        } => {
            let signing = parse_algorithm(signing_algorithm)?;
            let recovery = match recovery_algorithm.as_deref() {
                Some(a) => parse_algorithm(a)?,
                None => signing,
            };
            cmd_incept(&cli, signing, recovery).await
        }
        Commands::Rotate { prefix, algorithm } => {
            let algo = algorithm.as_deref().map(parse_algorithm).transpose()?;
            cmd_rotate(&cli, prefix, algo).await
        }
        Commands::RotateRecovery {
            prefix,
            signing_algorithm,
            recovery_algorithm,
        } => {
            let signing = signing_algorithm
                .as_deref()
                .map(parse_algorithm)
                .transpose()?;
            let recovery = recovery_algorithm
                .as_deref()
                .map(parse_algorithm)
                .transpose()?;
            cmd_rotate_recovery(&cli, prefix, signing, recovery).await
        }
        Commands::Sign { prefix, data } => cmd_sign(&cli, prefix, data).await,
        Commands::Anchor { prefix, said } => cmd_anchor(&cli, prefix, said).await,
        Commands::Recover {
            prefix,
            signing_algorithm,
            recovery_algorithm,
        } => {
            cmd_recover(
                &cli,
                prefix,
                signing_algorithm.as_deref(),
                recovery_algorithm.as_deref(),
            )
            .await
        }
        Commands::Contest { prefix } => cmd_contest(&cli, prefix).await,
        Commands::Decommission { prefix } => cmd_decommission(&cli, prefix).await,
        Commands::Get { prefix, audit } => cmd_get(&cli, prefix, *audit).await,
        Commands::List => cmd_list(&cli).await,
        Commands::ListNodes => cmd_list_nodes(&cli).await,
        Commands::Status { prefix } => cmd_status(&cli, prefix).await,
        Commands::Reset { prefix, yes } => cmd_reset(&cli, prefix.as_deref(), *yes).await,

        Commands::Sad(sad_cmd) => match sad_cmd {
            SadCommands::Put { file } => cmd_sad_put(&cli, file).await,
            SadCommands::Get { said } => cmd_sad_get(&cli, said).await,
            SadCommands::Submit { file } => cmd_sad_submit(&cli, file).await,
            SadCommands::Chain { prefix } => cmd_sad_chain(&cli, prefix).await,
            SadCommands::Prefix { kel_prefix, kind } => cmd_sad_prefix(kel_prefix, kind),
        },

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
