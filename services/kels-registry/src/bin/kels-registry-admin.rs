//! kels-registry-admin CLI - Peer allowlist management
//!
//! This CLI manages the peer allowlist in the kels-registry.
//! It connects to PostgreSQL for peer data and the identity service for KEL operations.

use anyhow::{Context, anyhow};
use clap::{Parser, Subcommand};
use kels::Peer;
use std::sync::Arc;
use verifiable_storage::VersionedRepository;
use verifiable_storage_postgres::PgPool;

use kels_registry::identity_client::IdentityClient;
use kels_registry::peer_store::PeerRepository;

#[derive(Parser)]
#[command(name = "kels-registry-admin")]
#[command(about = "KELS Registry Administration CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage peers in the allowlist
    Peer {
        #[command(subcommand)]
        action: PeerAction,
    },
    /// View allowlist information
    Allowlist {
        #[command(subcommand)]
        action: AllowlistAction,
    },
    /// Show registry identity status (managed by identity service)
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },
}

#[derive(Subcommand)]
enum PeerAction {
    /// Add a peer to the allowlist
    Add {
        /// libp2p PeerId (Base58 encoded)
        #[arg(long)]
        peer_id: String,
        /// Human-readable node name
        #[arg(long)]
        node_id: String,
    },
    /// Remove a peer from the allowlist
    Remove {
        /// libp2p PeerId (Base58 encoded)
        #[arg(long)]
        peer_id: String,
    },
    /// List all peers in the allowlist
    List,
}

#[derive(Subcommand)]
enum AllowlistAction {
    /// Show the current allowlist
    Show,
    /// Show allowlist version history
    History,
}

#[derive(Subcommand)]
enum IdentityAction {
    /// Show registry identity status
    Status {
        /// Output as JSON
        #[arg(short, long)]
        json: bool,
    },
}

/// Shared context for all commands
struct AdminContext {
    peer_repo: Arc<PeerRepository>,
    identity_client: IdentityClient,
}

impl AdminContext {
    async fn new() -> anyhow::Result<Self> {
        let postgres_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@postgres:5432/kels".to_string());
        let identity_url =
            std::env::var("IDENTITY_URL").unwrap_or_else(|_| "http://identity:80".to_string());

        let pg_pool = PgPool::connect(&postgres_url)
            .await
            .context("Failed to connect to PostgreSQL")?;

        let identity_client = IdentityClient::new(&identity_url);

        let peer_repo = Arc::new(PeerRepository::new(pg_pool));

        Ok(Self {
            peer_repo,
            identity_client,
        })
    }
}

async fn add_peer(ctx: &AdminContext, peer_id: &str, node_id: &str) -> anyhow::Result<()> {
    use verifiable_storage::Versioned;
    use verifiable_storage_postgres::{Order, Query, QueryExecutor};

    // Upsert pattern: load latest by node_id, if none create(), if some modify and increment()
    // Unique constraint on (node_id, version) prevents race conditions
    let query = Query::<Peer>::new()
        .eq("node_id", node_id)
        .order_by("version", Order::Desc)
        .limit(1);
    let existing: Vec<Peer> = ctx.peer_repo.pool.fetch(query).await?;

    let peer = match existing.first() {
        Some(latest) if latest.active && latest.peer_id == peer_id => {
            println!("Peer {} already authorized (node: {})", peer_id, node_id);
            return Ok(());
        }
        Some(latest) => {
            // Existing node - clone, update fields, increment version
            let mut peer = latest.clone();
            peer.peer_id = peer_id.to_string();
            peer.active = true;
            peer.increment()?;
            peer
        }
        None => {
            // New peer - create version 0
            Peer::create(peer_id.to_string(), node_id.to_string(), true)?
        }
    };

    // Insert new version (unique constraint will error on race condition)
    ctx.peer_repo
        .insert(peer.clone())
        .await
        .context("Failed to insert peer (possible race condition)")?;

    // Anchor the SAID in the registry's KEL via identity service
    ctx.identity_client
        .anchor(&peer.said)
        .await
        .context("Failed to anchor peer SAID in KEL")?;

    let action = if peer.version == 0 {
        "Added"
    } else {
        "Updated"
    };
    println!("{} peer {} (node: {})", action, peer_id, node_id);
    println!("Version: {} (SAID: {})", peer.version, peer.said);
    Ok(())
}

async fn remove_peer(ctx: &AdminContext, peer_id: &str) -> anyhow::Result<()> {
    use verifiable_storage_postgres::{Order, Query, QueryExecutor};

    // Query by peer_id field
    let query = Query::<Peer>::new()
        .eq("peer_id", peer_id)
        .order_by("version", Order::Desc)
        .limit(1);
    let results: Vec<Peer> = ctx.peer_repo.pool.fetch(query).await?;
    let existing = results
        .first()
        .ok_or_else(|| anyhow!("Peer not found: {}", peer_id))?;

    if !existing.active {
        println!("Peer {} already inactive", peer_id);
        return Ok(());
    }

    // Create new version with active=false
    let deactivated = existing.deactivate()?;
    ctx.peer_repo.insert(deactivated.clone()).await?;

    // Anchor the peer SAID in registry's KEL via identity service
    ctx.identity_client
        .anchor(&deactivated.said)
        .await
        .context("Failed to anchor peer SAID in KEL")?;

    println!("Removed peer {} (node: {})", peer_id, deactivated.node_id);
    println!(
        "Version: {} (SAID: {})",
        deactivated.version, deactivated.said
    );
    Ok(())
}

async fn list_peers(ctx: &AdminContext) -> anyhow::Result<()> {
    use verifiable_storage::ColumnQuery;
    use verifiable_storage_postgres::QueryExecutor;

    // Get all distinct prefixes
    let query = ColumnQuery::new(PeerRepository::TABLE_NAME, "prefix").distinct();
    let prefixes = ctx.peer_repo.pool.fetch_column(query).await?;

    if prefixes.is_empty() {
        println!("No peers in allowlist");
        return Ok(());
    }

    println!("{:<20} {:<50} {:<8}", "NODE_ID", "PEER_ID", "STATUS");
    println!("{}", "-".repeat(80));

    for prefix in prefixes {
        if let Some(peer) = ctx.peer_repo.get_latest(&prefix).await? {
            let status = if peer.active { "active" } else { "inactive" };
            println!("{:<20} {:<50} {:<8}", peer.node_id, peer.peer_id, status);
        }
    }

    Ok(())
}

async fn show_allowlist(ctx: &AdminContext) -> anyhow::Result<()> {
    use verifiable_storage::ColumnQuery;
    use verifiable_storage_postgres::QueryExecutor;

    // Get all distinct prefixes
    let query = ColumnQuery::new(PeerRepository::TABLE_NAME, "prefix").distinct();
    let prefixes = ctx.peer_repo.pool.fetch_column(query).await?;

    println!("Current Allowlist:");
    println!("{}", "=".repeat(60));

    let mut active_count = 0;
    for prefix in &prefixes {
        if let Some(peer) = ctx.peer_repo.get_latest(prefix).await?
            && peer.active
        {
            active_count += 1;
            println!("  {} ({})", peer.peer_id, peer.node_id);
        }
    }

    println!("{}", "=".repeat(60));
    println!("Total authorized peers: {}", active_count);
    Ok(())
}

async fn show_history(ctx: &AdminContext) -> anyhow::Result<()> {
    use verifiable_storage::ColumnQuery;
    use verifiable_storage_postgres::QueryExecutor;

    // Get all distinct prefixes
    let query = ColumnQuery::new(PeerRepository::TABLE_NAME, "prefix").distinct();
    let prefixes = ctx.peer_repo.pool.fetch_column(query).await?;

    if prefixes.is_empty() {
        println!("No peer history");
        return Ok(());
    }

    for prefix in prefixes {
        let history = ctx.peer_repo.get_history(&prefix).await?;
        if let Some(first) = history.first() {
            println!("\nPeer: {} ({})", first.peer_id, first.node_id);
            println!("{}", "-".repeat(60));
            for peer in &history {
                let status = if peer.active { "active" } else { "inactive" };
                println!(
                    "  v{}: {} - {} (SAID: {}...)",
                    peer.version,
                    status,
                    peer.created_at,
                    &peer.said[..12.min(peer.said.len())]
                );
            }
        }
    }

    Ok(())
}

async fn show_identity_status(ctx: &AdminContext, json: bool) -> anyhow::Result<()> {
    let prefix = ctx
        .identity_client
        .get_prefix()
        .await
        .context("Failed to get identity prefix")?;
    let kel = ctx
        .identity_client
        .get_kel()
        .await
        .context("Failed to get identity KEL")?;

    let version = kel.last_event().map(|e| e.event.version).unwrap_or(0);
    let is_decommissioned = kel.is_decommissioned();

    if json {
        let status = serde_json::json!({
            "initialized": true,
            "prefix": prefix,
            "version": version,
            "eventCount": kel.len(),
            "decommissioned": is_decommissioned
        });
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("Registry Identity Status");
        println!("{}", "=".repeat(40));
        println!("Prefix: {}", prefix);
        println!("Version: {}", version);
        println!("Event count: {}", kel.len());
        println!("Decommissioned: {}", is_decommissioned);
        println!();
        println!("Note: Identity management (rotate, decommission) is handled");
        println!("      by the identity-admin CLI in the identity service.");
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let ctx = AdminContext::new().await?;

    match cli.command {
        Commands::Peer { action } => match action {
            PeerAction::Add { peer_id, node_id } => {
                add_peer(&ctx, &peer_id, &node_id).await?;
            }
            PeerAction::Remove { peer_id } => {
                remove_peer(&ctx, &peer_id).await?;
            }
            PeerAction::List => {
                list_peers(&ctx).await?;
            }
        },
        Commands::Allowlist { action } => match action {
            AllowlistAction::Show => {
                show_allowlist(&ctx).await?;
            }
            AllowlistAction::History => {
                show_history(&ctx).await?;
            }
        },
        Commands::Identity { action } => match action {
            IdentityAction::Status { json } => {
                show_identity_status(&ctx, json).await?;
            }
        },
    }

    Ok(())
}
