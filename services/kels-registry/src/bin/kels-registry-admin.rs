//! kels-registry-admin CLI - Peer allowlist management
//!
//! This CLI manages the peer allowlist in the kels-registry.
//! For core peers in federation mode, it connects via localhost HTTP to the registry.
//! For regional peers, it writes directly to PostgreSQL.

use anyhow::{Context, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use kels::{Peer, PeerScope};
use serde::Deserialize;
use std::sync::Arc;
use verifiable_storage::{ChainedRepository, StorageDatetime};
use verifiable_storage_postgres::PgPool;

use kels_registry::federation::{FederationStatus, PeerProposal, Vote};
use kels_registry::identity_client::IdentityClient;
use kels_registry::peer_store::PeerRepository;

/// CLI representation of PeerScope for clap parsing
#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliPeerScope {
    Core,
    Regional,
}

impl From<CliPeerScope> for PeerScope {
    fn from(scope: CliPeerScope) -> Self {
        match scope {
            CliPeerScope::Core => PeerScope::Core,
            CliPeerScope::Regional => PeerScope::Regional,
        }
    }
}

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
    /// Federation management commands
    Federation {
        #[command(subcommand)]
        action: FederationAction,
    },
}

#[derive(Subcommand)]
enum PeerAction {
    /// Add a peer to the allowlist (use 'propose' for multi-party approval of core peers)
    Add {
        /// libp2p PeerId (Base58 encoded)
        #[arg(long)]
        peer_id: String,
        /// Human-readable node name
        #[arg(long)]
        node_id: String,
        /// Peer scope: core (replicated across federation) or regional (local only)
        #[arg(long, value_enum, default_value = "regional")]
        scope: CliPeerScope,
        /// HTTP URL for the KELS service
        #[arg(long)]
        kels_url: String,
        /// libp2p multiaddr for gossip connections
        #[arg(long)]
        gossip_multiaddr: String,
    },
    /// Remove a peer from the allowlist
    Remove {
        /// libp2p PeerId (Base58 encoded)
        #[arg(long)]
        peer_id: String,
    },
    /// List all peers in the allowlist
    List,
    /// Propose a new core peer (requires multi-party approval)
    Propose {
        /// libp2p PeerId (Base58 encoded)
        #[arg(long)]
        peer_id: String,
        /// Human-readable node name
        #[arg(long)]
        node_id: String,
        /// HTTP URL for the KELS service
        #[arg(long)]
        kels_url: String,
        /// libp2p multiaddr for gossip connections
        #[arg(long)]
        gossip_multiaddr: String,
    },
    /// Vote on a pending proposal
    Vote {
        /// Proposal ID
        #[arg(long)]
        proposal_id: String,
        /// Vote to approve (default) or reject
        #[arg(long, default_value = "true")]
        approve: bool,
    },
    /// List pending proposals
    Proposals,
    /// Get status of a specific proposal
    ProposalStatus {
        /// Proposal ID
        #[arg(long)]
        proposal_id: String,
    },
    /// Withdraw a pending proposal (proposer only)
    Withdraw {
        /// Proposal ID
        #[arg(long)]
        proposal_id: String,
    },
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

#[derive(Subcommand)]
enum FederationAction {
    /// Show federation status
    Status {
        /// Output as JSON
        #[arg(short, long)]
        json: bool,
    },
}

// Response types from admin API
#[derive(Debug, Deserialize)]
struct ProposalResponse {
    proposal_id: String,
    status: String,
    votes_needed: usize,
    current_votes: usize,
    message: String,
}

/// Shared context for all commands
struct AdminContext {
    peer_repo: Arc<PeerRepository>,
    identity_client: IdentityClient,
    registry_url: String,
    http_client: reqwest::Client,
}

impl AdminContext {
    async fn new() -> anyhow::Result<Self> {
        let postgres_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://postgres:postgres@postgres:5432/kels_registry".to_string()
        });
        let identity_url =
            std::env::var("IDENTITY_URL").unwrap_or_else(|_| "http://identity".to_string());
        let registry_url =
            std::env::var("REGISTRY_URL").unwrap_or_else(|_| "http://localhost".to_string());

        let pg_pool = PgPool::connect(&postgres_url)
            .await
            .context("Failed to connect to PostgreSQL")?;

        let identity_client = IdentityClient::new(&identity_url);

        let peer_repo = Arc::new(PeerRepository::new(pg_pool));

        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            peer_repo,
            identity_client,
            registry_url,
            http_client,
        })
    }

    /// Get federation status from the registry's HTTP API.
    /// Returns None if federation is not enabled or not available.
    async fn get_federation_status(&self) -> anyhow::Result<Option<FederationStatus>> {
        let url = format!("{}/api/federation/status", self.registry_url);
        let resp = self.http_client.get(&url).send().await;

        match resp {
            Ok(r) if r.status().is_success() => {
                let status: FederationStatus = r
                    .json()
                    .await
                    .context("Failed to parse federation status")?;
                Ok(Some(status))
            }
            Ok(r) if r.status().as_u16() == 404 => {
                // Federation not enabled
                Ok(None)
            }
            Ok(r) => Err(anyhow!("Federation status request failed: {}", r.status())),
            Err(e) => {
                // Connection error - federation might not be available
                Err(anyhow!("Failed to connect to registry: {}", e))
            }
        }
    }

    /// Get the leader URL for federation operations.
    /// Returns the leader's URL, or falls back to local registry if not in federation.
    async fn get_leader_url(&self) -> anyhow::Result<String> {
        match self.get_federation_status().await? {
            Some(status) if status.is_leader => {
                // We are the leader, use local URL
                Ok(self.registry_url.clone())
            }
            Some(status) => {
                // Not the leader, use leader's URL
                status
                    .leader_url
                    .ok_or_else(|| anyhow!("Federation has no leader (election in progress?)"))
            }
            None => {
                // Not in federation mode, use local URL
                Ok(self.registry_url.clone())
            }
        }
    }
}

/// Check if there's at least one active core peer in the registry.
async fn has_active_core_peer(ctx: &AdminContext) -> anyhow::Result<bool> {
    use verifiable_storage::ColumnQuery;
    use verifiable_storage_postgres::QueryExecutor;

    // Get all distinct prefixes
    let query = ColumnQuery::new(PeerRepository::TABLE_NAME, "prefix").distinct();
    let prefixes: Vec<String> = ctx.peer_repo.pool.fetch_column(query).await?;

    for prefix in prefixes {
        if let Some(peer) = ctx.peer_repo.get_latest(&prefix).await?
            && peer.active
            && peer.scope == PeerScope::Core
        {
            return Ok(true);
        }
    }

    Ok(false)
}

async fn add_peer(
    ctx: &AdminContext,
    peer_id: &str,
    node_id: &str,
    scope: PeerScope,
    kels_url: &str,
    gossip_multiaddr: &str,
) -> anyhow::Result<()> {
    use verifiable_storage::Chained;
    use verifiable_storage_postgres::{Order, Query, QueryExecutor};

    // Core peers must go through the proposal system for multi-party approval
    if scope == PeerScope::Core {
        return Err(anyhow!(
            "Core peers must go through the proposal system.\n\
             Use: kels-registry-admin peer propose --peer-id {} --node-id {} --kels-url {} --gossip-multiaddr {}",
            peer_id,
            node_id,
            kels_url,
            gossip_multiaddr
        ));
    }

    // For regional peers, require at least one active core peer to exist
    // (regional nodes need core nodes to connect to the gossip swarm)
    let has_core_peer = has_active_core_peer(ctx).await?;
    if !has_core_peer {
        return Err(anyhow!(
            "Cannot add regional peer - no active core peers exist.\n\
             Regional nodes need core nodes to connect to the gossip swarm.\n\
             Add at least one core peer first with: peer add --scope core ..."
        ));
    }

    // Upsert pattern: load latest by node_id, if none create(), if some modify and increment()
    // Unique constraint on (node_id, version) prevents race conditions
    let query = Query::<Peer>::new()
        .eq("node_id", node_id)
        .order_by("version", Order::Desc)
        .limit(1);
    let existing: Vec<Peer> = ctx.peer_repo.pool.fetch(query).await?;

    let peer = match existing.first() {
        Some(latest)
            if latest.active
                && latest.peer_id == peer_id
                && latest.scope == scope
                && latest.kels_url == kels_url
                && latest.gossip_multiaddr == gossip_multiaddr =>
        {
            println!(
                "Peer {} already authorized (node: {}, scope: {})",
                peer_id, node_id, scope
            );
            return Ok(());
        }
        Some(latest) => {
            // Existing node - clone, update fields, increment version
            let mut peer = latest.clone();
            peer.peer_id = peer_id.to_string();
            peer.active = true;
            peer.scope = scope;
            peer.kels_url = kels_url.to_string();
            peer.gossip_multiaddr = gossip_multiaddr.to_string();
            peer.increment()?;
            peer
        }
        None => {
            // New peer - create version 0
            Peer::create(
                peer_id.to_string(),
                node_id.to_string(),
                true,
                scope,
                kels_url.to_string(),
                gossip_multiaddr.to_string(),
            )?
        }
    };

    // Anchor the SAID in the registry's KEL via identity service
    ctx.identity_client
        .anchor(&peer.said)
        .await
        .context("Failed to anchor peer SAID in KEL")?;

    // Insert new version (unique constraint will error on race condition)
    ctx.peer_repo
        .insert(peer.clone())
        .await
        .context("Failed to insert peer")?;

    let action = if peer.version == 0 {
        "Added"
    } else {
        "Updated"
    };
    println!(
        "{} peer {} (node: {}, scope: {})",
        action, peer_id, node_id, scope
    );
    println!("Version: {} (SAID: {})", peer.version, peer.said);
    Ok(())
}

async fn remove_peer(ctx: &AdminContext, peer_id: &str) -> anyhow::Result<()> {
    use verifiable_storage_postgres::{Order, Query, QueryExecutor};

    // Query by peer_id field to determine scope
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

    // For core peers, use the admin API endpoint
    if existing.scope == PeerScope::Core {
        let url = format!("{}/api/admin/peers/{}", ctx.registry_url, peer_id);
        let resp = ctx.http_client.delete(&url).send().await?;

        if resp.status().is_success() {
            println!("Removed core peer {} (node: {})", peer_id, existing.node_id);
            return Ok(());
        } else {
            let error: serde_json::Value = resp.json().await.unwrap_or_default();
            return Err(anyhow!(
                "Failed to remove core peer: {}",
                error
                    .get("error")
                    .and_then(|e| e.as_str())
                    .unwrap_or("unknown error")
            ));
        }
    }

    // For regional peers, use direct DB access
    let deactivated = existing.deactivate()?;

    // Anchor the peer SAID in registry's KEL via identity service
    ctx.identity_client
        .anchor(&deactivated.said)
        .await
        .context("Failed to anchor peer SAID in KEL")?;

    ctx.peer_repo
        .insert(deactivated.clone())
        .await
        .context("Failed to insert peer")?;

    println!("Removed peer {} (node: {})", peer_id, deactivated.node_id);
    println!(
        "Version: {} (SAID: {})",
        deactivated.version, deactivated.said
    );
    Ok(())
}

/// Extract leader URL from a "Not leader" error message.
/// Expected format: "Not leader. Leader: Some(\"prefix\") at Some(\"http://...\")"
fn extract_leader_url_from_error(error_msg: &str) -> Option<String> {
    // Look for pattern: at Some("http://...")
    if let Some(at_pos) = error_msg.find("at Some(\"") {
        let start = at_pos + 9; // Length of "at Some(\""
        if let Some(end_pos) = error_msg[start..].find("\")") {
            return Some(error_msg[start..start + end_pos].to_string());
        }
    }
    None
}

async fn propose_peer(
    ctx: &AdminContext,
    peer_id: &str,
    node_id: &str,
    kels_url: &str,
    gossip_multiaddr: &str,
) -> anyhow::Result<()> {
    // Get this registry's prefix as proposer
    let proposer = ctx
        .identity_client
        .get_prefix()
        .await
        .context("Failed to get proposer prefix")?;

    // Create payload for signing
    let peer_proposal = PeerProposal::empty(
        peer_id,
        node_id,
        kels_url,
        gossip_multiaddr,
        &proposer,
        &StorageDatetime(chrono::Utc::now() + chrono::Duration::days(7)),
    )?;

    // Anchor the proposal's SAID in our KEL (this IS the signature)
    ctx.identity_client
        .anchor(&peer_proposal.said)
        .await
        .context("Failed to anchor proposal")?;

    // Get leader URL from federation status
    let mut target_url = ctx.get_leader_url().await?;

    // Retry loop for leader changes
    for attempt in 0..2 {
        let url = format!("{}/api/admin/proposals", target_url);
        let resp = ctx
            .http_client
            .post(&url)
            .json(&peer_proposal)
            .send()
            .await?;

        if resp.status().is_success() {
            let result: ProposalResponse = resp.json().await?;
            println!("Proposal created: {}", result.proposal_id);
            println!("{}", result.message);
            return Ok(());
        }

        let error: serde_json::Value = resp.json().await.unwrap_or_default();
        let error_msg = error
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("unknown error");

        // Check if this is a "not leader" error and extract new leader URL
        if error_msg.contains("Not leader")
            && let Some(new_leader_url) = extract_leader_url_from_error(error_msg)
            && attempt == 0
        {
            println!("Redirecting to leader at {}...", new_leader_url);
            target_url = new_leader_url;
            continue;
        }

        return Err(anyhow!("Failed to create proposal: {}", error_msg));
    }

    Err(anyhow!("Failed to create proposal after retries"))
}

async fn vote_proposal(ctx: &AdminContext, proposal_id: &str, approve: bool) -> anyhow::Result<()> {
    // Get this registry's prefix
    let voter = ctx
        .identity_client
        .get_prefix()
        .await
        .context("Failed to get voter prefix")?;

    // Create vote (SAID is auto-derived)
    let vote = Vote::create(proposal_id.to_string(), voter, approve, None)
        .context("Failed to create vote")?;

    // Anchor the vote's SAID in our KEL (this IS the signature)
    ctx.identity_client
        .anchor(&vote.said)
        .await
        .context("Failed to anchor vote in KEL")?;

    // Get leader URL from federation status
    let mut target_url = ctx.get_leader_url().await?;

    // Retry loop for leader changes
    for attempt in 0..2 {
        let url = format!("{}/api/admin/proposals/{}/vote", target_url, proposal_id);
        let resp = ctx.http_client.post(&url).json(&vote).send().await?;

        if resp.status().is_success() {
            let result: ProposalResponse = resp.json().await?;
            println!("{}", result.message);
            println!(
                "Progress: {}/{} approvals",
                result.current_votes, result.votes_needed
            );
            if result.status == "Approved" {
                println!("Peer has been added to the core set.");
            }
            return Ok(());
        }

        let error: serde_json::Value = resp.json().await.unwrap_or_default();
        let error_msg = error
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("unknown error");

        // Check if this is a "not leader" error and extract new leader URL
        if error_msg.contains("Not leader")
            && let Some(new_leader_url) = extract_leader_url_from_error(error_msg)
            && attempt == 0
        {
            println!("Redirecting to leader at {}...", new_leader_url);
            target_url = new_leader_url;
            continue;
        }

        return Err(anyhow!("Failed to vote: {}", error_msg));
    }

    Err(anyhow!("Failed to vote after retries"))
}

async fn list_proposals(ctx: &AdminContext) -> anyhow::Result<()> {
    let url = format!("{}/api/admin/proposals", ctx.registry_url);
    let resp = ctx.http_client.get(&url).send().await?;

    if resp.status().is_success() {
        let proposals: Vec<PeerProposal> = resp.json().await?;

        if proposals.is_empty() {
            println!("No pending proposals");
            return Ok(());
        }

        for p in proposals {
            let expires = p.expires_at.to_string();
            let expires = expires.split('T').next().unwrap_or(&expires);
            println!("Proposal:  {}", p.prefix);
            println!("Peer ID:   {}", p.peer_id);
            println!("Proposer:  {}", p.proposer);
            println!("Approvals: {}", p.approvals.len());
            println!("Expires:   {}", expires);
            println!();
        }
    } else {
        let error: serde_json::Value = resp.json().await.unwrap_or_default();
        return Err(anyhow!(
            "Failed to list proposals: {}",
            error
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("unknown error")
        ));
    }

    Ok(())
}

async fn get_proposal_status(ctx: &AdminContext, proposal_id: &str) -> anyhow::Result<()> {
    let url = format!("{}/api/admin/proposals/{}", ctx.registry_url, proposal_id);
    let resp = ctx.http_client.get(&url).send().await?;

    if resp.status().is_success() {
        let p: PeerProposal = resp.json().await?;
        println!("Proposal: {}", p.prefix);
        println!("{}", "=".repeat(50));
        println!("SAID:       {}", p.said);
        println!("Status:     {:?}", p.status);
        println!("Peer ID:    {}", p.peer_id);
        println!("Node ID:    {}", p.node_id);
        println!("Proposer:   {}", p.proposer);
        println!("Approvals:  {}", p.approvals.len());
        println!("Rejections: {}", p.rejections.len());
        println!("Created:    {}", p.created_at);
        println!("Expires:    {}", p.expires_at);
    } else {
        let error: serde_json::Value = resp.json().await.unwrap_or_default();
        return Err(anyhow!(
            "Failed to get proposal: {}",
            error
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("unknown error")
        ));
    }

    Ok(())
}

async fn withdraw_proposal(ctx: &AdminContext, proposal_id: &str) -> anyhow::Result<()> {
    // Get leader URL from federation status
    let mut target_url = ctx.get_leader_url().await?;

    // Retry loop for leader changes
    for attempt in 0..2 {
        let url = format!("{}/api/admin/proposals/{}", target_url, proposal_id);
        let resp = ctx.http_client.delete(&url).send().await?;

        if resp.status().is_success() {
            let result: ProposalResponse = resp.json().await?;
            println!("{}", result.message);
            return Ok(());
        }

        let error: serde_json::Value = resp.json().await.unwrap_or_default();
        let error_msg = error
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("unknown error");

        // Check if this is a "not leader" error and extract new leader URL
        if error_msg.contains("Not leader")
            && let Some(new_leader_url) = extract_leader_url_from_error(error_msg)
            && attempt == 0
        {
            println!("Redirecting to leader at {}...", new_leader_url);
            target_url = new_leader_url;
            continue;
        }

        return Err(anyhow!("Failed to withdraw proposal: {}", error_msg));
    }

    Err(anyhow!("Failed to withdraw proposal after retries"))
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

    println!(
        "{:<20} {:<50} {:<10} {:<8}",
        "NODE_ID", "PEER_ID", "SCOPE", "STATUS"
    );
    println!("{}", "-".repeat(92));

    for prefix in prefixes {
        if let Some(peer) = ctx.peer_repo.get_latest(&prefix).await? {
            let status = if peer.active { "active" } else { "inactive" };
            println!(
                "{:<20} {:<50} {:<10} {:<8}",
                peer.node_id, peer.peer_id, peer.scope, status
            );
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

async fn show_federation_status(ctx: &AdminContext, json: bool) -> anyhow::Result<()> {
    match ctx.get_federation_status().await {
        Ok(Some(status)) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!("Federation Status");
                println!("{}", "=".repeat(50));
                println!("Node ID:       {}", status.node_id);
                println!("Self Prefix:   {}", status.self_prefix);
                println!(
                    "Is Leader:     {}",
                    if status.is_leader { "Yes" } else { "No" }
                );
                if let Some(leader_id) = status.leader_id {
                    println!("Leader ID:     {}", leader_id);
                } else {
                    println!("Leader ID:     (none - election in progress)");
                }
                if let Some(ref leader_prefix) = status.leader_prefix {
                    println!("Leader Prefix: {}", leader_prefix);
                }
                println!("Term:          {}", status.term);
                println!("Last Log Idx:  {}", status.last_log_index);
                println!("Last Applied:  {}", status.last_applied);
                println!();
                println!("Federation Members:");
                for member in &status.members {
                    let marker = if Some(member.clone()) == status.leader_prefix {
                        " (leader)"
                    } else {
                        ""
                    };
                    println!("  {}{}", member, marker);
                }
            }
        }
        Ok(None) => {
            if json {
                println!("{{\"enabled\": false}}");
            } else {
                println!("Federation is not enabled on this registry.");
            }
        }
        Err(e) => {
            return Err(anyhow!("Failed to get federation status: {}", e));
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

    let is_decommissioned = kel.is_decommissioned();

    if json {
        let status = serde_json::json!({
            "initialized": true,
            "prefix": prefix,
            "eventCount": kel.len(),
            "decommissioned": is_decommissioned
        });
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("Registry Identity Status");
        println!("{}", "=".repeat(40));
        println!("Prefix: {}", prefix);
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
            PeerAction::Add {
                peer_id,
                node_id,
                scope,
                kels_url,
                gossip_multiaddr,
            } => {
                add_peer(
                    &ctx,
                    &peer_id,
                    &node_id,
                    scope.into(),
                    &kels_url,
                    &gossip_multiaddr,
                )
                .await?;
            }
            PeerAction::Remove { peer_id } => {
                remove_peer(&ctx, &peer_id).await?;
            }
            PeerAction::List => {
                list_peers(&ctx).await?;
            }
            PeerAction::Propose {
                peer_id,
                node_id,
                kels_url,
                gossip_multiaddr,
            } => {
                propose_peer(&ctx, &peer_id, &node_id, &kels_url, &gossip_multiaddr).await?;
            }
            PeerAction::Vote {
                proposal_id,
                approve,
            } => {
                vote_proposal(&ctx, &proposal_id, approve).await?;
            }
            PeerAction::Proposals => {
                list_proposals(&ctx).await?;
            }
            PeerAction::ProposalStatus { proposal_id } => {
                get_proposal_status(&ctx, &proposal_id).await?;
            }
            PeerAction::Withdraw { proposal_id } => {
                withdraw_proposal(&ctx, &proposal_id).await?;
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
        Commands::Federation { action } => match action {
            FederationAction::Status { json } => {
                show_federation_status(&ctx, json).await?;
            }
        },
    }

    Ok(())
}
