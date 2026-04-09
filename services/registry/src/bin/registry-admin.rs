//! registry-admin CLI - Peer allowlist management
//!
//! This CLI manages the peer allowlist in the registry.
//! All peer changes go through federation proposals (propose, vote, withdraw).
//! Connects via localhost HTTP to the registry for proposals and via identity service for signing.

use anyhow::{Context, anyhow};
use cesr::Matter;
use clap::{Parser, Subcommand};

use verifiable_storage::{Chained, StorageDatetime};

use kels_core::{
    FederationStatus, IdentityClient, KelsError, KelsRegistryClient, PeerAdditionProposal,
    PeerRemovalProposal, ProposalHistory, ProposalWithVotes, ProposalWithVotesMethods, Vote,
    compute_approval_threshold,
};

#[derive(Parser)]
#[command(name = "registry-admin")]
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
    /// List all peers in the allowlist
    List,
    /// Propose a new peer (requires multi-party approval)
    Propose {
        /// Peer identity (KELS prefix)
        #[arg(long)]
        peer_kel_prefix: String,
        /// Human-readable node name
        #[arg(long)]
        node_id: String,
        /// Base domain for service discovery (e.g., "node-a.kels")
        #[arg(long)]
        base_domain: String,
        /// Gossip address (host:port)
        #[arg(long)]
        gossip_addr: String,
    },
    /// Propose removing a peer (requires multi-party approval)
    ProposeRemoval {
        /// Peer prefix of the peer to remove
        #[arg(long)]
        peer_kel_prefix: String,
    },
    /// Vote on a pending proposal
    Vote {
        /// Proposal prefix
        #[arg(long)]
        proposal_prefix: String,
        /// Vote to approve (pass --approve) or reject (omit flag)
        #[arg(long)]
        approve: bool,
    },
    /// List pending proposals
    Proposals,
    /// Get status of a specific proposal
    ProposalStatus {
        /// Proposal prefix
        #[arg(long)]
        proposal_prefix: String,
    },
    /// Withdraw a pending proposal (proposer only)
    Withdraw {
        /// Proposal prefix
        #[arg(long)]
        proposal_prefix: String,
    },
}

#[derive(Subcommand)]
enum AllowlistAction {
    /// Show the current allowlist
    Show,
    /// Show allowlist version history (via completed proposals)
    History,
}

#[derive(Subcommand)]
enum IdentityAction {
    /// Show registry identity status
    Status {
        /// Output as JSON
        #[arg(short, long)]
        json: bool,
        /// Maximum number of pages to fetch
        #[arg(long, default_value_t = kels_core::max_pages())]
        max_pages: usize,
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

/// Shared context for all commands
struct AdminContext {
    identity_client: IdentityClient,
    self_prefix: cesr::Digest256,
    registry_url: String,
    registry_client: KelsRegistryClient,
}

impl AdminContext {
    async fn new() -> anyhow::Result<Self> {
        let identity_url =
            std::env::var("IDENTITY_URL").unwrap_or_else(|_| "http://identity".to_string());
        let registry_url =
            std::env::var("REGISTRY_URL").unwrap_or_else(|_| "http://localhost".to_string());

        let identity_client = IdentityClient::new(&identity_url)?;
        let self_prefix = identity_client.get_prefix().await?;
        let registry_client = KelsRegistryClient::new(&registry_url)?;

        Ok(Self {
            identity_client,
            self_prefix,
            registry_url,
            registry_client,
        })
    }

    /// Get federation status from the registry's HTTP API.
    /// Returns None if federation is not enabled or not available.
    async fn get_federation_status(&self) -> anyhow::Result<Option<FederationStatus>> {
        match self.registry_client.fetch_federation_status().await {
            Ok(status) => Ok(Some(status)),
            Err(KelsError::ServerError(_, kels_core::ErrorCode::NotFound)) => Ok(None),
            Err(e) => Err(anyhow!("Failed to get federation status: {}", e)),
        }
    }

    /// Get the leader URL for federation operations.
    /// Returns the leader's URL, or falls back to local registry if not in federation.
    async fn get_leader_url(&self) -> anyhow::Result<String> {
        match self.get_federation_status().await? {
            Some(status) if status.is_leader => Ok(self.registry_url.clone()),
            Some(status) => status
                .leader_url
                .ok_or_else(|| anyhow!("Federation has no leader (election in progress?)")),
            None => Ok(self.registry_url.clone()),
        }
    }

    /// Get a registry client pointed at the given URL.
    fn client_for(&self, url: &str) -> anyhow::Result<KelsRegistryClient> {
        Ok(KelsRegistryClient::new(url)?)
    }
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

/// Execute an operation against the leader, retrying once on leader redirect.
async fn with_leader_retry<T, F, Fut>(ctx: &AdminContext, f: F) -> anyhow::Result<T>
where
    F: Fn(KelsRegistryClient) -> Fut,
    Fut: std::future::Future<Output = Result<T, KelsError>>,
{
    let mut target_url = ctx.get_leader_url().await?;

    for attempt in 0..2 {
        let client = ctx.client_for(&target_url)?;
        match f(client).await {
            Ok(result) => return Ok(result),
            Err(KelsError::ServerError(ref msg, _))
                if msg.contains("Not leader") && attempt == 0 =>
            {
                if let Some(new_url) = extract_leader_url_from_error(msg) {
                    println!("Redirecting to leader at {}...", new_url);
                    target_url = new_url;
                    continue;
                }
                return Err(anyhow!("{}", msg));
            }
            Err(e) => return Err(anyhow!("{}", e)),
        }
    }

    Err(anyhow!("Failed after leader retries"))
}

async fn propose_peer(
    ctx: &AdminContext,
    peer_kel_prefix: &str,
    node_id: &str,
    base_domain: &str,
    gossip_addr: &str,
) -> anyhow::Result<()> {
    let peer_kel_prefix_digest =
        cesr::Digest256::from_qb64(peer_kel_prefix).context("Invalid peer prefix CESR")?;

    // Get this registry's prefix as proposer
    let proposer = ctx
        .identity_client
        .get_prefix()
        .await
        .context("Failed to get proposer prefix")?;

    // Get the approval threshold from federation status
    let threshold = match ctx.get_federation_status().await? {
        Some(status) => compute_approval_threshold(status.members.len()),
        None => return Err(anyhow!("Federation not configured")),
    };

    // Create payload for signing
    let peer_proposal = PeerAdditionProposal::empty(
        peer_kel_prefix_digest,
        node_id,
        base_domain,
        gossip_addr,
        proposer,
        threshold,
        &StorageDatetime(chrono::Utc::now() + chrono::Duration::days(7)),
    )?;

    // Anchor the proposal's SAID in our KEL (this IS the signature)
    ctx.identity_client
        .anchor(&peer_proposal.said)
        .await
        .context("Failed to anchor proposal")?;

    let result = with_leader_retry(ctx, |client| {
        let proposal = peer_proposal.clone();
        async move { client.submit_addition_proposal(&proposal).await }
    })
    .await?;

    println!("Proposal created: {}", result.proposal_prefix);
    println!("{}", result.message);
    Ok(())
}

async fn propose_removal(ctx: &AdminContext, peer_kel_prefix: &str) -> anyhow::Result<()> {
    let peer_kel_prefix_digest =
        cesr::Digest256::from_qb64(peer_kel_prefix).context("Invalid peer prefix CESR")?;

    // Get this registry's prefix as proposer
    let proposer = ctx
        .identity_client
        .get_prefix()
        .await
        .context("Failed to get proposer prefix")?;

    // Get the approval threshold from federation status
    let threshold = match ctx.get_federation_status().await? {
        Some(status) => compute_approval_threshold(status.members.len()),
        None => return Err(anyhow!("Federation not configured")),
    };

    // Create removal proposal
    let removal_proposal = PeerRemovalProposal::empty(
        peer_kel_prefix_digest,
        proposer,
        threshold,
        &StorageDatetime(chrono::Utc::now() + chrono::Duration::days(7)),
    )?;

    // Anchor the proposal's SAID in our KEL
    ctx.identity_client
        .anchor(&removal_proposal.said)
        .await
        .context("Failed to anchor removal proposal")?;

    let result = with_leader_retry(ctx, |client| {
        let proposal = removal_proposal.clone();
        async move { client.submit_removal_proposal(&proposal).await }
    })
    .await?;

    println!("Removal proposal created: {}", result.proposal_prefix);
    println!("{}", result.message);
    Ok(())
}

async fn vote_proposal(
    ctx: &AdminContext,
    proposal_prefix: &str,
    approve: bool,
) -> anyhow::Result<()> {
    // Get this registry's prefix
    let voter = ctx
        .identity_client
        .get_prefix()
        .await
        .context("Failed to get voter prefix")?;

    // Create vote (SAID is auto-derived)
    let proposal_digest =
        cesr::Digest256::from_qb64(proposal_prefix).context("Invalid proposal prefix CESR")?;
    let vote = Vote::create(proposal_digest, voter, approve).context("Failed to create vote")?;

    // Anchor the vote's SAID in our KEL (this IS the signature)
    ctx.identity_client
        .anchor(&vote.said)
        .await
        .context("Failed to anchor vote in KEL")?;

    let pid = proposal_prefix.to_string();
    let result = with_leader_retry(ctx, |client| {
        let v = vote.clone();
        let id = pid.clone();
        async move { client.submit_vote(&id, &v).await }
    })
    .await?;

    println!("{}", result.message);
    println!(
        "Progress: {}/{} approvals",
        result.current_votes, result.votes_needed
    );
    if result.status == "approved" {
        println!("Peer has been added.");
    } else if result.status == "removal_approved" {
        println!("Peer has been removed.");
    }
    Ok(())
}

async fn list_proposals(ctx: &AdminContext) -> anyhow::Result<()> {
    let response = ctx
        .registry_client
        .fetch_completed_proposals_audit()
        .await
        .map_err(|e| anyhow!("Failed to list proposals: {}", e))?;

    if response.additions.is_empty() && response.removals.is_empty() {
        println!("No proposals");
        return Ok(());
    }

    if !response.additions.is_empty() {
        println!("Addition Proposals");
        println!("{}", "=".repeat(50));
        for pwv in &response.additions {
            if let Some(p) = pwv.history.inception() {
                let status = pwv.status(p.threshold);
                let expires = p.expires_at.to_string();
                let expires = expires.split('T').next().unwrap_or(&expires);
                println!("Proposal:  {}", pwv.proposal_prefix());
                println!("Peer ID:   {}", p.peer_kel_prefix);
                println!("Proposer:  {}", p.proposer);
                println!("Status:    {:?}", status);
                println!("Approvals: {}", pwv.approval_count());
                println!("Expires:   {}", expires);
                println!();
            }
        }
    }

    if !response.removals.is_empty() {
        println!("Removal Proposals");
        println!("{}", "=".repeat(50));
        for rwv in &response.removals {
            if let Some(p) = rwv.history.inception() {
                let status = rwv.status(p.threshold);
                let expires = p.expires_at.to_string();
                let expires = expires.split('T').next().unwrap_or(&expires);
                println!("Proposal:  {}", rwv.proposal_prefix());
                println!("Peer ID:   {}", p.peer_kel_prefix);
                println!("Proposer:  {}", p.proposer);
                println!("Status:    {:?}", status);
                println!("Approvals: {}", rwv.approval_count());
                println!("Expires:   {}", expires);
                println!();
            }
        }
    }

    Ok(())
}

async fn get_proposal_status(ctx: &AdminContext, proposal_prefix: &str) -> anyhow::Result<()> {
    let proposal = ctx
        .registry_client
        .fetch_proposal(proposal_prefix)
        .await
        .map_err(|e| anyhow!("Failed to get proposal: {}", e))?;

    match proposal {
        ProposalWithVotes::Addition(pwv) => {
            if let Some(p) = pwv.history.inception() {
                println!("Addition Proposal: {}", pwv.proposal_prefix());
                println!("{}", "=".repeat(50));
                println!("SAID:       {}", p.said);
                println!("Peer ID:    {}", p.peer_kel_prefix);
                println!("Node ID:    {}", p.node_id);
                println!("Proposer:   {}", p.proposer);
                println!("Approvals:  {}", pwv.approval_count());
                println!("Rejections: {}", pwv.rejection_count());
                println!("Created:    {}", p.created_at);
                println!("Expires:    {}", p.expires_at);
                if pwv.history.is_withdrawn()
                    && let Some(latest) = pwv.history.latest()
                    && let Some(ref withdrawn_at) = latest.withdrawn_at
                {
                    println!("Withdrawn:  {}", withdrawn_at);
                }
            }
        }
        ProposalWithVotes::Removal(rwv) => {
            if let Some(p) = rwv.history.inception() {
                println!("Removal Proposal: {}", rwv.proposal_prefix());
                println!("{}", "=".repeat(50));
                println!("SAID:       {}", p.said);
                println!("Peer ID:    {}", p.peer_kel_prefix);
                println!("Proposer:   {}", p.proposer);
                println!("Approvals:  {}", rwv.approval_count());
                println!("Rejections: {}", rwv.rejection_count());
                println!("Created:    {}", p.created_at);
                println!("Expires:    {}", p.expires_at);
                if rwv.history.is_withdrawn()
                    && let Some(latest) = rwv.history.latest()
                    && let Some(ref withdrawn_at) = latest.withdrawn_at
                {
                    println!("Withdrawn:  {}", withdrawn_at);
                }
            }
        }
    }

    Ok(())
}

async fn withdraw_proposal(ctx: &AdminContext, proposal_prefix: &str) -> anyhow::Result<()> {
    // Fetch the current proposal from the registry
    let proposal = ctx
        .registry_client
        .fetch_proposal(proposal_prefix)
        .await
        .map_err(|e| anyhow!("Failed to fetch proposal: {}", e))?;

    match proposal {
        ProposalWithVotes::Addition(pwv) => {
            let current = pwv
                .history
                .inception()
                .ok_or_else(|| anyhow!("Proposal has no inception record"))?;

            if current.proposer != ctx.self_prefix {
                return Err(anyhow!(
                    "Only the proposer ({}) can withdraw. You are {}.",
                    current.proposer,
                    ctx.self_prefix
                ));
            }

            if pwv.history.is_withdrawn() {
                return Err(anyhow!("Proposal {} is already withdrawn", proposal_prefix));
            }

            let mut withdrawal = current.clone();
            withdrawal.withdrawn_at = Some(StorageDatetime::now());
            withdrawal
                .increment()
                .context("Failed to create withdrawal record")?;

            ctx.identity_client
                .anchor(&withdrawal.said)
                .await
                .context("Failed to anchor withdrawal in KEL")?;

            let result = with_leader_retry(ctx, |client| {
                let w = withdrawal.clone();
                async move { client.submit_addition_proposal(&w).await }
            })
            .await?;

            println!("{}", result.message);
            Ok(())
        }
        ProposalWithVotes::Removal(rwv) => {
            let current = rwv
                .history
                .inception()
                .ok_or_else(|| anyhow!("Proposal has no inception record"))?;

            if current.proposer != ctx.self_prefix {
                return Err(anyhow!(
                    "Only the proposer ({}) can withdraw. You are {}.",
                    current.proposer,
                    ctx.self_prefix
                ));
            }

            if rwv.history.is_withdrawn() {
                return Err(anyhow!("Proposal {} is already withdrawn", proposal_prefix));
            }

            let mut withdrawal = current.clone();
            withdrawal.withdrawn_at = Some(StorageDatetime::now());
            withdrawal
                .increment()
                .context("Failed to create withdrawal record")?;

            ctx.identity_client
                .anchor(&withdrawal.said)
                .await
                .context("Failed to anchor withdrawal in KEL")?;

            let result = with_leader_retry(ctx, |client| {
                let w = withdrawal.clone();
                async move { client.submit_removal_proposal(&w).await }
            })
            .await?;

            println!("{}", result.message);
            Ok(())
        }
    }
}

async fn list_peers(ctx: &AdminContext) -> anyhow::Result<()> {
    let response = ctx
        .registry_client
        .fetch_all_peers()
        .await
        .map_err(|e| anyhow!("Failed to list peers: {}", e))?;

    let peers: Vec<_> = response
        .peers
        .iter()
        .filter_map(|h| h.records.last())
        .collect();

    if peers.is_empty() {
        println!("No peers in allowlist");
        return Ok(());
    }

    println!("{:<20} {:<50} {:<8}", "NODE_ID", "PEER_ID", "STATUS");
    println!("{}", "-".repeat(82));

    for peer in peers {
        let status = if peer.active { "active" } else { "inactive" };
        println!("{:<20} {:<50} {:<8}", peer.node_id, peer.kel_prefix, status);
    }

    Ok(())
}

async fn show_allowlist(ctx: &AdminContext) -> anyhow::Result<()> {
    let response = ctx
        .registry_client
        .fetch_peers()
        .await
        .map_err(|e| anyhow!("Failed to fetch allowlist: {}", e))?;

    let active_peers: Vec<_> = response
        .peers
        .iter()
        .filter_map(|h| h.records.last())
        .filter(|p| p.active)
        .collect();

    println!("Current Allowlist:");
    println!("{}", "=".repeat(60));

    for peer in &active_peers {
        println!("  {} ({})", peer.kel_prefix, peer.node_id);
    }

    println!("{}", "=".repeat(60));
    println!("Total authorized peers: {}", active_peers.len());
    Ok(())
}

async fn show_history(ctx: &AdminContext) -> anyhow::Result<()> {
    let response = ctx
        .registry_client
        .fetch_completed_proposals_audit()
        .await
        .map_err(|e| anyhow!("Failed to fetch proposal history: {}", e))?;

    if response.additions.is_empty() && response.removals.is_empty() {
        println!("No peer history");
        return Ok(());
    }

    if !response.additions.is_empty() {
        println!("Addition History");
        println!("{}", "=".repeat(60));
        for pwv in &response.additions {
            if let Some(p) = pwv.history.inception() {
                let status = pwv.status(p.threshold);
                println!(
                    "  {} - {:?} (proposer: {}, votes: {})",
                    p.peer_kel_prefix,
                    status,
                    p.proposer,
                    pwv.approval_count()
                );
            }
        }
    }

    if !response.removals.is_empty() {
        println!("\nRemoval History");
        println!("{}", "=".repeat(60));
        for rwv in &response.removals {
            if let Some(p) = rwv.history.inception() {
                let status = rwv.status(p.threshold);
                println!(
                    "  {} - {:?} (proposer: {}, votes: {})",
                    p.peer_kel_prefix,
                    status,
                    p.proposer,
                    rwv.approval_count()
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
                    let marker = if Some(*member) == status.leader_prefix {
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

async fn show_identity_status(
    ctx: &AdminContext,
    json: bool,
    max_pages: usize,
) -> anyhow::Result<()> {
    let prefix = ctx
        .identity_client
        .get_prefix()
        .await
        .context("Failed to get identity prefix")?;
    let mut all_events = Vec::new();
    let mut since: Option<String> = None;
    for _ in 0..max_pages {
        let page = ctx
            .identity_client
            .get_key_events(since.as_deref(), kels_core::page_size())
            .await
            .context("Failed to get identity KEL")?;
        if page.events.is_empty() {
            break;
        }
        since = page.events.last().map(|e| e.event.said.to_string());
        all_events.extend(page.events);
        if !page.has_more {
            break;
        }
    }
    let event_count = all_events.len();
    let prefix_digest = prefix;
    let mut verifier = kels_core::KelVerifier::new(&prefix_digest);
    let verification = if verifier.verify_page(&all_events).is_ok() {
        verifier.into_verification().ok()
    } else {
        None
    };
    let is_decommissioned = verification
        .as_ref()
        .map(|c| c.is_decommissioned())
        .unwrap_or(false);

    if json {
        let status = serde_json::json!({
            "initialized": true,
            "prefix": prefix,
            "eventCount": event_count,
            "decommissioned": is_decommissioned
        });
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("Registry Identity Status");
        println!("{}", "=".repeat(40));
        println!("Prefix: {}", prefix);
        println!("Event count: {}", event_count);
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
            PeerAction::List => {
                list_peers(&ctx).await?;
            }
            PeerAction::Propose {
                peer_kel_prefix,
                node_id,
                base_domain,
                gossip_addr,
            } => {
                propose_peer(&ctx, &peer_kel_prefix, &node_id, &base_domain, &gossip_addr).await?;
            }
            PeerAction::ProposeRemoval { peer_kel_prefix } => {
                propose_removal(&ctx, &peer_kel_prefix).await?;
            }
            PeerAction::Vote {
                proposal_prefix,
                approve,
            } => {
                vote_proposal(&ctx, &proposal_prefix, approve).await?;
            }
            PeerAction::Proposals => {
                list_proposals(&ctx).await?;
            }
            PeerAction::ProposalStatus { proposal_prefix } => {
                get_proposal_status(&ctx, &proposal_prefix).await?;
            }
            PeerAction::Withdraw { proposal_prefix } => {
                withdraw_proposal(&ctx, &proposal_prefix).await?;
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
            IdentityAction::Status { json, max_pages } => {
                show_identity_status(&ctx, json, max_pages).await?;
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
