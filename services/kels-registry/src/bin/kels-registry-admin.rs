//! kels-registry-admin CLI - Peer allowlist management
//!
//! This CLI manages the peer allowlist in the kels-registry.
//! All peer changes go through federation proposals (propose, vote, withdraw).
//! Connects via localhost HTTP to the registry for proposals and via identity service for signing.

use anyhow::{Context, anyhow};
use clap::{Parser, Subcommand};
use serde::Deserialize;

use verifiable_storage::{Chained, StorageDatetime};

use kels::IdentityClient;
use kels::{
    AdminRequest, CompletedProposalsResponse, PeerAdditionProposal, PeerRemovalProposal,
    PeersResponse, ProposalHistory, ProposalWithVotes, ProposalWithVotesMethods, Vote,
};
use kels_registry::federation::FederationStatus;

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
    /// List all peers in the allowlist
    List,
    /// Propose a new peer (requires multi-party approval)
    Propose {
        /// Peer identity (KELS prefix)
        #[arg(long)]
        peer_prefix: String,
        /// Human-readable node name
        #[arg(long)]
        node_id: String,
        /// HTTP URL for the KELS service
        #[arg(long)]
        kels_url: String,
        /// Gossip address (host:port)
        #[arg(long)]
        gossip_addr: String,
    },
    /// Propose removing a peer (requires multi-party approval)
    ProposeRemoval {
        /// Peer prefix of the peer to remove
        #[arg(long)]
        peer_prefix: String,
    },
    /// Vote on a pending proposal
    Vote {
        /// Proposal ID
        #[arg(long)]
        proposal_id: String,
        /// Vote to approve (pass --approve) or reject (omit flag)
        #[arg(long)]
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
    identity_client: IdentityClient,
    self_prefix: String,
    registry_url: String,
    http_client: reqwest::Client,
}

impl AdminContext {
    async fn new() -> anyhow::Result<Self> {
        let identity_url =
            std::env::var("IDENTITY_URL").unwrap_or_else(|_| "http://identity".to_string());
        let registry_url =
            std::env::var("REGISTRY_URL").unwrap_or_else(|_| "http://localhost".to_string());

        let identity_client = IdentityClient::new(&identity_url);
        let self_prefix = identity_client.get_prefix().await?;

        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            identity_client,
            self_prefix,
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

/// Signs admin requests via the identity service (HSM-backed).
struct AdminSigner {
    identity_client: IdentityClient,
    self_prefix: String,
}

#[async_trait::async_trait]
impl kels::RegistrySigner for AdminSigner {
    async fn sign(&self, data: &[u8]) -> Result<kels::SignResult, kels::KelsError> {
        let data_str = std::str::from_utf8(data)
            .map_err(|e| kels::KelsError::SigningFailed(format!("Data is not UTF-8: {}", e)))?;

        let result = self
            .identity_client
            .sign(data_str)
            .await
            .map_err(|e| kels::KelsError::SigningFailed(e.to_string()))?;

        Ok(kels::SignResult {
            signature: result.signature,
            peer_prefix: self.self_prefix.clone(),
        })
    }
}

/// Build a signed admin request using the identity service.
async fn sign_admin_request(
    ctx: &AdminContext,
) -> anyhow::Result<kels::SignedRequest<AdminRequest>> {
    let request = AdminRequest {
        timestamp: chrono::Utc::now().timestamp(),
        nonce: kels::generate_nonce(),
    };
    let signer = AdminSigner {
        identity_client: IdentityClient::new(
            &std::env::var("IDENTITY_URL").unwrap_or_else(|_| "http://identity".to_string()),
        ),
        self_prefix: ctx.self_prefix.clone(),
    };
    kels::sign_request(&signer, &request)
        .await
        .map_err(|e| anyhow!("Failed to sign admin request: {}", e))
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

/// Submit own KEL to the leader so anchoring can be verified.
///
/// After anchoring a SAID in the local identity KEL, the new event must reach
/// Raft before the leader can verify it. Submits all events; merge() deduplicates.
async fn sync_kel_to_leader(ctx: &AdminContext, leader_url: &str) -> anyhow::Result<()> {
    let page = ctx
        .identity_client
        .get_key_events(None, kels::MAX_EVENTS_PER_KEL_RESPONSE)
        .await
        .context("Failed to get own KEL")?;
    let events = page.events;
    if events.is_empty() {
        return Ok(());
    }

    let url = format!(
        "{}/api/federation/key-events",
        leader_url.trim_end_matches('/')
    );
    let resp = ctx.http_client.post(&url).json(&events).send().await?;
    if !resp.status().is_success() {
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        let error = body["error"].as_str().unwrap_or("unknown error");
        return Err(anyhow!("Failed to sync KEL to leader: {}", error));
    }
    Ok(())
}

async fn propose_peer(
    ctx: &AdminContext,
    peer_prefix: &str,
    node_id: &str,
    kels_url: &str,
    gossip_addr: &str,
) -> anyhow::Result<()> {
    // Get this registry's prefix as proposer
    let proposer = ctx
        .identity_client
        .get_prefix()
        .await
        .context("Failed to get proposer prefix")?;

    // Get the approval threshold from federation status
    let threshold = match ctx.get_federation_status().await? {
        Some(status) => kels_registry::federation::FederationConfig::compute_approval_threshold(
            status.members.len(),
        ),
        None => return Err(anyhow!("Federation not configured")),
    };

    // Create payload for signing
    let peer_proposal = PeerAdditionProposal::empty(
        peer_prefix,
        node_id,
        kels_url,
        gossip_addr,
        &proposer,
        threshold,
        &StorageDatetime(chrono::Utc::now() + chrono::Duration::days(7)),
    )?;

    // Anchor the proposal's SAID in our KEL (this IS the signature)
    ctx.identity_client
        .anchor(&peer_proposal.said)
        .await
        .context("Failed to anchor proposal")?;

    // Get leader URL from federation status
    let mut target_url = ctx.get_leader_url().await?;

    // Sync KEL to leader so anchor is available for verification
    sync_kel_to_leader(ctx, &target_url).await?;

    // Retry loop for leader changes
    for attempt in 0..2 {
        let url = format!("{}/api/admin/addition-proposals", target_url);
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

async fn propose_removal(ctx: &AdminContext, peer_prefix: &str) -> anyhow::Result<()> {
    // Get this registry's prefix as proposer
    let proposer = ctx
        .identity_client
        .get_prefix()
        .await
        .context("Failed to get proposer prefix")?;

    // Get the approval threshold from federation status
    let threshold = match ctx.get_federation_status().await? {
        Some(status) => kels_registry::federation::FederationConfig::compute_approval_threshold(
            status.members.len(),
        ),
        None => return Err(anyhow!("Federation not configured")),
    };

    // Create removal proposal
    let removal_proposal = PeerRemovalProposal::empty(
        peer_prefix,
        &proposer,
        threshold,
        &StorageDatetime(chrono::Utc::now() + chrono::Duration::days(7)),
    )?;

    // Anchor the proposal's SAID in our KEL
    ctx.identity_client
        .anchor(&removal_proposal.said)
        .await
        .context("Failed to anchor removal proposal")?;

    // Get leader URL from federation status
    let mut target_url = ctx.get_leader_url().await?;

    // Sync KEL to leader so anchor is available for verification
    sync_kel_to_leader(ctx, &target_url).await?;

    // Retry loop for leader changes
    for attempt in 0..2 {
        let url = format!("{}/api/admin/removal-proposals", target_url);
        let resp = ctx
            .http_client
            .post(&url)
            .json(&removal_proposal)
            .send()
            .await?;

        if resp.status().is_success() {
            let result: ProposalResponse = resp.json().await?;
            println!("Removal proposal created: {}", result.proposal_id);
            println!("{}", result.message);
            return Ok(());
        }

        let error: serde_json::Value = resp.json().await.unwrap_or_default();
        let error_msg = error
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("unknown error");

        if error_msg.contains("Not leader")
            && let Some(new_leader_url) = extract_leader_url_from_error(error_msg)
            && attempt == 0
        {
            println!("Redirecting to leader at {}...", new_leader_url);
            target_url = new_leader_url;
            continue;
        }

        return Err(anyhow!("Failed to create removal proposal: {}", error_msg));
    }

    Err(anyhow!("Failed to create removal proposal after retries"))
}

async fn vote_proposal(ctx: &AdminContext, proposal_id: &str, approve: bool) -> anyhow::Result<()> {
    // Get this registry's prefix
    let voter = ctx
        .identity_client
        .get_prefix()
        .await
        .context("Failed to get voter prefix")?;

    // Create vote (SAID is auto-derived)
    let vote =
        Vote::create(proposal_id.to_string(), voter, approve).context("Failed to create vote")?;

    // Anchor the vote's SAID in our KEL (this IS the signature)
    ctx.identity_client
        .anchor(&vote.said)
        .await
        .context("Failed to anchor vote in KEL")?;

    // Get leader URL from federation status
    let mut target_url = ctx.get_leader_url().await?;

    // Sync KEL to leader so anchor is available for verification
    sync_kel_to_leader(ctx, &target_url).await?;

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
            if result.status == "approved" {
                println!("Peer has been added.");
            } else if result.status == "removal_approved" {
                println!("Peer has been removed.");
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
    let url = format!("{}/api/federation/proposals?audit=true", ctx.registry_url);
    let resp = ctx.http_client.get(&url).send().await?;

    if resp.status().is_success() {
        let response: CompletedProposalsResponse = resp.json().await?;

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
                    println!("Proposal:  {}", pwv.proposal_id());
                    println!("Peer ID:   {}", p.peer_prefix);
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
                    println!("Proposal:  {}", rwv.proposal_id());
                    println!("Peer ID:   {}", p.peer_prefix);
                    println!("Proposer:  {}", p.proposer);
                    println!("Status:    {:?}", status);
                    println!("Approvals: {}", rwv.approval_count());
                    println!("Expires:   {}", expires);
                    println!();
                }
            }
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
    let signed = sign_admin_request(ctx).await?;
    let url = format!("{}/api/admin/proposals/{}", ctx.registry_url, proposal_id);
    let resp = ctx.http_client.post(&url).json(&signed).send().await?;

    if resp.status().is_success() {
        let proposal: ProposalWithVotes = resp.json().await?;
        match proposal {
            ProposalWithVotes::Addition(pwv) => {
                if let Some(p) = pwv.history.inception() {
                    println!("Addition Proposal: {}", pwv.proposal_id());
                    println!("{}", "=".repeat(50));
                    println!("SAID:       {}", p.said);
                    println!("Peer ID:    {}", p.peer_prefix);
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
                    println!("Removal Proposal: {}", rwv.proposal_id());
                    println!("{}", "=".repeat(50));
                    println!("SAID:       {}", p.said);
                    println!("Peer ID:    {}", p.peer_prefix);
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
    // 1. Fetch the current proposal from the registry
    let mut target_url = ctx.get_leader_url().await?;
    let signed = sign_admin_request(ctx).await?;
    let fetch_url = format!("{}/api/admin/proposals/{}", target_url, proposal_id);
    let resp = ctx
        .http_client
        .post(&fetch_url)
        .json(&signed)
        .send()
        .await?;

    if !resp.status().is_success() {
        let error: serde_json::Value = resp.json().await.unwrap_or_default();
        return Err(anyhow!(
            "Failed to fetch proposal: {}",
            error
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("unknown error")
        ));
    }

    let proposal: ProposalWithVotes = resp
        .json()
        .await
        .context("Failed to parse proposal response")?;

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
                return Err(anyhow!("Proposal {} is already withdrawn", proposal_id));
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

            sync_kel_to_leader(ctx, &target_url).await?;

            for attempt in 0..2 {
                let url = format!("{}/api/admin/addition-proposals", target_url);
                let resp = ctx.http_client.post(&url).json(&withdrawal).send().await?;

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
                return Err(anyhow!("Proposal {} is already withdrawn", proposal_id));
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

            sync_kel_to_leader(ctx, &target_url).await?;

            for attempt in 0..2 {
                let url = format!("{}/api/admin/removal-proposals", target_url);
                let resp = ctx.http_client.post(&url).json(&withdrawal).send().await?;

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

                if error_msg.contains("Not leader")
                    && let Some(new_leader_url) = extract_leader_url_from_error(error_msg)
                    && attempt == 0
                {
                    println!("Redirecting to leader at {}...", new_leader_url);
                    target_url = new_leader_url;
                    continue;
                }

                return Err(anyhow!(
                    "Failed to withdraw removal proposal: {}",
                    error_msg
                ));
            }

            Err(anyhow!("Failed to withdraw removal proposal after retries"))
        }
    }
}

async fn list_peers(ctx: &AdminContext) -> anyhow::Result<()> {
    let url = format!("{}/api/peers?all=true", ctx.registry_url);
    let resp = ctx.http_client.get(&url).send().await?;

    if !resp.status().is_success() {
        let error: serde_json::Value = resp.json().await.unwrap_or_default();
        return Err(anyhow!(
            "Failed to list peers: {}",
            error
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("unknown error")
        ));
    }

    let response: PeersResponse = resp.json().await?;
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
        println!(
            "{:<20} {:<50} {:<8}",
            peer.node_id, peer.peer_prefix, status
        );
    }

    Ok(())
}

async fn show_allowlist(ctx: &AdminContext) -> anyhow::Result<()> {
    let url = format!("{}/api/peers", ctx.registry_url);
    let resp = ctx.http_client.get(&url).send().await?;

    if !resp.status().is_success() {
        let error: serde_json::Value = resp.json().await.unwrap_or_default();
        return Err(anyhow!(
            "Failed to fetch allowlist: {}",
            error
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("unknown error")
        ));
    }

    let response: PeersResponse = resp.json().await?;
    let active_peers: Vec<_> = response
        .peers
        .iter()
        .filter_map(|h| h.records.last())
        .filter(|p| p.active)
        .collect();

    println!("Current Allowlist:");
    println!("{}", "=".repeat(60));

    for peer in &active_peers {
        println!("  {} ({})", peer.peer_prefix, peer.node_id);
    }

    println!("{}", "=".repeat(60));
    println!("Total authorized peers: {}", active_peers.len());
    Ok(())
}

async fn show_history(ctx: &AdminContext) -> anyhow::Result<()> {
    let url = format!("{}/api/federation/proposals?audit=true", ctx.registry_url);
    let resp = ctx.http_client.get(&url).send().await?;

    if !resp.status().is_success() {
        let error: serde_json::Value = resp.json().await.unwrap_or_default();
        return Err(anyhow!(
            "Failed to fetch proposal history: {}",
            error
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("unknown error")
        ));
    }

    let response: CompletedProposalsResponse = resp.json().await?;

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
                    p.peer_prefix,
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
                    p.peer_prefix,
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
    let page = ctx
        .identity_client
        .get_key_events(None, kels::MAX_EVENTS_PER_KEL_RESPONSE)
        .await
        .context("Failed to get identity KEL")?;
    let kel = kels::Kel::from_events(page.events, true)?;

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
            PeerAction::List => {
                list_peers(&ctx).await?;
            }
            PeerAction::Propose {
                peer_prefix,
                node_id,
                kels_url,
                gossip_addr,
            } => {
                propose_peer(&ctx, &peer_prefix, &node_id, &kels_url, &gossip_addr).await?;
            }
            PeerAction::ProposeRemoval { peer_prefix } => {
                propose_removal(&ctx, &peer_prefix).await?;
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
