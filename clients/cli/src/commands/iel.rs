//! Identity Event Log (IEL) command handlers.
//!
//! Each staging command runs one `IdentityEventBuilder` lifecycle per CLI
//! invocation: construct, stage the event, optionally publish to the SAD
//! object store, print the SAID, exit. No anchoring (that's
//! `kels kel anchor`); no submission (that's `kels iel submit`).
//!
//! `submit` and `get` operate against the server directly and don't use
//! the builder. `submit` fetches each pending event from the SAD object
//! store by SAID before posting the batch — the always-publish flow is
//! load-bearing here.

use std::sync::Mutex;

use anyhow::{Context, Result, anyhow};
use cesr::Matter;
use colored::Colorize;
use kels_core::{HttpIelSource, IdentityEvent, IdentityEventBuilder, SadStoreClient};

use crate::Cli;
use crate::helpers::{sad_store_anchored_checker, submit_with_deferred_deps_poll};

pub(crate) async fn cmd_iel_incept(
    cli: &Cli,
    topic: &str,
    auth_policy: &str,
    governance_policy: &str,
    publish: bool,
) -> Result<()> {
    let auth =
        cesr::Digest256::from_qb64(auth_policy).context("Invalid --auth-policy SAID (CESR)")?;
    let gov = cesr::Digest256::from_qb64(governance_policy)
        .context("Invalid --governance-policy SAID (CESR)")?;

    let sad_client = SadStoreClient::new(&cli.sadstore_url())?;
    let mut builder = IdentityEventBuilder::new(Some(sad_client), None, None);
    let said = builder
        .incept(auth, gov, topic)
        .context("Failed to stage IEL Icp")?;

    if publish {
        builder
            .publish_pending()
            .await
            .context("Failed to publish staged IEL event to SAD object store")?;
    }

    println!("{}", said);
    Ok(())
}

pub(crate) async fn cmd_iel_evolve(
    cli: &Cli,
    iel_prefix: &str,
    auth_policy: Option<&str>,
    governance_policy: Option<&str>,
    publish: bool,
) -> Result<()> {
    let prefix = cesr::Digest256::from_qb64(iel_prefix).context("Invalid IEL prefix CESR")?;
    let auth = auth_policy
        .map(|s| cesr::Digest256::from_qb64(s).context("Invalid --auth-policy SAID (CESR)"))
        .transpose()?;
    let gov = governance_policy
        .map(|s| cesr::Digest256::from_qb64(s).context("Invalid --governance-policy SAID (CESR)"))
        .transpose()?;

    let sad_client = SadStoreClient::new(&cli.sadstore_url())?;
    let checker = sad_store_anchored_checker(cli, &sad_client)?;

    let mut builder = IdentityEventBuilder::with_remote_prefix(sad_client, checker, &prefix)
        .await
        .context("Failed to hydrate IEL state from server")?;

    let said = builder
        .evolve(auth, gov)
        .context("Failed to stage IEL Evl")?;

    if publish {
        builder
            .publish_pending()
            .await
            .context("Failed to publish staged IEL event to SAD object store")?;
    }

    println!("{}", said);
    Ok(())
}

pub(crate) async fn cmd_iel_contest(cli: &Cli, iel_prefix: &str, publish: bool) -> Result<()> {
    let prefix = cesr::Digest256::from_qb64(iel_prefix).context("Invalid IEL prefix CESR")?;

    let sad_client = SadStoreClient::new(&cli.sadstore_url())?;
    let checker = sad_store_anchored_checker(cli, &sad_client)?;

    let mut builder = IdentityEventBuilder::with_remote_prefix(sad_client, checker, &prefix)
        .await
        .context("Failed to hydrate IEL state from server")?;

    let said = builder.contest().await.context("Failed to stage IEL Cnt")?;

    if publish {
        builder
            .publish_pending()
            .await
            .context("Failed to publish staged IEL event to SAD object store")?;
    }

    println!("{}", said);
    Ok(())
}

pub(crate) async fn cmd_iel_decommission(cli: &Cli, iel_prefix: &str, publish: bool) -> Result<()> {
    let prefix = cesr::Digest256::from_qb64(iel_prefix).context("Invalid IEL prefix CESR")?;

    let sad_client = SadStoreClient::new(&cli.sadstore_url())?;
    let checker = sad_store_anchored_checker(cli, &sad_client)?;

    let mut builder = IdentityEventBuilder::with_remote_prefix(sad_client, checker, &prefix)
        .await
        .context("Failed to hydrate IEL state from server")?;

    let said = builder
        .decommission()
        .await
        .context("Failed to stage IEL Dec")?;

    if publish {
        builder
            .publish_pending()
            .await
            .context("Failed to publish staged IEL event to SAD object store")?;
    }

    println!("{}", said);
    Ok(())
}

pub(crate) async fn cmd_iel_get(cli: &Cli, iel_prefix: &str) -> Result<()> {
    let prefix = cesr::Digest256::from_qb64(iel_prefix).context("Invalid IEL prefix CESR")?;
    let sad_client = SadStoreClient::new(&cli.sadstore_url())?;
    let checker = sad_store_anchored_checker(cli, &sad_client)?;
    let source = HttpIelSource::new(&cli.sadstore_url())?;

    // Streaming/diagnostic lines go to stderr; stdout is reserved for the
    // final JSON so callers can pipe `iel get` through `jq` cleanly.
    eprintln!("{}", format!("Fetching IEL {}...", iel_prefix).green());

    // Verifier-driven walk mirrors `kels kel get` (which uses
    // `verify_key_events_with`). Stream summary lines per page while
    // collecting events for the JSON dump, and read divergent /
    // terminal state off the resulting verification token.
    let collected: Mutex<Vec<IdentityEvent>> = Mutex::new(Vec::new());
    let verification = kels_core::verify_identity_events_with(
        &prefix,
        &source,
        checker,
        kels_core::page_size(),
        kels_core::max_pages(),
        |events| {
            for event in events {
                eprintln!("  [{}] {:?} - {}", event.version, event.kind, event.said);
            }
            #[allow(clippy::expect_used)]
            collected
                .lock()
                .expect("collector mutex poisoned")
                .extend_from_slice(events);
        },
    )
    .await
    .map_err(|e| anyhow!("{}", e))?;

    let events = collected
        .into_inner()
        .map_err(|e| anyhow!("collector mutex poisoned: {}", e))?;

    let output = serde_json::json!({
        "prefix": iel_prefix,
        "events": events,
        "diverged_at": verification.diverged_at_version(),
        "is_divergent": verification.is_divergent(),
        "is_contested": verification.is_contested(),
        "is_decommissioned": verification.is_decommissioned(),
    });

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

pub(crate) async fn cmd_iel_submit(cli: &Cli, saids: &[String]) -> Result<()> {
    if saids.is_empty() {
        return Err(anyhow!("iel submit requires at least one SAID"));
    }

    let client = SadStoreClient::new(&cli.sadstore_url())?;
    let mut events = Vec::with_capacity(saids.len());
    for s in saids {
        let said = cesr::Digest256::from_qb64(s)
            .with_context(|| format!("Invalid IEL event SAID: {}", s))?;
        let value = client
            .get_sad_object(&said)
            .await
            .with_context(|| format!("Failed to fetch IEL event {} from SAD object store", s))?;
        let event: IdentityEvent = serde_json::from_value(value)
            .with_context(|| format!("Failed to parse {} as IdentityEvent", s))?;
        events.push(event);
    }

    let response =
        submit_with_deferred_deps_poll("IEL submit", || client.submit_identity_events(&events))
            .await
            .context("Failed to submit IEL events")?;

    match (response.applied, &response.terminal) {
        (true, _) => {
            println!(
                "{}",
                format!("{} IEL event(s) submitted", events.len()).green()
            );
        }
        (false, Some(terminal)) => {
            println!(
                "{}",
                format!(
                    "chain is already terminal ({:?}) — submit was a no-op",
                    terminal
                )
                .yellow()
            );
        }
        (false, None) => {
            println!(
                "{}",
                "no new events submitted (all already present on server)".yellow()
            );
        }
    }
    if let Some(at) = response.diverged_at {
        eprintln!(
            "{}",
            format!(
                "warning: IEL diverged at version {} — stage a contest to resolve",
                at
            )
            .yellow()
        );
    }
    Ok(())
}
