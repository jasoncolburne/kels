//! SAD Event Log (SEL) command handlers.
//!
//! Each staging command runs one `SadEventBuilder` lifecycle per CLI
//! invocation: construct, stage the event, optionally publish to the SAD
//! object store, print the SAID(s), exit. No anchoring (that's
//! `kels kel anchor`); no submission (that's `kels sel submit`).
//!
//! `submit` and `get` operate against the server directly. `submit` fetches
//! each pending event from the SAD object store by SAID before posting the
//! batch — the always-publish flow is load-bearing here. `get` runs a
//! verifier-driven walk via `verify_sad_events_with` (mirrors `kel get`).

use std::collections::BTreeSet;
use std::sync::Mutex;

use anyhow::{Context, Result, anyhow};
use cesr::Matter;
use colored::Colorize;
use kels_core::{
    HttpKelSource, HttpSadSource, KelVerifier, SadEvent, SadEventBuilder, SadStoreClient,
};

use crate::Cli;
use crate::helpers::sad_store_anchored_checker;

pub(crate) async fn cmd_sel_incept(
    cli: &Cli,
    topic: &str,
    identity: &str,
    initial_content: &str,
    publish: bool,
) -> Result<()> {
    let identity =
        cesr::Digest256::from_qb64(identity).context("Invalid --identity SAID (CESR)")?;
    let content = cesr::Digest256::from_qb64(initial_content)
        .context("Invalid --initial-content SAID (CESR)")?;

    let sad_client = SadStoreClient::new(&cli.sadstore_url())?;
    let checker = sad_store_anchored_checker(cli, &sad_client)?;

    // incept_chain calls fetch_current_iel_binding, which needs both
    // sad_client and checker. Build a fresh builder with both wired.
    let mut builder = SadEventBuilder::new(Some(sad_client), None, Some(checker));
    let (icp_said, upd_said) = builder
        .incept_chain(identity, topic, content)
        .await
        .context("Failed to stage atomic [Icp, Upd]")?;

    if publish {
        builder
            .publish_pending()
            .await
            .context("Failed to publish staged SEL events to SAD object store")?;
    }

    println!("{}", icp_said);
    println!("{}", upd_said);
    Ok(())
}

pub(crate) async fn cmd_sel_update(
    cli: &Cli,
    sel_prefix: &str,
    content_said: &str,
    publish: bool,
) -> Result<()> {
    let prefix = cesr::Digest256::from_qb64(sel_prefix).context("Invalid SEL prefix CESR")?;
    let content =
        cesr::Digest256::from_qb64(content_said).context("Invalid content SAID (CESR)")?;

    let sad_client = SadStoreClient::new(&cli.sadstore_url())?;
    let checker = sad_store_anchored_checker(cli, &sad_client)?;

    let mut builder = SadEventBuilder::with_remote_prefix(sad_client, checker, &prefix)
        .await
        .context("Failed to hydrate SE state from server")?;

    let said = builder
        .update(content)
        .await
        .context("Failed to stage Upd")?;

    if publish {
        builder
            .publish_pending()
            .await
            .context("Failed to publish staged SEL event to SAD object store")?;
    }

    println!("{}", said);
    Ok(())
}

pub(crate) async fn cmd_sel_seal(cli: &Cli, sel_prefix: &str, publish: bool) -> Result<()> {
    let prefix = cesr::Digest256::from_qb64(sel_prefix).context("Invalid SEL prefix CESR")?;

    let sad_client = SadStoreClient::new(&cli.sadstore_url())?;
    let checker = sad_store_anchored_checker(cli, &sad_client)?;

    let mut builder = SadEventBuilder::with_remote_prefix(sad_client, checker, &prefix)
        .await
        .context("Failed to hydrate SE state from server")?;

    let said = builder.seal().await.context("Failed to stage Sea")?;

    if publish {
        builder
            .publish_pending()
            .await
            .context("Failed to publish staged SEL event to SAD object store")?;
    }

    println!("{}", said);
    Ok(())
}

pub(crate) async fn cmd_sel_repair(
    cli: &Cli,
    sel_prefix: &str,
    owner_prefix: Option<&str>,
    publish: bool,
) -> Result<()> {
    let prefix = cesr::Digest256::from_qb64(sel_prefix).context("Invalid SEL prefix CESR")?;

    let sad_client = SadStoreClient::new(&cli.sadstore_url())?;
    let checker = sad_store_anchored_checker(cli, &sad_client)?;

    // Resolve the owner-anchored SAID set (kels-style silent-extension
    // boundary discovery). Walk the owner's KEL via verifier-driven page
    // walk, harvest each Ixn's anchor field. Stale-cache-free: every
    // repair invocation queries the KEL afresh — owner identity is the
    // KEL prefix, not local state.
    let owner_anchors: Option<BTreeSet<cesr::Digest256>> = match owner_prefix {
        Some(p) => {
            let owner_kel_prefix =
                cesr::Digest256::from_qb64(p).context("Invalid --owner-prefix CESR")?;
            let kel_source = HttpKelSource::new(&cli.kels_url(), "/api/v1/kels/kel/fetch")
                .context("Failed to build KEL source for owner anchor walk")?;
            let anchors: Mutex<BTreeSet<cesr::Digest256>> = Mutex::new(BTreeSet::new());
            kels_core::verify_key_events_with(
                &owner_kel_prefix,
                &kel_source,
                KelVerifier::new(&owner_kel_prefix),
                kels_core::page_size(),
                kels_core::max_pages(),
                |events| {
                    #[allow(clippy::expect_used)]
                    let mut set = anchors.lock().expect("anchor collector mutex poisoned");
                    for signed in events {
                        if let Some(a) = signed.event.anchor {
                            set.insert(a);
                        }
                    }
                },
            )
            .await
            .map_err(|e| anyhow!("Failed to verify owner's KEL ({}): {}", p, e))?;
            Some(
                anchors
                    .into_inner()
                    .map_err(|e| anyhow!("anchor collector mutex poisoned: {}", e))?,
            )
        }
        None => None,
    };

    let mut builder = SadEventBuilder::with_remote_prefix(sad_client, checker, &prefix)
        .await
        .context("Failed to hydrate SE state from server")?;

    let said = builder
        .repair(owner_anchors.as_ref())
        .await
        .context("Failed to stage Rpr")?;

    if publish {
        builder
            .publish_pending()
            .await
            .context("Failed to publish staged SEL event to SAD object store")?;
    }

    println!("{}", said);
    Ok(())
}

pub(crate) async fn cmd_sel_contest(cli: &Cli, sel_prefix: &str, publish: bool) -> Result<()> {
    let prefix = cesr::Digest256::from_qb64(sel_prefix).context("Invalid SEL prefix CESR")?;

    let sad_client = SadStoreClient::new(&cli.sadstore_url())?;
    let checker = sad_store_anchored_checker(cli, &sad_client)?;

    let mut builder = SadEventBuilder::with_remote_prefix(sad_client, checker, &prefix)
        .await
        .context("Failed to hydrate SE state from server")?;

    let said = builder.contest().await.context("Failed to stage Cnt")?;

    if publish {
        builder
            .publish_pending()
            .await
            .context("Failed to publish staged SEL event to SAD object store")?;
    }

    println!("{}", said);
    Ok(())
}

pub(crate) async fn cmd_sel_decommission(cli: &Cli, sel_prefix: &str, publish: bool) -> Result<()> {
    let prefix = cesr::Digest256::from_qb64(sel_prefix).context("Invalid SEL prefix CESR")?;

    let sad_client = SadStoreClient::new(&cli.sadstore_url())?;
    let checker = sad_store_anchored_checker(cli, &sad_client)?;

    let mut builder = SadEventBuilder::with_remote_prefix(sad_client, checker, &prefix)
        .await
        .context("Failed to hydrate SE state from server")?;

    let said = builder
        .decommission()
        .await
        .context("Failed to stage Dec")?;

    if publish {
        builder
            .publish_pending()
            .await
            .context("Failed to publish staged SEL event to SAD object store")?;
    }

    println!("{}", said);
    Ok(())
}

pub(crate) async fn cmd_sel_submit(cli: &Cli, saids: &[String]) -> Result<()> {
    if saids.is_empty() {
        return Err(anyhow!("sel submit requires at least one SAID"));
    }

    let client = SadStoreClient::new(&cli.sadstore_url())?;
    let mut events = Vec::with_capacity(saids.len());
    for s in saids {
        let said = cesr::Digest256::from_qb64(s)
            .with_context(|| format!("Invalid SEL event SAID: {}", s))?;
        let value = client
            .get_sad_object(&said)
            .await
            .with_context(|| format!("Failed to fetch SEL event {} from SAD object store", s))?;
        let event: SadEvent = serde_json::from_value(value)
            .with_context(|| format!("Failed to parse {} as SadEvent", s))?;
        events.push(event);
    }

    let response = client
        .submit_sad_events(&events)
        .await
        .context("Failed to submit SEL events")?;

    match (response.applied, &response.terminal) {
        (true, _) => {
            println!(
                "{}",
                format!("{} SEL event(s) submitted", events.len()).green()
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
                "warning: SEL diverged at version {} — stage a repair (unsealed) \
                 or contest (sealed) to resolve",
                at
            )
            .yellow()
        );
    }
    Ok(())
}

pub(crate) async fn cmd_sel_get(cli: &Cli, sel_prefix: &str) -> Result<()> {
    let prefix = cesr::Digest256::from_qb64(sel_prefix).context("Invalid SEL prefix CESR")?;
    let sad_client = SadStoreClient::new(&cli.sadstore_url())?;
    let checker = sad_store_anchored_checker(cli, &sad_client)?;
    let source = HttpSadSource::new(&cli.sadstore_url())?;

    // Streaming/diagnostic lines go to stderr; stdout is reserved for the
    // final JSON so callers can pipe `sel get` through `jq` cleanly.
    eprintln!("{}", format!("Fetching SEL {}...", sel_prefix).green());

    // Verifier-driven walk through `transfer_sad_events` (via
    // `verify_sad_events_with`). Streams summary lines per page while
    // collecting events for the JSON dump; reads divergent / terminal
    // state off the resulting verification token. Mirrors
    // `kels kel get` and `kels iel get`.
    //
    // The IelResolver the verifier needs is built inside
    // `verify_server_chain_pre_action` shape — but here we want
    // the streaming-verify-with-callback API rather than the builder
    // shape. We reuse the same pattern: pre-walk for queried IEL SAIDs,
    // build an AnchoredIelResolver, then run the verifier.
    let queried = kels_core::collect_identity_event_saids(
        &prefix,
        &source,
        kels_core::page_size(),
        kels_core::max_pages(),
    )
    .await
    .context("Failed to pre-walk SEL chain for queried IEL SAIDs")?;

    let iel_source: std::sync::Arc<dyn kels_core::PagedIelSource + Send + Sync> =
        std::sync::Arc::new(sad_client.as_iel_source()?);
    let iel_resolver: std::sync::Arc<dyn kels_core::IelResolver + Send + Sync> =
        std::sync::Arc::new(
            kels_core::AnchoredIelResolver::new(
                iel_source,
                std::sync::Arc::clone(&checker),
                kels_core::page_size(),
                kels_core::max_pages(),
            )
            .with_queried_saids(queried),
        );

    let collected: Mutex<Vec<SadEvent>> = Mutex::new(Vec::new());
    let verification = kels_core::verify_sad_events_with(
        &prefix,
        &source,
        checker,
        iel_resolver,
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
        "prefix": sel_prefix,
        "events": events,
        "diverged_at": verification.diverged_at_version(),
        "is_divergent": verification.is_divergent(),
        "is_contested": verification.is_contested(),
        "is_decommissioned": verification.is_decommissioned(),
    });

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

pub(crate) fn cmd_sel_prefix(identity: &str, topic: &str) -> Result<()> {
    let identity_digest = cesr::Digest256::from_qb64(identity).context("Invalid identity CESR")?;
    let prefix = kels_core::compute_sad_event_prefix(identity_digest, topic)
        .context("Failed to compute SEL prefix")?;
    println!("{}", prefix);
    Ok(())
}
