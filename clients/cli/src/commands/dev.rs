//! Development and testing command handlers.

use anyhow::{Result, anyhow, bail};
use cesr::Matter;
use colored::Colorize;
use kels_core::{EventKind, KelStore, ProviderConfig};

use crate::Cli;
use crate::helpers::*;

pub(crate) async fn cmd_dev_truncate(cli: &Cli, prefix: &str, count: usize) -> Result<()> {
    println!(
        "{}",
        format!("Truncating local KEL {} to {} events...", prefix, count).yellow()
    );

    let prefix_digest = cesr::Digest::from_qb64(prefix).map_err(|e| anyhow!("{}", e))?;
    let kel_store = create_kel_store(cli, prefix)?;
    let source = kels_core::StoreKelSource::new(&kel_store);

    let mut events = kels_core::resolve_key_events(
        &prefix_digest,
        &source,
        kels_core::page_size(),
        kels_core::max_pages(),
        None,
    )
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
    kel_store.overwrite(&prefix_digest, &events).await?;

    println!(
        "{}",
        format!("Truncated to {} events.", count).green().bold()
    );

    Ok(())
}

pub(crate) async fn cmd_dev_dump_kel(cli: &Cli, prefix: &str) -> Result<()> {
    let prefix_digest = cesr::Digest::from_qb64(prefix).map_err(|e| anyhow!("{}", e))?;
    let kel_store = create_kel_store(cli, prefix)?;
    let source = kels_core::StoreKelSource::new(&kel_store);
    let all_events = kels_core::resolve_key_events(
        &prefix_digest,
        &source,
        kels_core::page_size(),
        kels_core::max_pages(),
        None,
    )
    .await
    .map_err(|e| anyhow!("{}", e))?;

    if all_events.is_empty() {
        return Err(anyhow!("KEL not found locally: {}", prefix));
    }

    let json = serde_json::to_string_pretty(&all_events)?;
    println!("{}", json);

    Ok(())
}

pub(crate) async fn cmd_adversary_inject(cli: &Cli, prefix: &str, events_str: &str) -> Result<()> {
    use kels_core::KeyEventBuilder;

    println!(
        "{}",
        format!("ADVERSARY: Injecting events to {} (server only)...", prefix)
            .yellow()
            .bold()
    );

    // Load the local KEL to get the chain state (dev-tools, not production)
    let prefix_digest = cesr::Digest::from_qb64(prefix).map_err(|e| anyhow!("{}", e))?;
    let kel_store = create_kel_store(cli, prefix)?;
    let source = kels_core::StoreKelSource::new(&kel_store);
    let events = kels_core::resolve_key_events(
        &prefix_digest,
        &source,
        kels_core::page_size(),
        kels_core::max_pages(),
        None,
    )
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
                let anchor = kels_core::generate_nonce();
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
