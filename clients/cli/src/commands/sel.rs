//! SAD Event Log (SEL) command handlers.

use std::path::PathBuf;

use anyhow::{Context, Result};
use cesr::Matter;
use colored::Colorize;

use crate::Cli;

pub(crate) async fn cmd_sel_submit(cli: &Cli, file: &PathBuf) -> Result<()> {
    let data = std::fs::read_to_string(file)
        .with_context(|| format!("Failed to read file: {}", file.display()))?;
    let events: Vec<kels_core::SadEvent> =
        serde_json::from_str(&data).context("Failed to parse SadEvent JSON")?;

    let client = kels_core::SadStoreClient::new(&cli.sadstore_url())?;
    let response = client
        .submit_sad_events(&events)
        .await
        .context("Failed to submit SAD events")?;

    if response.applied {
        println!(
            "{}",
            format!("{} SAD event(s) submitted", events.len()).green()
        );
    } else {
        println!(
            "{}",
            "no new events submitted (all already present on server)".yellow()
        );
    }
    if let Some(at) = response.diverged_at {
        eprintln!(
            "{}",
            format!(
                "warning: SEL diverged at version {} — stage a repair to resolve",
                at
            )
            .yellow()
        );
    }
    Ok(())
}

pub(crate) async fn cmd_sel_get(cli: &Cli, prefix: &str) -> Result<()> {
    let prefix_digest = cesr::Digest256::from_qb64(prefix).context("Invalid prefix CESR")?;
    let client = kels_core::SadStoreClient::new(&cli.sadstore_url())?;
    let page = client
        .fetch_sad_events(&prefix_digest, None)
        .await
        .context("Failed to fetch SAD Event Log")?;

    println!("{}", serde_json::to_string_pretty(&page)?);
    Ok(())
}

pub(crate) fn cmd_sel_prefix(write_policy: &str, topic: &str) -> Result<()> {
    let write_policy_digest =
        cesr::Digest256::from_qb64(write_policy).context("Invalid write policy CESR")?;
    let prefix = kels_core::compute_sad_event_prefix(write_policy_digest, topic)
        .context("Failed to compute SEL prefix")?;
    println!("{}", prefix);
    Ok(())
}
