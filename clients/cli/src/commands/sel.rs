//! SAD Event Log (SEL) command handlers.

use std::path::PathBuf;

use anyhow::{Context, Result};
use cesr::Matter;
use colored::Colorize;

use crate::Cli;

pub(crate) async fn cmd_sel_submit(cli: &Cli, file: &PathBuf) -> Result<()> {
    let data = std::fs::read_to_string(file)
        .with_context(|| format!("Failed to read file: {}", file.display()))?;
    let records: Vec<kels_core::SadEvent> =
        serde_json::from_str(&data).context("Failed to parse SadEvent JSON")?;

    let client = kels_core::SadStoreClient::new(&cli.sadstore_url())?;
    client
        .submit_sad_events(&records)
        .await
        .context("Failed to submit SAD records")?;

    println!(
        "{}",
        format!("{} SAD record(s) submitted", records.len()).green()
    );
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
        .context("Failed to compute SAD prefix")?;
    println!("{}", prefix);
    Ok(())
}
