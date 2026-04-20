//! SAD store command handlers.

use std::path::PathBuf;

use anyhow::{Context, Result};
use cesr::Matter;
use colored::Colorize;
use verifiable_storage::SelfAddressed;

use crate::Cli;

pub(crate) async fn cmd_sad_put(cli: &Cli, file: &PathBuf) -> Result<()> {
    let data = std::fs::read_to_string(file)
        .with_context(|| format!("Failed to read file: {}", file.display()))?;
    let mut value: serde_json::Value =
        serde_json::from_str(&data).context("Failed to parse JSON file")?;

    // Extract current said, compute the correct one, and validate
    let current_said = value
        .get("said")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    value
        .derive_said()
        .context("Failed to compute SAID for object")?;

    if !current_said.is_empty()
        && !current_said.chars().all(|c| c == '#')
        && current_said != value.get_said().to_string()
    {
        anyhow::bail!(
            "SAID mismatch: provided {} but computed {}",
            current_said,
            value.get_said()
        );
    }

    let client = kels_core::SadStoreClient::new(&cli.sadstore_url())?;
    let said = client
        .post_sad_object(&value)
        .await
        .context("Failed to store SAD object")?;

    println!("{}", said);
    Ok(())
}

pub(crate) async fn cmd_sad_get(cli: &Cli, said: &str) -> Result<()> {
    let said = cesr::Digest256::from_qb64(said).context("Invalid SAID")?;
    let client = kels_core::SadStoreClient::new(&cli.sadstore_url())?;
    let value = client
        .get_sad_object(&said)
        .await
        .context("Failed to retrieve SAD object")?;

    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

pub(crate) async fn cmd_sad_submit(cli: &Cli, file: &PathBuf) -> Result<()> {
    let data = std::fs::read_to_string(file)
        .with_context(|| format!("Failed to read file: {}", file.display()))?;
    let records: Vec<kels_core::SadPointer> =
        serde_json::from_str(&data).context("Failed to parse SadPointer JSON")?;

    let client = kels_core::SadStoreClient::new(&cli.sadstore_url())?;
    client
        .submit_sad_pointer(&records)
        .await
        .context("Failed to submit SAD records")?;

    println!(
        "{}",
        format!("{} SAD record(s) submitted", records.len()).green()
    );
    Ok(())
}

pub(crate) async fn cmd_sad_chain(cli: &Cli, prefix: &str) -> Result<()> {
    let prefix_digest = cesr::Digest256::from_qb64(prefix).context("Invalid prefix CESR")?;
    let client = kels_core::SadStoreClient::new(&cli.sadstore_url())?;
    let page = client
        .fetch_sad_pointer(&prefix_digest, None)
        .await
        .context("Failed to fetch SAD chain")?;

    println!("{}", serde_json::to_string_pretty(&page)?);
    Ok(())
}

pub(crate) fn cmd_sad_prefix(write_policy: &str, topic: &str) -> Result<()> {
    let write_policy_digest =
        cesr::Digest256::from_qb64(write_policy).context("Invalid write policy CESR")?;
    let prefix = kels_core::compute_sad_pointer_prefix(write_policy_digest, topic)
        .context("Failed to compute SAD prefix")?;
    println!("{}", prefix);
    Ok(())
}
