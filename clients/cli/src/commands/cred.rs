//! Credential management command handlers.

use std::path::PathBuf;

use anyhow::{Context, Result};
use colored::Colorize;
use kels_core::{KeyEventBuilder, ProviderConfig, SadStore};
use verifiable_storage::SelfAddressed;

use crate::Cli;
use crate::helpers::{create_client, create_kel_store, create_sad_store, provider_config};

pub(crate) async fn cmd_cred_issue(
    cli: &Cli,
    prefix: &str,
    schema_path: &PathBuf,
    policy_path: &PathBuf,
    claims_path: &PathBuf,
    subject: Option<&str>,
    unique: bool,
) -> Result<()> {
    println!("{}", "Issuing credential...".green());

    // Load schema
    let schema_data = std::fs::read_to_string(schema_path)
        .with_context(|| format!("Failed to read schema: {}", schema_path.display()))?;
    let schema: kels_creds::Schema =
        serde_json::from_str(&schema_data).context("Failed to parse schema")?;

    // Load policy
    let policy_data = std::fs::read_to_string(policy_path)
        .with_context(|| format!("Failed to read policy: {}", policy_path.display()))?;
    let policy: kels_creds::Policy =
        serde_json::from_str(&policy_data).context("Failed to parse policy")?;

    // Load claims (as generic JSON Value with SelfAddressed support)
    let claims_data = std::fs::read_to_string(claims_path)
        .with_context(|| format!("Failed to read claims: {}", claims_path.display()))?;
    let claims: serde_json::Value =
        serde_json::from_str(&claims_data).context("Failed to parse claims")?;

    // Build credential
    let (credential, canonical_said) = kels_creds::Credential::build(
        &schema,
        &policy,
        subject.map(|s| s.to_string()),
        claims,
        unique,
        None, // edges
        None, // rules
        None, // expires_at
    )
    .await
    .context("Failed to build credential")?;

    println!("  Credential SAID: {}", credential.said);
    println!("  Canonical SAID:  {}", canonical_said);

    // Anchor the canonical SAID in the KEL via ixn
    let client = create_client(cli).await?;
    let key_provider = provider_config(cli, prefix)?.load_provider().await?;
    let kel_store = create_kel_store(cli, prefix)?;

    let mut builder = KeyEventBuilder::with_dependencies(
        key_provider,
        Some(client),
        Some(std::sync::Arc::new(kel_store)),
        Some(prefix),
    )
    .await?;

    let signed = builder
        .interact(&canonical_said)
        .await
        .context("Failed to anchor credential SAID in KEL")?;
    println!("  Anchored in KEL: {} (ixn)", signed.event.said);

    // Store credential, schema, and policy locally
    let sad_store = create_sad_store(cli)?;
    let cred_value = serde_json::to_value(&credential)?;
    sad_store.store(&credential.said, &cred_value).await?;
    let schema_value = serde_json::to_value(&schema)?;
    sad_store.store(&schema.said, &schema_value).await?;
    let policy_value = serde_json::to_value(&policy)?;
    sad_store.store(&policy.said, &policy_value).await?;

    println!(
        "{}",
        format!("Credential issued: {}", canonical_said)
            .green()
            .bold()
    );

    Ok(())
}

pub(crate) async fn cmd_cred_store(
    cli: &Cli,
    file_path: &PathBuf,
    schema_path: &PathBuf,
) -> Result<()> {
    let data = std::fs::read_to_string(file_path)
        .with_context(|| format!("Failed to read credential: {}", file_path.display()))?;
    let value: serde_json::Value =
        serde_json::from_str(&data).context("Failed to parse credential JSON")?;

    // Verify SAID
    value
        .verify_said()
        .context("Credential SAID verification failed")?;

    let said = value.get_said();

    // Store credential and schema
    let sad_store = create_sad_store(cli)?;
    sad_store.store(&said, &value).await?;

    let schema_data = std::fs::read_to_string(schema_path)
        .with_context(|| format!("Failed to read schema: {}", schema_path.display()))?;
    let schema_value: serde_json::Value =
        serde_json::from_str(&schema_data).context("Failed to parse schema")?;
    let schema_said = schema_value.get_said();
    if !schema_said.is_empty() {
        sad_store.store(&schema_said, &schema_value).await?;
    }

    println!("{}", format!("Credential stored: {}", said).green().bold());

    Ok(())
}

pub(crate) async fn cmd_cred_list(cli: &Cli) -> Result<()> {
    let sad_store = create_sad_store(cli)?;

    let mut count = 0;
    let mut since: Option<String> = None;
    loop {
        let (saids, has_more) = sad_store
            .list(since.as_deref(), kels_core::page_size())
            .await?;

        for said in &saids {
            if let Ok(value) = sad_store.load(said).await
                && value.get("schema").is_some()
                && value.get("policy").is_some()
            {
                let schema = value.get("schema").and_then(|v| v.as_str()).unwrap_or("-");
                let policy = value.get("policy").and_then(|v| v.as_str()).unwrap_or("-");
                println!("  {} | schema: {} | policy: {}", said, schema, policy);
                count += 1;
            }
        }

        if !has_more {
            break;
        }
        since = saids.last().cloned();
    }

    if count == 0 {
        println!("{}", "No credentials stored locally.".yellow());
    } else {
        println!("{}", format!("{} credential(s)", count).cyan().bold());
    }

    Ok(())
}

pub(crate) async fn cmd_cred_show(cli: &Cli, said: &str) -> Result<()> {
    let sad_store = create_sad_store(cli)?;
    let value = sad_store.load(said).await?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

pub(crate) async fn cmd_cred_poison(cli: &Cli, prefix: &str, said: &str) -> Result<()> {
    println!("{}", format!("Poisoning credential {}...", said).yellow());

    let poison = kels_policy::poison_hash(said);
    println!("  Poison hash: {}", poison);

    // Anchor poison hash in KEL via ixn
    let client = create_client(cli).await?;
    let key_provider = provider_config(cli, prefix)?.load_provider().await?;
    let kel_store = create_kel_store(cli, prefix)?;

    let mut builder = KeyEventBuilder::with_dependencies(
        key_provider,
        Some(client),
        Some(std::sync::Arc::new(kel_store)),
        Some(prefix),
    )
    .await?;

    let signed = builder
        .interact(&poison)
        .await
        .context("Failed to anchor poison hash in KEL")?;
    println!("  Anchored in KEL: {} (ixn)", signed.event.said);

    println!("{}", format!("Credential {} poisoned", said).green().bold());

    Ok(())
}
