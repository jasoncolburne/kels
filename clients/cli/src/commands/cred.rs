//! Credential management command handlers.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use colored::Colorize;
use kels_core::{KeyEventBuilder, ProviderConfig};
use verifiable_storage::SelfAddressed;

use crate::Cli;
use crate::helpers::{config_dir, create_client, create_kel_store, provider_config};

/// Directory for locally stored credentials.
fn creds_dir(cli: &Cli) -> Result<PathBuf> {
    Ok(config_dir(cli)?.join("creds"))
}

/// Store a credential JSON locally by SAID.
fn store_cred_locally(creds_dir: &Path, said: &str, value: &serde_json::Value) -> Result<()> {
    std::fs::create_dir_all(creds_dir)?;
    let path = creds_dir.join(format!("{}.json", said));
    let json = serde_json::to_string_pretty(value)?;
    std::fs::write(&path, json).context("Failed to write credential file")?;
    Ok(())
}

/// Load a credential JSON by SAID.
fn load_cred(creds_dir: &Path, said: &str) -> Result<serde_json::Value> {
    let path = creds_dir.join(format!("{}.json", said));
    let data = std::fs::read_to_string(&path)
        .with_context(|| format!("Credential not found locally: {}", said))?;
    serde_json::from_str(&data).context("Failed to parse credential JSON")
}

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

    // Store credential locally
    let creds = creds_dir(cli)?;
    let cred_value = serde_json::to_value(&credential)?;
    store_cred_locally(&creds, &credential.said, &cred_value)?;

    // Also store schema and policy locally for later use
    let schema_value = serde_json::to_value(&schema)?;
    store_cred_locally(&creds, &schema.said, &schema_value)?;
    let policy_value = serde_json::to_value(&policy)?;
    store_cred_locally(&creds, &policy.said, &policy_value)?;

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

    let said = value
        .get("said")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Credential missing 'said' field"))?;

    // Verify SAID
    value
        .verify_said()
        .context("Credential SAID verification failed")?;

    // Store credential
    let creds = creds_dir(cli)?;
    store_cred_locally(&creds, said, &value)?;

    // Store schema
    let schema_data = std::fs::read_to_string(schema_path)
        .with_context(|| format!("Failed to read schema: {}", schema_path.display()))?;
    let schema_value: serde_json::Value =
        serde_json::from_str(&schema_data).context("Failed to parse schema")?;
    if let Some(schema_said) = schema_value.get("said").and_then(|v| v.as_str()) {
        store_cred_locally(&creds, schema_said, &schema_value)?;
    }

    println!("{}", format!("Credential stored: {}", said).green().bold());

    Ok(())
}

pub(crate) async fn cmd_cred_list(cli: &Cli) -> Result<()> {
    let creds = creds_dir(cli)?;
    if !creds.exists() {
        println!("{}", "No credentials stored locally.".yellow());
        return Ok(());
    }

    let mut count = 0;
    for entry in std::fs::read_dir(&creds)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json")
            && let Ok(data) = std::fs::read_to_string(&path)
            && let Ok(value) = serde_json::from_str::<serde_json::Value>(&data)
            && value.get("schema").is_some()
            && value.get("policy").is_some()
        {
            let said = value.get("said").and_then(|v| v.as_str()).unwrap_or("-");
            let schema = value.get("schema").and_then(|v| v.as_str()).unwrap_or("-");
            let policy = value.get("policy").and_then(|v| v.as_str()).unwrap_or("-");
            println!("  {} | schema: {} | policy: {}", said, schema, policy);
            count += 1;
        }
    }

    if count == 0 {
        println!("{}", "No credentials stored locally.".yellow());
    } else {
        println!("{}", format!("{} credential(s)", count).cyan().bold());
    }

    Ok(())
}

pub(crate) async fn cmd_cred_show(cli: &Cli, said: &str) -> Result<()> {
    let creds = creds_dir(cli)?;
    let value = load_cred(&creds, said)?;
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
