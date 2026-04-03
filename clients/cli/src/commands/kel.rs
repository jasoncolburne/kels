//! KEL command handlers.

use std::iter;

use anyhow::{Context, Result, anyhow};
use colored::Colorize;
use kels_core::{
    FileKelStore, HttpKelSource, KelVerification, KelVerifier, KeyEventBuilder, KeyProvider,
    ProviderConfig, SoftwareKeyProvider, VerificationKeyCode,
};

use crate::Cli;
use crate::helpers::*;

pub(crate) async fn cmd_list_nodes(cli: &Cli) -> Result<()> {
    let registry_urls = parse_registry_urls(&cli.registry);
    if registry_urls.is_empty() {
        return Err(anyhow!("No registry URLs provided"));
    }

    println!(
        "{}",
        format!("Discovering nodes from {}...", cli.registry).green()
    );

    let store = create_kel_store(cli, "registry-discovery")?;
    let peers = kels_core::peers_sorted_by_latency(
        &registry_urls,
        std::time::Duration::from_secs(2),
        &store,
    )
    .await?;

    if peers.is_empty() {
        println!("{}", "No ready peers found.".yellow());
        return Ok(());
    }

    println!();
    println!("{}", "Ready Peers (sorted by latency):".cyan().bold());

    for peer in &peers {
        let kels_url = format!("http://kels.{}", peer.base_domain);
        let latency_str = if let Ok(client) =
            kels_core::KelsClient::with_timeout(&kels_url, std::time::Duration::from_secs(2))
        {
            client
                .test_latency()
                .await
                .map(|d| format!("{}ms", d.as_millis()))
                .unwrap_or_else(|_| "-".to_string())
        } else {
            "-".to_string()
        };

        println!(
            "  {} [{}] - {} (latency: {})",
            peer.node_id,
            "READY".green(),
            peer.base_domain,
            latency_str
        );
    }

    Ok(())
}

pub(crate) async fn cmd_incept(
    cli: &Cli,
    signing: VerificationKeyCode,
    recovery: VerificationKeyCode,
) -> Result<()> {
    println!("{}", "Creating new KEL...".green());

    let client = create_client(cli).await?;
    let key_provider = SoftwareKeyProvider::new(signing, recovery);

    // Pass a kel_store to the builder so add_and_flush saves automatically
    let kel_dir = kel_dir(cli)?;
    let kel_store = FileKelStore::new(&kel_dir).context("Failed to create KEL store")?;
    let mut builder = KeyEventBuilder::with_dependencies(
        key_provider,
        Some(client),
        Some(std::sync::Arc::new(kel_store)),
        None,
    )
    .await?;

    let icp = builder.incept().await.context("Inception failed")?;

    // Save keys to the correct prefix directory
    let config = provider_config(cli, &icp.event.prefix)?;
    config.save_provider(builder.key_provider()).await?;

    println!("{}", "KEL created successfully!".green().bold());
    println!("  Prefix: {}", icp.event.prefix.cyan());
    println!("  SAID:   {}", icp.event.said);

    Ok(())
}

pub(crate) async fn cmd_rotate(
    cli: &Cli,
    prefix: &str,
    algorithm: Option<VerificationKeyCode>,
) -> Result<()> {
    println!(
        "{}",
        format!("Rotating signing key for {}...", prefix).green()
    );

    let config = provider_config(cli, prefix)?;
    let client = create_client(cli).await?;
    let key_provider = config.load_provider().await?;
    let kel_store = create_kel_store(cli, prefix)?;

    let mut builder = KeyEventBuilder::with_dependencies(
        key_provider,
        Some(client),
        Some(std::sync::Arc::new(kel_store)),
        Some(prefix),
    )
    .await?;

    if let Some(algo) = algorithm {
        builder
            .key_provider_mut()
            .set_signing_algorithm(algo)
            .await?;
    }

    match builder.rotate().await {
        Ok(rot) => {
            config.save_provider(builder.key_provider()).await?;
            println!("{}", "Rotation successful!".green().bold());
            println!("  Event SAID: {}", rot.event.said);
            Ok(())
        }
        Err(kels_core::KelsError::DivergenceDetected {
            submission_accepted: true,
            ref diverged_at,
        }) => {
            // Keys were committed internally - save them before returning error
            config.save_provider(builder.key_provider()).await?;
            Err(anyhow!(
                "Divergence detected at: {}, submission_accepted: true",
                diverged_at
            ))
        }
        Err(e) => Err(e.into()),
    }
}

pub(crate) async fn cmd_rotate_recovery(
    cli: &Cli,
    prefix: &str,
    signing_algorithm: Option<VerificationKeyCode>,
    recovery_algorithm: Option<VerificationKeyCode>,
) -> Result<()> {
    println!(
        "{}",
        format!("Rotating signing and recovery keys for {}...", prefix).green()
    );

    let config = provider_config(cli, prefix)?;
    let client = create_client(cli).await?;
    let key_provider = config.load_provider().await?;
    let kel_store = create_kel_store(cli, prefix)?;

    let mut builder = KeyEventBuilder::with_dependencies(
        key_provider,
        Some(client),
        Some(std::sync::Arc::new(kel_store)),
        Some(prefix),
    )
    .await?;

    if let Some(algo) = signing_algorithm {
        builder
            .key_provider_mut()
            .set_signing_algorithm(algo)
            .await?;
    }
    if let Some(algo) = recovery_algorithm {
        builder
            .key_provider_mut()
            .set_recovery_algorithm(algo)
            .await?;
    }

    let ror = builder
        .rotate_recovery()
        .await
        .context("Recovery rotation failed")?;
    config.save_provider(builder.key_provider()).await?;

    println!("{}", "Recovery rotation successful!".green().bold());
    println!("  Event SAID: {}", ror.event.said);

    Ok(())
}

pub(crate) async fn cmd_sign(cli: &Cli, prefix: &str, data: &str) -> Result<()> {
    use cesr::Matter;

    let key_provider = provider_config(cli, prefix)?.load_provider().await?;
    let sig = key_provider
        .sign(data.as_bytes())
        .await
        .context("Signing failed")?;
    println!("{}", sig.qb64());
    Ok(())
}

pub(crate) async fn cmd_anchor(cli: &Cli, prefix: &str, said: &str) -> Result<()> {
    println!("{}", format!("Anchoring SAID in {}...", prefix).green());

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

    let ixn = builder.interact(said).await.context("Interaction failed")?;

    println!("{}", "Anchor successful!".green().bold());
    println!("  Event SAID: {}", ixn.event.said);
    println!("  Anchored:   {}", said);

    Ok(())
}

pub(crate) async fn cmd_recover(
    cli: &Cli,
    prefix: &str,
    signing_algorithm: Option<&str>,
    recovery_algorithm: Option<&str>,
) -> Result<()> {
    println!("{}", format!("Recovering KEL {}...", prefix).yellow());

    let config = provider_config(cli, prefix)?;
    let client = create_client(cli).await?;
    let mut key_provider = config.load_provider().await?;

    if let Some(algo) = signing_algorithm {
        let algo = parse_algorithm(algo)?;
        key_provider.set_signing_algorithm(algo).await?;
    }
    if let Some(algo) = recovery_algorithm {
        let algo = parse_algorithm(algo)?;
        key_provider.set_recovery_algorithm(algo).await?;
    }

    let kel_store = create_kel_store(cli, prefix)?;

    let mut builder = KeyEventBuilder::with_dependencies(
        key_provider,
        Some(client.clone()),
        Some(std::sync::Arc::new(kel_store)),
        Some(prefix),
    )
    .await?;

    // Verify server KEL to detect if adversary revealed the rotation key
    let source = kels_core::HttpKelSource::new(client.base_url(), "/api/v1/kels/kel/{prefix}")?;
    let server_verification = kels_core::verify_key_events(
        prefix,
        &source,
        KelVerifier::new(prefix),
        kels_core::page_size(),
        kels_core::max_pages(),
    )
    .await
    .map_err(|e| anyhow!("{}", e))?;
    let owner_last_est_serial = builder
        .last_establishment_event()
        .map(|e| e.serial)
        .unwrap_or(0);
    let add_rot = kels_core::should_rotate_with_recovery(
        &server_verification,
        builder.rotation_count(),
        owner_last_est_serial,
    );
    let rec = builder.recover(add_rot).await.context("Recovery failed")?;
    config.save_provider(builder.key_provider()).await?;

    println!("{}", "Recovery successful!".green().bold());
    println!("  Event SAID: {}", rec.event.said);

    Ok(())
}

pub(crate) async fn cmd_contest(cli: &Cli, prefix: &str) -> Result<()> {
    println!("{}", format!("Contesting KEL {}...", prefix).red().bold());
    println!(
        "{}",
        "WARNING: This will permanently freeze the KEL.".yellow()
    );

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

    let cnt = builder.contest().await.context("Contest failed")?;

    println!("{}", "KEL contested and permanently frozen.".red().bold());
    println!("  Event SAID: {}", cnt.event.said);

    Ok(())
}

pub(crate) async fn cmd_decommission(cli: &Cli, prefix: &str) -> Result<()> {
    println!(
        "{}",
        format!("Decommissioning KEL {}...", prefix).yellow().bold()
    );
    println!(
        "{}",
        "WARNING: This is permanent. No further events can be added.".red()
    );

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

    let dec = builder
        .decommission()
        .await
        .context("Decommission failed")?;

    println!("{}", "KEL decommissioned.".green().bold());
    println!("  Event SAID: {}", dec.event.said);

    Ok(())
}

pub(crate) fn print_kel_status(kel_verification: &KelVerification, verbose: bool) {
    if verbose {
        println!("  Verified: Yes");
    }
    if kel_verification.is_contested() {
        println!("  Status: {}", "CONTESTED".red());
    } else if kel_verification.is_decommissioned() {
        println!("  Status: {}", "DECOMMISSIONED".red());
    } else if kel_verification.is_divergent() {
        println!("  Status: {}", "DIVERGENT".yellow());
    } else {
        println!("  Status: {}", "OK".green());
    }
}

pub(crate) fn print_kel_summary(prefix: &str, kel_verification: &KelVerification) {
    println!();
    println!("{}", format!("KEL: {}", prefix).cyan().bold());
    println!("  Events: {}", kel_verification.event_count());

    if let Some(tip) = kel_verification.branch_tips().last() {
        println!("  Latest SAID: {}", tip.tip.event.said);
        println!("  Latest Type: {}", tip.tip.event.kind);
    }
}

pub(crate) async fn cmd_get(cli: &Cli, prefix: &str, audit: bool) -> Result<()> {
    let client = create_client(cli).await?;
    let source = HttpKelSource::new(client.base_url(), "/api/v1/kels/kel/{prefix}")?;

    let msg = if audit {
        format!("Fetching KEL {} with audit records...", prefix)
    } else {
        format!("Fetching KEL {}...", prefix)
    };
    println!("{}", msg.green());

    // Verify and print events in a single pass
    let kel_verification = kels_core::verify_key_events_with(
        prefix,
        &source,
        KelVerifier::new(prefix),
        kels_core::page_size(),
        kels_core::max_pages(),
        |events| {
            for signed_event in events {
                let event = &signed_event.event;
                println!(
                    "  [{}] {} - {}",
                    event.serial,
                    event.kind.as_str().to_uppercase(),
                    &event.said[..16]
                );
            }
        },
    )
    .await
    .map_err(|e| anyhow!("{}", e))?;

    print_kel_summary(prefix, &kel_verification);
    print_kel_status(&kel_verification, !audit);

    if audit {
        let mut all_records = Vec::new();
        let mut offset = 0u64;
        loop {
            let page = client
                .fetch_kel_audit(prefix, kels_core::page_size(), offset)
                .await?;
            all_records.extend(page.records);
            if !page.has_more {
                break;
            }
            offset += kels_core::page_size() as u64;
        }
        if !all_records.is_empty() {
            println!();
            println!("{}", "Recovery History:".yellow().bold());
            for (i, record) in all_records.iter().enumerate() {
                println!("  [{}] {} ({})", i, &record.said[..16], record.created_at);
                println!(
                    "      diverged_at={} recovery_serial={}",
                    record.diverged_at, record.recovery_serial
                );
            }
        } else {
            println!();
            println!("{}", "Recovery History: (none)".yellow());
        }
    }

    Ok(())
}

pub(crate) async fn cmd_list(cli: &Cli) -> Result<()> {
    let kel_dir = kel_dir(cli)?;

    if !kel_dir.exists() {
        println!("{}", "No KELs found.".yellow());
        return Ok(());
    }

    println!("{}", "Local KELs:".cyan().bold());

    let mut found = false;
    for entry in std::fs::read_dir(&kel_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().is_some_and(|e| e == "jsonl")
            && let Some(stem) = path.file_stem()
            && let Some(prefix) = stem.to_str()
        {
            // Remove .kel suffix if present
            let prefix = prefix.strip_suffix(".kel").unwrap_or(prefix);
            println!("  {}", prefix);
            found = true;
        }
    }

    if !found {
        println!("{}", "  (none)".yellow());
    }

    Ok(())
}

pub(crate) async fn cmd_status(cli: &Cli, prefix: &str) -> Result<()> {
    let kel_store = create_kel_store(cli, prefix)?;

    let kel_verification = kels_core::completed_verification(
        &mut kels_core::StorePageLoader::new(&kel_store),
        prefix,
        kels_core::page_size(),
        kels_core::max_pages(),
        iter::empty(),
    )
    .await?;

    if kel_verification.is_empty() {
        return Err(anyhow!("KEL not found locally: {}", prefix));
    }

    let event_count = kel_verification.event_count();

    println!("{}", format!("KEL Status: {}", prefix).cyan().bold());
    println!("  Local Events: {}", event_count);

    if let Some(bt) = kel_verification.branch_tips().first() {
        println!("  Latest SAID:  {}", bt.tip.event.said);
        println!("  Latest Type:  {}", bt.tip.event.kind);
    }
    if kel_verification.is_contested() {
        println!("  Status:       {}", "CONTESTED".red());
    } else if kel_verification.is_decommissioned() {
        println!("  Status:       {}", "DECOMMISSIONED".red());
    } else if kel_verification.is_divergent() {
        println!("  Status:       {}", "DIVERGENT".yellow());
        if let Some(serial) = kel_verification.diverged_at_serial() {
            println!("  Diverged At:  s{}", serial);
        }
    } else {
        println!("  Status:       {}", "OK".green());
    }
    let key_dir = config_dir(cli)?.join("keys").join(prefix);
    let has_keys = key_dir.join("current.key").exists();
    println!(
        "  Keys:         {}",
        if has_keys {
            "present".green()
        } else {
            "missing".red()
        }
    );

    Ok(())
}

pub(crate) async fn cmd_reset(cli: &Cli, prefix: Option<&str>, yes: bool) -> Result<()> {
    use std::io::{self, Write};

    let config = config_dir(cli)?;
    let kel_dir = kel_dir(cli)?;
    let keys_dir = config.join("keys");

    if let Some(p) = prefix {
        // Reset specific KEL
        let kel_file = kel_dir.join(format!("{}.kel.json", p));
        let key_dir = keys_dir.join(p);

        if !kel_file.exists() && !key_dir.exists() {
            println!("{}", format!("No local state found for {}", p).yellow());
            return Ok(());
        }

        if !yes {
            print!(
                "{}",
                format!(
                    "Reset local state for {}? This will delete local KEL and keys. [y/N] ",
                    p
                )
                .red()
            );
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                println!("Aborted.");
                return Ok(());
            }
        }

        if kel_file.exists() {
            std::fs::remove_file(&kel_file)?;
            println!("  Deleted KEL: {}", kel_file.display());
        }
        if key_dir.exists() {
            std::fs::remove_dir_all(&key_dir)?;
            println!("  Deleted keys: {}", key_dir.display());
        }

        println!("{}", format!("Reset complete for {}", p).green().bold());
    } else {
        // Reset all local state
        if !yes {
            print!(
                "{}",
                "Reset ALL local state? This will delete ALL local KELs and keys. [y/N] "
                    .red()
                    .bold()
            );
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                println!("Aborted.");
                return Ok(());
            }
        }

        let mut count = 0;
        if kel_dir.exists() {
            for entry in std::fs::read_dir(&kel_dir)? {
                let entry = entry?;
                std::fs::remove_file(entry.path())?;
                count += 1;
            }
            println!("  Deleted {} KEL file(s)", count);
        }

        if keys_dir.exists() {
            let key_count = std::fs::read_dir(&keys_dir)?.count();
            std::fs::remove_dir_all(&keys_dir)?;
            std::fs::create_dir_all(&keys_dir)?;
            println!("  Deleted {} key directory(ies)", key_count);
        }

        println!(
            "{}",
            "Reset complete - all local state cleared.".green().bold()
        );
    }

    Ok(())
}
