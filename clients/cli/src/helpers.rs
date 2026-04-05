//! Shared helper functions for CLI commands.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use colored::Colorize;
use kels_core::{
    FileKelStore, FileSadStore, KelsClient, SoftwareProviderConfig, VerificationKeyCode,
};

use crate::Cli;

pub(crate) fn parse_algorithm(algorithm: &str) -> Result<VerificationKeyCode> {
    match algorithm {
        "secp256r1" => Ok(VerificationKeyCode::Secp256r1),
        "ml-dsa-65" => Ok(VerificationKeyCode::MlDsa65),
        "ml-dsa-87" => Ok(VerificationKeyCode::MlDsa87),
        _ => Err(anyhow!(
            "Unknown algorithm '{}'. Valid options: secp256r1, ml-dsa-65, ml-dsa-87",
            algorithm
        )),
    }
}

pub(crate) fn config_dir(cli: &Cli) -> Result<PathBuf> {
    if let Some(ref dir) = cli.config_dir {
        return Ok(dir.clone());
    }

    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(home.join(".kels-cli"))
}

pub(crate) fn kel_dir(cli: &Cli) -> Result<PathBuf> {
    Ok(config_dir(cli)?.join("kels"))
}

pub(crate) fn provider_config(cli: &Cli, prefix: &str) -> Result<SoftwareProviderConfig> {
    let key_dir = config_dir(cli)?.join("keys").join(prefix);
    Ok(SoftwareProviderConfig::new(
        key_dir,
        VerificationKeyCode::MlDsa65,
        VerificationKeyCode::MlDsa65,
    ))
}

/// Parse comma-separated registry URLs into a Vec.
pub(crate) fn parse_registry_urls(registry: &str) -> Vec<String> {
    registry
        .split(',')
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
        .collect()
}

pub(crate) async fn create_client(cli: &Cli) -> Result<KelsClient> {
    if cli.auto_select {
        let registry_urls = parse_registry_urls(&cli.registry);
        if registry_urls.is_empty() {
            return Err(anyhow!("No registry URLs provided"));
        }

        let store = create_kel_store(cli, "registry-discovery")?;
        let peers = kels_core::peers_sorted_by_latency(
            &registry_urls,
            std::time::Duration::from_secs(2),
            &store,
        )
        .await
        .context("Failed to discover nodes from registry")?;

        println!("{}", "Ready Peers:".cyan());
        for peer in &peers {
            println!("  {} - {}", peer.node_id, peer.base_domain);
        }
        println!();

        let url = match peers.first() {
            Some(p) => format!("http://kels.{}", p.base_domain),
            None => return Err(anyhow!("No ready peers found")),
        };
        Ok(KelsClient::new(&url)?)
    } else {
        Ok(KelsClient::new(&cli.kels_url())?)
    }
}

pub(crate) fn create_kel_store(cli: &Cli, prefix: &str) -> Result<FileKelStore> {
    let dir = kel_dir(cli)?;
    FileKelStore::with_owner(dir, prefix.to_string()).context("Failed to create KEL store")
}

pub(crate) fn create_sad_store(cli: &Cli) -> Result<FileSadStore> {
    let dir = config_dir(cli)?.join("sad");
    FileSadStore::new(dir).context("Failed to create SAD store")
}
