//! Shared helper functions for CLI commands.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use cesr::Matter;
use colored::Colorize;
use kels_core::{
    FileKelStore, FileSadStore, HttpKelSource, KelsClient, PagedKelSource, PolicyChecker,
    SadStoreClient, SoftwareProviderConfig, VerificationKeyCode,
};
use verifiable_storage::SelfAddressed;

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

fn sad_dir(cli: &Cli) -> Result<PathBuf> {
    Ok(config_dir(cli)?.join("sad"))
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

        let store = create_kel_store(cli, "registry-discovery").await?;
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

pub(crate) async fn create_kel_store(cli: &Cli, prefix: &str) -> Result<FileKelStore> {
    let dir = kel_dir(cli)?;
    match cesr::Digest256::from_qb64(prefix) {
        Ok(prefix_digest) => FileKelStore::with_owner(dir, prefix_digest)
            .await
            .context("Failed to create KEL store"),
        Err(_) => {
            // Non-CESR prefix (e.g., "registry-discovery") — create without owner
            FileKelStore::new(dir)
                .await
                .context("Failed to create KEL store")
        }
    }
}

pub(crate) async fn create_sad_store(cli: &Cli) -> Result<FileSadStore> {
    let dir = sad_dir(cli)?;
    FileSadStore::new(dir)
        .await
        .context("Failed to create SAD store")
}

/// Build the write_policy for exchange key publication.
/// Creates a single-endorser policy from the KEL prefix.
pub(crate) fn exchange_write_policy(kel_prefix: &cesr::Digest256) -> Result<kels_policy::Policy> {
    kels_policy::Policy::build(&format!("endorse({})", kel_prefix), None, false)
        .context("Failed to build exchange write policy")
}

pub(crate) fn kem_key_path(cli: &Cli, prefix: &str) -> Result<PathBuf> {
    Ok(config_dir(cli)?.join("keys").join(prefix).join("kem.key"))
}

/// `PolicyResolver` that fetches policies from SADStore via
/// `get_sad_object`. SAID-verified on read so a tampered server can't
/// substitute a different policy under the same SAID.
struct SadStoreSourcedPolicyResolver {
    client: SadStoreClient,
}

#[async_trait::async_trait]
impl kels_policy::PolicyResolver for SadStoreSourcedPolicyResolver {
    async fn resolve_policy(
        &self,
        said: &cesr::Digest256,
    ) -> Result<kels_policy::Policy, kels_policy::PolicyError> {
        let value = self.client.get_sad_object(said).await.map_err(|e| {
            kels_policy::PolicyError::ResolutionError(format!("fetch {}: {}", said, e))
        })?;
        let policy: kels_policy::Policy = serde_json::from_value(value).map_err(|e| {
            kels_policy::PolicyError::ResolutionError(format!("parse {}: {}", said, e))
        })?;
        policy.verify_said().map_err(|e| {
            kels_policy::PolicyError::ResolutionError(format!(
                "SAID verification failed for {}: {}",
                said, e
            ))
        })?;
        Ok(policy)
    }
}

/// Build an `AnchoredPolicyChecker` whose KEL source is the CLI's `kels`
/// service and whose policy resolver fetches from the CLI's `sadstore`
/// service. Used by the IEL/SEL stage-and-exit lifecycle commands when
/// they need to hydrate a builder against the server's verified view.
pub(crate) fn sad_store_anchored_checker(
    cli: &Cli,
    sad_client: &SadStoreClient,
) -> Result<Arc<dyn PolicyChecker + Send + Sync>> {
    let kel_source: Arc<dyn PagedKelSource + Send + Sync> = Arc::new(
        HttpKelSource::new(&cli.kels_url(), "/api/v1/kels/kel/fetch")
            .context("Failed to build KEL source")?,
    );
    let resolver: Arc<dyn kels_policy::PolicyResolver + Send + Sync> =
        Arc::new(SadStoreSourcedPolicyResolver {
            client: sad_client.clone(),
        });
    Ok(Arc::new(kels_policy::AnchoredPolicyChecker::new(
        kel_source, resolver,
    )))
}

pub(crate) fn load_decap_key(path: &std::path::Path) -> Result<cesr::DecapsulationKey> {
    let data = std::fs::read_to_string(path).context("Failed to read decapsulation key")?;
    cesr::DecapsulationKey::from_qb64(data.trim()).context("Failed to parse decapsulation key")
}
