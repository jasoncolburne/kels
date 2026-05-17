//! Shared helper functions for CLI commands.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use cesr::Matter;
use colored::Colorize;
use kels_core::{
    DeferredDepsResponse, ErrorCode, FileKelStore, FileSadStore, HttpKelSource, KelsClient,
    KelsError, MissingDependency, PagedKelSource, PolicyChecker, SadStoreClient,
    SoftwareProviderConfig, TransientChainState, VerificationKeyCode,
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
    // CLI staging helpers don't have an in-process IEL store at hand; iel(...)
    // leaves in any policy reached from here will loud-fail per the
    // UnavailableIelResolver contract. CLI commands that need iel-resolution
    // can wire a real resolver explicitly when they're added.
    let iel_resolver: Arc<dyn kels_core::IelResolver + Send + Sync> =
        Arc::new(kels_core::UnavailableIelResolver);
    Ok(Arc::new(kels_policy::AnchoredPolicyChecker::new(
        kel_source,
        resolver,
        iel_resolver,
    )))
}

pub(crate) fn load_decap_key(path: &std::path::Path) -> Result<cesr::DecapsulationKey> {
    let data = std::fs::read_to_string(path).context("Failed to read decapsulation key")?;
    cesr::DecapsulationKey::from_qb64(data.trim()).context("Failed to parse decapsulation key")
}

/// #156: retry a submit operation when sadstore returns a typed-422
/// deferred-deps response. Applies exponential backoff up to a 30s budget;
/// surfaces "deferred — polling for arrival" + dep list on first 422 and
/// the latest deps again on final timeout.
///
/// Caller passes `submit` as a closure that constructs and awaits the
/// submit on each call (so retries don't reuse a consumed future). The
/// closure typically borrows the same client + events buffer each call;
/// for `&mut self` flows like `SadEventBuilder::flush`, an FnMut closure
/// re-borrows on each call.
pub(crate) async fn submit_with_deferred_deps_poll<F, Fut, T>(
    label: &str,
    mut submit: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<T, KelsError>>,
{
    const TOTAL_BUDGET: Duration = Duration::from_secs(30);
    const INITIAL_DELAY: Duration = Duration::from_millis(250);
    const MAX_DELAY: Duration = Duration::from_secs(4);

    let start = Instant::now();
    let mut delay = INITIAL_DELAY;
    let mut surfaced = false;

    loop {
        match submit().await {
            Ok(t) => return Ok(t),
            Err(e) => {
                let Some(response) = parse_deferred_deps_response(&e) else {
                    return Err(anyhow!(e));
                };
                if !surfaced {
                    eprintln!(
                        "{}",
                        format!("{}: deferred — polling for dependency arrival...", label).yellow()
                    );
                    print_deferred_deps(&response);
                    surfaced = true;
                }
                let elapsed = start.elapsed();
                if elapsed >= TOTAL_BUDGET {
                    eprintln!(
                        "{}",
                        format!(
                            "{}: timed out after {}s — dependencies still missing:",
                            label,
                            elapsed.as_secs()
                        )
                        .red()
                    );
                    print_deferred_deps(&response);
                    return Err(anyhow!(
                        "{}: deferred-deps poll timeout; dependencies never arrived",
                        label
                    ));
                }
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(MAX_DELAY);
            }
        }
    }
}

/// #156: specialization of the deferred-deps poll for `&mut SadEventBuilder::flush`.
/// The generic `submit_with_deferred_deps_poll` takes an `FnMut` closure
/// whose returned future cannot borrow from captures — `flush()` borrows
/// `&mut self`, so we duplicate the loop here. Each retry calls
/// `builder.flush()` afresh; on success, the builder absorbs pending and
/// returns the outcome. On 422-Err, pending stays staged and the next
/// retry re-attempts.
pub(crate) async fn flush_with_deferred_deps_poll(
    label: &str,
    builder: &mut kels_core::SadEventBuilder,
) -> Result<kels_core::FlushOutcome> {
    const TOTAL_BUDGET: Duration = Duration::from_secs(30);
    const INITIAL_DELAY: Duration = Duration::from_millis(250);
    const MAX_DELAY: Duration = Duration::from_secs(4);

    let start = Instant::now();
    let mut delay = INITIAL_DELAY;
    let mut surfaced = false;

    loop {
        match builder.flush().await {
            Ok(t) => return Ok(t),
            Err(e) => {
                let Some(response) = parse_deferred_deps_response(&e) else {
                    return Err(anyhow!(e));
                };
                if !surfaced {
                    eprintln!(
                        "{}",
                        format!("{}: deferred — polling for dependency arrival...", label).yellow()
                    );
                    print_deferred_deps(&response);
                    surfaced = true;
                }
                let elapsed = start.elapsed();
                if elapsed >= TOTAL_BUDGET {
                    eprintln!(
                        "{}",
                        format!(
                            "{}: timed out after {}s — dependencies still missing:",
                            label,
                            elapsed.as_secs()
                        )
                        .red()
                    );
                    print_deferred_deps(&response);
                    return Err(anyhow!(
                        "{}: deferred-deps poll timeout; dependencies never arrived",
                        label
                    ));
                }
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(MAX_DELAY);
            }
        }
    }
}

/// Parse a `KelsError::ServerError` body as the typed-422 deferred-deps
/// response. Returns `None` for any other error or for a body that doesn't
/// match the wire shape (genuine 5xx, conflict, transport).
fn parse_deferred_deps_response(e: &KelsError) -> Option<DeferredDepsResponse> {
    let KelsError::ServerError(body, ErrorCode::InternalError) = e else {
        return None;
    };
    let parsed: DeferredDepsResponse = serde_json::from_str(body).ok()?;
    if parsed.is_empty() {
        return None;
    }
    Some(parsed)
}

fn print_deferred_deps(response: &DeferredDepsResponse) {
    let DeferredDepsResponse::Rejected {
        missing_dependencies,
        transient_chain_state,
    } = response;
    for md in missing_dependencies {
        match md {
            MissingDependency::KelAnchor {
                kel_prefix,
                anchor_said,
                ..
            } => {
                eprintln!(
                    "  - kel_anchor: kel_prefix={} anchor_said={}",
                    kel_prefix, anchor_said
                );
            }
            MissingDependency::IelEvent {
                iel_prefix,
                event_said,
                ..
            } => {
                eprintln!(
                    "  - iel_event: iel_prefix={} event_said={}",
                    iel_prefix, event_said
                );
            }
            MissingDependency::IelPrefix { iel_prefix } => {
                eprintln!("  - iel_prefix: {}", iel_prefix);
            }
            MissingDependency::SadObject { said } => {
                eprintln!("  - sad_object: said={}", said);
            }
        }
    }
    for tcs in transient_chain_state {
        let TransientChainState {
            prefix,
            effective_said,
        } = tcs;
        eprintln!(
            "  - transient_chain: prefix={} effective_said={}",
            prefix, effective_said
        );
    }
}
