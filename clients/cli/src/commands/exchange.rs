//! Exchange protocol command handlers.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use cesr::Matter;
use colored::Colorize;
use kels_core::{
    HttpKelSource, KeyEventBuilder, KeyProvider, ProviderConfig, SadStoreClient,
    VerificationKeyCode,
};
use verifiable_storage::SelfAddressed;

use crate::Cli;
use crate::helpers::*;

fn save_decap_key(path: &std::path::Path, dk: &cesr::DecapsulationKey) -> Result<()> {
    std::fs::write(path, dk.qb64()).context("Failed to write decapsulation key")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .context("Failed to set decapsulation key permissions")?;
    }

    Ok(())
}

fn parse_kem_algorithm(
    algorithm: Option<&str>,
    signing_algorithm: VerificationKeyCode,
) -> Result<&'static str> {
    match algorithm {
        Some("ml-kem-768") => Ok(kels_exchange::ML_KEM_768),
        Some("ml-kem-1024") => Ok(kels_exchange::ML_KEM_1024),
        Some(other) => Err(anyhow!(
            "Unknown KEM algorithm '{}'. Valid: ml-kem-768, ml-kem-1024",
            other
        )),
        None => match signing_algorithm {
            VerificationKeyCode::MlDsa87 => Ok(kels_exchange::ML_KEM_1024),
            _ => Ok(kels_exchange::ML_KEM_768),
        },
    }
}

/// Build a KEL source for `AnchoredPolicyChecker` pointed at the CLI's KELs
/// service.
fn kel_source(cli: &Cli) -> Result<HttpKelSource> {
    HttpKelSource::new(&cli.kels_url(), "/api/v1/kels/kel/fetch")
        .context("Failed to build KEL source")
}

pub(crate) async fn cmd_exchange_publish_key(
    cli: &Cli,
    prefix: &str,
    algorithm: Option<&str>,
) -> Result<()> {
    println!("{}", "Publishing ML-KEM encapsulation key...".green());

    // Load signing key to determine default KEM algorithm
    let provider = provider_config(cli, prefix)?.load_provider().await?;
    let current_pub = provider
        .current_public_key()
        .await
        .context("No current key — incept first")?;
    let kem_algo = parse_kem_algorithm(algorithm, current_pub.algorithm())?;

    // Generate ML-KEM keypair
    let (encap_key, decap_key) = if kem_algo == kels_exchange::ML_KEM_1024 {
        cesr::generate_ml_kem_1024().context("ML-KEM-1024 key generation failed")?
    } else {
        cesr::generate_ml_kem_768().context("ML-KEM-768 key generation failed")?
    };

    // Save decapsulation key locally
    let kem_path = kem_key_path(cli, prefix)?;
    if let Some(parent) = kem_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    save_decap_key(&kem_path, &decap_key)?;
    println!("  Decapsulation key saved to {}", kem_path.display());

    // Build and upload the publication SAD object (payload, not SEL event).
    let mut publication = kels_exchange::EncapsulationKeyPublication {
        said: cesr::Digest256::default(),
        algorithm: kem_algo.to_string(),
        encapsulation_key: encap_key.clone(),
    };
    publication
        .derive_said()
        .context("SAID derivation failed")?;

    let sad_client = SadStoreClient::new(&cli.sadstore_url())?;
    let pub_json = serde_json::to_value(&publication)?;
    sad_client
        .post_sad_object(&pub_json)
        .await
        .context("Failed to upload key publication to SADStore")?;
    println!("  Key publication uploaded (SAID: {})", publication.said);

    // Build and upload the write/governance policy. Exchange keys currently
    // reuse the same single-endorser policy for both roles — testing-grade
    // defaults per sad-events.md "Governance policy reuse".
    let prefix_digest = cesr::Digest256::from_qb64(prefix).context("Invalid prefix CESR")?;
    let policy = exchange_write_policy(&prefix_digest)?;
    let policy_json = serde_json::to_value(&policy)?;
    sad_client.post_sad_object(&policy_json).await?;
    let write_policy = policy.said;
    let governance_policy = policy.said;

    // Stage the SEL via the builder. `incept_deterministic` keeps v0's SAID a
    // pure function of (topic, write_policy) so `rotate-key` / `lookup-key`
    // can recompute the prefix without fetching v0.
    let kels_client = create_client(cli).await?;
    let kel_store = create_kel_store(cli, prefix).await?;
    let kel_builder = KeyEventBuilder::with_dependencies(
        provider,
        Some(kels_client),
        Some(Arc::new(kel_store)),
        Some(&prefix_digest),
    )
    .await?;

    let kel_source: Arc<dyn kels_core::PagedKelSource + Send + Sync> = Arc::new(kel_source(cli)?);
    let resolver: Arc<dyn kels_policy::PolicyResolver + Send + Sync> =
        Arc::new(kels_policy::InMemoryPolicyResolver::new(vec![policy]));
    let checker: Arc<dyn kels_core::PolicyChecker + Send + Sync> = Arc::new(
        kels_policy::AnchoredPolicyChecker::new(kel_source, resolver),
    );

    let sad_store = Arc::new(create_sad_store(cli).await?);

    // Round-12 Gap 5 stub: this CLI command is parked pending Gap 11's
    // CLI rewrite. The pre-round-12 flow (`incept_deterministic`
    // declaring both `write_policy` and `governance_policy`) doesn't
    // translate directly — round-12 SE chains bind to an existing IEL
    // via the `identity` parameter rather than declaring policies
    // inline. Gap 11 will reshape the CLI surface to feed an IEL
    // identity into `incept_chain(identity, topic, initial_content)`.
    //
    // Variables are referenced via `_ = ...` to suppress unused-binding
    // warnings while keeping the Gap-11 rewrite a localized swap.
    let _ = (
        write_policy,
        governance_policy,
        publication,
        kel_builder,
        sad_store,
        checker,
        sad_client,
    );
    Err(anyhow::anyhow!(
        "kels exchange publish-key: parked pending Gap 11 CLI rewrite — \
         the round-12 SE builder requires an IEL `identity` rather than \
         inline write_policy/governance_policy declaration"
    ))
}

pub(crate) async fn cmd_exchange_rotate_key(
    cli: &Cli,
    prefix: &str,
    algorithm: Option<&str>,
) -> Result<()> {
    println!("{}", "Rotating ML-KEM encapsulation key...".green());

    let provider = provider_config(cli, prefix)?.load_provider().await?;
    let current_pub = provider
        .current_public_key()
        .await
        .context("No current key")?;
    let kem_algo = parse_kem_algorithm(algorithm, current_pub.algorithm())?;

    // Generate new keypair
    let (encap_key, decap_key) = if kem_algo == kels_exchange::ML_KEM_1024 {
        cesr::generate_ml_kem_1024().context("ML-KEM-1024 key generation failed")?
    } else {
        cesr::generate_ml_kem_768().context("ML-KEM-768 key generation failed")?
    };

    // Overwrite decapsulation key
    let kem_path = kem_key_path(cli, prefix)?;
    save_decap_key(&kem_path, &decap_key)?;

    // Build new publication and upload as payload SAD object.
    let mut publication = kels_exchange::EncapsulationKeyPublication {
        said: cesr::Digest256::default(),
        algorithm: kem_algo.to_string(),
        encapsulation_key: encap_key.clone(),
    };
    publication
        .derive_said()
        .context("SAID derivation failed")?;

    let sad_client = SadStoreClient::new(&cli.sadstore_url())?;
    let pub_json = serde_json::to_value(&publication)?;
    sad_client.post_sad_object(&pub_json).await?;

    // The policy SAD must exist server-side for verification to resolve it.
    let prefix_digest = cesr::Digest256::from_qb64(prefix).context("Invalid prefix CESR")?;
    let policy = exchange_write_policy(&prefix_digest)?;
    let policy_json = serde_json::to_value(&policy)?;
    sad_client.post_sad_object(&policy_json).await?;
    let write_policy = policy.said;
    let sel_prefix =
        kels_core::compute_sad_event_prefix(write_policy, kels_exchange::ENCAP_KEY_KIND)
            .context("Failed to compute SEL prefix")?;

    // Hydrate the builder from the server-verified chain state, then stage
    // the Upd. The checker is owned by the builder; hydration and flush both
    // pull from the same Arc.
    let kel_source: Arc<dyn kels_core::PagedKelSource + Send + Sync> = Arc::new(kel_source(cli)?);
    let resolver: Arc<dyn kels_policy::PolicyResolver + Send + Sync> =
        Arc::new(kels_policy::InMemoryPolicyResolver::new(vec![policy]));
    let checker: Arc<dyn kels_core::PolicyChecker + Send + Sync> = Arc::new(
        kels_policy::AnchoredPolicyChecker::new(kel_source, resolver),
    );

    let sad_store = Arc::new(create_sad_store(cli).await?);

    // Round-12 Gap 5 stub: parked pending Gap 11 CLI rewrite. Round-12
    // `update` is async (`update(content) -> Result<…>`) and the
    // builder's IEL-binding flow needs the SE chain's `identity`
    // resolved (currently inferred from `compute_sad_event_prefix(write_policy, …)`,
    // which is no longer how SE prefixes are derived). Gap 11 reshapes
    // this CLI command to take an IEL identity reference.
    let _ = (
        provider,
        sad_client,
        publication,
        write_policy,
        sel_prefix,
        prefix,
        prefix_digest,
        sad_store,
        checker,
    );
    Err(anyhow::anyhow!(
        "kels exchange rotate-key: parked pending Gap 11 CLI rewrite — \
         the round-12 SE builder needs an IEL identity rather than \
         a write_policy-derived SEL prefix"
    ))
}

pub(crate) async fn cmd_exchange_lookup_key(cli: &Cli, kel_prefix: &str) -> Result<()> {
    let kel_digest = cesr::Digest256::from_qb64(kel_prefix).context("Invalid KEL prefix CESR")?;
    let policy = exchange_write_policy(&kel_digest)?;
    let write_policy = policy.said;
    let sel_prefix =
        kels_core::compute_sad_event_prefix(write_policy, kels_exchange::ENCAP_KEY_KIND)
            .context("Failed to compute SEL prefix")?;

    let sad_client = SadStoreClient::new(&cli.sadstore_url())?;
    let page = sad_client
        .fetch_sad_events(&sel_prefix, None)
        .await
        .context("Failed to fetch key chain")?;

    let tip = page
        .events
        .last()
        .ok_or_else(|| anyhow!("No encapsulation key found for {}", kel_prefix))?;

    let content_said = tip
        .content
        .as_ref()
        .ok_or_else(|| anyhow!("Tip event has no content"))?;

    let value = sad_client
        .get_sad_object(content_said)
        .await
        .context("Failed to fetch key publication object")?;

    let publication: kels_exchange::EncapsulationKeyPublication =
        serde_json::from_value(value).context("Failed to parse key publication")?;

    println!("{}", "Encapsulation Key:".cyan().bold());
    println!("  KEL Prefix:  {}", kel_prefix);
    println!("  Algorithm:   {}", publication.algorithm);
    println!("  Key SAID:    {}", publication.said);
    println!("  SEL Prefix:  {}", sel_prefix);
    let key_qb64 = publication.encapsulation_key.qb64();
    if key_qb64.len() > 30 {
        println!(
            "  Encap Key:   {}...{}",
            &key_qb64[..20],
            &key_qb64[key_qb64.len() - 10..]
        );
    } else {
        println!("  Encap Key:   {}", key_qb64);
    }

    Ok(())
}
