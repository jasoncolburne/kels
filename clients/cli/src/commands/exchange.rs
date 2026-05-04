//! Exchange protocol command handlers.
//!
//! Single-device ergonomic wrappers around the SE primitive for
//! ML-KEM encapsulation-key publication. Each command runs the full
//! stage → publish → anchor → submit cycle in one CLI invocation against
//! a caller-supplied `--identity` (IEL prefix). Multi-device flows use
//! the generic `kels sel *` + `kels kel anchor` decomposition instead.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use cesr::Matter;
use colored::Colorize;
use kels_core::{
    KeyEventBuilder, KeyProvider, ProviderConfig, SadEventBuilder, SadStoreClient,
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

/// Build, save, and post a new ML-KEM encapsulation-key publication SAD
/// object. Returns the publication's SAID — used as the SEL chain's content
/// reference.
async fn build_and_post_publication(
    cli: &Cli,
    sad_client: &SadStoreClient,
    kel_prefix: &str,
    algorithm: Option<&str>,
) -> Result<cesr::Digest256> {
    let provider = provider_config(cli, kel_prefix)?.load_provider().await?;
    let current_pub = provider
        .current_public_key()
        .await
        .context("No current key — incept the KEL first")?;
    let kem_algo = parse_kem_algorithm(algorithm, current_pub.algorithm())?;

    let (encap_key, decap_key) = if kem_algo == kels_exchange::ML_KEM_1024 {
        cesr::generate_ml_kem_1024().context("ML-KEM-1024 key generation failed")?
    } else {
        cesr::generate_ml_kem_768().context("ML-KEM-768 key generation failed")?
    };

    let kem_path = kem_key_path(cli, kel_prefix)?;
    if let Some(parent) = kem_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    save_decap_key(&kem_path, &decap_key)?;

    let mut publication = kels_exchange::EncapsulationKeyPublication {
        said: cesr::Digest256::default(),
        algorithm: kem_algo.to_string(),
        encapsulation_key: encap_key,
    };
    publication
        .derive_said()
        .context("SAID derivation failed")?;

    let pub_json = serde_json::to_value(&publication)?;
    sad_client
        .post_sad_object(&pub_json)
        .await
        .context("Failed to upload key publication to SADStore")?;

    println!("  Decapsulation key saved to {}", kem_path.display());
    println!("  Key publication uploaded (SAID: {})", publication.said);

    Ok(publication.said)
}

/// Anchor a SAID in the caller's KEL via an Ixn event. Submits to the
/// kels service synchronously.
async fn anchor_in_kel(cli: &Cli, kel_prefix: &str, said: &cesr::Digest256) -> Result<()> {
    let prefix_digest =
        cesr::Digest256::from_qb64(kel_prefix).context("Invalid KEL prefix CESR")?;
    let key_provider = provider_config(cli, kel_prefix)?.load_provider().await?;
    let kels_client = create_client(cli).await?;
    let kel_store = create_kel_store(cli, kel_prefix).await?;

    let mut builder = KeyEventBuilder::with_dependencies(
        key_provider,
        Some(kels_client),
        Some(Arc::new(kel_store)),
        Some(&prefix_digest),
    )
    .await?;

    builder
        .interact(said)
        .await
        .with_context(|| format!("Failed to anchor {} in KEL {}", said, kel_prefix))?;
    Ok(())
}

pub(crate) async fn cmd_exchange_publish_key(
    cli: &Cli,
    kel_prefix: &str,
    identity: &str,
    algorithm: Option<&str>,
) -> Result<()> {
    println!("{}", "Publishing ML-KEM encapsulation key...".green());

    let identity_digest =
        cesr::Digest256::from_qb64(identity).context("Invalid --identity CESR (IEL prefix)")?;

    let sad_client = SadStoreClient::new(&cli.sadstore_url())?;
    let publication_said =
        build_and_post_publication(cli, &sad_client, kel_prefix, algorithm).await?;

    let checker = sad_store_anchored_checker(cli, &sad_client)?;
    let mut sad_builder =
        SadEventBuilder::new(Some(sad_client.clone()), None, Some(Arc::clone(&checker)));
    let (icp_said, upd_said) = sad_builder
        .incept_chain(
            identity_digest,
            kels_exchange::ENCAP_KEY_KIND,
            publication_said,
        )
        .await
        .context("Failed to stage atomic [Icp, Upd] for SEL chain")?;

    sad_builder
        .publish_pending()
        .await
        .context("Failed to publish staged SEL events to SAD object store")?;

    println!("  Anchoring Icp ({}) in KEL...", icp_said);
    anchor_in_kel(cli, kel_prefix, &icp_said).await?;
    println!("  Anchoring Upd ({}) in KEL...", upd_said);
    anchor_in_kel(cli, kel_prefix, &upd_said).await?;

    let outcome = flush_with_deferred_deps_poll("exchange publish-key flush", &mut sad_builder)
        .await
        .context("Failed to submit SEL events")?;

    if outcome.applied {
        println!("{}", "Publish successful!".green().bold());
        println!("  Icp SAID: {}", icp_said);
        println!("  Upd SAID: {}", upd_said);
    } else if let Some(terminal) = outcome.terminal {
        return Err(anyhow!(
            "SEL chain is already terminal ({:?}) — submit was a no-op",
            terminal
        ));
    } else {
        println!(
            "{}",
            "warning: server reported no events submitted (chain already present?)".yellow()
        );
    }
    if let Some(at) = outcome.diverged_at {
        eprintln!(
            "{}",
            format!("warning: SEL chain diverged at version {}", at).yellow()
        );
    }

    Ok(())
}

pub(crate) async fn cmd_exchange_rotate_key(
    cli: &Cli,
    kel_prefix: &str,
    identity: &str,
    algorithm: Option<&str>,
) -> Result<()> {
    println!("{}", "Rotating ML-KEM encapsulation key...".green());

    let identity_digest =
        cesr::Digest256::from_qb64(identity).context("Invalid --identity CESR (IEL prefix)")?;
    let sel_prefix =
        kels_core::compute_sad_event_prefix(identity_digest, kels_exchange::ENCAP_KEY_KIND)
            .context("Failed to compute SEL prefix")?;

    let sad_client = SadStoreClient::new(&cli.sadstore_url())?;
    let publication_said =
        build_and_post_publication(cli, &sad_client, kel_prefix, algorithm).await?;

    let checker = sad_store_anchored_checker(cli, &sad_client)?;
    let mut sad_builder =
        SadEventBuilder::with_remote_prefix(sad_client.clone(), checker, &sel_prefix)
            .await
            .context("Failed to hydrate SE state from server")?;

    let upd_said = sad_builder
        .update(publication_said)
        .await
        .context("Failed to stage Upd")?;

    sad_builder
        .publish_pending()
        .await
        .context("Failed to publish staged Upd to SAD object store")?;

    println!("  Anchoring Upd ({}) in KEL...", upd_said);
    anchor_in_kel(cli, kel_prefix, &upd_said).await?;

    let outcome = flush_with_deferred_deps_poll("exchange rotate-key flush", &mut sad_builder)
        .await
        .context("Failed to submit Upd")?;

    if outcome.applied {
        println!("{}", "Rotation successful!".green().bold());
        println!("  Upd SAID: {}", upd_said);
        println!("  SEL Prefix: {}", sel_prefix);
    } else if let Some(terminal) = outcome.terminal {
        return Err(anyhow!(
            "SEL chain is already terminal ({:?}) — submit was a no-op",
            terminal
        ));
    } else {
        println!(
            "{}",
            "warning: server reported no events submitted (Upd already present?)".yellow()
        );
    }
    if let Some(at) = outcome.diverged_at {
        eprintln!(
            "{}",
            format!("warning: SEL chain diverged at version {}", at).yellow()
        );
    }

    Ok(())
}

pub(crate) async fn cmd_exchange_lookup_key(cli: &Cli, identity: &str) -> Result<()> {
    let identity_digest =
        cesr::Digest256::from_qb64(identity).context("Invalid identity CESR (IEL prefix)")?;
    let sel_prefix =
        kels_core::compute_sad_event_prefix(identity_digest, kels_exchange::ENCAP_KEY_KIND)
            .context("Failed to compute SEL prefix")?;

    let sad_client = SadStoreClient::new(&cli.sadstore_url())?;
    let page = sad_client
        .fetch_sel_events(&sel_prefix, None)
        .await
        .context("Failed to fetch key chain")?;

    let tip = page
        .events
        .last()
        .ok_or_else(|| anyhow!("No encapsulation key found for identity {}", identity))?;

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
    println!("  Identity:    {}", identity);
    println!("  SEL Prefix:  {}", sel_prefix);
    println!("  Algorithm:   {}", publication.algorithm);
    println!("  Key SAID:    {}", publication.said);
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
