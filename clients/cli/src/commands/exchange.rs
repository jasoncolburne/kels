//! Exchange protocol command handlers.

use anyhow::{Context, Result, anyhow};
use cesr::Matter;
use colored::Colorize;
use kels_core::{KeyEventBuilder, KeyProvider, ProviderConfig, VerificationKeyCode};
use verifiable_storage::{Chained, SelfAddressed};

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

    // Build EncapsulationKeyPublication SAD object
    let mut publication = kels_exchange::EncapsulationKeyPublication {
        said: cesr::Digest256::default(),
        algorithm: kem_algo.to_string(),
        encapsulation_key: encap_key.clone(),
    };
    publication
        .derive_said()
        .context("SAID derivation failed")?;

    // Upload SAD object
    let sad_client = kels_core::SadStoreClient::new(&cli.sadstore_url())?;
    let pub_json = serde_json::to_value(&publication)?;
    sad_client
        .post_sad_object(&pub_json)
        .await
        .context("Failed to upload key publication to SADStore")?;
    println!("  Key publication uploaded (SAID: {})", publication.said);

    // Create SadEvent chain (v0 inception + v1 with content)
    let prefix_digest = cesr::Digest256::from_qb64(prefix).context("Invalid prefix CESR")?;
    let policy = exchange_write_policy(&prefix_digest)?;
    let policy_json = serde_json::to_value(&policy)?;
    sad_client.post_sad_object(&policy_json).await?;
    let write_policy = policy.said;
    let v0 = kels_core::SadEvent::create(
        kels_exchange::ENCAP_KEY_KIND.to_string(),
        kels_core::SadEventKind::Icp,
        None,
        None,
        Some(write_policy),
        None,
    )
    .context("Failed to create inception event")?;

    let mut v1 = v0.clone();
    v1.content = Some(publication.said);
    v1.kind = kels_core::SadEventKind::Est;
    v1.write_policy = None; // Est forbids write_policy
    v1.governance_policy = Some(write_policy); // first declaration, not evaluated
    v1.increment().context("Failed to increment event")?;

    // Anchor event SAIDs in the KEL (required for write_policy authorization)
    let client = create_client(cli).await?;
    let kel_store = create_kel_store(cli, prefix).await?;
    let mut builder = KeyEventBuilder::with_dependencies(
        provider,
        Some(client),
        Some(std::sync::Arc::new(kel_store)),
        Some(&prefix_digest),
    )
    .await?;
    builder
        .interact(&v0.said)
        .await
        .context("Failed to anchor v0 SAID in KEL")?;
    builder
        .interact(&v1.said)
        .await
        .context("Failed to anchor v1 SAID in KEL")?;

    let records = vec![v0.clone(), v1];

    sad_client
        .submit_sad_event(&records)
        .await
        .context("Failed to submit event chain")?;

    println!(
        "{}",
        format!("Key published! Chain prefix: {}", records[0].prefix)
            .green()
            .bold()
    );

    Ok(())
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

    // Build new publication
    let mut publication = kels_exchange::EncapsulationKeyPublication {
        said: cesr::Digest256::default(),
        algorithm: kem_algo.to_string(),
        encapsulation_key: encap_key.clone(),
    };
    publication
        .derive_said()
        .context("SAID derivation failed")?;

    let sad_client = kels_core::SadStoreClient::new(&cli.sadstore_url())?;
    let pub_json = serde_json::to_value(&publication)?;
    sad_client.post_sad_object(&pub_json).await?;

    // Fetch current chain to get tip for increment
    let prefix_digest = cesr::Digest256::from_qb64(prefix).context("Invalid prefix CESR")?;
    let policy = exchange_write_policy(&prefix_digest)?;
    let policy_json = serde_json::to_value(&policy)?;
    sad_client.post_sad_object(&policy_json).await?;
    let write_policy = policy.said;
    let chain_prefix =
        kels_core::compute_sad_event_prefix(write_policy, kels_exchange::ENCAP_KEY_KIND)
            .context("Failed to compute event prefix")?;
    let page = sad_client
        .fetch_sad_event(&chain_prefix, None)
        .await
        .context("Failed to fetch current chain")?;

    let tip = page
        .events
        .last()
        .ok_or_else(|| anyhow!("No existing key chain found — use publish-key first"))?;

    let mut next = tip.clone();
    next.content = Some(publication.said);
    next.kind = kels_core::SadEventKind::Upd;
    next.write_policy = None; // Upd forbids write_policy
    next.governance_policy = None;
    next.increment().context("Failed to increment event")?;

    // Anchor event SAID in the KEL (required for write_policy authorization)
    let client = create_client(cli).await?;
    let kel_store = create_kel_store(cli, prefix).await?;
    let mut builder = KeyEventBuilder::with_dependencies(
        provider,
        Some(client),
        Some(std::sync::Arc::new(kel_store)),
        Some(&prefix_digest),
    )
    .await?;
    builder
        .interact(&next.said)
        .await
        .context("Failed to anchor event SAID in KEL")?;

    sad_client.submit_sad_event(&[next]).await?;

    println!("{}", "Key rotated!".green().bold());
    Ok(())
}

pub(crate) async fn cmd_exchange_lookup_key(cli: &Cli, kel_prefix: &str) -> Result<()> {
    let kel_digest = cesr::Digest256::from_qb64(kel_prefix).context("Invalid KEL prefix CESR")?;
    let policy = exchange_write_policy(&kel_digest)?;
    let write_policy = policy.said;
    let chain_prefix =
        kels_core::compute_sad_event_prefix(write_policy, kels_exchange::ENCAP_KEY_KIND)
            .context("Failed to compute event prefix")?;

    let sad_client = kels_core::SadStoreClient::new(&cli.sadstore_url())?;
    let page = sad_client
        .fetch_sad_event(&chain_prefix, None)
        .await
        .context("Failed to fetch key chain")?;

    let tip = page
        .events
        .last()
        .ok_or_else(|| anyhow!("No encapsulation key found for {}", kel_prefix))?;

    let content_said = tip
        .content
        .as_ref()
        .ok_or_else(|| anyhow!("Tip record has no content"))?;

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
    println!("  Chain Prefix: {}", chain_prefix);
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
