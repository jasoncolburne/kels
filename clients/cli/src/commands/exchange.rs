//! Exchange protocol command handlers.

use std::{collections::BTreeSet, path::PathBuf};

use anyhow::{Context, Result, anyhow};
use cesr::Matter;
use colored::Colorize;
use kels_core::{KelVerifier, KeyProvider, ProviderConfig, VerificationKeyCode};
use verifiable_storage::{Chained, SelfAddressed};

use crate::Cli;
use crate::helpers::*;

pub(crate) fn kem_key_path(cli: &Cli, prefix: &str) -> Result<PathBuf> {
    Ok(config_dir(cli)?.join("keys").join(prefix).join("kem.key"))
}

pub(crate) fn save_decap_key(path: &std::path::Path, dk: &cesr::DecapsulationKey) -> Result<()> {
    std::fs::write(path, dk.qb64()).context("Failed to write decapsulation key")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .context("Failed to set decapsulation key permissions")?;
    }

    Ok(())
}

pub(crate) fn load_decap_key(path: &std::path::Path) -> Result<cesr::DecapsulationKey> {
    let data = std::fs::read_to_string(path).context("Failed to read decapsulation key")?;
    cesr::DecapsulationKey::from_qb64(data.trim()).context("Failed to parse decapsulation key")
}

pub(crate) fn parse_kem_algorithm(
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

async fn current_establishment_serial(cli: &Cli, prefix: &str) -> Result<u64> {
    let prefix_digest = cesr::Digest::from_qb64(prefix).context("Invalid prefix CESR")?;
    let kel_store = create_kel_store(cli, prefix)?;
    let verification = kels_core::completed_verification(
        &mut kels_core::StorePageLoader::new(&kel_store),
        &prefix_digest,
        kels_core::page_size(),
        kels_core::max_pages(),
        std::iter::empty(),
    )
    .await?;
    verification
        .last_establishment_event()
        .map(|e| e.event.serial)
        .ok_or_else(|| anyhow!("No local KEL found — incept first"))
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
        said: cesr::Digest::default(),
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

    // Create SadPointer chain (v0 inception + v1 with content)
    let prefix_digest = cesr::Digest::from_qb64(prefix).context("Invalid prefix CESR")?;
    let v0 = kels_core::SadPointer::create(
        prefix_digest,
        kels_exchange::ENCAP_KEY_KIND.to_string(),
        None,
    )
    .context("Failed to create inception pointer")?;

    let mut v1 = v0.clone();
    v1.content_said = Some(publication.said);
    v1.increment().context("Failed to increment pointer")?;

    // Sign both records (signature is over the SAID qb64 bytes)
    let v0_sig = provider.sign(v0.said.qb64().as_bytes()).await?;
    let v1_sig = provider.sign(v1.said.qb64().as_bytes()).await?;

    let establishment_serial = current_establishment_serial(cli, prefix).await?;

    let signed_records = vec![
        kels_core::SignedSadPointer {
            pointer: v0,
            signature: v0_sig,
            establishment_serial,
        },
        kels_core::SignedSadPointer {
            pointer: v1,
            signature: v1_sig,
            establishment_serial,
        },
    ];

    sad_client
        .submit_sad_pointer(&signed_records)
        .await
        .context("Failed to submit pointer chain")?;

    println!(
        "{}",
        format!(
            "Key published! Chain prefix: {}",
            signed_records[0].pointer.prefix
        )
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
        said: cesr::Digest::default(),
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
    let prefix_digest = cesr::Digest::from_qb64(prefix).context("Invalid prefix CESR")?;
    let chain_prefix =
        kels_core::compute_sad_pointer_prefix(prefix_digest, kels_exchange::ENCAP_KEY_KIND)
            .context("Failed to compute pointer prefix")?;
    let page = sad_client
        .fetch_sad_pointer(chain_prefix.as_ref(), None)
        .await
        .context("Failed to fetch current chain")?;

    let tip = page
        .pointers
        .last()
        .ok_or_else(|| anyhow!("No existing key chain found — use publish-key first"))?;

    let mut next = tip.pointer.clone();
    next.content_said = Some(publication.said);
    next.increment().context("Failed to increment pointer")?;

    let sig = provider.sign(next.said.qb64().as_bytes()).await?;

    let establishment_serial = current_establishment_serial(cli, prefix).await?;

    let signed = vec![kels_core::SignedSadPointer {
        pointer: next,
        signature: sig,
        establishment_serial,
    }];

    sad_client.submit_sad_pointer(&signed).await?;

    println!("{}", "Key rotated!".green().bold());
    Ok(())
}

pub(crate) async fn cmd_exchange_lookup_key(cli: &Cli, kel_prefix: &str) -> Result<()> {
    let kel_digest = cesr::Digest::from_qb64(kel_prefix).context("Invalid KEL prefix CESR")?;
    let chain_prefix =
        kels_core::compute_sad_pointer_prefix(kel_digest, kels_exchange::ENCAP_KEY_KIND)
            .context("Failed to compute pointer prefix")?;

    let sad_client = kels_core::SadStoreClient::new(&cli.sadstore_url())?;
    let page = sad_client
        .fetch_sad_pointer(chain_prefix.as_ref(), None)
        .await
        .context("Failed to fetch key chain")?;

    let tip = page
        .pointers
        .last()
        .ok_or_else(|| anyhow!("No encapsulation key found for {}", kel_prefix))?;

    let content_said = tip
        .pointer
        .content_said
        .as_ref()
        .ok_or_else(|| anyhow!("Tip record has no content"))?;

    let value = sad_client
        .get_sad_object(content_said.as_ref())
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

pub(crate) async fn cmd_exchange_send(
    cli: &Cli,
    prefix: &str,
    recipient: &str,
    topic: &str,
    payload_path: &PathBuf,
) -> Result<()> {
    println!("{}", "Sending ESSR-encrypted message...".green());

    // Load sender's signing key
    let provider = provider_config(cli, prefix)?.load_provider().await?;

    // Look up recipient's encapsulation key
    let recipient_digest =
        cesr::Digest::from_qb64(recipient).context("Invalid recipient prefix CESR")?;
    let chain_prefix =
        kels_core::compute_sad_pointer_prefix(recipient_digest, kels_exchange::ENCAP_KEY_KIND)?;
    let sad_client = kels_core::SadStoreClient::new(&cli.sadstore_url())?;
    let page = sad_client
        .fetch_sad_pointer(chain_prefix.as_ref(), None)
        .await?;
    let tip = page
        .pointers
        .last()
        .ok_or_else(|| anyhow!("No encapsulation key for recipient {}", recipient))?;
    let content_said = tip
        .pointer
        .content_said
        .as_ref()
        .ok_or_else(|| anyhow!("Recipient key chain has no content"))?;
    let value = sad_client.get_sad_object(content_said.as_ref()).await?;
    let publication: kels_exchange::EncapsulationKeyPublication = serde_json::from_value(value)?;
    let encap_key = publication.encapsulation_key;

    // Read payload
    let payload = std::fs::read(payload_path)
        .with_context(|| format!("Failed to read payload: {}", payload_path.display()))?;

    // Get sender's latest establishment event serial from local KEL
    let prefix_digest = cesr::Digest::from_qb64(prefix).context("Invalid prefix CESR")?;
    let kel_store = create_kel_store(cli, prefix)?;
    let kel_verification = kels_core::completed_verification(
        &mut kels_core::StorePageLoader::new(&kel_store),
        &prefix_digest,
        kels_core::page_size(),
        kels_core::max_pages(),
        std::iter::empty(),
    )
    .await?;
    let sender_serial = kel_verification
        .last_establishment_event()
        .map(|e| e.event.serial)
        .ok_or_else(|| anyhow!("No local KEL found for sender — incept first"))?;

    // Get current signing key for ESSR
    let signing_key_qb64 = {
        let key_dir = config_dir(cli)?.join("keys").join(prefix);
        let current_path = key_dir.join("current.key");
        std::fs::read_to_string(&current_path).context("Failed to read signing key")?
    };
    let signing_key = cesr::SigningKey::from_qb64(signing_key_qb64.trim())?;

    // ESSR seal
    let sender_digest = cesr::Digest::from_qb64(prefix).context("Invalid sender prefix CESR")?;
    let inner = kels_exchange::EssrInner {
        sender: sender_digest,
        topic: topic.to_string(),
        payload,
    };

    let signed_envelope = kels_exchange::seal(
        &inner,
        sender_serial,
        &recipient_digest,
        &encap_key,
        &signing_key,
    )?;

    // Serialize and send to mail service
    let envelope_bytes = serde_json::to_vec(&signed_envelope)?;
    let blob_digest = kels_exchange::compute_blob_digest(&envelope_bytes);

    println!("  Envelope SAID: {}", signed_envelope.envelope.said);
    println!("  Blob digest:   {}", blob_digest);
    println!("  Payload size:  {} bytes", envelope_bytes.len());

    // Send via mail service
    let mail_client =
        kels_exchange::MailClient::new(&cli.mail_url()).context("Failed to create mail client")?;
    mail_client
        .send(
            &sender_digest,
            &recipient_digest,
            &envelope_bytes,
            &provider,
        )
        .await
        .context("Failed to send mail")?;

    println!("{}", "Message sent!".green().bold());

    Ok(())
}

pub(crate) async fn cmd_exchange_inbox(cli: &Cli, prefix: &str) -> Result<()> {
    let provider = provider_config(cli, prefix)?.load_provider().await?;
    let prefix_digest = cesr::Digest::from_qb64(prefix).context("Invalid prefix CESR")?;

    let mail_client =
        kels_exchange::MailClient::new(&cli.mail_url()).context("Failed to create mail client")?;
    let response = mail_client
        .inbox(&prefix_digest, &provider)
        .await
        .context("Failed to check inbox")?;

    if response.messages.is_empty() {
        println!("{}", "Inbox empty.".yellow());
    } else {
        println!(
            "{}",
            format!("Inbox ({} messages):", response.messages.len())
                .cyan()
                .bold()
        );
        for msg in &response.messages {
            println!(
                "  {} | from: {} | digest: {} | expires: {}",
                msg.said, msg.source_node_prefix, msg.blob_digest, msg.expires_at,
            );
        }
    }

    Ok(())
}

pub(crate) async fn cmd_exchange_fetch(cli: &Cli, prefix: &str, mail_said: &str) -> Result<()> {
    println!("{}", "Fetching and decrypting message...".green());

    let provider = provider_config(cli, prefix)?.load_provider().await?;
    let prefix_digest = cesr::Digest::from_qb64(prefix).context("Invalid prefix CESR")?;
    let mail_said_digest = cesr::Digest::from_qb64(mail_said).context("Invalid mail SAID CESR")?;

    // Look up message metadata from local inbox to find source node
    let local_mail =
        kels_exchange::MailClient::new(&cli.mail_url()).context("Failed to create mail client")?;
    let inbox = local_mail
        .inbox(&prefix_digest, &provider)
        .await
        .context("Failed to query inbox")?;

    let message = inbox
        .messages
        .iter()
        .find(|m| m.said.as_ref() == mail_said)
        .ok_or_else(|| anyhow!("Message {} not found in inbox", mail_said))?;

    // Resolve source node's base domain via registry
    let registry_urls = parse_registry_urls(&cli.registry);
    let kel_store = create_kel_store(cli, "registry-discovery")?;
    let peers = kels_core::peers_sorted_by_latency(
        &registry_urls,
        std::time::Duration::from_secs(2),
        &kel_store,
    )
    .await
    .context("Failed to query registry peers")?;

    let source_peer = peers
        .iter()
        .find(|p| p.kel_prefix == message.source_node_prefix)
        .ok_or_else(|| {
            anyhow!(
                "Source node {} not found in registry",
                message.source_node_prefix
            )
        })?;

    println!("  Source node:  {}", source_peer.base_domain);

    // Fetch the blob from the source node's mail service
    let source_mail_url = format!("http://mail.{}", source_peer.base_domain);
    let source_mail = kels_exchange::MailClient::new(&source_mail_url)
        .context("Failed to create source mail client")?;
    let blob = source_mail
        .fetch(&prefix_digest, &mail_said_digest, &provider)
        .await
        .context("Failed to fetch mail")?;

    // Verify blob digest
    let digest = kels_exchange::compute_blob_digest(&blob);
    println!("  Blob digest: {}", digest);
    println!("  Blob size:   {} bytes", blob.len());

    // Parse as SignedEssrEnvelope
    let signed_envelope: kels_exchange::SignedEssrEnvelope =
        serde_json::from_slice(&blob).context("Failed to parse ESSR envelope")?;

    let sender_prefix = &signed_envelope.envelope.sender;
    let sender_serial = signed_envelope.envelope.sender_serial;
    println!("  Sender:      {}", sender_prefix);
    println!("  Serial:      {}", sender_serial);

    // Verify sender's KEL and collect the verification key at sender_serial
    let kels_client = create_client(cli).await?;
    let source =
        kels_core::HttpKelSource::new(kels_client.base_url(), "/api/v1/kels/kel/{prefix}")?;
    let verifier = KelVerifier::new(sender_prefix).with_establishment_key_collection(
        BTreeSet::from([sender_serial]),
        kels_core::max_collected_keys(),
    )?;

    let (_verification, keys) = kels_core::verify_key_events_collecting_establishment_keys(
        sender_prefix,
        &source,
        verifier,
        kels_core::page_size(),
        kels_core::max_pages(),
    )
    .await
    .map_err(|e| anyhow!("Sender KEL verification failed: {}", e))?;

    let sender_vk = keys.get(&sender_serial).ok_or_else(|| {
        anyhow!(
            "Sender's verification key at serial {} not found",
            sender_serial
        )
    })?;

    // Load local decapsulation key
    let kem_path = kem_key_path(cli, prefix)?;
    let decap_key = load_decap_key(&kem_path)
        .context("Failed to load decapsulation key — have you published a key?")?;

    // ESSR open
    let inner = kels_exchange::open(&signed_envelope, &decap_key, sender_vk)
        .map_err(|e| anyhow!("ESSR open failed: {}", e))?;

    println!("  Topic:       {}", inner.topic);
    println!("  Payload:     {} bytes", inner.payload.len());
    println!();

    // Write payload to stdout
    std::io::Write::write_all(&mut std::io::stdout(), &inner.payload)?;

    Ok(())
}

pub(crate) async fn cmd_exchange_ack(cli: &Cli, prefix: &str, saids: &[String]) -> Result<()> {
    let provider = provider_config(cli, prefix)?.load_provider().await?;
    let prefix_digest = cesr::Digest::from_qb64(prefix).context("Invalid prefix CESR")?;
    let said_digests: Vec<cesr::Digest> = saids
        .iter()
        .map(|s| cesr::Digest::from_qb64(s))
        .collect::<Result<_, _>>()
        .context("Invalid SAID CESR")?;

    let mail_client =
        kels_exchange::MailClient::new(&cli.mail_url()).context("Failed to create mail client")?;
    mail_client
        .ack(&prefix_digest, &said_digests, &provider)
        .await
        .context("Failed to acknowledge messages")?;

    println!(
        "{}",
        format!("{} message(s) acknowledged", saids.len())
            .green()
            .bold()
    );

    Ok(())
}
