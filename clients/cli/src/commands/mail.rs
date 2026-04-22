//! Mail (ESSR messaging) command handlers.

use std::{collections::BTreeSet, path::PathBuf};

use anyhow::{Context, Result, anyhow};
use cesr::Matter;
use colored::Colorize;
use kels_core::{KelVerifier, ProviderConfig};

use crate::Cli;
use crate::helpers::*;

pub(crate) async fn cmd_mail_send(
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
        cesr::Digest256::from_qb64(recipient).context("Invalid recipient prefix CESR")?;
    let recipient_policy = exchange_write_policy(&recipient_digest)?;
    let recipient_write_policy = recipient_policy.said;
    let chain_prefix =
        kels_core::compute_sad_event_prefix(recipient_write_policy, kels_exchange::ENCAP_KEY_KIND)?;
    let sad_client = kels_core::SadStoreClient::new(&cli.sadstore_url())?;
    let page = sad_client.fetch_sad_events(&chain_prefix, None).await?;
    let tip = page
        .events
        .last()
        .ok_or_else(|| anyhow!("No encapsulation key for recipient {}", recipient))?;
    let content_said = tip
        .content
        .as_ref()
        .ok_or_else(|| anyhow!("Recipient key chain has no content"))?;
    let value = sad_client.get_sad_object(content_said).await?;
    let publication: kels_exchange::EncapsulationKeyPublication = serde_json::from_value(value)?;
    let encap_key = publication.encapsulation_key;

    // Read payload
    let payload = std::fs::read(payload_path)
        .with_context(|| format!("Failed to read payload: {}", payload_path.display()))?;

    // Get sender's latest establishment event serial from local KEL
    let prefix_digest = cesr::Digest256::from_qb64(prefix).context("Invalid prefix CESR")?;
    let kel_store = create_kel_store(cli, prefix).await?;
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
    let sender_digest = cesr::Digest256::from_qb64(prefix).context("Invalid sender prefix CESR")?;
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

pub(crate) async fn cmd_mail_inbox(cli: &Cli, prefix: &str) -> Result<()> {
    let provider = provider_config(cli, prefix)?.load_provider().await?;
    let prefix_digest = cesr::Digest256::from_qb64(prefix).context("Invalid prefix CESR")?;

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

pub(crate) async fn cmd_mail_fetch(cli: &Cli, prefix: &str, mail_said: &str) -> Result<()> {
    println!("{}", "Fetching and decrypting message...".green());

    let provider = provider_config(cli, prefix)?.load_provider().await?;
    let prefix_digest = cesr::Digest256::from_qb64(prefix).context("Invalid prefix CESR")?;
    let mail_said_digest =
        cesr::Digest256::from_qb64(mail_said).context("Invalid mail SAID CESR")?;

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

    // Resolve source node's mail URL — use explicit mail URL if provided,
    // otherwise look up source node via registry
    let source_mail_url = if let Some(ref mail_url) = cli.mail_url {
        println!("  Using configured mail URL (skipping registry lookup)");
        mail_url.clone()
    } else {
        let registry_urls = parse_registry_urls(&cli.registry);
        let kel_store = create_kel_store(cli, "registry-discovery").await?;
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
        format!("http://mail.{}", source_peer.base_domain)
    };

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
    let source = kels_core::HttpKelSource::new(kels_client.base_url(), "/api/v1/kels/kel/fetch")?;
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

pub(crate) async fn cmd_mail_ack(cli: &Cli, prefix: &str, saids: &[String]) -> Result<()> {
    let provider = provider_config(cli, prefix)?.load_provider().await?;
    let prefix_digest = cesr::Digest256::from_qb64(prefix).context("Invalid prefix CESR")?;
    let said_digests: Vec<cesr::Digest256> = saids
        .iter()
        .map(|s| cesr::Digest256::from_qb64(s))
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
