//! Exchange protocol command handlers.

use std::path::PathBuf;

use base64::Engine;

use anyhow::{Context, Result, anyhow};
use cesr::Matter;
use colored::Colorize;
use kels_core::{KeyProvider, ProviderConfig, VerificationKeyCode};
use verifiable_storage::{Chained, SelfAddressed};

use crate::Cli;
use crate::helpers::*;

pub(crate) fn kem_key_path(cli: &Cli, prefix: &str) -> Result<PathBuf> {
    Ok(config_dir(cli)?.join("keys").join(prefix).join("kem.key"))
}

pub(crate) fn save_decap_key(path: &std::path::Path, dk: &cesr::DecapsulationKey) -> Result<()> {
    let (algo, raw) = match dk {
        cesr::DecapsulationKey::MlKem768(bytes) => ("ml-kem-768", bytes.as_slice()),
        cesr::DecapsulationKey::MlKem1024(bytes) => ("ml-kem-1024", bytes.as_slice()),
    };
    let encoded = format!(
        "{}:{}",
        algo,
        base64::engine::general_purpose::STANDARD.encode(raw)
    );
    std::fs::write(path, encoded).context("Failed to write decapsulation key")
}

pub(crate) fn _load_decap_key(path: &std::path::Path) -> Result<cesr::DecapsulationKey> {
    let data = std::fs::read_to_string(path).context("Failed to read decapsulation key")?;
    let (algo, b64) = data
        .split_once(':')
        .ok_or_else(|| anyhow!("Invalid decapsulation key format"))?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .context("Invalid base64 in decapsulation key")?;
    match algo {
        "ml-kem-768" => Ok(cesr::DecapsulationKey::MlKem768(raw)),
        "ml-kem-1024" => Ok(cesr::DecapsulationKey::MlKem1024(raw)),
        _ => Err(anyhow!("Unknown KEM algorithm: {}", algo)),
    }
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
        said: String::new(),
        algorithm: kem_algo.to_string(),
        encapsulation_key: encap_key.qb64(),
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
    let v0 = kels_core::SadPointer::create(
        prefix.to_string(),
        kels_exchange::ENCAP_KEY_KIND.to_string(),
        None,
    )
    .context("Failed to create inception pointer")?;

    let mut v1 = v0.clone();
    v1.content_said = Some(publication.said.clone());
    v1.increment().context("Failed to increment pointer")?;

    // Sign both records (signature is over the SAID string, not serialized JSON)
    let v0_sig = provider.sign(v0.said.as_bytes()).await?;
    let v1_sig = provider.sign(v1.said.as_bytes()).await?;

    let signed_records = vec![
        kels_core::SignedSadPointer {
            pointer: v0,
            signature: v0_sig.qb64(),
            establishment_serial: 0,
        },
        kels_core::SignedSadPointer {
            pointer: v1,
            signature: v1_sig.qb64(),
            establishment_serial: 0,
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
        said: String::new(),
        algorithm: kem_algo.to_string(),
        encapsulation_key: encap_key.qb64(),
    };
    publication
        .derive_said()
        .context("SAID derivation failed")?;

    let sad_client = kels_core::SadStoreClient::new(&cli.sadstore_url())?;
    let pub_json = serde_json::to_value(&publication)?;
    sad_client.post_sad_object(&pub_json).await?;

    // Fetch current chain to get tip for increment
    let chain_prefix = kels_core::compute_sad_pointer_prefix(prefix, kels_exchange::ENCAP_KEY_KIND)
        .context("Failed to compute pointer prefix")?;
    let page = sad_client
        .fetch_sad_pointer(&chain_prefix, None)
        .await
        .context("Failed to fetch current chain")?;

    let tip = page
        .pointers
        .last()
        .ok_or_else(|| anyhow!("No existing key chain found — use publish-key first"))?;

    let mut next = tip.pointer.clone();
    next.content_said = Some(publication.said.clone());
    next.increment().context("Failed to increment pointer")?;

    let sig = provider.sign(next.said.as_bytes()).await?;

    let signed = vec![kels_core::SignedSadPointer {
        pointer: next,
        signature: sig.qb64(),
        establishment_serial: 0,
    }];

    sad_client.submit_sad_pointer(&signed).await?;

    println!("{}", "Key rotated!".green().bold());
    Ok(())
}

pub(crate) async fn cmd_exchange_lookup_key(cli: &Cli, kel_prefix: &str) -> Result<()> {
    let chain_prefix =
        kels_core::compute_sad_pointer_prefix(kel_prefix, kels_exchange::ENCAP_KEY_KIND)
            .context("Failed to compute pointer prefix")?;

    let sad_client = kels_core::SadStoreClient::new(&cli.sadstore_url())?;
    let page = sad_client
        .fetch_sad_pointer(&chain_prefix, None)
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
    println!(
        "  Encap Key:   {}...{}",
        &publication.encapsulation_key[..20],
        &publication.encapsulation_key[publication.encapsulation_key.len() - 10..]
    );

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
    let chain_prefix =
        kels_core::compute_sad_pointer_prefix(recipient, kels_exchange::ENCAP_KEY_KIND)?;
    let sad_client = kels_core::SadStoreClient::new(&cli.sadstore_url())?;
    let page = sad_client.fetch_sad_pointer(&chain_prefix, None).await?;
    let tip = page
        .pointers
        .last()
        .ok_or_else(|| anyhow!("No encapsulation key for recipient {}", recipient))?;
    let content_said = tip
        .pointer
        .content_said
        .as_ref()
        .ok_or_else(|| anyhow!("Recipient key chain has no content"))?;
    let value = sad_client.get_sad_object(content_said).await?;
    let publication: kels_exchange::EncapsulationKeyPublication = serde_json::from_value(value)?;
    let encap_key = cesr::EncapsulationKey::from_qb64(&publication.encapsulation_key)
        .context("Invalid encapsulation key")?;

    // Read payload
    let payload = std::fs::read(payload_path)
        .with_context(|| format!("Failed to read payload: {}", payload_path.display()))?;

    // Get current signing key for ESSR
    let signing_key_qb64 = {
        let key_dir = config_dir(cli)?.join("keys").join(prefix);
        let current_path = key_dir.join("current.key");
        std::fs::read_to_string(&current_path).context("Failed to read signing key")?
    };
    let signing_key = cesr::SigningKey::from_qb64(signing_key_qb64.trim())?;

    // ESSR seal
    let inner = kels_exchange::EssrInner {
        sender: prefix.to_string(),
        topic: topic.to_string(),
        payload,
    };

    let signed_envelope = kels_exchange::seal(&inner, 0, recipient, &encap_key, &signing_key)?;

    // Serialize and send to mail service
    let envelope_bytes = serde_json::to_vec(&signed_envelope)?;
    let blob_digest = kels_exchange::compute_blob_digest(&envelope_bytes);

    println!("  Envelope SAID: {}", signed_envelope.envelope.said);
    println!("  Blob digest:   {}", blob_digest);
    println!("  Payload size:  {} bytes", envelope_bytes.len());

    // POST to mail service
    let mail_url = cli.mail_url();
    let timestamp = chrono::Utc::now().timestamp();
    let nonce = kels_core::crypto::generate_nonce();

    let send_request = kels_exchange::SendRequest {
        timestamp,
        nonce,
        recipient_kel_prefix: recipient.to_string(),
        blob: base64::engine::general_purpose::STANDARD.encode(&envelope_bytes),
    };

    let request_json = serde_json::to_vec(&send_request)?;
    let signature = provider.sign(&request_json).await?;

    let signed_request = kels_core::SignedRequest {
        payload: send_request,
        peer_prefix: prefix.to_string(),
        signature: signature.qb64(),
    };

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/api/v1/mail/send", mail_url))
        .json(&signed_request)
        .send()
        .await
        .context("Failed to send mail")?;

    if response.status().is_success() {
        println!("{}", "Message sent!".green().bold());
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("Mail send failed ({}): {}", status, body));
    }

    Ok(())
}

pub(crate) async fn cmd_exchange_inbox(cli: &Cli, prefix: &str) -> Result<()> {
    let provider = provider_config(cli, prefix)?.load_provider().await?;

    let mail_url = cli.mail_url();
    let timestamp = chrono::Utc::now().timestamp();
    let nonce = kels_core::crypto::generate_nonce();

    let inbox_request = kels_exchange::InboxRequest {
        timestamp,
        nonce,
        limit: None,
        offset: None,
    };

    let request_json = serde_json::to_vec(&inbox_request)?;
    let signature = provider.sign(&request_json).await?;

    let signed_request = kels_core::SignedRequest {
        payload: inbox_request,
        peer_prefix: prefix.to_string(),
        signature: signature.qb64(),
    };

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/api/v1/mail/inbox", mail_url))
        .json(&signed_request)
        .send()
        .await
        .context("Failed to check inbox")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("Inbox fetch failed ({}): {}", status, body));
    }

    let body: serde_json::Value = response.json().await?;
    let messages = body["messages"].as_array();

    match messages {
        Some(msgs) if msgs.is_empty() => {
            println!("{}", "Inbox empty.".yellow());
        }
        Some(msgs) => {
            println!(
                "{}",
                format!("Inbox ({} messages):", msgs.len()).cyan().bold()
            );
            for msg in msgs {
                println!(
                    "  {} | from: {} | digest: {} | expires: {}",
                    msg["said"].as_str().unwrap_or("-"),
                    msg["sourceNodePrefix"].as_str().unwrap_or("-"),
                    msg["blobDigest"].as_str().unwrap_or("-"),
                    msg["expiresAt"].as_str().unwrap_or("-"),
                );
            }
        }
        None => {
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
    }

    Ok(())
}
