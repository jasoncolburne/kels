//! HTTP handlers for the mail service.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::IntoResponse,
};
use dashmap::DashMap;
use redis::AsyncCommands;
use tracing::{debug, info, warn};
use verifiable_storage::SelfAddressed;

use kels_exchange::{
    AckRequest, FetchRequest, InboxRequest, InboxResponse, MailAnnouncement, MailMessage,
    SendRequest, compute_blob_digest,
};

use crate::{blob_store::BlobStore, repository::MailRepository};

const SECS_PER_DAY: u64 = 86_400;
const RATE_LIMIT_REAP_INTERVAL: Duration = Duration::from_secs(300);

fn nonce_window_secs() -> u64 {
    kels_core::env_usize("KELS_NONCE_WINDOW_SECS", 60) as u64
}

fn max_messages_per_sender_per_day() -> u32 {
    kels_core::env_usize("MAIL_MAX_MESSAGES_PER_SENDER_PER_DAY", 100) as u32
}

fn max_inbox_size() -> usize {
    kels_core::env_usize("MAIL_MAX_INBOX_SIZE", 10_000)
}

fn max_storage_per_recipient_mb() -> usize {
    kels_core::env_usize("MAIL_MAX_STORAGE_PER_RECIPIENT_MB", 100)
}

fn message_ttl_days() -> i64 {
    kels_core::env_usize("MAIL_MESSAGE_TTL_DAYS", 30) as i64
}

/// Shared application state.
pub struct AppState {
    pub repo: Arc<MailRepository>,
    pub blob_store: Arc<BlobStore>,
    pub kels_client: kels_core::KelsClient,
    pub redis_conn: Option<redis::aio::ConnectionManager>,
    pub node_prefix: String,
    pub sender_rate_limits: DashMap<String, (u32, Instant)>,
    pub ip_rate_limits: DashMap<IpAddr, (u32, Instant)>,
    pub nonce_cache: DashMap<String, Instant>,
}

/// Spawn a background task that periodically removes expired entries.
pub fn spawn_reaper(state: Arc<AppState>) {
    let gc_state = Arc::clone(&state);
    tokio::spawn(async move {
        let nonce_window = Duration::from_secs(nonce_window_secs());
        loop {
            tokio::time::sleep(RATE_LIMIT_REAP_INTERVAL).await;
            let now = Instant::now();
            let day = Duration::from_secs(SECS_PER_DAY);
            gc_state
                .sender_rate_limits
                .retain(|_, (_, t)| now.duration_since(*t) < day);
            gc_state
                .ip_rate_limits
                .retain(|_, (_, t)| now.duration_since(*t) < day);
            gc_state
                .nonce_cache
                .retain(|_, t| now.duration_since(*t) < nonce_window);

            // GC expired messages
            match gc_state.repo.messages.delete_expired().await {
                Ok(saids) => {
                    for said in &saids {
                        // Delete blob if local
                        let _ = gc_state.blob_store.delete(said).await;
                        // Gossip removal
                        if let Some(ref redis) = gc_state.redis_conn {
                            let announcement = MailAnnouncement::Removal { said: said.clone() };
                            if let Ok(json) = serde_json::to_string(&announcement) {
                                let mut conn = redis.clone();
                                let _: Result<(), _> = conn.publish("mail_updates", &json).await;
                            }
                        }
                    }
                    if !saids.is_empty() {
                        info!("GC: removed {} expired messages", saids.len());
                    }
                }
                Err(e) => warn!("GC: failed to delete expired messages: {}", e),
            }
        }
    });
}

// ==================== Rate Limiting ====================

fn check_sender_rate_limit(
    limits: &DashMap<String, (u32, Instant)>,
    sender: &str,
) -> Result<(), String> {
    let now = Instant::now();
    let max = max_messages_per_sender_per_day();
    let mut entry = limits.entry(sender.to_string()).or_insert((0, now));

    if now.duration_since(entry.1) >= Duration::from_secs(SECS_PER_DAY) {
        entry.0 = 0;
        entry.1 = now;
    }

    if entry.0 >= max {
        return Err(format!("Sender rate limit exceeded ({} messages/day)", max));
    }

    entry.0 += 1;
    Ok(())
}

fn check_ip_rate_limit(limits: &DashMap<IpAddr, (u32, Instant)>, ip: IpAddr) -> Result<(), String> {
    let now = Instant::now();
    let burst: u32 = 500;
    let refill_rate: u32 = 100;
    let mut entry = limits.entry(ip).or_insert((burst, now));
    let elapsed = now.duration_since(entry.1);
    let refill = (elapsed.as_secs_f64() * refill_rate as f64) as u32;
    if refill > 0 {
        entry.0 = (entry.0 + refill).min(burst);
        entry.1 = now;
    }
    if entry.0 == 0 {
        return Err("Too many requests".to_string());
    }
    entry.0 -= 1;
    Ok(())
}

// ==================== KEL Authentication ====================

/// Authenticate a signed request by verifying the signer's KEL and signature.
async fn authenticate_request<T: serde::Serialize>(
    state: &AppState,
    signed_request: &kels_core::SignedRequest<T>,
    timestamp: i64,
    nonce: &str,
) -> Result<(), (StatusCode, String)> {
    if !kels_core::validate_timestamp(timestamp, 60) {
        return Err((StatusCode::FORBIDDEN, "Request timestamp expired".into()));
    }

    let window = nonce_window_secs();
    if window > 0
        && state
            .nonce_cache
            .insert(nonce.to_string(), Instant::now())
            .is_some()
    {
        return Err((StatusCode::FORBIDDEN, "Duplicate nonce".into()));
    }

    let verifier = kels_core::KelVerifier::new(&signed_request.peer_prefix);
    let kel_verification = kels_core::verify_key_events(
        &signed_request.peer_prefix,
        &state.kels_client.as_kel_source().map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to build HTTP client: {}", e),
            )
        })?,
        verifier,
        kels_core::page_size(),
        kels_core::max_pages(),
    )
    .await
    .map_err(|_| (StatusCode::FORBIDDEN, "KEL verification failed".into()))?;

    signed_request
        .verify_signature(&kel_verification)
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "Signature verification failed".into(),
            )
        })?;

    Ok(())
}

// ==================== Health ====================

pub async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

// ==================== Send ====================

pub async fn send_mail(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(signed): Json<kels_core::SignedRequest<SendRequest>>,
) -> impl IntoResponse {
    if let Err(msg) = check_ip_rate_limit(&state.ip_rate_limits, addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
    }

    let payload = &signed.payload;
    if let Err(e) = authenticate_request(&state, &signed, payload.timestamp, &payload.nonce).await {
        return e.into_response();
    }

    let sender = &signed.peer_prefix;
    if let Err(msg) = check_sender_rate_limit(&state.sender_rate_limits, sender) {
        return (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
    }

    // Check inbox cap
    match state
        .repo
        .messages
        .count_for_recipient(&payload.recipient_kel_prefix)
        .await
    {
        Ok(count) if count >= max_inbox_size() => {
            return (StatusCode::INSUFFICIENT_STORAGE, "Recipient inbox full").into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
                .into_response();
        }
        _ => {}
    }

    // Decode blob
    let blob = match base64_decode(&payload.blob) {
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("Invalid blob: {}", e)).into_response(),
    };

    // Check cumulative local storage cap for this recipient
    let max_bytes = (max_storage_per_recipient_mb() * 1024 * 1024) as i64;
    match state
        .repo
        .messages
        .local_storage_for_recipient(&state.node_prefix, &payload.recipient_kel_prefix)
        .await
    {
        Ok(current) if current + blob.len() as i64 > max_bytes => {
            return (
                StatusCode::INSUFFICIENT_STORAGE,
                "Recipient storage cap exceeded",
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
                .into_response();
        }
        _ => {}
    }

    let blob_digest = compute_blob_digest(&blob);

    // Build MailMessage
    let now = verifiable_storage::StorageDatetime::now();
    let expires_at = verifiable_storage::StorageDatetime::from(
        chrono::Utc::now() + chrono::Duration::days(message_ttl_days()),
    );

    let mut mail_message = MailMessage {
        said: String::new(),
        source_node_prefix: state.node_prefix.clone(),
        recipient_kel_prefix: payload.recipient_kel_prefix.clone(),
        blob_digest: blob_digest.clone(),
        blob_size: blob.len() as i64,
        created_at: now,
        expires_at,
    };

    if let Err(e) = mail_message.derive_said() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("SAID derivation failed: {}", e),
        )
            .into_response();
    }

    // Store blob first, then metadata. On metadata failure, clean up the blob.
    if let Err(e) = state.blob_store.put(&blob_digest, &blob).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Blob storage failed: {}", e),
        )
            .into_response();
    }

    if let Err(e) = state.repo.messages.store(&mail_message).await {
        let _ = state.blob_store.delete(&blob_digest).await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Metadata storage failed: {}", e),
        )
            .into_response();
    }

    // Gossip announcement
    if let Some(ref redis) = state.redis_conn {
        let announcement = MailAnnouncement::Message(mail_message.clone());
        if let Ok(json) = serde_json::to_string(&announcement) {
            let mut conn = redis.clone();
            let _: Result<(), _> = conn.publish("mail_updates", &json).await;
        }
    }

    debug!("Stored mail message: {}", mail_message.said);
    (StatusCode::OK, Json(mail_message)).into_response()
}

// ==================== Inbox ====================

pub async fn inbox(
    State(state): State<Arc<AppState>>,
    Json(signed): Json<kels_core::SignedRequest<InboxRequest>>,
) -> impl IntoResponse {
    let payload = &signed.payload;
    if let Err(e) = authenticate_request(&state, &signed, payload.timestamp, &payload.nonce).await {
        return e.into_response();
    }

    let limit = payload.limit.unwrap_or(100).min(1000);
    let offset = payload.offset.unwrap_or(0);

    match state
        .repo
        .messages
        .inbox(&signed.peer_prefix, limit, offset)
        .await
    {
        Ok(messages) => (StatusCode::OK, Json(InboxResponse { messages })).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response(),
    }
}

// ==================== Fetch ====================

pub async fn fetch(
    State(state): State<Arc<AppState>>,
    Json(signed): Json<kels_core::SignedRequest<FetchRequest>>,
) -> impl IntoResponse {
    let payload = &signed.payload;
    if let Err(e) = authenticate_request(&state, &signed, payload.timestamp, &payload.nonce).await {
        return e.into_response();
    }

    // Look up message metadata
    let message = match state.repo.messages.get_by_said(&payload.mail_said).await {
        Ok(Some(m)) => m,
        Ok(None) => return (StatusCode::NOT_FOUND, "Message not found").into_response(),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
                .into_response();
        }
    };

    // Verify the requester is the recipient
    if message.recipient_kel_prefix != signed.peer_prefix {
        return (StatusCode::FORBIDDEN, "Not the recipient").into_response();
    }

    // Only serve blobs for local messages
    if message.source_node_prefix != state.node_prefix {
        return (StatusCode::NOT_FOUND, "Blob not local").into_response();
    }

    match state.blob_store.get(&message.blob_digest).await {
        Ok(blob) => {
            // Verify integrity
            let digest = compute_blob_digest(&blob);
            if digest != message.blob_digest {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Blob integrity check failed",
                )
                    .into_response();
            }
            (StatusCode::OK, blob).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Blob fetch failed: {}", e),
        )
            .into_response(),
    }
}

// ==================== Ack ====================

pub async fn ack(
    State(state): State<Arc<AppState>>,
    Json(signed): Json<kels_core::SignedRequest<AckRequest>>,
) -> impl IntoResponse {
    let payload = &signed.payload;
    if let Err(e) = authenticate_request(&state, &signed, payload.timestamp, &payload.nonce).await {
        return e.into_response();
    }

    let mut deleted = 0u32;
    for said in &payload.saids {
        // Verify recipient
        let message = match state.repo.messages.get_by_said(said).await {
            Ok(Some(m)) if m.recipient_kel_prefix == signed.peer_prefix => m,
            _ => continue,
        };

        // Delete blob if local
        if message.source_node_prefix == state.node_prefix {
            let _ = state.blob_store.delete(&message.blob_digest).await;
        }

        // Delete metadata
        if state.repo.messages.delete(said).await.unwrap_or(false) {
            deleted += 1;

            // Gossip removal
            if let Some(ref redis) = state.redis_conn {
                let announcement = MailAnnouncement::Removal { said: said.clone() };
                if let Ok(json) = serde_json::to_string(&announcement) {
                    let mut conn = redis.clone();
                    let _: Result<(), _> = conn.publish("mail_updates", &json).await;
                }
            }
        }
    }

    debug!("Acknowledged {} messages", deleted);
    (StatusCode::OK, format!("{}", deleted)).into_response()
}

fn base64_decode(data: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|e| e.to_string())
}
