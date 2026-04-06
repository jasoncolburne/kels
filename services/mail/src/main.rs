//! KELS Mail - General-purpose ESSR messaging service

use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "kels_mail=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    info!("Starting KELS Mail - General-purpose ESSR messaging service");

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "80".to_string())
        .parse()
        .map_err(|e| format!("PORT must be a valid number: {}", e))?;

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@database:5432/mail".to_string());
    let redis_url = std::env::var("REDIS_URL").ok().filter(|s| !s.is_empty());
    let kels_url = std::env::var("KELS_URL").unwrap_or_else(|_| "http://kels:80".to_string());
    let identity_url =
        std::env::var("IDENTITY_URL").unwrap_or_else(|_| "http://identity:80".to_string());
    info!(
        "Fetching node prefix from identity service at {}",
        identity_url
    );
    let identity_client = kels_core::IdentityClient::new(&identity_url)?;
    let node_prefix = identity_client
        .get_prefix()
        .await
        .map_err(|e| format!("Failed to fetch node prefix from identity service: {}", e))?;
    info!("Node prefix: {}", node_prefix);

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;

    kels_mail::run(
        listener,
        &database_url,
        redis_url.as_deref(),
        &kels_url,
        node_prefix.as_ref(),
    )
    .await?;

    Ok(())
}
