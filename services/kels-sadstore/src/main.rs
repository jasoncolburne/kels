//! KELS SADStore - Replicated Self-Addressed Data Store

use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "kels_sadstore=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    info!("Starting KELS SADStore - Replicated Self-Addressed Data Store");

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "80".to_string())
        .parse()
        .map_err(|e| format!("PORT must be a valid number: {}", e))?;

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@database:5432/sadstore".to_string());
    let redis_url = std::env::var("REDIS_URL").ok().filter(|s| !s.is_empty());
    let kels_url = std::env::var("KELS_URL").unwrap_or_else(|_| "http://kels:80".to_string());

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;

    kels_sadstore::run(listener, &database_url, redis_url.as_deref(), &kels_url).await?;

    Ok(())
}
