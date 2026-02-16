//! KELS Registry - Node Registration Service

use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "kels_registry=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    info!("Starting KELS Registry Service");

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "80".to_string())
        .parse()
        .map_err(|e| format!("PORT must be a valid number: {}", e))?;

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;

    kels_registry::run(listener).await?;

    Ok(())
}
