//! KELS Gossip Service Entry Point

use kels_gossip::Config;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "kels_gossip=info,libp2p=info".into()),
        )
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    // Load configuration
    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Configuration error: {}", e);
            std::process::exit(1);
        }
    };

    // Run the service
    if let Err(e) = kels_gossip::run(config).await {
        tracing::error!("Service error: {}", e);
        std::process::exit(1);
    }
}
