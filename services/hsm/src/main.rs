//! HSM Service - SoftHSM2 PKCS#11 wrapper

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "hsm=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    tracing::info!("Starting HSM Service");

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "80".to_string())
        .parse()
        .map_err(|e| format!("PORT must be a valid number: {}", e))?;

    hsm::server::run(port).await?;

    Ok(())
}
