//! KELS Admin CLI
//!
//! Administrative commands for the Key Event Log Service.

use clap::{Parser, Subcommand};
use kels_service::KelsRepository;
use verifiable_storage::RepositoryConnection;

#[derive(Parser)]
#[command(name = "kels-admin")]
#[command(about = "Key Event Log Service Administration")]
struct Cli {
    /// PostgreSQL database URL
    #[arg(
        long,
        env = "DATABASE_URL",
        default_value = "postgres://postgres:postgres@database:5432/kels"
    )]
    database_url: String,

    /// Output as JSON
    #[arg(short, long)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize database schema (run migrations)
    Init,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            let repo = KelsRepository::connect(&cli.database_url).await?;
            repo.initialize().await?;

            if !cli.json {
                println!("Database initialized successfully.");
            }
        }
    }

    Ok(())
}
