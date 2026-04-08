//! Identity Admin CLI
//!
//! Administrative commands for the KELS registry identity.

use clap::{Parser, Subcommand};
use colored::Colorize;

use kels_core::{IdentityClient, RotateMode};

#[derive(Parser)]
#[command(name = "identity-admin")]
#[command(about = "KELS Registry Identity Administration")]
struct Cli {
    /// Identity service URL
    #[arg(long, env = "IDENTITY_URL", default_value = "http://localhost:80")]
    identity_url: String,

    /// Output as JSON
    #[arg(short, long)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show current identity status
    Status,
    /// Rotate the registry's signing key
    Rotate,
    /// Rotate the registry's recovery key (requires both current and recovery signatures)
    RotateRecovery,
    /// Recover control using the recovery key (creates REC event from current tail)
    Recover,
    /// Contest a malicious recovery (creates CNT event, permanently freezes KEL)
    Contest,
    /// Decommission the registry identity (permanent, cannot be undone)
    Decommission,
    /// Perform scheduled rotation (auto-selects ROT vs ROR based on rotation count)
    ScheduledRotate,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let identity_client = IdentityClient::new(&cli.identity_url)?;

    if let Commands::Status = &cli.command {
        cmd_status(&identity_client, cli.json).await?;
        return Ok(());
    }

    let prefix = identity_client
        .get_prefix()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get prefix: {}", e))?;

    let operation = match &cli.command {
        Commands::Rotate => kels_core::ManageKelOperation::Rotate {
            mode: RotateMode::Standard,
        },
        Commands::RotateRecovery => kels_core::ManageKelOperation::Rotate {
            mode: RotateMode::Recovery,
        },
        Commands::ScheduledRotate => kels_core::ManageKelOperation::Rotate {
            mode: RotateMode::Scheduled,
        },
        Commands::Recover => kels_core::ManageKelOperation::Recover,
        Commands::Contest => kels_core::ManageKelOperation::Contest,
        Commands::Decommission => kels_core::ManageKelOperation::Decommission,
        Commands::Status => unreachable!(),
    };

    let response = manage_kel(&identity_client, &prefix, operation).await?;
    print_manage_response(&response, cli.json);

    Ok(())
}

async fn manage_kel(
    identity_client: &IdentityClient,
    prefix: &cesr::Digest,
    operation: kels_core::ManageKelOperation,
) -> anyhow::Result<kels_core::ManageKelResponse> {
    let request = kels_core::ManageKelRequest {
        prefix: prefix.clone(),
        operation,
    };
    identity_client
        .manage_kel(&request)
        .await
        .map_err(|e| anyhow::anyhow!("Operation failed: {}", e))
}

fn print_manage_response(response: &kels_core::ManageKelResponse, json: bool) {
    if json {
        if let Ok(s) = serde_json::to_string_pretty(response) {
            println!("{}", s);
        }
    } else {
        println!("{}", "Operation Successful!".green().bold());
        println!("{}", "=".repeat(60));
        println!("  {}: {}", "Prefix".cyan(), response.prefix);
        println!("  {}: {}", "Event Kind".cyan(), response.event_kind);
        println!("  {}: {}", "SAID".cyan(), response.said);
        if let Some(n) = response.rotation_number {
            println!("  {}: {}", "Rotation #".cyan(), n);
        }
        println!(
            "  {}: {}",
            "Current Key".cyan(),
            response.current_key_handle
        );
    }
}

async fn cmd_status(identity_client: &IdentityClient, json: bool) -> anyhow::Result<()> {
    let status = identity_client
        .get_status()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get status: {}", e))?;

    if !status.initialized {
        if json {
            println!("{}", serde_json::json!({"initialized": false}));
        } else {
            println!("{}", "Registry identity not initialized.".red());
            println!("The identity service will auto-incept on startup.");
        }
        return Ok(());
    }

    if json {
        if let Ok(s) = serde_json::to_string_pretty(&status) {
            println!("{}", s);
        }
    } else {
        println!("{}", "Registry Identity Status".cyan().bold());
        println!("{}", "=".repeat(60));
        if let Some(ref prefix) = status.prefix {
            println!("  {}: {}", "Prefix".cyan(), prefix.as_ref().yellow());
        }
        if let Some(ref said) = status.last_said {
            println!("  {}: {}", "Last SAID".cyan(), said);
        }
        if let Some(ref key) = status.current_key_handle {
            println!("  {}: {}", "Current Key".cyan(), key);
        }
    }

    Ok(())
}
