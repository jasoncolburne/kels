//! kels-cli - KELS Command Line Interface

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

mod commands;
mod helpers;

use helpers::{config_dir, parse_algorithm};

const DEFAULT_BASE_DOMAIN: &str = "node-a.kels";
const DEFAULT_REGISTRY_URL: &str = "http://registry.registry-a.kels";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Base domain for service discovery (e.g., "node-a.kels").
    /// KELS URL = http://kels.{domain}, SADStore URL = http://sadstore.{domain}
    #[arg(short = 'd', long, env = "BASE_DOMAIN", default_value = DEFAULT_BASE_DOMAIN)]
    base_domain: String,

    /// Registry URLs for node discovery (comma-separated)
    #[arg(long, env = "KELS_REGISTRY_URLS", default_value = DEFAULT_REGISTRY_URL)]
    registry: String,

    /// Auto-select the fastest available node from registry (requires --registry)
    #[arg(long)]
    auto_select: bool,

    /// Override KELS URL (takes precedence over base_domain)
    #[arg(long, env = "KELS_URL")]
    kels_url: Option<String>,

    /// Override SADStore URL (takes precedence over base_domain)
    #[arg(long, env = "SADSTORE_URL")]
    sadstore_url: Option<String>,

    /// Override Mail URL (takes precedence over base_domain)
    #[arg(long, env = "MAIL_URL")]
    mail_url: Option<String>,

    /// Config directory (default: ~/.kels-cli)
    #[arg(long, env = "KELS_CLI_HOME")]
    config_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Create a new KEL (inception event)
    Incept {
        /// Signing key algorithm (ml-dsa-65, ml-dsa-87, or secp256r1)
        #[arg(long, default_value = "ml-dsa-65")]
        signing_algorithm: String,

        /// Recovery key algorithm (defaults to signing algorithm)
        #[arg(long)]
        recovery_algorithm: Option<String>,
    },

    /// Rotate the signing key
    Rotate {
        /// KEL prefix to rotate
        #[arg(long)]
        prefix: String,

        /// Algorithm for the new signing key (defaults to current)
        #[arg(long)]
        algorithm: Option<String>,
    },

    /// Rotate both signing and recovery keys (requires dual signatures)
    RotateRecovery {
        /// KEL prefix
        #[arg(long)]
        prefix: String,

        /// Algorithm for the new signing key (defaults to current)
        #[arg(long)]
        signing_algorithm: Option<String>,

        /// Algorithm for the new recovery key (defaults to current)
        #[arg(long)]
        recovery_algorithm: Option<String>,
    },

    /// Anchor a SAID in the KEL (interaction event)
    Anchor {
        /// KEL prefix
        #[arg(long)]
        prefix: String,

        /// SAID to anchor
        #[arg(long)]
        said: String,
    },

    /// Recover from divergence by submitting a recovery event (rec).
    Recover {
        /// KEL prefix to recover
        #[arg(long)]
        prefix: String,

        /// Algorithm for the new signing key (defaults to current)
        #[arg(long)]
        signing_algorithm: Option<String>,

        /// Algorithm for the new recovery key (defaults to current)
        #[arg(long)]
        recovery_algorithm: Option<String>,
    },

    /// Contest a malicious recovery by submitting a contest event (cnt).
    /// Use this when an adversary has revealed your recovery key.
    /// The KEL will be permanently frozen after contesting.
    Contest {
        /// KEL prefix to contest
        #[arg(long)]
        prefix: String,
    },

    /// Decommission the KEL (permanent, no further events allowed)
    Decommission {
        /// KEL prefix to decommission
        #[arg(long)]
        prefix: String,
    },

    /// Fetch and display a KEL
    Get {
        /// KEL prefix to fetch
        prefix: String,

        /// Include audit records in response
        #[arg(long)]
        audit: bool,
    },

    /// List all local KELs
    List,

    /// List registered nodes from registry
    ListNodes,

    /// Show status of a local KEL
    Status {
        /// KEL prefix
        #[arg(long)]
        prefix: String,
    },

    /// Reset local state (delete local KEL and keys)
    Reset {
        /// KEL prefix to reset (if omitted, resets all local state)
        #[arg(long)]
        prefix: Option<String>,

        /// Skip confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Sign arbitrary data with the current signing key and print the CESR signature
    Sign {
        /// KEL prefix whose signing key to use
        #[arg(long)]
        prefix: String,

        /// Data to sign (raw string)
        data: String,
    },

    /// SAD store commands (self-addressed data)
    #[command(subcommand)]
    Sad(SadCommands),

    /// Exchange protocol commands (ESSR messaging + key publication)
    #[command(subcommand)]
    Exchange(ExchangeCommands),

    /// Credential management commands
    #[command(subcommand)]
    Cred(CredCommands),

    /// Development and testing commands
    #[cfg(feature = "dev-tools")]
    #[command(subcommand)]
    Dev(DevCommands),

    /// Adversary simulation commands (for testing divergence)
    #[cfg(feature = "dev-tools")]
    #[command(subcommand)]
    Adversary(AdversaryCommands),
}

#[cfg(feature = "dev-tools")]
#[derive(Subcommand, Debug)]
enum DevCommands {
    /// Truncate local KEL to N events (simulates being behind server)
    Truncate {
        /// KEL prefix
        #[arg(long)]
        prefix: String,

        /// Number of events to keep
        #[arg(long)]
        count: usize,
    },

    /// Dump local KEL as JSON
    DumpKel {
        /// KEL prefix
        #[arg(long)]
        prefix: String,
    },
}

#[cfg(feature = "dev-tools")]
#[derive(Subcommand, Debug)]
enum AdversaryCommands {
    /// Inject events to server only (not local storage) - simulates adversary
    Inject {
        /// KEL prefix to attack
        #[arg(long)]
        prefix: String,

        /// Comma-separated list of event types to inject (e.g., "ixn,ixn,rot")
        #[arg(long)]
        events: String,
    },
}

#[derive(Subcommand, Debug)]
enum SadCommands {
    /// Store a self-addressed JSON object in the SAD store
    Put {
        /// Path to JSON file containing the self-addressed object
        file: PathBuf,
    },

    /// Retrieve a self-addressed object by SAID
    Get {
        /// The SAID of the object to retrieve
        said: String,
    },

    /// Submit a signed SAD pointer to a chain
    Submit {
        /// Path to JSON file containing SignedSadPointer(s)
        file: PathBuf,

        /// Submit as a repair operation (truncates divergent records and replaces)
        #[arg(long)]
        repair: bool,
    },

    /// Fetch and display a SAD pointer chain
    Pointer {
        /// The chain prefix to fetch
        prefix: String,
    },

    /// Compute a SAD pointer prefix from a write policy SAID and topic
    Prefix {
        /// The write policy SAID
        write_policy: String,

        /// The topic (e.g., "kels/exchange/v1/keys/mlkem")
        topic: String,
    },
}

#[derive(Subcommand, Debug)]
enum ExchangeCommands {
    /// Publish an ML-KEM encapsulation key to the SADStore
    PublishKey {
        /// KEL prefix whose key to publish
        #[arg(long)]
        prefix: String,

        /// ML-KEM algorithm (ml-kem-768 or ml-kem-1024; defaults to match signing key)
        #[arg(long)]
        algorithm: Option<String>,
    },

    /// Rotate the ML-KEM encapsulation key (appends new version to pointer chain)
    RotateKey {
        /// KEL prefix whose key to rotate
        #[arg(long)]
        prefix: String,

        /// ML-KEM algorithm (ml-kem-768 or ml-kem-1024; defaults to match signing key)
        #[arg(long)]
        algorithm: Option<String>,
    },

    /// Look up a prefix's encapsulation key from the SADStore
    LookupKey {
        /// KEL prefix to look up
        prefix: String,
    },

    /// Send an ESSR-encrypted message to a recipient via the mail service
    Send {
        /// Sender KEL prefix
        #[arg(long)]
        prefix: String,

        /// Recipient KEL prefix
        #[arg(long)]
        recipient: String,

        /// Topic string (e.g., "kels/exchange/v1/topics/exchange")
        #[arg(long, default_value = "kels/exchange/v1/topics/exchange")]
        topic: String,

        /// Path to file containing the payload (or - for stdin)
        #[arg(long)]
        payload: PathBuf,
    },

    /// Check inbox for messages
    Inbox {
        /// Recipient KEL prefix
        #[arg(long)]
        prefix: String,
    },

    /// Fetch and decrypt a message
    Fetch {
        /// Recipient KEL prefix
        #[arg(long)]
        prefix: String,

        /// Mail message SAID
        #[arg(long)]
        said: String,
    },

    /// Acknowledge (delete) messages
    Ack {
        /// Recipient KEL prefix
        #[arg(long)]
        prefix: String,

        /// Mail message SAIDs to acknowledge
        #[arg(long, num_args = 1..)]
        saids: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
enum CredCommands {
    /// Issue a new credential (build, anchor in KEL, store locally)
    Issue {
        /// KEL prefix of the endorser
        #[arg(long)]
        prefix: String,

        /// Path to schema JSON file
        #[arg(long)]
        schema: PathBuf,

        /// Path to policy JSON file
        #[arg(long)]
        policy: PathBuf,

        /// Path to claims JSON file
        #[arg(long)]
        claims: PathBuf,

        /// Subject prefix (optional)
        #[arg(long)]
        subject: Option<String>,

        /// Generate a unique nonce (for non-deterministic credentials)
        #[arg(long)]
        unique: bool,
    },

    /// Store a received credential locally (no anchoring)
    Store {
        /// Path to credential JSON file
        #[arg(long)]
        file: PathBuf,

        /// Path to schema JSON file
        #[arg(long)]
        schema: PathBuf,
    },

    /// List locally stored credentials
    List,

    /// Show a credential by SAID
    Show {
        /// Credential SAID
        said: String,
    },

    /// Poison a credential (anchor poison hash in KEL)
    Poison {
        /// KEL prefix of the endorser
        #[arg(long)]
        prefix: String,

        /// Credential SAID to poison
        #[arg(long)]
        said: String,
    },
}

impl Cli {
    fn kels_url(&self) -> String {
        self.kels_url
            .clone()
            .unwrap_or_else(|| format!("http://kels.{}", self.base_domain))
    }

    fn sadstore_url(&self) -> String {
        self.sadstore_url
            .clone()
            .unwrap_or_else(|| format!("http://sadstore.{}", self.base_domain))
    }

    fn mail_url(&self) -> String {
        self.mail_url
            .clone()
            .unwrap_or_else(|| format!("http://mail.{}", self.base_domain))
    }
}

// ==================== Main ====================

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config_dir = config_dir(&cli)?;
    std::fs::create_dir_all(&config_dir)?;

    match &cli.command {
        Commands::Incept {
            signing_algorithm,
            recovery_algorithm,
        } => {
            let signing = parse_algorithm(signing_algorithm)?;
            let recovery = match recovery_algorithm.as_deref() {
                Some(a) => parse_algorithm(a)?,
                None => signing,
            };
            commands::kel::cmd_incept(&cli, signing, recovery).await
        }
        Commands::Rotate { prefix, algorithm } => {
            let algo = algorithm.as_deref().map(parse_algorithm).transpose()?;
            commands::kel::cmd_rotate(&cli, prefix, algo).await
        }
        Commands::RotateRecovery {
            prefix,
            signing_algorithm,
            recovery_algorithm,
        } => {
            let signing = signing_algorithm
                .as_deref()
                .map(parse_algorithm)
                .transpose()?;
            let recovery = recovery_algorithm
                .as_deref()
                .map(parse_algorithm)
                .transpose()?;
            commands::kel::cmd_rotate_recovery(&cli, prefix, signing, recovery).await
        }
        Commands::Sign { prefix, data } => commands::kel::cmd_sign(&cli, prefix, data).await,
        Commands::Anchor { prefix, said } => commands::kel::cmd_anchor(&cli, prefix, said).await,
        Commands::Recover {
            prefix,
            signing_algorithm,
            recovery_algorithm,
        } => {
            commands::kel::cmd_recover(
                &cli,
                prefix,
                signing_algorithm.as_deref(),
                recovery_algorithm.as_deref(),
            )
            .await
        }
        Commands::Contest { prefix } => commands::kel::cmd_contest(&cli, prefix).await,
        Commands::Decommission { prefix } => commands::kel::cmd_decommission(&cli, prefix).await,
        Commands::Get { prefix, audit } => commands::kel::cmd_get(&cli, prefix, *audit).await,
        Commands::List => commands::kel::cmd_list(&cli).await,
        Commands::ListNodes => commands::kel::cmd_list_nodes(&cli).await,
        Commands::Status { prefix } => commands::kel::cmd_status(&cli, prefix).await,
        Commands::Reset { prefix, yes } => {
            commands::kel::cmd_reset(&cli, prefix.as_deref(), *yes).await
        }

        Commands::Sad(sad_cmd) => match sad_cmd {
            SadCommands::Put { file } => commands::sad::cmd_sad_put(&cli, file).await,
            SadCommands::Get { said } => commands::sad::cmd_sad_get(&cli, said).await,
            SadCommands::Submit { file, repair } => {
                commands::sad::cmd_sad_submit(&cli, file, *repair).await
            }
            SadCommands::Pointer { prefix } => commands::sad::cmd_sad_chain(&cli, prefix).await,
            SadCommands::Prefix {
                write_policy,
                topic,
            } => commands::sad::cmd_sad_prefix(write_policy, topic),
        },

        Commands::Exchange(ex_cmd) => match ex_cmd {
            ExchangeCommands::PublishKey { prefix, algorithm } => {
                commands::exchange::cmd_exchange_publish_key(&cli, prefix, algorithm.as_deref())
                    .await
            }
            ExchangeCommands::RotateKey { prefix, algorithm } => {
                commands::exchange::cmd_exchange_rotate_key(&cli, prefix, algorithm.as_deref())
                    .await
            }
            ExchangeCommands::LookupKey { prefix } => {
                commands::exchange::cmd_exchange_lookup_key(&cli, prefix).await
            }
            ExchangeCommands::Send {
                prefix,
                recipient,
                topic,
                payload,
            } => {
                commands::exchange::cmd_exchange_send(&cli, prefix, recipient, topic, payload).await
            }
            ExchangeCommands::Inbox { prefix } => {
                commands::exchange::cmd_exchange_inbox(&cli, prefix).await
            }
            ExchangeCommands::Fetch { prefix, said } => {
                commands::exchange::cmd_exchange_fetch(&cli, prefix, said).await
            }
            ExchangeCommands::Ack { prefix, saids } => {
                commands::exchange::cmd_exchange_ack(&cli, prefix, saids).await
            }
        },

        Commands::Cred(cred_cmd) => match cred_cmd {
            CredCommands::Issue {
                prefix,
                schema,
                policy,
                claims,
                subject,
                unique,
            } => {
                commands::cred::cmd_cred_issue(
                    &cli,
                    prefix,
                    schema,
                    policy,
                    claims,
                    subject.as_deref(),
                    *unique,
                )
                .await
            }
            CredCommands::Store { file, schema } => {
                commands::cred::cmd_cred_store(&cli, file, schema).await
            }
            CredCommands::List => commands::cred::cmd_cred_list(&cli).await,
            CredCommands::Show { said } => commands::cred::cmd_cred_show(&cli, said).await,
            CredCommands::Poison { prefix, said } => {
                commands::cred::cmd_cred_poison(&cli, prefix, said).await
            }
        },

        #[cfg(feature = "dev-tools")]
        Commands::Dev(dev_cmd) => match dev_cmd {
            DevCommands::Truncate { prefix, count } => {
                commands::dev::cmd_dev_truncate(&cli, prefix, *count).await
            }
            DevCommands::DumpKel { prefix } => commands::dev::cmd_dev_dump_kel(&cli, prefix).await,
        },

        #[cfg(feature = "dev-tools")]
        Commands::Adversary(adv_cmd) => match adv_cmd {
            AdversaryCommands::Inject { prefix, events } => {
                commands::dev::cmd_adversary_inject(&cli, prefix, events).await
            }
        },
    }
}
