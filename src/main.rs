use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use sometimes::{config::Config, naive::client::Client};
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Parser)]
#[command(version, about = "Local TPROXY to NaiveProxy client built with Rama")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate configuration without opening sockets or changing networking.
    Check {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Start transparent TCP listeners; routing must be configured separately.
    Run {
        #[arg(short, long)]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Command::Check { config } => {
            let config = Config::load(&config)?;
            let _client = Client::new(config.upstream, config.outbound_mark)?;
            println!("Configuration is valid");
            Ok(())
        }
        Command::Run { config } => {
            let config = Config::load(&config)?;
            fmt()
                .with_env_filter(
                    EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| EnvFilter::new(config.log.level.as_str())),
                )
                .init();
            sometimes::linux::run(config).await
        }
    }
}
