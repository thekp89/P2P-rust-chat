use anyhow::Result;
use clap::Parser;
use p2p_chat::{ChatApp, Config};
use std::path::PathBuf;
use tracing::{info, Level};
use tracing_subscriber;

#[derive(Parser)]
#[command(name = "p2p-chat")]
#[command(about = "Encrypted P2P terminal chat")]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value = "0")]
    port: u16,
    
    /// Enable mDNS discovery
    #[arg(short, long)]
    mdns: bool,
    
    /// Connect to specific peer (IP:PORT)
    #[arg(short, long)]
    connect: Option<String>,
    
    /// Username
    #[arg(short, long, default_value = "anonymous")]
    username: String,
    
    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    // Setup logging
    let level = match args.log_level.as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };
    
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .init();

    info!("Starting P2P Chat...");

    let config = Config {
        port: args.port,
        enable_mdns: args.mdns,
        connect_to: args.connect,
        username: args.username,
    };

    let mut app = ChatApp::new(config).await?;
    app.run().await?;

    Ok(())
}