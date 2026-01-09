use anyhow::Result;
use clap::Parser;
use p2p_chat::{ChatApp, Config};
use p2p_chat::ui::{Menu, MenuItem, TerminalGuard, next_event};
use tracing::{info, Level};
use tracing_subscriber;
use crossterm::event::{Event, KeyCode, EventStream};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;

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

    info!("Starting P2P Chat configuration...");

    // Run Menu
    let config = {
        let _guard = TerminalGuard::new()?;
        let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
        let mut menu = Menu::new(args.username.clone(), args.port, args.mdns, args.connect.clone());
        let mut events = EventStream::new();

        loop {
            menu.draw(&mut terminal)?;

            if let Some(Ok(Event::Key(key))) = next_event(&mut events).await {
                match key.code {
                    KeyCode::Up => menu.previous(),
                    KeyCode::Down => menu.next(),
                    KeyCode::Enter if matches!(menu.selected, MenuItem::Start) => break,
                    _ => menu.handle_input(key.code),
                }
            }
        }
        
        // Parse port, default to 0 if invalid
        let port = menu.port.parse().unwrap_or(0);
        let connect_to = if menu.connect_addr.trim().is_empty() {
            None
        } else {
            Some(menu.connect_addr.trim().to_string())
        };

        Config {
            port,
            enable_mdns: menu.mdns,
            connect_to,
            username: menu.username,
        }
    }; // TerminalGuard drops here, restoring terminal

    // Start Chat App
    let mut app = ChatApp::new(config).await?;
    app.run().await?;

    Ok(())
}