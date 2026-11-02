use anyhow::Result;
use clap::Parser;
use crossterm::event::{Event, KeyCode, EventStream};
use p2p_chat::{ChatApp, Config};
use p2p_chat::ui::{Menu, MenuItem, TerminalGuard, next_event};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::fs::OpenOptions;
use std::io;
use tracing::Level;
use tracing_subscriber;

#[derive(Parser)]
#[command(name = "p2p-chat")]
#[command(about = "Encrypted P2P terminal chat")]
struct Args {
    /// Port to listen on (0 for random available port)
    #[arg(short, long, default_value = "0")]
    port: u16,

    /// Enable mDNS local peer discovery
    #[arg(short, long)]
    mdns: bool,

    /// Connect to a specific peer (IP:PORT or Multiaddr)
    #[arg(short, long)]
    connect: Option<String>,

    /// Username for chat
    #[arg(short, long, default_value = "anonymous")]
    username: String,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Log file path (defaults to "chat.log" to avoid corrupting TUI)
    #[arg(long, default_value = "chat.log")]
    log_file: String,

    /// Skip setup menu and start chat immediately with CLI arguments
    #[arg(long)]
    no_menu: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Setup logging to a file to prevent stderr from corrupting the TUI display
    let level = match args.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    if let Ok(file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&args.log_file)
    {
        let _ = tracing_subscriber::fmt()
            .with_max_level(level)
            .with_writer(file)
            .with_ansi(false)
            .try_init();
    }

    let config = if args.no_menu {
        Config {
            port: args.port,
            enable_mdns: args.mdns,
            connect_to: args.connect,
            username: args.username,
        }
    } else {
        // Run interactive setup menu
        let _guard = TerminalGuard::new()?;
        let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
        let mut menu = Menu::new(args.username, args.port, args.mdns, args.connect);
        let mut events = EventStream::new();

        loop {
            menu.draw(&mut terminal)?;

            if let Some(Ok(Event::Key(key))) = next_event(&mut events).await {
                if key.kind == crossterm::event::KeyEventKind::Press {
                    match key.code {
                        KeyCode::Esc => {
                            // Clean exit from menu
                            return Ok(());
                        }
                        KeyCode::Up | KeyCode::BackTab => menu.previous(),
                        KeyCode::Down | KeyCode::Tab => menu.next(),
                        KeyCode::Enter if matches!(menu.selected, MenuItem::Start) => break,
                        _ => menu.handle_input(key.code),
                    }
                }
            }
        }

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
    }; // TerminalGuard for menu drops here, resetting terminal before ChatApp starts

    // Start Chat Application
    let mut app = ChatApp::new(config).await?;
    app.run().await?;

    Ok(())
}
