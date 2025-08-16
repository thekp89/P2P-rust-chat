use anyhow::Result;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures::prelude::*;
use libp2p::{
    gossipsub::{self, IdentTopic, MessageAuthenticity, ValidationMode},
    identify, mdns,
    noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm, Transport, SwarmBuilder,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame, Terminal,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{select, time};
use tracing::{debug, info};
use x25519_dalek::{EphemeralSecret, PublicKey};

pub struct Config {
    pub port: u16,
    pub enable_mdns: bool,
    pub connect_to: Option<String>,
    pub username: String,
}

#[derive(NetworkBehaviour)]
pub struct ChatBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub identify: identify::Behaviour,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChatMessage {
    pub username: String,
    pub content: String,
    pub timestamp: u64,
    pub encrypted_content: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyExchange {
    pub public_key: [u8; 32],
    pub peer_id: String,
}

pub struct ChatApp {
    swarm: Swarm<ChatBehaviour>,
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
    messages: Vec<String>,
    input: String,
    config: Config,
    shared_secrets: HashMap<PeerId, [u8; 32]>,
    my_public: PublicKey,
    topic: IdentTopic,
}

impl ChatApp {
    pub async fn new(config: Config) -> Result<Self> {
        // Create identity keypair
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());
        info!("Local peer id: {local_peer_id}");

        // Create gossipsub config
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(1))
            .validation_mode(ValidationMode::Strict)
            .build()
            .expect("Valid config");

        // Create gossipsub behaviour
        let gossipsub = gossipsub::Behaviour::new(
            MessageAuthenticity::Signed(local_key.clone()),
            gossipsub_config,
        ).expect("Valid gossipsub config");

        // Create mDNS behaviour
        let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?;

        // Create identify behaviour
        let identify = identify::Behaviour::new(identify::Config::new(
            "/p2p-chat/1.0.0".into(),
            local_key.public(),
        ));

        // Create behaviour
        let behaviour = ChatBehaviour {
            gossipsub,
            mdns,
            identify,
        };

        // Create swarm using the new builder API
        let mut swarm = SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
            .with_behaviour(|_| behaviour)?
            .build();

        // Listen on all interfaces
        let listen_addr = format!("/ip4/0.0.0.0/tcp/{}", config.port);
        swarm.listen_on(listen_addr.parse()?)?;

        // Generate X25519 keys
        let my_secret = EphemeralSecret::random_from_rng(&mut OsRng);
        let my_public = PublicKey::from(&my_secret);

        // Subscribe to chat topic
        let topic = IdentTopic::new("chat");
        swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;

        let mut app = ChatApp {
            swarm,
            terminal,
            messages: Vec::new(),
            input: String::new(),
            config,
            shared_secrets: HashMap::new(),
            my_public,
            topic,
        };

        // Connect to peer if specified
        if let Some(addr) = &app.config.connect_to {
            let multiaddr: Multiaddr = format!("/ip4/{}/tcp/{}", 
                addr.split(':').next().unwrap_or("127.0.0.1"),
                addr.split(':').nth(1).unwrap_or("8080")
            ).parse()?;
            app.swarm.dial(multiaddr)?;
        }

        Ok(app)
    }

    pub async fn run(&mut self) -> Result<()> {
        info!("Chat app started. Press 'q' to quit, 'Enter' to send message");
        
        let mut tick_interval = time::interval(Duration::from_millis(100));
        
        loop {
            select! {
                _ = tokio::time::sleep(Duration::from_millis(50)) => {
                    // Check for keyboard events
                    if event::poll(Duration::from_millis(0))? {
                        if let Event::Key(key) = event::read()? {
                            if key.kind == KeyEventKind::Press {
                                match key.code {
                                    KeyCode::Char('q') => break,
                                    KeyCode::Enter => {
                                        self.send_message().await?;
                                    }
                                    KeyCode::Backspace => {
                                        self.input.pop();
                                    }
                                    KeyCode::Char(c) => {
                                        self.input.push(c);
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
                
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event).await?;
                }
                
                _ = tick_interval.tick() => {
                    self.draw()?;
                }
            }
        }

        // Cleanup terminal
        disable_raw_mode()?;
        execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        self.terminal.show_cursor()?;

        Ok(())
    }

    async fn handle_swarm_event(&mut self, event: SwarmEvent<ChatBehaviourEvent>) -> Result<()> {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {address}");
                self.messages.push(format!("🎧 Listening on {address}"));
            }
            SwarmEvent::Behaviour(ChatBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                for (peer_id, multiaddr) in list {
                    debug!("mDNS discovered peer: {peer_id} at {multiaddr}");
                    self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                }
            }
            SwarmEvent::Behaviour(ChatBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source: _,
                message_id: _,
                message,
            })) => {
                let msg = String::from_utf8_lossy(&message.data);
                if let Ok(chat_msg) = serde_json::from_str::<ChatMessage>(&msg) {
                    if let Some(decrypted) = self.decrypt_message(&chat_msg, &message.source.unwrap()) {
                        let timestamp = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        self.messages.push(format!(
                            "[{}] {}: {}",
                            timestamp, chat_msg.username, decrypted
                        ));
                    }
                } else if let Ok(key_exchange) = serde_json::from_str::<KeyExchange>(&msg) {
                    self.handle_key_exchange(key_exchange, message.source.unwrap()).await?;
                }
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                info!("Connected to {peer_id}");
                self.messages.push(format!("🔗 Connected to peer"));
                
                // Send our public key for key exchange
                self.send_key_exchange(peer_id).await?;
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                info!("Connection to {peer_id} closed: {cause:?}");
                self.messages.push(format!("🔌 Peer disconnected"));
                self.shared_secrets.remove(&peer_id);
            }
            _ => {}
        }
        Ok(())
    }

    async fn send_key_exchange(&mut self, peer_id: PeerId) -> Result<()> {
        let key_exchange = KeyExchange {
            public_key: self.my_public.to_bytes(),
            peer_id: peer_id.to_string(),
        };
        
        let message = serde_json::to_string(&key_exchange)?;
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(self.topic.clone(), message.as_bytes())?;
        
        debug!("Sent key exchange to {peer_id}");
        Ok(())
    }

    async fn handle_key_exchange(&mut self, key_exchange: KeyExchange, from_peer: PeerId) -> Result<()> {
        let peer_public = PublicKey::from(key_exchange.public_key);
        let my_secret = EphemeralSecret::random_from_rng(&mut OsRng);
        let shared_secret = my_secret.diffie_hellman(&peer_public);
        
        self.shared_secrets.insert(from_peer, *shared_secret.as_bytes());
        self.messages.push(format!("🔑 Secure channel established"));
        
        debug!("Key exchange completed with {from_peer}");
        Ok(())
    }

    async fn send_message(&mut self) -> Result<()> {
        if self.input.trim().is_empty() {
            return Ok(());
        }

        let content = self.input.clone();
        self.input.clear();

        // For now, send to all peers (we'll improve this later)
        for (_peer_id, shared_secret) in &self.shared_secrets {
            if let Some(encrypted) = self.encrypt_message(&content, shared_secret) {
                let chat_msg = ChatMessage {
                    username: self.config.username.clone(),
                    content: String::new(), // Don't send plaintext
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    encrypted_content: encrypted.0,
                    nonce: encrypted.1,
                };

                let message = serde_json::to_string(&chat_msg)?;
                self.swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(self.topic.clone(), message.as_bytes())?;
            }
        }

        // Add to our own messages
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.messages.push(format!(
            "[{}] {}: {}",
            timestamp, self.config.username, content
        ));

        Ok(())
    }

    fn encrypt_message(&self, content: &str, shared_secret: &[u8; 32]) -> Option<(Vec<u8>, Vec<u8>)> {
        let key = Key::from_slice(shared_secret);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        
        if let Ok(ciphertext) = cipher.encrypt(&nonce, content.as_bytes()) {
            Some((ciphertext, nonce.to_vec()))
        } else {
            None
        }
    }

    fn decrypt_message(&self, msg: &ChatMessage, from_peer: &PeerId) -> Option<String> {
        if let Some(shared_secret) = self.shared_secrets.get(from_peer) {
            let key = Key::from_slice(shared_secret);
            let cipher = ChaCha20Poly1305::new(key);
            let nonce = Nonce::from_slice(&msg.nonce);
            
            if let Ok(plaintext) = cipher.decrypt(nonce, msg.encrypted_content.as_slice()) {
                String::from_utf8(plaintext).ok()
            } else {
                None
            }
        } else {
            None
        }
    }

    fn draw(&mut self) -> Result<()> {
        let messages = self.messages.clone();
        let input = self.input.clone();
        
        self.terminal.draw(move |f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([Constraint::Min(0), Constraint::Length(3)].as_ref())
                .split(f.size());

            // Messages area
            let message_items: Vec<ListItem> = messages
                .iter()
                .enumerate()
                .map(|(_, m)| {
                    ListItem::new(Line::from(Span::styled(m, Style::default().fg(Color::White))))
                })
                .collect();

            let messages_list = List::new(message_items)
                .block(Block::default().borders(Borders::ALL).title("Chat"));
            f.render_widget(messages_list, chunks[0]);

            // Input area
            let input_widget = Paragraph::new(input.as_str())
                .style(Style::default().fg(Color::Yellow))
                .block(Block::default().borders(Borders::ALL).title("Message"));
            f.render_widget(input_widget, chunks[1]);
        })?;
        Ok(())
    }
}