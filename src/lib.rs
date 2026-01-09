pub mod crypto;
pub mod network;
pub mod ui;

use anyhow::{Result, Context};
use crypto::{CryptoState, encrypt, decrypt};
use network::{ChatBehaviour, ChatMessage, KeyExchangeRequest, KeyExchangeResponse, P2PMessage};
use ui::{UiState, TerminalGuard};

use crossterm::event::{Event, KeyCode, KeyEventKind, EventStream};
use futures::prelude::*;
use libp2p::identify as libp2p_identify;
use libp2p::{
    gossipsub,
    mdns,
    noise,
    swarm::{SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{
    collections::HashMap,
    io,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{select, time};
use tracing::{debug, info};
use x25519_dalek::PublicKey;

pub struct Config {
    pub port: u16,
    pub enable_mdns: bool,
    pub connect_to: Option<String>,
    pub username: String,
}

pub struct ChatApp {
    swarm: Swarm<ChatBehaviour>,
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
    ui: UiState,
    config: Config,
    crypto: CryptoState,
    shared_secrets: HashMap<PeerId, [u8; 32]>,
    topic: gossipsub::IdentTopic,
    _guard: TerminalGuard,
}

impl ChatApp {
    pub async fn new(config: Config) -> Result<Self> {
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());
        info!("Local peer id: {local_peer_id}");

        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(1))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .build()
            .map_err(|e| anyhow::anyhow!(e))?;

        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(local_key.clone()),
            gossipsub_config,
        ).map_err(|e| anyhow::anyhow!(e))?;

        let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?;

        let identify = libp2p_identify::Behaviour::new(libp2p_identify::Config::new(
            "/p2p-chat/1.0.0".into(),
            local_key.public(),
        ));

        let behaviour = ChatBehaviour {
            gossipsub,
            mdns,
            identify,
        };

        let mut swarm = SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
            .with_behaviour(|_| behaviour)?
            .build();

        let listen_addr = format!("/ip4/0.0.0.0/tcp/{}", config.port);
        swarm.listen_on(listen_addr.parse()?)?;

        let topic = gossipsub::IdentTopic::new("chat");
        swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

        let guard = TerminalGuard::new()?;
        let backend = CrosstermBackend::new(io::stdout());
        let terminal = Terminal::new(backend)?;

        let mut app = ChatApp {
            swarm,
            terminal,
            ui: UiState::new(),
            config,
            crypto: CryptoState::new(),
            shared_secrets: HashMap::new(),
            topic,
            _guard: guard,
        };

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
        let mut events = EventStream::new();
        let mut tick_interval = time::interval(Duration::from_millis(100));
        
        loop {
            select! {
                maybe_event = events.next() => {
                    match maybe_event {
                        Some(Ok(Event::Key(key))) => {
                            if key.kind == KeyEventKind::Press {
                                match key.code {
                                    KeyCode::Char('q') => break,
                                    KeyCode::Enter => {
                                        self.send_message().await?;
                                    }
                                    KeyCode::Backspace => {
                                        self.ui.input.pop();
                                    }
                                    KeyCode::Char(c) => {
                                        self.ui.input.push(c);
                                    }
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }
                
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event).await?;
                }
                
                _ = tick_interval.tick() => {
                    self.ui.draw(&mut self.terminal)?;
                }
            }
        }
        Ok(())
    }

    async fn handle_swarm_event(&mut self, event: SwarmEvent<network::ChatBehaviourEvent>) -> Result<()> {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                self.ui.messages.push(format!("🎧 Listening on {address}"));
            }
            SwarmEvent::Behaviour(network::ChatBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                for (peer_id, multiaddr) in list {
                    debug!("mDNS discovered peer: {peer_id} at {multiaddr}");
                    self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                }
            }
            SwarmEvent::Behaviour(network::ChatBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                message,
                ..
            })) => {
                if let Ok(p2p_msg) = serde_json::from_slice::<P2PMessage>(&message.data) {
                    let source = message.source.context("Missing source peer id")?;
                    match p2p_msg {
                        P2PMessage::Chat(chat_msg) => {
                            if let Some(shared_secret) = self.shared_secrets.get(&source) {
                                if let Some(decrypted) = decrypt(&chat_msg.encrypted_content, &chat_msg.nonce, shared_secret) {
                                    let timestamp = chat_msg.timestamp;
                                    self.ui.messages.push(format!(
                                        "[{}] {}: {}",
                                        timestamp, chat_msg.username, decrypted
                                    ));
                                }
                            }
                        }
                        P2PMessage::KeyRequest(req) => {
                            let peer_public = PublicKey::from(req.public_key);
                            let shared_secret = self.crypto.generate_shared_secret(&peer_public);
                            self.shared_secrets.insert(source, shared_secret);
                            
                            // Send our response
                            let resp = P2PMessage::KeyResponse(KeyExchangeResponse {
                                public_key: self.crypto.my_public.to_bytes(),
                            });
                            let data = serde_json::to_vec(&resp)?;
                            self.swarm.behaviour_mut().gossipsub.publish(self.topic.clone(), data)?;
                            self.ui.messages.push(format!("🔑 Secure channel established with {source}"));
                        }
                        P2PMessage::KeyResponse(resp) => {
                            let peer_public = PublicKey::from(resp.public_key);
                            let shared_secret = self.crypto.generate_shared_secret(&peer_public);
                            self.shared_secrets.insert(source, shared_secret);
                            self.ui.messages.push(format!("🔑 Secure channel established with {source}"));
                        }
                    }
                }
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                self.ui.messages.push(format!("🔗 Connected to {peer_id}"));
                // Initiate key exchange
                let req = P2PMessage::KeyRequest(KeyExchangeRequest {
                    public_key: self.crypto.my_public.to_bytes(),
                });
                let data = serde_json::to_vec(&req)?;
                self.swarm.behaviour_mut().gossipsub.publish(self.topic.clone(), data)?;
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                self.ui.messages.push(format!("🔌 Peer {peer_id} disconnected"));
                self.shared_secrets.remove(&peer_id);
            }
            _ => {}
        }
        Ok(())
    }

    async fn send_message(&mut self) -> Result<()> {
        if self.ui.input.trim().is_empty() {
            return Ok(());
        }

        let content = self.ui.input.clone();
        self.ui.input.clear();

        for (_peer_id, shared_secret) in &self.shared_secrets {
            if let Some((encrypted, nonce)) = encrypt(&content, shared_secret) {
                let chat_msg = ChatMessage {
                    username: self.config.username.clone(),
                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                    encrypted_content: encrypted,
                    nonce: nonce,
                };

                let msg = P2PMessage::Chat(chat_msg);
                let data = serde_json::to_vec(&msg)?;
                self.swarm.behaviour_mut().gossipsub.publish(self.topic.clone(), data)?;
            }
        }

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        self.ui.messages.push(format!(
            "[{}] {}: {}",
            timestamp, self.config.username, content
        ));

        Ok(())
    }
}