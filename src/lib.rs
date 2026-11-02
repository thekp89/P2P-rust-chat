pub mod crypto;
pub mod network;
pub mod ui;

use anyhow::Result;
use crypto::{CryptoState, encrypt, encrypt_bytes, decrypt, decrypt_bytes, generate_message_key};
use network::{
    ChatBehaviour, ChatMessage, EncryptedKeyForPeer, KeyExchangeRequest, KeyExchangeResponse,
    P2PMessage,
};
use ui::{TerminalGuard, UiState};

use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind, KeyModifiers};
use futures::prelude::*;
use libp2p::identify as libp2p_identify;
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::{
    gossipsub, mdns, noise,
    swarm::SwarmEvent,
    tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{
    collections::HashMap,
    io,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{select, time};
use tracing::{debug, info, warn};
use x25519_dalek::PublicKey;

pub struct Config {
    pub port: u16,
    pub enable_mdns: bool,
    pub connect_to: Option<String>,
    pub username: String,
}

pub fn parse_peer_addr(addr_str: &str) -> Result<Multiaddr> {
    let trimmed = addr_str.trim();
    if trimmed.starts_with('/') {
        trimmed.parse().map_err(Into::into)
    } else {
        let parts: Vec<&str> = trimmed.split(':').collect();
        if parts.len() == 2 {
            format!("/ip4/{}/tcp/{}", parts[0], parts[1]).parse().map_err(Into::into)
        } else {
            anyhow::bail!("Invalid address format. Expected IP:PORT or /ip4/.../tcp/...")
        }
    }
}

pub struct ChatApp {
    swarm: Swarm<ChatBehaviour>,
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
    ui: UiState,
    config: Config,
    local_key: libp2p::identity::Keypair,
    local_peer_id: PeerId,
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
        )
        .map_err(|e| anyhow::anyhow!(e))?;

        // Toggle mDNS discovery based on configuration
        let mdns = if config.enable_mdns {
            let mdns_behaviour = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?;
            Toggle::from(Some(mdns_behaviour))
        } else {
            Toggle::from(None)
        };

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

        let mut ui = UiState::new();
        ui.local_peer_id = local_peer_id.to_string();
        ui.local_username = config.username.clone();

        let mut app = ChatApp {
            swarm,
            terminal,
            ui,
            config,
            local_key,
            local_peer_id,
            crypto: CryptoState::new(),
            shared_secrets: HashMap::new(),
            topic,
            _guard: guard,
        };

        app.ui.add_system(format!(
            "Welcome to P2P Encrypted Chat, {}! Type /help for commands.",
            app.config.username
        ));
        app.ui.add_system(format!("Local Peer ID: {}", app.local_peer_id));

        if let Some(addr) = &app.config.connect_to {
            match parse_peer_addr(addr) {
                Ok(multiaddr) => {
                    app.ui.add_system(format!("Dialing configured peer: {multiaddr}..."));
                    if let Err(e) = app.swarm.dial(multiaddr) {
                        app.ui.add_error(format!("Dial error: {e}"));
                    }
                }
                Err(e) => {
                    app.ui.add_error(format!("Invalid connect address '{addr}': {e}"));
                }
            }
        }

        Ok(app)
    }

    pub async fn run(&mut self) -> Result<()> {
        let mut events = EventStream::new();
        let mut tick_interval = time::interval(Duration::from_millis(50));

        loop {
            select! {
                maybe_event = events.next() => {
                    if let Some(Ok(Event::Key(key))) = maybe_event {
                        if key.kind == KeyEventKind::Press {
                            // Check for exit shortcuts: Esc or Ctrl+C
                            if key.code == KeyCode::Esc || (key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c')) {
                                break;
                            }

                            match key.code {
                                KeyCode::Enter => {
                                    if self.handle_submit().await? {
                                        break; // user executed /quit or /exit
                                    }
                                }
                                KeyCode::Backspace => {
                                    self.ui.delete_char_before_cursor();
                                }
                                KeyCode::Delete => {
                                    self.ui.delete_char_at_cursor();
                                }
                                KeyCode::Left => {
                                    self.ui.move_cursor_left();
                                }
                                KeyCode::Right => {
                                    self.ui.move_cursor_right();
                                }
                                KeyCode::Home => {
                                    self.ui.move_cursor_home();
                                }
                                KeyCode::End => {
                                    self.ui.move_cursor_end();
                                    self.ui.scroll_to_bottom();
                                }
                                KeyCode::Up | KeyCode::PageUp => {
                                    self.ui.scroll_up(3);
                                }
                                KeyCode::Down | KeyCode::PageDown => {
                                    self.ui.scroll_down(3);
                                }
                                KeyCode::Char(c) => {
                                    // Properly inserts any character, including 'q', into the text buffer
                                    self.ui.insert_char(c);
                                }
                                _ => {}
                            }
                        }
                    }
                }

                event = self.swarm.select_next_some() => {
                    if let Err(e) = self.handle_swarm_event(event).await {
                        warn!("Error handling swarm event: {e}");
                    }
                }

                _ = tick_interval.tick() => {
                    self.ui.draw(&mut self.terminal)?;
                }
            }
        }
        Ok(())
    }

    /// Handles Enter key submission: processes slash commands or sends chat message.
    /// Returns true if app should exit.
    async fn handle_submit(&mut self) -> Result<bool> {
        let text = self.ui.input.trim().to_string();
        if text.is_empty() {
            return Ok(false);
        }

        self.ui.input.clear();
        self.ui.cursor_pos = 0;

        if text.starts_with('/') {
            let mut parts = text.split_whitespace();
            let cmd = parts.next().unwrap_or("");
            match cmd {
                "/quit" | "/exit" => {
                    return Ok(true);
                }
                "/help" => {
                    self.ui.add_system("--- Available Commands ---".into());
                    self.ui.add_system("/help             - Show this help message".into());
                    self.ui.add_system("/peers            - List connected peers and encryption status".into());
                    self.ui.add_system("/connect <addr>   - Dial peer (IP:PORT or Multiaddr)".into());
                    self.ui.add_system("/clear            - Clear chat messages".into());
                    self.ui.add_system("/quit (or Esc)    - Exit the application".into());
                    self.ui.add_system("PageUp / PageDown - Scroll chat history".into());
                }
                "/clear" => {
                    self.ui.messages.clear();
                    self.ui.add_system("Chat history cleared.".into());
                }
                "/peers" => {
                    let peer_lines: Vec<String> = self.ui.peers.iter().map(|p| {
                        let status = if p.is_secure { "🔒 Secured (E2EE)" } else { "⏳ Key exchange pending" };
                        let name = p.username.as_deref().unwrap_or("unknown");
                        format!("• {name} ({}) - {status}", p.peer_id)
                    }).collect();

                    self.ui.add_system(format!("--- Connected Peers ({}) ---", peer_lines.len()));
                    if peer_lines.is_empty() {
                        self.ui.add_system("No peers connected.".into());
                    } else {
                        for line in peer_lines {
                            self.ui.add_system(line);
                        }
                    }
                }
                "/connect" => {
                    if let Some(target) = parts.next() {
                        match parse_peer_addr(target) {
                            Ok(multiaddr) => {
                                self.ui.add_system(format!("Dialing {multiaddr}..."));
                                if let Err(e) = self.swarm.dial(multiaddr) {
                                    self.ui.add_error(format!("Dial failed: {e}"));
                                }
                            }
                            Err(e) => {
                                self.ui.add_error(format!("Address format error: {e}"));
                            }
                        }
                    } else {
                        self.ui.add_error("Usage: /connect <IP:PORT or Multiaddr>".into());
                    }
                }
                unknown => {
                    self.ui.add_error(format!("Unknown command '{unknown}'. Type /help for assistance."));
                }
            }
            return Ok(false);
        }

        // Send normal chat message
        self.send_chat_message(&text).await?;
        Ok(false)
    }

    async fn handle_swarm_event(
        &mut self,
        event: SwarmEvent<network::ChatBehaviourEvent>,
    ) -> Result<()> {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                let addr_str = address.to_string();
                self.ui.listen_addr = Some(addr_str.clone());
                self.ui.add_system(format!("🎧 Listening on {addr_str}"));
            }

            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                self.ui.upsert_peer(peer_id.to_string(), None, false);
                self.ui.add_system(format!("🔗 Connected to peer {peer_id}"));

                // Initiate authenticated key exchange with the newly connected peer
                if let Err(e) = self.send_key_request(&peer_id) {
                    self.ui.add_error(format!("Failed to initiate key exchange with {peer_id}: {e}"));
                }
            }

            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                self.shared_secrets.remove(&peer_id);
                self.ui.remove_peer(&peer_id.to_string());
                self.ui.add_system(format!("🔌 Peer {peer_id} disconnected"));
            }

            SwarmEvent::Behaviour(network::ChatBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                for (peer_id, multiaddr) in list {
                    debug!("mDNS discovered peer: {peer_id} at {multiaddr}");
                    self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                }
            }

            SwarmEvent::Behaviour(network::ChatBehaviourEvent::Identify(
                libp2p_identify::Event::Received { peer_id, info },
            )) => {
                debug!("Identify received from {peer_id}: agent={}", info.agent_version);
                for addr in info.listen_addrs {
                    self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                    debug!("Peer {peer_id} listen addr: {addr}");
                }
            }

            SwarmEvent::Behaviour(network::ChatBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                message,
                ..
            })) => {
                if let Ok(p2p_msg) = serde_json::from_slice::<P2PMessage>(&message.data) {
                    let source = match message.source {
                        Some(s) => s,
                        None => return Ok(()),
                    };

                    match p2p_msg {
                        P2PMessage::Chat(chat_msg) => {
                            self.handle_incoming_chat(source, chat_msg);
                        }

                        P2PMessage::KeyRequest(req) => {
                            // Only respond if this request was targeted at us
                            if req.recipient == self.local_peer_id.to_string() {
                                if let Err(e) = self.handle_key_request(source, req) {
                                    self.ui.add_error(format!("Key exchange request error from {source}: {e}"));
                                }
                            }
                        }

                        P2PMessage::KeyResponse(resp) => {
                            // Only process if this response was targeted at us
                            if resp.recipient == self.local_peer_id.to_string() {
                                if let Err(e) = self.handle_key_response(source, resp) {
                                    self.ui.add_error(format!("Key exchange response error from {source}: {e}"));
                                }
                            }
                        }
                    }
                }
            }

            _ => {}
        }
        Ok(())
    }

    fn send_key_request(&mut self, peer_id: &PeerId) -> Result<()> {
        let x25519_bytes = self.crypto.my_public.to_bytes();
        let signature = self
            .local_key
            .sign(&x25519_bytes)
            .map_err(|e| anyhow::anyhow!("Signing error: {e}"))?;
        let ed25519_public = self.local_key.public().encode_protobuf();

        let req = P2PMessage::KeyRequest(KeyExchangeRequest {
            sender: self.local_peer_id.to_string(),
            recipient: peer_id.to_string(),
            x25519_public: x25519_bytes,
            ed25519_public,
            signature,
        });

        let data = serde_json::to_vec(&req)?;
        let _ = self.swarm.behaviour_mut().gossipsub.publish(self.topic.clone(), data);
        Ok(())
    }

    fn handle_key_request(&mut self, source: PeerId, req: KeyExchangeRequest) -> Result<()> {
        // Authenticate the peer identity
        let ed_public = libp2p::identity::PublicKey::try_decode_protobuf(&req.ed25519_public)
            .map_err(|e| anyhow::anyhow!("Invalid Ed25519 public key format: {e}"))?;

        if PeerId::from(&ed_public) != source {
            anyhow::bail!("Ed25519 public key does not match message source PeerId");
        }

        if !ed_public.verify(&req.x25519_public, &req.signature) {
            anyhow::bail!("X25519 public key signature verification failed! Possible MITM attack.");
        }

        let peer_x25519_public = PublicKey::from(req.x25519_public);
        let shared_secret = self.crypto.generate_shared_secret(&peer_x25519_public);
        self.shared_secrets.insert(source, shared_secret);
        self.ui.upsert_peer(source.to_string(), None, true);
        self.ui.add_success(format!("Secure E2EE established with {source}"));

        // Send KeyResponse back to requester
        let my_x25519_bytes = self.crypto.my_public.to_bytes();
        let signature = self
            .local_key
            .sign(&my_x25519_bytes)
            .map_err(|e| anyhow::anyhow!("Signing error: {e}"))?;
        let ed25519_public = self.local_key.public().encode_protobuf();

        let resp = P2PMessage::KeyResponse(KeyExchangeResponse {
            sender: self.local_peer_id.to_string(),
            recipient: source.to_string(),
            x25519_public: my_x25519_bytes,
            ed25519_public,
            signature,
        });

        let data = serde_json::to_vec(&resp)?;
        let _ = self.swarm.behaviour_mut().gossipsub.publish(self.topic.clone(), data);
        Ok(())
    }

    fn handle_key_response(&mut self, source: PeerId, resp: KeyExchangeResponse) -> Result<()> {
        // Authenticate the peer identity
        let ed_public = libp2p::identity::PublicKey::try_decode_protobuf(&resp.ed25519_public)
            .map_err(|e| anyhow::anyhow!("Invalid Ed25519 public key format: {e}"))?;

        if PeerId::from(&ed_public) != source {
            anyhow::bail!("Ed25519 public key does not match message source PeerId");
        }

        if !ed_public.verify(&resp.x25519_public, &resp.signature) {
            anyhow::bail!("X25519 public key signature verification failed! Possible MITM attack.");
        }

        let peer_x25519_public = PublicKey::from(resp.x25519_public);
        let shared_secret = self.crypto.generate_shared_secret(&peer_x25519_public);
        self.shared_secrets.insert(source, shared_secret);
        self.ui.upsert_peer(source.to_string(), None, true);
        self.ui.add_success(format!("Secure E2EE established with {source}"));
        Ok(())
    }

    fn handle_incoming_chat(&mut self, source: PeerId, chat_msg: ChatMessage) {
        let is_known = self.shared_secrets.contains_key(&source);
        self.ui.upsert_peer(source.to_string(), Some(chat_msg.username.clone()), is_known);

        // Check if our PeerId is among the authorized recipients
        let my_id_str = self.local_peer_id.to_string();
        if let Some(key_entry) = chat_msg.keys.iter().find(|k| k.recipient == my_id_str) {
            if let Some(shared_secret) = self.shared_secrets.get(&source) {
                // 1. Decrypt the one-time message key
                if let Some(msg_key_bytes) = decrypt_bytes(&key_entry.encrypted_key, &key_entry.nonce, shared_secret) {
                    if msg_key_bytes.len() == 32 {
                        let mut msg_key = [0u8; 32];
                        msg_key.copy_from_slice(&msg_key_bytes);

                        // 2. Decrypt the actual chat content
                        if let Some(decrypted_text) = decrypt(&chat_msg.encrypted_content, &chat_msg.nonce, &msg_key) {
                            self.ui.add_chat(chat_msg.username, decrypted_text, false);
                            return;
                        }
                    }
                }
            }
        }

        // If we get here, the message wasn't addressed to us or decryption failed
        debug!("Received broadcast message not decryptable by this node from {source}");
    }

    async fn send_chat_message(&mut self, content: &str) -> Result<()> {
        if self.shared_secrets.is_empty() {
            self.ui.add_error("Cannot send: No peers with established secure keys are connected.".into());
            return Ok(());
        }

        // Generate a random one-time symmetric message key
        let message_key = generate_message_key();

        // Encrypt the chat content with this one-time message key
        let (encrypted_content, nonce) = match encrypt(content, &message_key) {
            Some(pair) => pair,
            None => {
                self.ui.add_error("Failed to encrypt message.".into());
                return Ok(());
            }
        };

        // Encrypt the message key for every connected peer with an established shared secret
        let mut keys = Vec::new();
        for (peer_id, shared_secret) in &self.shared_secrets {
            if let Some((enc_key, key_nonce)) = encrypt_bytes(&message_key, shared_secret) {
                keys.push(EncryptedKeyForPeer {
                    recipient: peer_id.to_string(),
                    encrypted_key: enc_key,
                    nonce: key_nonce,
                });
            }
        }

        let now_epoch = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
        let chat_msg = ChatMessage {
            id: format!("{}-{}", self.local_peer_id, now_epoch),
            username: self.config.username.clone(),
            timestamp: (now_epoch / 1000) as u64,
            encrypted_content,
            nonce,
            keys,
        };

        let msg = P2PMessage::Chat(chat_msg);
        let data = serde_json::to_vec(&msg)?;

        match self.swarm.behaviour_mut().gossipsub.publish(self.topic.clone(), data) {
            Ok(_) => {
                // Add message to local UI
                self.ui.add_chat(self.config.username.clone(), content.to_string(), true);
            }
            Err(e) => {
                self.ui.add_error(format!("Failed to broadcast message: {e}"));
            }
        }

        Ok(())
    }
}
