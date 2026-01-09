use libp2p::swarm::NetworkBehaviour;
use serde::{Deserialize, Serialize};

#[derive(NetworkBehaviour)]
pub struct ChatBehaviour {
    pub gossipsub: libp2p::gossipsub::Behaviour,
    pub mdns: libp2p::mdns::tokio::Behaviour,
    pub identify: libp2p::identify::Behaviour,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChatMessage {
    pub username: String,
    pub timestamp: u64,
    pub encrypted_content: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeyExchangeRequest {
    pub public_key: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeyExchangeResponse {
    pub public_key: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum P2PMessage {
    Chat(ChatMessage),
    KeyRequest(KeyExchangeRequest),
    KeyResponse(KeyExchangeResponse),
}
