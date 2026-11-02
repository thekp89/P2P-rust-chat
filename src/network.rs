use libp2p::swarm::NetworkBehaviour;
use libp2p::swarm::behaviour::toggle::Toggle;
use serde::{Deserialize, Serialize};

#[derive(NetworkBehaviour)]
pub struct ChatBehaviour {
    pub gossipsub: libp2p::gossipsub::Behaviour,
    pub mdns: Toggle<libp2p::mdns::tokio::Behaviour>,
    pub identify: libp2p::identify::Behaviour,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct EncryptedKeyForPeer {
    /// Target peer ID (as string representation)
    pub recipient: String,
    /// Message key encrypted using recipient's pairwise shared secret
    pub encrypted_key: Vec<u8>,
    /// Nonce used to encrypt the message key
    pub nonce: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ChatMessage {
    /// Unique identifier for deduplication
    pub id: String,
    pub username: String,
    pub timestamp: u64,
    /// Main payload encrypted with a random one-time message key
    pub encrypted_content: Vec<u8>,
    pub nonce: Vec<u8>,
    /// The one-time message key encrypted separately for each authorized recipient
    pub keys: Vec<EncryptedKeyForPeer>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct KeyExchangeRequest {
    pub sender: String,
    pub recipient: String,
    pub x25519_public: [u8; 32],
    pub ed25519_public: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct KeyExchangeResponse {
    pub sender: String,
    pub recipient: String,
    pub x25519_public: [u8; 32],
    pub ed25519_public: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum P2PMessage {
    Chat(ChatMessage),
    KeyRequest(KeyExchangeRequest),
    KeyResponse(KeyExchangeResponse),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_deserialize_chat_message() {
        let msg = P2PMessage::Chat(ChatMessage {
            id: "msg-12345".into(),
            username: "Alice".into(),
            timestamp: 1700000000,
            encrypted_content: vec![1, 2, 3, 4],
            nonce: vec![5, 6, 7],
            keys: vec![EncryptedKeyForPeer {
                recipient: "12D3KooWPeer1".into(),
                encrypted_key: vec![10, 20, 30],
                nonce: vec![40, 50],
            }],
        });

        let serialized = serde_json::to_vec(&msg).expect("Serialize failed");
        let deserialized: P2PMessage = serde_json::from_slice(&serialized).expect("Deserialize failed");

        assert_eq!(msg, deserialized);
    }

    #[test]
    fn test_serialize_deserialize_key_exchange() {
        let req = P2PMessage::KeyRequest(KeyExchangeRequest {
            sender: "PeerA".into(),
            recipient: "PeerB".into(),
            x25519_public: [42u8; 32],
            ed25519_public: vec![1, 2, 3],
            signature: vec![9, 8, 7],
        });

        let serialized = serde_json::to_vec(&req).unwrap();
        let deserialized: P2PMessage = serde_json::from_slice(&serialized).unwrap();
        assert_eq!(req, deserialized);
    }
}
