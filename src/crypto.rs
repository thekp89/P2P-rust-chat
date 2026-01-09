use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use x25519_dalek::{EphemeralSecret, PublicKey};

pub struct CryptoState {
    pub my_public: PublicKey,
    pub ephemeral_secret: Option<EphemeralSecret>,
}

impl CryptoState {
    pub fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(&mut OsRng);
        let public = PublicKey::from(&secret);
        Self {
            my_public: public,
            ephemeral_secret: Some(secret),
        }
    }

    pub fn generate_shared_secret(&mut self, peer_public: &PublicKey) -> [u8; 32] {
        let secret = self.ephemeral_secret.take().expect("Ephemeral secret must be present");
        let shared = secret.diffie_hellman(peer_public);
        *shared.as_bytes()
    }
}

pub fn encrypt(content: &str, shared_secret: &[u8; 32]) -> Option<(Vec<u8>, Vec<u8>)> {
    let key = Key::from_slice(shared_secret);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    
    if let Ok(ciphertext) = cipher.encrypt(&nonce, content.as_bytes()) {
        Some((ciphertext, nonce.to_vec()))
    } else {
        None
    }
}

pub fn decrypt(encrypted_content: &[u8], nonce_bytes: &[u8], shared_secret: &[u8; 32]) -> Option<String> {
    let key = Key::from_slice(shared_secret);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    if let Ok(plaintext) = cipher.decrypt(nonce, encrypted_content) {
        String::from_utf8(plaintext).ok()
    } else {
        None
    }
}
