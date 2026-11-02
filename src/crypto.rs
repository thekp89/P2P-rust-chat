use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

pub struct CryptoState {
    pub my_public: PublicKey,
    secret: StaticSecret,
}

impl CryptoState {
    pub fn new() -> Self {
        let secret = StaticSecret::random_from_rng(&mut OsRng);
        let public = PublicKey::from(&secret);
        Self {
            my_public: public,
            secret,
        }
    }

    /// Derives a shared secret for a given peer public key.
    /// Can be called multiple times without consuming state.
    pub fn generate_shared_secret(&self, peer_public: &PublicKey) -> [u8; 32] {
        let shared = self.secret.diffie_hellman(peer_public);
        *shared.as_bytes()
    }
}

/// Generates a fresh random 256-bit symmetric key for a single message.
pub fn generate_message_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Encrypts raw bytes using ChaCha20Poly1305 with a random 96-bit nonce.
pub fn encrypt_bytes(data: &[u8], key_bytes: &[u8; 32]) -> Option<(Vec<u8>, Vec<u8>)> {
    let key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

    if let Ok(ciphertext) = cipher.encrypt(&nonce, data) {
        Some((ciphertext, nonce.to_vec()))
    } else {
        None
    }
}

/// Decrypts raw bytes using ChaCha20Poly1305.
pub fn decrypt_bytes(encrypted_data: &[u8], nonce_bytes: &[u8], key_bytes: &[u8; 32]) -> Option<Vec<u8>> {
    if nonce_bytes.len() != 12 {
        return None;
    }
    let key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher.decrypt(nonce, encrypted_data).ok()
}

/// Encrypts UTF-8 text using ChaCha20Poly1305.
pub fn encrypt(content: &str, shared_secret: &[u8; 32]) -> Option<(Vec<u8>, Vec<u8>)> {
    encrypt_bytes(content.as_bytes(), shared_secret)
}

/// Decrypts UTF-8 text using ChaCha20Poly1305.
pub fn decrypt(encrypted_content: &[u8], nonce_bytes: &[u8], shared_secret: &[u8; 32]) -> Option<String> {
    let bytes = decrypt_bytes(encrypted_content, nonce_bytes, shared_secret)?;
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diffie_hellman_shared_secret() {
        let alice = CryptoState::new();
        let bob = CryptoState::new();

        let secret_alice = alice.generate_shared_secret(&bob.my_public);
        let secret_bob = bob.generate_shared_secret(&alice.my_public);

        assert_eq!(secret_alice, secret_bob);
        assert_ne!(secret_alice, [0u8; 32]);
    }

    #[test]
    fn test_multiple_handshakes_without_panic() {
        let alice = CryptoState::new();
        let bob = CryptoState::new();
        let charlie = CryptoState::new();

        let s1 = alice.generate_shared_secret(&bob.my_public);
        let s2 = alice.generate_shared_secret(&charlie.my_public);
        let s3 = alice.generate_shared_secret(&bob.my_public);

        assert_eq!(s1, s3);
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = generate_message_key();
        let plaintext = "Hello from encrypted P2P!";

        let (ciphertext, nonce) = encrypt(plaintext, &key).expect("Encryption failed");
        assert_ne!(ciphertext, plaintext.as_bytes());

        let decrypted = decrypt(&ciphertext, &nonce, &key).expect("Decryption failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_with_tampered_ciphertext() {
        let key = generate_message_key();
        let (mut ciphertext, nonce) = encrypt("Sensitive data", &key).unwrap();
        ciphertext[0] ^= 0xFF; // tamper

        let result = decrypt(&ciphertext, &nonce, &key);
        assert!(result.is_none());
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let key1 = generate_message_key();
        let key2 = generate_message_key();
        let (ciphertext, nonce) = encrypt("Hello world", &key1).unwrap();

        let result = decrypt(&ciphertext, &nonce, &key2);
        assert!(result.is_none());
    }
}
