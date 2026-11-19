//! Plaintext-at-rest encryption for cracked passwords (AES-256-GCM).
//! Stored as `nonce(12) || ciphertext` in the `hashes.plain` bytea column.
use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use sha2::{Digest, Sha256};

use crate::config::Config;

#[derive(Clone)]
pub struct Cipher {
    key: Key<Aes256Gcm>,
}

impl Cipher {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            key: *Key::<Aes256Gcm>::from_slice(&bytes),
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new(&self.key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let mut out = nonce.to_vec();
        if let Ok(ct) = cipher.encrypt(&nonce, plaintext) {
            out.extend(ct);
        }
        out
    }

    pub fn decrypt(&self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 12 {
            return None;
        }
        let (nonce, ct) = data.split_at(12);
        let cipher = Aes256Gcm::new(&self.key);
        cipher.decrypt(Nonce::from_slice(nonce), ct).ok()
    }
}

/// Load the key from the configured hex key file (AD-supplied or
/// installer-generated); otherwise derive it from the JWT secret for dev.
pub fn key_from_config(cfg: &Config) -> [u8; 32] {
    if let Some(path) = &cfg.crypto.plaintext_key_file {
        if let Ok(text) = std::fs::read_to_string(path) {
            if let Ok(bytes) = hex::decode(text.trim()) {
                if bytes.len() == 32 {
                    let mut k = [0u8; 32];
                    k.copy_from_slice(&bytes);
                    return k;
                }
            }
        }
    }
    let digest = Sha256::digest(cfg.auth.jwt_secret.as_bytes());
    let mut k = [0u8; 32];
    k.copy_from_slice(&digest);
    k
}
