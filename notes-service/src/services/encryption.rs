//! AES encryption helpers for optional note-at-rest encryption.

use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct EncryptionService {
    key: [u8; 32],
}

impl EncryptionService {
    pub fn from_env() -> Result<Self, String> {
        let key_material = std::env::var("NOTE_ENCRYPTION_KEY")
            .map_err(|_| "NOTE_ENCRYPTION_KEY is required".to_string())?;

        Self::from_passphrase(&key_material)
    }

    pub fn from_passphrase(passphrase: &str) -> Result<Self, String> {
        if passphrase.len() < 16 {
            return Err("Encryption key material must be at least 16 characters".to_string());
        }

        Ok(Self {
            key: derive_key(passphrase),
        })
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<String, String> {
        encrypt_with_key(&self.key, plaintext)
    }

    pub fn decrypt(&self, payload: &str) -> Result<String, String> {
        decrypt_with_key(&self.key, payload)
    }

    pub fn encrypt_with_passphrase(passphrase: &str, plaintext: &str) -> Result<String, String> {
        if passphrase.len() < 8 {
            return Err("Private key must be at least 8 characters".to_string());
        }
        let key = derive_key(passphrase);
        encrypt_with_key(&key, plaintext)
    }

    pub fn decrypt_with_passphrase(passphrase: &str, payload: &str) -> Result<String, String> {
        if passphrase.len() < 8 {
            return Err("Private key must be at least 8 characters".to_string());
        }
        let key = derive_key(passphrase);
        decrypt_with_key(&key, payload)
    }
}

fn derive_key(passphrase: &str) -> [u8; 32] {
    let digest = Sha256::digest(passphrase.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest[..32]);
    key
}

fn encrypt_with_key(key: &[u8; 32], plaintext: &str) -> Result<String, String> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| "failed to initialize cipher".to_string())?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| "encryption failed".to_string())?;

    let mut payload = Vec::with_capacity(12 + ciphertext.len());
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&ciphertext);

    Ok(STANDARD.encode(payload))
}

fn decrypt_with_key(key: &[u8; 32], payload: &str) -> Result<String, String> {
    let bytes = STANDARD
        .decode(payload)
        .map_err(|_| "invalid encrypted payload".to_string())?;

    if bytes.len() < 13 {
        return Err("encrypted payload is too short".to_string());
    }

    let (nonce_bytes, ciphertext) = bytes.split_at(12);
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| "failed to initialize cipher".to_string())?;

    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| "decryption failed".to_string())?;

    String::from_utf8(plaintext).map_err(|_| "decrypted text is not valid utf-8".to_string())
}

/// Basic XSS mitigation: keep notes as plain text by escaping HTML special characters.
pub fn sanitize_note_content(content: &str) -> String {
    content
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

#[cfg(test)]
mod tests {
    use super::{sanitize_note_content, EncryptionService};

    #[test]
    fn encryption_roundtrip() {
        let service = EncryptionService::from_passphrase("a-very-long-demo-key").unwrap();
        let encrypted = service.encrypt("secret text").unwrap();
        let decrypted = service.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, "secret text");
    }

    #[test]
    fn passphrase_encryption_roundtrip() {
        let encrypted = EncryptionService::encrypt_with_passphrase("manual123", "hidden").unwrap();
        let decrypted =
            EncryptionService::decrypt_with_passphrase("manual123", &encrypted).unwrap();
        assert_eq!(decrypted, "hidden");
    }

    #[test]
    fn sanitize_escapes_html_tags() {
        let sanitized = sanitize_note_content("<script>alert('x')</script>");
        assert!(!sanitized.contains("<script>"));
        assert!(sanitized.contains("&lt;script&gt;"));
    }
}
