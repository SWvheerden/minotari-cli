use anyhow::anyhow;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, Generate, KeyInit},
};
use phc::Salt;
use tari_common_types::types::{CompressedPublicKey, PrivateKey};
use tari_utilities::byte_array::ByteArray;

fn derive_key(password: &str, salt: &[u8]) -> Result<Key, anyhow::Error> {
    let params = Params::default();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key_bytes = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key_bytes)
        .map_err(|e| anyhow!("Key derivation failed: {}", e))?;
    Ok(Key::from(key_bytes))
}

#[derive(Debug, Clone)]
pub struct FullEncryptedData<S = Vec<u8>> {
    pub ciphertext: S,
    pub nonce: S,
    pub salt_bytes: S,
}

/// An XChaCha20-Poly1305 cipher keyed by an Argon2id-derived password, together with the salt used
/// to derive it.
///
/// Use this when several values have to be encrypted under the same password. Every call to
/// [`PasswordCipher::encrypt`] draws a fresh nonce, so a caller cannot accidentally reuse one.
/// Reusing a nonce across two messages under the same key is fatal for a stream cipher: the two
/// ciphertexts share a keystream, so anyone who knows (or can guess) one plaintext recovers the
/// other, and the Poly1305 one-time key leaks along with it.
pub struct PasswordCipher {
    cipher: XChaCha20Poly1305,
    salt_bytes: Vec<u8>,
}

impl PasswordCipher {
    /// Derives a cipher from `password` using Argon2id over a freshly generated salt.
    pub fn new(password: &str) -> Result<Self, anyhow::Error> {
        let salt = Salt::generate();
        let key = derive_key(password, salt.as_ref())?;

        Ok(Self {
            cipher: XChaCha20Poly1305::new(&key),
            salt_bytes: salt.as_ref().to_vec(),
        })
    }

    /// The salt this cipher's key was derived from. Store it alongside the ciphertext; decryption
    /// needs it to re-derive the key.
    pub fn salt(&self) -> &[u8] {
        &self.salt_bytes
    }

    /// Encrypts `data` under a freshly generated nonce, returning `(ciphertext, nonce)`.
    pub fn encrypt(&self, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), anyhow::Error> {
        let nonce = XNonce::generate();

        let ciphertext = self
            .cipher
            .encrypt(&nonce, data)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        Ok((ciphertext, nonce.to_vec()))
    }
}

/// Encrypts data using XChaCha20-Poly1305.
pub fn encrypt_data(data: &[u8], password: &str) -> Result<FullEncryptedData, anyhow::Error> {
    let cipher = PasswordCipher::new(password)?;
    let (ciphertext, nonce) = cipher.encrypt(data)?;

    Ok(FullEncryptedData {
        ciphertext,
        nonce,
        salt_bytes: cipher.salt().to_vec(),
    })
}

/// Decrypts data using XChaCha20-Poly1305.
pub fn decrypt_data<S: AsRef<[u8]>>(data: &FullEncryptedData<S>, password: &str) -> Result<Vec<u8>, anyhow::Error> {
    let salt = data.salt_bytes.as_ref();
    let key = derive_key(password, salt)?;
    let cipher = XChaCha20Poly1305::new(&key);

    let nonce_slice = data.nonce.as_ref();
    let nonce_bytes: &[u8; 24] = nonce_slice.try_into().map_err(|_| anyhow!("Nonce must be 24 bytes"))?;

    let xnonce = XNonce::from(*nonce_bytes);

    let plaintext = cipher
        .decrypt(&xnonce, data.ciphertext.as_ref())
        .map_err(|e| anyhow!("Decryption failed: {}", e))?;

    Ok(plaintext)
}

/// Decodes a hex string into a [`CompressedPublicKey`].
pub fn parse_public_key_hex(s: &str) -> Result<CompressedPublicKey, anyhow::Error> {
    let bytes = hex::decode(s).map_err(|e| anyhow!("Invalid public key hex: {}", e))?;
    CompressedPublicKey::from_canonical_bytes(&bytes).map_err(|e| anyhow!("Invalid public key: {}", e))
}

/// Decodes a hex string into a [`PrivateKey`].
pub fn parse_private_key_hex(s: &str) -> Result<PrivateKey, anyhow::Error> {
    let bytes = hex::decode(s).map_err(|e| anyhow!("Invalid private key hex: {}", e))?;
    PrivateKey::from_canonical_bytes(&bytes).map_err(|e| anyhow!("Invalid private key: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_cipher_never_reuses_a_nonce() {
        let cipher = PasswordCipher::new("correct horse battery staple").unwrap();

        let (first_ciphertext, first_nonce) = cipher.encrypt(b"same plaintext").unwrap();
        let (second_ciphertext, second_nonce) = cipher.encrypt(b"same plaintext").unwrap();

        assert_ne!(first_nonce, second_nonce, "Nonce was reused across encryptions");
        assert_ne!(
            first_ciphertext, second_ciphertext,
            "Identical plaintexts produced identical ciphertexts"
        );
    }

    #[test]
    fn public_plaintext_does_not_leak_a_secret_encrypted_under_the_same_key() {
        // The wallet file stores the (public) spend key next to the (secret) view key. With a
        // shared nonce, xoring the two ciphertexts cancels the keystream and the known public
        // value hands over the secret one. Distinct nonces must break that.
        let cipher = PasswordCipher::new("password").unwrap();

        let secret = [0xABu8; 32];
        let public = [0xCDu8; 32];

        let (secret_ciphertext, _) = cipher.encrypt(&secret).unwrap();
        let (public_ciphertext, _) = cipher.encrypt(&public).unwrap();

        let recovered: Vec<u8> = secret_ciphertext
            .iter()
            .zip(public_ciphertext.iter())
            .zip(public.iter())
            .map(|((s, p), known)| s ^ p ^ known)
            .take(secret.len())
            .collect();

        assert_ne!(
            recovered.as_slice(),
            secret.as_slice(),
            "Secret recovered from public plaintext"
        );
    }

    #[test]
    fn encrypt_data_round_trips() {
        let encrypted = encrypt_data(b"seed words go here", "hunter2").unwrap();

        assert_eq!(encrypted.nonce.len(), 24);
        assert!(!encrypted.salt_bytes.is_empty());
        assert_eq!(decrypt_data(&encrypted, "hunter2").unwrap(), b"seed words go here");
        assert!(decrypt_data(&encrypted, "wrong password").is_err());
    }

    #[test]
    fn short_and_long_passwords_are_accepted_and_distinct() {
        // The key is derived, not the raw password bytes, so length is irrelevant and a padded
        // short password is not equivalent to any other.
        let short = encrypt_data(b"data", "a").unwrap();
        assert_eq!(decrypt_data(&short, "a").unwrap(), b"data");
        assert!(decrypt_data(&short, "a\0\0\0").is_err());

        let long = encrypt_data(b"data", &"z".repeat(200)).unwrap();
        assert_eq!(decrypt_data(&long, &"z".repeat(200)).unwrap(), b"data");
        assert!(decrypt_data(&long, &"z".repeat(32)).is_err());
    }
}
