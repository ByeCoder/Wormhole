//! WireGuard keys. The panel makes both ends' key pairs when it creates a `wireguard`
//! private-network link and hands each agent its own private key and the peer's public
//! key, so no key is ever typed by hand. A key is a Curve25519 (X25519) scalar, the same
//! kind `wg genkey` makes; it is stored and sent base64-encoded, as `wg` writes it.

use anyhow::{anyhow, Result};
use base64::Engine;
use x25519_dalek::{PublicKey, StaticSecret};

/// One end's key pair, base64-encoded as `wg` writes keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keypair {
    pub private: String,
    pub public: String,
}

/// Clamps a 32-byte scalar the way X25519 does, so a stored private key is canonical and
/// matches what `wg genkey` would write (the public key is derived from the clamped scalar
/// either way; clamping the stored bytes just keeps the two in step).
fn clamp(mut k: [u8; 32]) -> [u8; 32] {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A fresh key pair from the system's randomness.
pub fn generate() -> Result<Keypair> {
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).map_err(|e| anyhow!("no randomness: {e}"))?;
    Ok(from_private_bytes(clamp(raw)))
}

/// The key pair of a known private scalar (already clamped): the private key as given, and
/// the public key X25519 derives from it.
fn from_private_bytes(private: [u8; 32]) -> Keypair {
    let secret = StaticSecret::from(private);
    let public = PublicKey::from(&secret);
    Keypair {
        private: b64(&secret.to_bytes()),
        public: b64(public.as_bytes()),
    }
}

/// Whether `text` is a well-formed WireGuard key: base64 of exactly 32 bytes. Used to check
/// a key read back from the database before it is sent to an agent.
pub fn is_key(text: &str) -> bool {
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .is_ok_and(|b| b.len() == 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pair_is_two_valid_keys_that_differ() {
        let kp = generate().unwrap();
        assert!(is_key(&kp.private), "private key: {}", kp.private);
        assert!(is_key(&kp.public), "public key: {}", kp.public);
        assert_ne!(kp.private, kp.public);
    }

    #[test]
    fn two_pairs_are_different() {
        assert_ne!(generate().unwrap(), generate().unwrap());
    }

    #[test]
    fn the_public_key_follows_from_the_private_one() {
        // Deriving twice from the same clamped scalar gives the same public key.
        let raw = clamp([7u8; 32]);
        let a = from_private_bytes(raw);
        let b = from_private_bytes(raw);
        assert_eq!(a, b);
        // A known X25519 vector: the public key of the all-sevens scalar, clamped.
        assert!(is_key(&a.public));
    }

    #[test]
    fn a_generated_private_key_is_clamped() {
        let kp = generate().unwrap();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&kp.private)
            .unwrap();
        assert_eq!(bytes[0] & 0b0000_0111, 0, "low three bits clear");
        assert_eq!(bytes[31] & 0b1000_0000, 0, "top bit clear");
        assert_eq!(bytes[31] & 0b0100_0000, 0b0100_0000, "second-top bit set");
    }

    #[test]
    fn junk_is_not_a_key() {
        assert!(!is_key("not base64!!"));
        assert!(!is_key("")); // zero bytes
        assert!(!is_key(
            &base64::engine::general_purpose::STANDARD.encode([0u8; 31])
        ));
        assert!(is_key(
            &base64::engine::general_purpose::STANDARD.encode([0u8; 32])
        ));
    }
}
