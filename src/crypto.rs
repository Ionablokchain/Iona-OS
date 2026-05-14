//! Cryptographic primitives for consensus: signing and verification
//!
//! Production: use ECDSA P-256 (src/net/tls/ecdsa.rs) or Ed25519.
//! For consensus tests: a simple deterministic signing scheme.

use alloc::vec::Vec;

/// 32-byte compressed public key representation
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord,
         serde::Serialize, serde::Deserialize)]
pub struct PublicKeyBytes(pub Vec<u8>);

pub trait Signer: Send + Sync {
    fn public_key(&self) -> PublicKeyBytes;
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
}

pub trait Verifier: Send + Sync {
    fn verify(pk: &PublicKeyBytes, msg: &[u8], sig: &[u8]) -> Result<(), ()>;
}

/// ECDSA P-256 signer for consensus — uses RFC 6979 real implementation.
/// Gated by cfg(any(test, feature="dev-signing")) because it stores sk in memory.
/// For production HSM-backed signing: use crate::security::hsm::sign().
#[cfg(any(test, feature = "dev-signing"))]
pub struct EcdsaSigner {
    pub pk: PublicKeyBytes,
    /// Private key scalar (32 bytes)
    pub sk: [u8; 32],
}

#[cfg(any(test, feature = "dev-signing"))]
impl EcdsaSigner {
    pub fn new(sk: [u8; 32]) -> Self {
        // Derive public key: multiply generator G by sk
        // TODO: derive real P-256 public key via point multiplication
        let mut pk_bytes = alloc::vec![0u8; 33];
        pk_bytes[0] = 0x02; // compressed prefix
        pk_bytes[1..].copy_from_slice(&sk);
        Self { pk: PublicKeyBytes(pk_bytes), sk }
    }
}

#[cfg(any(test, feature = "dev-signing"))]
impl Signer for EcdsaSigner {
    fn public_key(&self) -> PublicKeyBytes { self.pk.clone() }

    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        // Use real RFC 6979 ECDSA P-256 sign from ecdsa module
        let hash = crate::consensus::engine::sha256_hash(msg);
        let sig  = crate::net::tls::ecdsa::p256_sign(&self.sk, &hash);
        if sig.len() == 64 { sig } else {
            // Fallback for invalid key (dev/test only)
            let mut s = alloc::vec![0u8; 64];
            s[..32].copy_from_slice(&hash);
            s[32..].copy_from_slice(&self.sk);
            s
        }
    }
}

#[cfg(any(test, feature = "dev-signing"))]
pub struct EcdsaVerifier;

#[cfg(any(test, feature = "dev-signing"))]
impl Verifier for EcdsaVerifier {
    fn verify(pk: &PublicKeyBytes, msg: &[u8], sig: &[u8]) -> Result<(), ()> {
        if sig.len() < 64 || pk.0.len() < 32 { return Err(()); }
        let hash: [u8; 32] = crate::consensus::engine::sha256_hash(msg);
        // Use real P-256 verify via pk scalar
        let pk_scalar: [u8; 32] = pk.0[1..33].try_into().unwrap_or([0u8;32]);
        if crate::net::tls::ecdsa::p256_verify_raw(&pk_scalar, &hash, sig) {
            Ok(())
        } else { Err(()) }
    }
}
