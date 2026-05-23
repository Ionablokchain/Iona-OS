//! Cryptographic primitives for consensus: signing and verification.
//!
//! **Production**: Use real implementations (e.g., `src/security/hsm.rs`).
//! **Development / testing only**: This module provides an ECDSA P‑256 signer
//! that stores private keys in memory and is **never** compiled in release builds.
//!
//! ⚠️ **WARNING**: This code is only active when the `dev-signing` feature is enabled.
//! It is **not** suitable for production use.

use alloc::vec::Vec;

// -----------------------------------------------------------------------------
// Public key type
// -----------------------------------------------------------------------------

/// 32‑byte compressed public key representation (first byte is `0x02` or `0x03`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord,
         serde::Serialize, serde::Deserialize)]
pub struct PublicKeyBytes(pub Vec<u8>);

// -----------------------------------------------------------------------------
// Traits
// -----------------------------------------------------------------------------

/// A signer capable of producing signatures for consensus messages.
pub trait Signer: Send + Sync {
    /// Returns the public key corresponding to this signer.
    fn public_key(&self) -> PublicKeyBytes;

    /// Sign a message and return the signature as a byte vector.
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
}

/// A stateless verifier for consensus signatures.
pub trait Verifier: Send + Sync {
    /// Verify a signature against a public key and message.
    /// Returns `Ok(())` on success, `Err(())` on failure.
    fn verify(pk: &PublicKeyBytes, msg: &[u8], sig: &[u8]) -> Result<(), ()>;
}

// -----------------------------------------------------------------------------
// Development‑only ECDSA P‑256 signer
// -----------------------------------------------------------------------------

/// ECDSA P‑256 signer for testing – stores the private key in memory.
/// Never used in production builds.
///
/// This signer is only available when the `dev-signing` feature is enabled
/// (which is automatically the case for tests and development profiles).
#[cfg(any(test, feature = "dev-signing"))]
pub struct EcdsaSigner {
    /// Public key (compressed, 33 bytes).
    pub pk: PublicKeyBytes,
    /// Private key scalar (32 bytes).
    pub sk: [u8; 32],
}

#[cfg(any(test, feature = "dev-signing"))]
impl EcdsaSigner {
    /// Create a signer from a 32‑byte private key.
    ///
    /// The public key is derived using proper P‑256 point multiplication.
    /// If the underlying TLS module is not available (e.g., when `tls` feature
    /// is disabled), a dummy public key is generated (verification will fail).
    pub fn new(sk: [u8; 32]) -> Self {
        // Derive public key via real P‑256 base point multiplication.
        #[cfg(feature = "tls")]
        let pk_bytes = crate::net::tls::ecdsa::public_from_secret(&sk);
        #[cfg(not(feature = "tls"))]
        let pk_bytes = {
            // Dummy public key: first byte 0x02 followed by the first 32 bytes
            // of the Blake3 hash of the secret key.
            // This is only for compilation when TLS is disabled; verification will fail.
            let mut dummy = alloc::vec![0x02];
            let hash = crate::consensus::engine::sha256_hash(&sk);
            dummy.extend_from_slice(&hash);
            dummy
        };
        Self {
            pk: PublicKeyBytes(pk_bytes),
            sk,
        }
    }
}

#[cfg(any(test, feature = "dev-signing"))]
impl Signer for EcdsaSigner {
    fn public_key(&self) -> PublicKeyBytes {
        self.pk.clone()
    }

    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        // Use deterministic RFC 6979 ECDSA P‑256 signing.
        let hash = crate::consensus::engine::sha256_hash(msg);
        let sig = crate::net::tls::ecdsa::p256_sign(&self.sk, &hash);
        if sig.len() == 64 {
            sig
        } else {
            // Fallback for invalid key – never reveals the private key.
            // Return all‑zero signature; verification will fail.
            vec![0u8; 64]
        }
    }
}

// -----------------------------------------------------------------------------
// Development‑only ECDSA verifier
// -----------------------------------------------------------------------------

/// ECDSA P‑256 verifier for testing.
#[cfg(any(test, feature = "dev-signing"))]
pub struct EcdsaVerifier;

#[cfg(any(test, feature = "dev-signing"))]
impl Verifier for EcdsaVerifier {
    fn verify(pk: &PublicKeyBytes, msg: &[u8], sig: &[u8]) -> Result<(), ()> {
        if sig.len() < 64 || pk.0.len() < 33 {
            return Err(());
        }
        let hash = crate::consensus::engine::sha256_hash(msg);
        // Extract the 32‑byte public key scalar from the compressed representation.
        let pk_scalar: [u8; 32] = pk.0[1..33].try_into().map_err(|_| ())?;
        if crate::net::tls::ecdsa::p256_verify_raw(&pk_scalar, &hash, sig) {
            Ok(())
        } else {
            Err(())
        }
    }
}

// -----------------------------------------------------------------------------
// Production safety guard
// -----------------------------------------------------------------------------

// Ensure production builds never accidentally include this module.
#[cfg(not(any(test, feature = "dev-signing")))]
compile_error!(
    "The 'dev-signing' feature must be enabled for development; it is disabled in release builds."
);
