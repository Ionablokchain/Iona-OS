//! Cryptographic primitives for IONA consensus and networking.
//!
//! This module provides:
//!
//! - **Core traits**: `Signer` and `Verifier` for pluggable signing backends.
//! - **Ed25519 implementation**: Production‑grade signing using `ed25519_dalek`.
//! - **Remote signer client**: HTTP‑based signing service with mTLS and retries.
//! - **HSM abstraction**: Support for PKCS#11, AWS KMS, Azure Key Vault, GCP Cloud KMS.
//! - **Development signer**: In‑memory ECDSA P‑256 for testing (feature‑gated).
//! - **Keystore**: Encrypted storage for private keys.
//! - **Transaction signing**: Utilities for signing and verifying transactions.
//!
//! # Security Notes
//!
//! - The Ed25519 implementation uses constant‑time operations and zeroizes secrets.
//! - The remote signer client supports mTLS and API key authentication.
//! - The HSM abstraction is designed for production use with hardware security modules.
//! - The development signer is **only** available with the `dev-signing` feature.
//!
//! # Feature Flags
//!
//! - `dev-signing`: Enables the in‑memory ECDSA P‑256 signer for development/testing.
//! - `pkcs11`: Enables PKCS#11 HSM support.
//! - `aws-kms`: Enables AWS KMS support.
//! - `azure-kv`: Enables Azure Key Vault support.
//! - `gcp-kms`: Enables GCP Cloud KMS support.
//!
//! # Example
//!
//! ```
//! use iona::crypto::{Signer, Verifier, ed25519::Ed25519Signer};
//!
//! let signer = Ed25519Signer::random();
//! let pk = signer.public_key();
//! let msg = b"hello world";
//! let sig = signer.sign(msg);
//! assert!(Ed25519Verifier::verify(&pk, msg, &sig).is_ok());
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Core types
// -----------------------------------------------------------------------------

/// Public key bytes wrapper with hex serialisation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKeyBytes(pub Vec<u8>);

impl std::fmt::Display for PublicKeyBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl std::str::FromStr for PublicKeyBytes {
    type Err = hex::FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(PublicKeyBytes(hex::decode(s)?))
    }
}

impl Serialize for PublicKeyBytes {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for PublicKeyBytes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s)
            .map(PublicKeyBytes)
            .map_err(serde::de::Error::custom)
    }
}

/// Signature bytes wrapper (usually 64 bytes for Ed25519).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureBytes(pub Vec<u8>);

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

/// Cryptographic errors that can occur during signing or verification.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Signature verification failed.
    #[error("invalid signature")]
    InvalidSignature,

    /// Key‑related error (invalid format, unsupported algorithm).
    #[error("key error: {0}")]
    Key(String),

    /// Invalid key length.
    #[error("invalid key length: expected {expected}, got {actual}")]
    KeyLength { expected: usize, actual: usize },

    /// Invalid signature length.
    #[error("invalid signature length: expected {expected}, got {actual}")]
    SignatureLength { expected: usize, actual: usize },

    /// Network error (for remote signer).
    #[error("network error: {0}")]
    Network(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Timeout error.
    #[error("operation timed out")]
    Timeout,

    /// HSM error.
    #[error("HSM error: {0}")]
    Hsm(String),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

pub type CryptoResult<T> = Result<T, CryptoError>;

// -----------------------------------------------------------------------------
// Core traits
// -----------------------------------------------------------------------------

/// A signer that can produce signatures for arbitrary messages.
///
/// Implementations must be thread‑safe (`Send + Sync`) and can be backed
/// by local keys, remote signing services, or hardware security modules.
pub trait Signer: Send + Sync {
    /// Return the public key corresponding to this signer.
    fn public_key(&self) -> PublicKeyBytes;

    /// Sign the given message and return the signature.
    ///
    /// # Panics
    /// Implementations should avoid panicking; they may return an empty
    /// signature if signing fails (the caller must handle that case).
    fn sign(&self, msg: &[u8]) -> SignatureBytes;
}

/// A stateless verifier that can validate signatures against public keys.
pub trait Verifier: Send + Sync {
    /// Verify that `sig` is a valid signature for `msg` under `pk`.
    ///
    /// # Returns
    /// `Ok(())` if the signature is valid, `Err(CryptoError::InvalidSignature)` otherwise.
    fn verify(pk: &PublicKeyBytes, msg: &[u8], sig: &SignatureBytes) -> CryptoResult<()>;
}

// -----------------------------------------------------------------------------
// Submodules
// -----------------------------------------------------------------------------

pub mod ed25519;
pub mod tx;
pub mod keystore;
pub mod remote_signer;
pub mod hsm;

// Development signer (feature‑gated)
#[cfg(any(test, feature = "dev-signing"))]
pub mod dev;

// -----------------------------------------------------------------------------
// Re‑exports
// -----------------------------------------------------------------------------

// Ed25519 (production default)
pub use ed25519::{Ed25519Signer, Ed25519Verifier};

// Transaction signing
pub use tx::{derive_address, sign_tx, tx_sign_bytes, verify_tx_signature};

// Keystore
pub use keystore::{
    change_keystore_password, decrypt_seed32_from_file, encrypt_seed32_to_file,
    keystore_exists, validate_keystore, KeystoreError, KeystoreOptions,
};

// Remote signer
pub use remote_signer::{
    connect_simple, RemoteSigner, RemoteSignerConfig, RemoteSignerError,
};

// HSM
pub use hsm::{
    create_signer, KeyBackendConfig, LocalSigner, HsmSigner,
};

// Development signer (feature‑gated)
#[cfg(any(test, feature = "dev-signing"))]
pub use dev::{EcdsaSigner, EcdsaVerifier};

// -----------------------------------------------------------------------------
// Factory function
// -----------------------------------------------------------------------------

/// Create a signer from a configuration.
///
/// This is a convenience wrapper around `hsm::create_signer`.
pub fn create_signer(config: &KeyBackendConfig) -> CryptoResult<Box<dyn Signer>> {
    hsm::create_signer(config).map(|s| s as Box<dyn Signer>)
}

// -----------------------------------------------------------------------------
// Version information
// -----------------------------------------------------------------------------

/// Returns the crypto module version.
pub fn module_version() -> &'static str {
    "1.0.0"
}

/// Returns the Ed25519 implementation version.
pub fn ed25519_version() -> &'static str {
    ed25519_dalek::VERSION
}

// -----------------------------------------------------------------------------
// Prelude
// -----------------------------------------------------------------------------

/// Convenience prelude for the crypto module.
///
/// # Example
/// ```rust,ignore
/// use iona::crypto::prelude::*;
/// ```
pub mod prelude {
    pub use super::{
        CryptoError, CryptoResult, PublicKeyBytes, SignatureBytes,
        Signer, Verifier,
        Ed25519Signer, Ed25519Verifier,
        derive_address, sign_tx, verify_tx_signature,
        create_signer, KeyBackendConfig,
    };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519::Ed25519Signer;

    #[test]
    fn test_ed25519_roundtrip() {
        let signer = Ed25519Signer::random();
        let pk = signer.public_key();
        let msg = b"test message";
        let sig = signer.sign(msg);
        assert!(Ed25519Verifier::verify(&pk, msg, &sig).is_ok());
    }

    #[test]
    fn test_public_key_display() {
        let pk = PublicKeyBytes(vec![0xAA; 32]);
        let s = pk.to_string();
        assert_eq!(s, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    }

    #[test]
    fn test_public_key_serialization() {
        let pk = PublicKeyBytes(vec![0xAA; 32]);
        let json = serde_json::to_string(&pk).unwrap();
        assert_eq!(json, "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"");
        let pk2: PublicKeyBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(pk, pk2);
    }
}
