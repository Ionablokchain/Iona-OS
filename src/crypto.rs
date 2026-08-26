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
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                           Crypto Module                               │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   Config    │    Error     │    Metrics    │         Types            │
//! │ (CryptoCfg) │ (CryptoErr)  │ (CryptoMetr)  │ (PubKey, Sig, KeyBackend)│
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   Manager   │   Submodules │    Legacy     │                          │
//! │ (CryptoMgr) │ (ed25519,    │ (global fns)  │                          │
//! │             │  tx, hsm,    │               │                          │
//! │             │  remote,     │               │                          │
//! │             │  keystore,   │               │                          │
//! │             │  dev)        │               │                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::crypto::{CryptoManager, CryptoConfig};
//!
//! let config = CryptoConfig::default();
//! let manager = CryptoManager::new(config);
//! let signer = manager.create_signer(&KeyBackendConfig::local("seed"))?;
//! let sig = signer.sign(b"hello");
//! ```

#![allow(dead_code)]

// -----------------------------------------------------------------------------
// Submodule declarations
// -----------------------------------------------------------------------------

pub mod ed25519;
pub mod tx;
pub mod keystore;
pub mod remote_signer;
pub mod hsm;

#[cfg(any(test, feature = "dev-signing"))]
pub mod dev;

// -----------------------------------------------------------------------------
// Inline submodules for the manager
// -----------------------------------------------------------------------------

mod config {
    //! Configuration for the crypto subsystem.
    use serde::{Deserialize, Serialize};
    use super::hsm::KeyBackendConfig;

    /// Configuration for the crypto subsystem.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CryptoConfig {
        pub default_backend: KeyBackendConfig,
        pub collect_metrics: bool,
        pub log_operations: bool,
        pub max_signature_retries: usize,
        pub remote_signer_timeout_secs: u64,
        pub allow_dev_signer: bool,
    }

    impl Default for CryptoConfig {
        fn default() -> Self {
            Self {
                default_backend: KeyBackendConfig::Local { seed: vec![0u8; 32] },
                collect_metrics: true,
                log_operations: false,
                max_signature_retries: 3,
                remote_signer_timeout_secs: 10,
                allow_dev_signer: false,
            }
        }
    }

    impl CryptoConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.max_signature_retries == 0 {
                return Err("max_signature_retries must be > 0");
            }
            if self.remote_signer_timeout_secs == 0 {
                return Err("remote_signer_timeout_secs must be > 0");
            }
            Ok(())
        }

        pub fn with_metrics(mut self) -> Self {
            self.collect_metrics = true;
            self
        }

        pub fn with_logging(mut self) -> Self {
            self.log_operations = true;
            self
        }
    }
}

mod error {
    //! Error types for the crypto subsystem.
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum CryptoError {
        #[error("invalid signature")]
        InvalidSignature,

        #[error("key error: {0}")]
        Key(String),

        #[error("invalid key length: expected {expected}, got {actual}")]
        KeyLength { expected: usize, actual: usize },

        #[error("invalid signature length: expected {expected}, got {actual}")]
        SignatureLength { expected: usize, actual: usize },

        #[error("network error: {0}")]
        Network(String),

        #[error("configuration error: {0}")]
        Config(String),

        #[error("operation timed out")]
        Timeout,

        #[error("HSM error: {0}")]
        Hsm(String),

        #[error("internal error: {0}")]
        Internal(String),

        #[error("signer not available")]
        SignerUnavailable,
    }

    pub type CryptoResult<T> = Result<T, CryptoError>;
}

mod types {
    //! Core types for the crypto subsystem.
    use serde::{Deserialize, Serialize};
    use core::fmt;

    /// Public key bytes wrapper with hex serialisation.
    #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub struct PublicKeyBytes(pub Vec<u8>);

    impl fmt::Display for PublicKeyBytes {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

    /// Core signer trait.
    pub trait Signer: Send + Sync {
        fn public_key(&self) -> PublicKeyBytes;
        fn sign(&self, msg: &[u8]) -> SignatureBytes;
    }

    /// Core verifier trait.
    pub trait Verifier: Send + Sync {
        fn verify(pk: &PublicKeyBytes, msg: &[u8], sig: &SignatureBytes) -> super::error::CryptoResult<()>;
    }
}

mod metrics {
    //! Metrics for the crypto subsystem.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct CryptoMetrics {
        pub signatures_created: AtomicU64,
        pub signatures_verified: AtomicU64,
        pub signature_failures: AtomicU64,
        pub verification_failures: AtomicU64,
        pub remote_signer_requests: AtomicU64,
        pub remote_signer_errors: AtomicU64,
        pub hsm_operations: AtomicU64,
        pub hsm_errors: AtomicU64,
        pub keystore_operations: AtomicU64,
        pub keystore_errors: AtomicU64,
    }

    impl CryptoMetrics {
        pub fn inc_signed(&self) {
            self.signatures_created.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_verified(&self) {
            self.signatures_verified.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_sig_failure(&self) {
            self.signature_failures.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_verify_failure(&self) {
            self.verification_failures.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_remote_req(&self) {
            self.remote_signer_requests.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_remote_err(&self) {
            self.remote_signer_errors.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_hsm_op(&self) {
            self.hsm_operations.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_hsm_err(&self) {
            self.hsm_errors.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_keystore_op(&self) {
            self.keystore_operations.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_keystore_err(&self) {
            self.keystore_errors.fetch_add(1, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> CryptoMetricsSnapshot {
            CryptoMetricsSnapshot {
                signatures_created: self.signatures_created.load(Ordering::Relaxed),
                signatures_verified: self.signatures_verified.load(Ordering::Relaxed),
                signature_failures: self.signature_failures.load(Ordering::Relaxed),
                verification_failures: self.verification_failures.load(Ordering::Relaxed),
                remote_signer_requests: self.remote_signer_requests.load(Ordering::Relaxed),
                remote_signer_errors: self.remote_signer_errors.load(Ordering::Relaxed),
                hsm_operations: self.hsm_operations.load(Ordering::Relaxed),
                hsm_errors: self.hsm_errors.load(Ordering::Relaxed),
                keystore_operations: self.keystore_operations.load(Ordering::Relaxed),
                keystore_errors: self.keystore_errors.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CryptoMetricsSnapshot {
        pub signatures_created: u64,
        pub signatures_verified: u64,
        pub signature_failures: u64,
        pub verification_failures: u64,
        pub remote_signer_requests: u64,
        pub remote_signer_errors: u64,
        pub hsm_operations: u64,
        pub hsm_errors: u64,
        pub keystore_operations: u64,
        pub keystore_errors: u64,
    }
}

mod manager {
    //! Centralised manager for the crypto subsystem.
    use super::{
        config::CryptoConfig,
        error::{CryptoError, CryptoResult},
        metrics::CryptoMetrics,
        types::{PublicKeyBytes, SignatureBytes, Signer, Verifier},
        hsm::{KeyBackendConfig, create_signer as hsm_create_signer},
        ed25519::{Ed25519Signer, Ed25519Verifier},
    };
    use core::sync::atomic::Ordering;
    use tracing::{debug, info, warn};

    /// Manager for the crypto subsystem.
    pub struct CryptoManager {
        config: CryptoConfig,
        metrics: CryptoMetrics,
        initialized: bool,
    }

    impl CryptoManager {
        pub fn new(config: CryptoConfig) -> Self {
            config.validate().expect("invalid CryptoConfig");
            Self {
                config,
                metrics: CryptoMetrics::default(),
                initialized: false,
            }
        }

        pub fn default() -> Self {
            Self::new(CryptoConfig::default())
        }

        pub fn config(&self) -> &CryptoConfig {
            &self.config
        }

        pub fn metrics(&self) -> &CryptoMetrics {
            &self.metrics
        }

        /// Initialise the crypto subsystem (e.g., load default signer).
        pub fn init(&mut self) {
            self.initialized = true;
            info!("crypto subsystem initialised");
        }

        /// Create a signer from a backend configuration.
        pub fn create_signer(&self, backend: &KeyBackendConfig) -> CryptoResult<Box<dyn Signer>> {
            if self.config.log_operations {
                debug!("creating signer from backend: {:?}", backend);
            }
            let signer = hsm_create_signer(backend)?;
            // Record metrics if enabled.
            if self.config.collect_metrics {
                self.metrics.inc_hsm_op();
            }
            Ok(signer)
        }

        /// Create a default signer from the configuration's default backend.
        pub fn default_signer(&self) -> CryptoResult<Box<dyn Signer>> {
            self.create_signer(&self.config.default_backend)
        }

        /// Create a random Ed25519 signer (for testing).
        pub fn random_ed25519(&self) -> CryptoResult<Box<dyn Signer>> {
            if self.config.log_operations {
                debug!("creating random Ed25519 signer");
            }
            let signer = Ed25519Signer::random();
            if self.config.collect_metrics {
                self.metrics.inc_hsm_op();
            }
            Ok(Box::new(signer))
        }

        /// Verify a signature using the Ed25519 verifier.
        pub fn verify_ed25519(
            &self,
            pk: &PublicKeyBytes,
            msg: &[u8],
            sig: &SignatureBytes,
        ) -> CryptoResult<()> {
            if self.config.log_operations {
                trace!("verifying Ed25519 signature");
            }
            let result = Ed25519Verifier::verify(pk, msg, sig);
            if self.config.collect_metrics {
                if result.is_ok() {
                    self.metrics.inc_verified();
                } else {
                    self.metrics.inc_verify_failure();
                }
            }
            result
        }

        /// Get a metrics snapshot.
        pub fn metrics_snapshot(&self) -> super::metrics::CryptoMetricsSnapshot {
            self.metrics.snapshot()
        }

        /// Reset metrics.
        pub fn reset_metrics(&self) {
            *self.metrics = CryptoMetrics::default();
        }

        /// Check if the crypto subsystem is initialised.
        pub fn is_initialised(&self) -> bool {
            self.initialized
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::CryptoConfig;
pub use error::{CryptoError, CryptoResult};
pub use types::{PublicKeyBytes, SignatureBytes, Signer, Verifier};
pub use metrics::{CryptoMetrics, CryptoMetricsSnapshot};
pub use manager::CryptoManager;

// -----------------------------------------------------------------------------
// Submodule re‑exports (preserve existing API)
// -----------------------------------------------------------------------------

pub use ed25519::{Ed25519Signer, Ed25519Verifier};
pub use tx::{derive_address, sign_tx, tx_sign_bytes, verify_tx_signature};
pub use keystore::{
    change_keystore_password, decrypt_seed32_from_file, encrypt_seed32_to_file,
    keystore_exists, validate_keystore, KeystoreError, KeystoreOptions,
};
pub use remote_signer::{
    connect_simple, RemoteSigner, RemoteSignerConfig, RemoteSignerError,
};
pub use hsm::{
    create_signer as hsm_create_signer, KeyBackendConfig, LocalSigner, HsmSigner,
};

#[cfg(any(test, feature = "dev-signing"))]
pub use dev::{EcdsaSigner, EcdsaVerifier};

// -----------------------------------------------------------------------------
// Legacy global functions (backward compatibility)
// -----------------------------------------------------------------------------

use spin::Once;

static GLOBAL_MANAGER: Once<CryptoManager> = Once::new();

/// Get the global manager (initialises with defaults if not yet set).
fn global_manager() -> &'static CryptoManager {
    GLOBAL_MANAGER.get_or_init(|| CryptoManager::new(CryptoConfig::default()))
}

/// Create a signer from a configuration (legacy).
pub fn create_signer(config: &KeyBackendConfig) -> CryptoResult<Box<dyn Signer>> {
    global_manager().create_signer(config)
}

/// Create a default signer (legacy).
pub fn default_signer() -> CryptoResult<Box<dyn Signer>> {
    global_manager().default_signer()
}

/// Verify an Ed25519 signature (legacy).
pub fn verify_ed25519(pk: &PublicKeyBytes, msg: &[u8], sig: &SignatureBytes) -> CryptoResult<()> {
    global_manager().verify_ed25519(pk, msg, sig)
}

/// Get module version (legacy).
pub fn module_version() -> &'static str {
    "1.0.0"
}

/// Get Ed25519 version (legacy).
pub fn ed25519_version() -> &'static str {
    ed25519_dalek::VERSION
}

// -----------------------------------------------------------------------------
// Prelude
// -----------------------------------------------------------------------------

/// Convenience prelude for the crypto module.
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

    #[test]
    fn test_manager_creation() {
        let config = CryptoConfig::default();
        let manager = CryptoManager::new(config);
        assert!(!manager.is_initialised());
        // We can't easily test signer creation without a real backend, but we can test the API.
        // Create a random signer.
        let signer = manager.random_ed25519().unwrap();
        let pk = signer.public_key();
        let sig = signer.sign(b"hello");
        assert!(manager.verify_ed25519(&pk, b"hello", &sig).is_ok());
        assert_eq!(manager.metrics().snapshot().signatures_created, 1);
    }
}
