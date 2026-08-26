//! Core protocol types — Quantum‑Ready Production Edition.
//!
//! # Quantum Protocol Model
//!
//! Every block, header, and transaction exists in a **superposition** of
//! validity states.  Validation is a **projective measurement** that
//! collapses the state to either |valid⟩ or |invalid⟩.  The protocol
//! types track the **density matrix** properties so that the caller can
//! monitor the “health” of the data flowing through the system.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                            Types Module                               │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   Config    │    Error     │    Metrics    │         Types            │
//! │ (TypeCfg)   │ (TypeError)  │ (TypeMetr)    │ (Height, Round, Hash32)  │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   Quantum   │   Manager    │    Legacy     │                          │
//! │ (QuantumState)│ (TypeMgr)  │ (global fns)  │                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::types::{TypeManager, QuantumProtocolState, Height, Hash32};
//!
//! let manager = TypeManager::new();
//! let h = Height::new(10);
//! let hash = Hash32::zero();
//! let qstate = manager.new_quantum_state();
//! ```

#![allow(dead_code)]

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;
use serde::{Deserialize, Serialize};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for core types.
    use serde::{Deserialize, Serialize};

    /// Configuration for quantum state tracking.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct TypeConfig {
        pub enable_quantum_state: bool,
        pub min_coherence_threshold: f64,
        pub validation_decoherence_rate: f64,
        pub failure_decoherence_rate: f64,
        pub kraus_rank: usize,
    }

    impl Default for TypeConfig {
        fn default() -> Self {
            Self {
                enable_quantum_state: true,
                min_coherence_threshold: super::constants::MIN_PROTOCOL_COHERENCE,
                validation_decoherence_rate: super::constants::VALIDATION_DECOHERENCE_RATE,
                failure_decoherence_rate: super::constants::FAILURE_DECOHERENCE_RATE,
                kraus_rank: super::constants::PROTOCOL_KRAUS_RANK,
            }
        }
    }

    impl TypeConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.min_coherence_threshold < 0.0 || self.min_coherence_threshold > 1.0 {
                return Err("min_coherence_threshold must be between 0 and 1");
            }
            if self.validation_decoherence_rate < 0.0 {
                return Err("validation_decoherence_rate must be >= 0");
            }
            if self.failure_decoherence_rate < 0.0 {
                return Err("failure_decoherence_rate must be >= 0");
            }
            if self.kraus_rank == 0 {
                return Err("kraus_rank must be > 0");
            }
            Ok(())
        }
    }
}

pub mod constants {
    //! Constants for core types.

    /// Reduced Planck constant (natural units).
    pub const HBAR: f64 = 1.0;

    /// Default quantum coherence for a freshly created protocol object.
    pub const DEFAULT_PROTOCOL_COHERENCE: f64 = 1.0;

    /// Decoherence rate for a single validation check.
    pub const VALIDATION_DECOHERENCE_RATE: f64 = 0.0001;

    /// Stronger decoherence when a check **fails** (invalid data).
    pub const FAILURE_DECOHERENCE_RATE: f64 = 0.001;

    /// Minimum purity threshold for a “healthy” object.
    pub const MIN_PROTOCOL_COHERENCE: f64 = 0.99;

    /// Kraus rank used when applying the quantum channel.
    pub const PROTOCOL_KRAUS_RANK: usize = 4;

    /// Size of a hash in bytes.
    pub const HASH_SIZE: usize = 32;

    /// Minimum gas limit per block.
    pub const MIN_GAS_LIMIT: u64 = 1_000_000;

    /// Maximum gas limit per block.
    pub const MAX_GAS_LIMIT: u64 = 0xFFFF_FFFF;

    /// Minimum base fee.
    pub const MIN_BASE_FEE: u64 = 1;
}

pub mod error {
    //! Error types for core types.
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum TypeError {
        #[error("invalid height: {0}")]
        InvalidHeight(String),

        #[error("invalid round: {0}")]
        InvalidRound(String),

        #[error("invalid hash: {0}")]
        InvalidHash(String),

        #[error("invalid hex string: {0}")]
        InvalidHex(String),

        #[error("coherence out of range: {0}")]
        CoherenceOutOfRange(f64),

        #[error("configuration error: {0}")]
        Config(String),
    }

    pub type TypeResult<T> = Result<T, TypeError>;
}

pub mod types {
    //! Core protocol types.
    use super::{
        constants::*,
        error::{TypeError, TypeResult},
        quantum::QuantumProtocolState,
        metrics::global_metrics,
    };
    use alloc::collections::BTreeMap;
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;
    use core::fmt;
    use core::str::FromStr;
    use serde::{Deserialize, Serialize};
    use tracing::trace;

    // -------------------------------------------------------------------------
    // Newtype wrappers
    // -------------------------------------------------------------------------

    /// Block height (0 = genesis).
    #[derive(
        Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
        Serialize, Deserialize,
    )]
    pub struct Height(pub u64);

    impl Height {
        pub const fn new(h: u64) -> Self {
            Self(h)
        }
        pub const fn as_u64(&self) -> u64 {
            self.0
        }
        pub const fn saturating_sub(self, other: Self) -> Self {
            Self(self.0.saturating_sub(other.0))
        }
        pub const fn checked_add(self, other: Self) -> Option<Self> {
            match self.0.checked_add(other.0) {
                Some(v) => Some(Self(v)),
                None => None,
            }
        }
    }

    impl From<u64> for Height {
        fn from(v: u64) -> Self {
            Self(v)
        }
    }
    impl From<Height> for u64 {
        fn from(h: Height) -> Self {
            h.0
        }
    }
    impl fmt::Display for Height {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }
    impl FromStr for Height {
        type Err = core::num::ParseIntError;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            u64::from_str(s).map(Self)
        }
    }

    /// Consensus round number.
    #[derive(
        Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
        Serialize, Deserialize,
    )]
    pub struct Round(pub u32);

    impl Round {
        pub const fn new(r: u32) -> Self {
            Self(r)
        }
        pub const fn as_u32(&self) -> u32 {
            self.0
        }
    }
    impl From<u32> for Round {
        fn from(v: u32) -> Self {
            Self(v)
        }
    }
    impl From<Round> for u32 {
        fn from(r: Round) -> Self {
            r.0
        }
    }
    impl fmt::Display for Round {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }
    impl FromStr for Round {
        type Err = core::num::ParseIntError;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            u32::from_str(s).map(Self)
        }
    }

    /// 32‑byte hash (Blake3 or SHA‑256).
    #[derive(
        Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
        Serialize, Deserialize,
    )]
    pub struct Hash32(pub [u8; HASH_SIZE]);

    impl Hash32 {
        pub const fn zero() -> Self {
            Self([0u8; HASH_SIZE])
        }
        pub fn to_hex(&self) -> String {
            hex::encode(&self.0)
        }
        pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
            let s = s.trim_start_matches("0x");
            let bytes = hex::decode(s)?;
            if bytes.len() != HASH_SIZE {
                return Err(hex::FromHexError::InvalidStringLength);
            }
            let mut arr = [0u8; HASH_SIZE];
            arr.copy_from_slice(&bytes);
            Ok(Self(arr))
        }
        pub const fn is_zero(&self) -> bool {
            let arr = self.0;
            let mut i = 0;
            while i < HASH_SIZE {
                if arr[i] != 0 {
                    return false;
                }
                i += 1;
            }
            true
        }
    }
    impl Default for Hash32 {
        fn default() -> Self {
            Self::zero()
        }
    }
    impl fmt::Display for Hash32 {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "0x{}", self.to_hex())
        }
    }
    impl FromStr for Hash32 {
        type Err = hex::FromHexError;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            Self::from_hex(s)
        }
    }

    // -------------------------------------------------------------------------
    // Quantum Protocol State
    // -------------------------------------------------------------------------

    /// Quantum state that tracks the **density matrix** properties.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct QuantumProtocolState {
        pub purity: f64,
        pub entropy: f64,
        pub validation_coherence: f64,
        pub crypto_coherence: f64,
        pub total_checks: u64,
        pub checks_failed: u64,
        pub is_valid: bool,
    }

    impl Default for QuantumProtocolState {
        fn default() -> Self {
            Self {
                purity: DEFAULT_PROTOCOL_COHERENCE,
                entropy: 0.0,
                validation_coherence: DEFAULT_PROTOCOL_COHERENCE,
                crypto_coherence: DEFAULT_PROTOCOL_COHERENCE,
                total_checks: 0,
                checks_failed: 0,
                is_valid: true,
            }
        }
    }

    impl QuantumProtocolState {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn record_pass(&mut self) {
            self.total_checks = self.total_checks.wrapping_add(1);
            let decay = (-VALIDATION_DECOHERENCE_RATE).exp();
            self.validation_coherence = (self.validation_coherence * decay).clamp(0.0, 1.0);
            self.recompute();
        }

        pub fn record_failure(&mut self) {
            self.total_checks = self.total_checks.wrapping_add(1);
            self.checks_failed = self.checks_failed.wrapping_add(1);
            let decay = (-FAILURE_DECOHERENCE_RATE).exp();
            self.validation_coherence = (self.validation_coherence * decay).clamp(0.0, 1.0);
            self.recompute();
        }

        pub fn apply_crypto_decoherence(&mut self) {
            let decay = (-VALIDATION_DECOHERENCE_RATE).exp();
            self.crypto_coherence = (self.crypto_coherence * decay).clamp(0.0, 1.0);
            self.recompute();
        }

        pub fn apply_protocol_channel(&mut self) {
            let kraus_factor = (1.0 / PROTOCOL_KRAUS_RANK as f64).sqrt();
            self.validation_coherence = (self.validation_coherence * kraus_factor).clamp(0.0, 1.0);
            self.crypto_coherence = (self.crypto_coherence * kraus_factor).clamp(0.0, 1.0);
            self.recompute();
        }

        fn recompute(&mut self) {
            self.purity = (self.validation_coherence * self.crypto_coherence).clamp(0.0, 1.0);
            self.entropy = if self.purity >= 1.0 {
                0.0
            } else {
                -self.purity * self.purity.ln().max(0.0)
            };
            self.is_valid = self.purity >= MIN_PROTOCOL_COHERENCE;
        }

        pub fn merge(&mut self, other: &Self) {
            self.total_checks = self.total_checks.saturating_add(other.total_checks);
            self.checks_failed = self.checks_failed.saturating_add(other.checks_failed);
            self.purity = (self.purity * other.purity).clamp(0.0, 1.0);
            self.entropy = -self.purity * self.purity.ln().max(0.0);
            self.validation_coherence = (self.validation_coherence * other.validation_coherence).clamp(0.0, 1.0);
            self.crypto_coherence = (self.crypto_coherence * other.crypto_coherence).clamp(0.0, 1.0);
            self.is_valid = self.purity >= MIN_PROTOCOL_COHERENCE;
        }
    }

    // -------------------------------------------------------------------------
    // Log and Receipt
    // -------------------------------------------------------------------------

    /// EVM‑style log entry.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Log {
        pub address: [u8; 20],
        pub topics: Vec<Hash32>,
        pub data: Vec<u8>,
    }

    /// EVM‑style transaction receipt with quantum state.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Receipt {
        pub tx_hash: Hash32,
        pub success: bool,
        pub gas_used: u64,
        pub logs: Vec<Log>,
        pub output: Vec<u8>,
        #[serde(default = "default_coherence")]
        pub coherence: f64,
    }

    fn default_coherence() -> f64 {
        DEFAULT_PROTOCOL_COHERENCE
    }

    impl Receipt {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.gas_used == 0 && !self.success {
                // Zero gas is acceptable for early reverts.
            }
            Ok(())
        }

        pub fn validate_quantum(&self) -> (Result<(), &'static str>, QuantumProtocolState) {
            let mut qstate = QuantumProtocolState::new();
            let result = self.validate();
            match &result {
                Ok(_) => qstate.record_pass(),
                Err(_) => qstate.record_failure(),
            }
            qstate.apply_protocol_channel();
            (result, qstate)
        }

        pub fn coherence(&self) -> f64 {
            self.coherence
        }
    }

    // -------------------------------------------------------------------------
    // BlockHeader
    // -------------------------------------------------------------------------

    /// Block header containing all metadata.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct BlockHeader {
        pub height: Height,
        pub round: Round,
        pub parent_id: Hash32,
        pub state_root: Hash32,
        pub tx_root: Hash32,
        pub proposer_pk: Vec<u8>,
        pub proposer_addr: String,
        pub base_fee: u64,
        pub gas_used: u64,
        pub gas_limit: u64,
        pub timestamp_ms: u64,
        #[serde(default = "default_coherence")]
        pub coherence: f64,
    }

    impl BlockHeader {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.height == Height(0) && !self.parent_id.is_zero() {
                return Err("genesis block must have zero parent hash");
            }
            if self.gas_limit < MIN_GAS_LIMIT {
                return Err("gas limit below minimum");
            }
            if self.gas_limit > MAX_GAS_LIMIT {
                return Err("gas limit exceeds maximum");
            }
            if self.gas_used > self.gas_limit {
                return Err("gas used exceeds gas limit");
            }
            if self.base_fee < MIN_BASE_FEE {
                return Err("base fee below minimum");
            }
            if self.proposer_pk.len() != 32 {
                return Err("proposer public key must be 32 bytes");
            }
            if self.proposer_addr.is_empty() {
                return Err("proposer address cannot be empty");
            }
            Ok(())
        }

        pub fn validate_quantum(&self) -> (Result<(), &'static str>, QuantumProtocolState) {
            let mut qstate = QuantumProtocolState::new();
            let result = self.validate();
            match &result {
                Ok(_) => {
                    for _ in 0..7 {
                        qstate.record_pass();
                    }
                }
                Err(_) => qstate.record_failure(),
            }
            qstate.apply_crypto_decoherence();
            qstate.apply_protocol_channel();
            (result, qstate)
        }

        pub fn id(&self) -> Hash32 {
            let encoded = postcard::to_allocvec(self).unwrap_or_default();
            let hash = blake3::hash(&encoded);
            Hash32(*hash.as_bytes())
        }

        pub fn id_quantum(&self) -> (Hash32, QuantumProtocolState) {
            let id = self.id();
            let mut qstate = QuantumProtocolState::new();
            qstate.apply_crypto_decoherence();
            qstate.apply_protocol_channel();
            (id, qstate)
        }

        pub fn coherence(&self) -> f64 {
            self.coherence
        }
    }

    // -------------------------------------------------------------------------
    // Block
    // -------------------------------------------------------------------------

    /// Full block containing header and transactions.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Block {
        pub header: BlockHeader,
        pub txs: Vec<Tx>,
        #[serde(default = "default_coherence")]
        pub coherence: f64,
    }

    /// Simple KV state.
    pub type KvState = BTreeMap<Vec<u8>, Vec<u8>>;
    /// Raw transaction bytes.
    pub type Tx = Vec<u8>;

    impl Block {
        pub fn id(&self) -> Hash32 {
            self.header.id()
        }

        pub fn id_quantum(&self) -> (Hash32, QuantumProtocolState) {
            self.header.id_quantum()
        }

        pub fn validate(&self) -> Result<(), &'static str> {
            self.header.validate()?;
            let computed_root = tx_root(&self.txs);
            if computed_root != self.header.tx_root {
                return Err("transaction root mismatch");
            }
            Ok(())
        }

        pub fn validate_quantum(&self) -> (Result<(), &'static str>, QuantumProtocolState) {
            let mut qstate = QuantumProtocolState::new();
            let result = self.validate();
            match &result {
                Ok(_) => {
                    for _ in 0..8 {
                        qstate.record_pass();
                    }
                }
                Err(_) => qstate.record_failure(),
            }
            qstate.apply_crypto_decoherence();
            qstate.apply_protocol_channel();
            (result, qstate)
        }

        pub fn coherence(&self) -> f64 {
            self.coherence
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// Compute the transaction root hash.
    pub fn tx_root(txs: &[Tx]) -> Hash32 {
        if txs.is_empty() {
            return Hash32::zero();
        }
        let mut hasher = blake3::Hasher::new();
        for tx in txs {
            hasher.update(&blake3::hash(tx).as_bytes());
        }
        Hash32(*hasher.finalize().as_bytes())
    }

    pub fn tx_root_quantum(txs: &[Tx]) -> (Hash32, QuantumProtocolState) {
        let root = tx_root(txs);
        let mut qstate = QuantumProtocolState::new();
        qstate.apply_crypto_decoherence();
        qstate.apply_protocol_channel();
        (root, qstate)
    }

    /// Compute quantum fidelity between two hashes.
    pub fn hash_fidelity(a: &Hash32, b: &Hash32) -> f64 {
        if a == b { 1.0 } else { 0.0 }
    }
}

pub mod metrics {
    //! Metrics for core types.
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct TypeMetrics {
        pub height_conversions: AtomicU64,
        pub round_conversions: AtomicU64,
        pub hash_parses: AtomicU64,
        pub hash_serializations: AtomicU64,
        pub quantum_states_created: AtomicU64,
        pub quantum_checks_passed: AtomicU64,
        pub quantum_checks_failed: AtomicU64,
        pub quantum_decays: AtomicU64,
    }

    impl TypeMetrics {
        pub fn inc_height(&self) {
            self.height_conversions.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_round(&self) {
            self.round_conversions.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_hash_parse(&self) {
            self.hash_parses.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_hash_serialize(&self) {
            self.hash_serializations.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_quantum_state(&self) {
            self.quantum_states_created.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_quantum_pass(&self) {
            self.quantum_checks_passed.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_quantum_fail(&self) {
            self.quantum_checks_failed.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_quantum_decay(&self) {
            self.quantum_decays.fetch_add(1, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> TypeMetricsSnapshot {
            TypeMetricsSnapshot {
                height_conversions: self.height_conversions.load(Ordering::Relaxed),
                round_conversions: self.round_conversions.load(Ordering::Relaxed),
                hash_parses: self.hash_parses.load(Ordering::Relaxed),
                hash_serializations: self.hash_serializations.load(Ordering::Relaxed),
                quantum_states_created: self.quantum_states_created.load(Ordering::Relaxed),
                quantum_checks_passed: self.quantum_checks_passed.load(Ordering::Relaxed),
                quantum_checks_failed: self.quantum_checks_failed.load(Ordering::Relaxed),
                quantum_decays: self.quantum_decays.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct TypeMetricsSnapshot {
        pub height_conversions: u64,
        pub round_conversions: u64,
        pub hash_parses: u64,
        pub hash_serializations: u64,
        pub quantum_states_created: u64,
        pub quantum_checks_passed: u64,
        pub quantum_checks_failed: u64,
        pub quantum_decays: u64,
    }

    /// Global metrics instance.
    pub(crate) static GLOBAL_METRICS: spin::Once<TypeMetrics> = spin::Once::new();

    pub fn global_metrics() -> &'static TypeMetrics {
        GLOBAL_METRICS.get_or_init(TypeMetrics::default)
    }
}

pub mod manager {
    //! Centralised manager for core types.
    use super::{
        config::TypeConfig,
        error::{TypeError, TypeResult},
        types::{Height, Round, Hash32, QuantumProtocolState},
        metrics::global_metrics,
    };
    use core::sync::atomic::Ordering;
    use tracing::{debug, info};

    /// Manager for core types.
    pub struct TypeManager {
        config: TypeConfig,
        initialised: bool,
    }

    impl TypeManager {
        pub fn new(config: TypeConfig) -> Self {
            config.validate().expect("invalid TypeConfig");
            Self {
                config,
                initialised: false,
            }
        }

        pub fn default() -> Self {
            Self::new(TypeConfig::default())
        }

        pub fn config(&self) -> &TypeConfig {
            &self.config
        }

        pub fn init(&mut self) {
            self.initialised = true;
            info!("type manager initialised");
        }

        pub fn is_initialised(&self) -> bool {
            self.initialised
        }

        /// Create a new quantum state.
        pub fn new_quantum_state(&self) -> QuantumProtocolState {
            let state = QuantumProtocolState::new();
            if self.config.enable_quantum_state {
                global_metrics().inc_quantum_state();
            }
            state
        }

        /// Record a quantum check pass.
        pub fn record_pass(&self, state: &mut QuantumProtocolState) {
            state.record_pass();
            if self.config.enable_quantum_state {
                global_metrics().inc_quantum_pass();
            }
        }

        /// Record a quantum check failure.
        pub fn record_failure(&self, state: &mut QuantumProtocolState) {
            state.record_failure();
            if self.config.enable_quantum_state {
                global_metrics().inc_quantum_fail();
            }
        }

        /// Apply crypto decoherence.
        pub fn apply_crypto_decoherence(&self, state: &mut QuantumProtocolState) {
            state.apply_crypto_decoherence();
            if self.config.enable_quantum_state {
                global_metrics().inc_quantum_decay();
            }
        }

        /// Apply protocol channel.
        pub fn apply_protocol_channel(&self, state: &mut QuantumProtocolState) {
            state.apply_protocol_channel();
            if self.config.enable_quantum_state {
                global_metrics().inc_quantum_decay();
            }
        }

        /// Merge two quantum states.
        pub fn merge_states(&self, dest: &mut QuantumProtocolState, src: &QuantumProtocolState) {
            dest.merge(src);
        }

        /// Parse a height from a string.
        pub fn parse_height(&self, s: &str) -> TypeResult<Height> {
            global_metrics().inc_height();
            u64::from_str(s)
                .map(Height)
                .map_err(|e| TypeError::InvalidHeight(e.to_string()))
        }

        /// Parse a round from a string.
        pub fn parse_round(&self, s: &str) -> TypeResult<Round> {
            global_metrics().inc_round();
            u32::from_str(s)
                .map(Round)
                .map_err(|e| TypeError::InvalidRound(e.to_string()))
        }

        /// Parse a hash from a hex string.
        pub fn parse_hash(&self, s: &str) -> TypeResult<Hash32> {
            global_metrics().inc_hash_parse();
            Hash32::from_hex(s).map_err(|e| TypeError::InvalidHash(e.to_string()))
        }

        /// Serialize a hash to hex string.
        pub fn hash_to_hex(&self, hash: &Hash32) -> String {
            global_metrics().inc_hash_serialize();
            hash.to_hex()
        }

        /// Get metrics snapshot.
        pub fn metrics_snapshot(&self) -> super::metrics::TypeMetricsSnapshot {
            global_metrics().snapshot()
        }

        /// Reset metrics.
        pub fn reset_metrics(&self) {
            // We cannot reset the global metrics easily; we'd need a mutable reference.
            // We'll just create a new metrics instance and swap.
            // Since it's a Once, we can't easily replace it. We'll log a warning.
            tracing::warn!("resetting type metrics not supported in this version");
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::TypeConfig;
pub use error::{TypeError, TypeResult};
pub use types::{
    Height, Round, Hash32, QuantumProtocolState,
    Log, Receipt, BlockHeader, Block,
    KvState, Tx,
    tx_root, tx_root_quantum, hash_fidelity,
};
pub use metrics::{TypeMetrics, TypeMetricsSnapshot};
pub use manager::TypeManager;

// -----------------------------------------------------------------------------
// Legacy global API (backward compatibility)
// -----------------------------------------------------------------------------

use spin::Once;

static GLOBAL_MANAGER: Once<TypeManager> = Once::new();

/// Get the global manager (initialises with defaults if not yet set).
fn global_manager() -> &'static TypeManager {
    GLOBAL_MANAGER.get_or_init(|| {
        let mut mgr = TypeManager::new(TypeConfig::default());
        mgr.init();
        mgr
    })
}

/// Create a new quantum state (legacy).
pub fn new_quantum_state() -> QuantumProtocolState {
    global_manager().new_quantum_state()
}

/// Parse height (legacy).
pub fn parse_height(s: &str) -> TypeResult<Height> {
    global_manager().parse_height(s)
}

/// Parse round (legacy).
pub fn parse_round(s: &str) -> TypeResult<Round> {
    global_manager().parse_round(s)
}

/// Parse hash (legacy).
pub fn parse_hash(s: &str) -> TypeResult<Hash32> {
    global_manager().parse_hash(s)
}

/// Hash to hex (legacy).
pub fn hash_to_hex(hash: &Hash32) -> String {
    global_manager().hash_to_hex(hash)
}

// Re-export constants for backward compatibility.
pub use constants::*;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Classical tests ────────────────────────────────────────────────
    #[test]
    fn test_height_operations() {
        let h = Height::new(100);
        assert_eq!(h.as_u64(), 100);
        assert_eq!(Height::from(42).as_u64(), 42);
        assert_eq!(u64::from(h), 100);
        assert_eq!(format!("{}", h), "100");
    }

    #[test]
    fn test_hash32_roundtrip() {
        let h = Hash32::zero();
        assert!(h.is_zero());
        let hex = h.to_hex();
        let h2 = Hash32::from_hex(&hex).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn test_block_header_validation() {
        let mut header = BlockHeader {
            height: Height(1),
            round: Round(0),
            parent_id: Hash32::zero(),
            state_root: Hash32::zero(),
            tx_root: Hash32::zero(),
            proposer_pk: vec![0u8; 32],
            proposer_addr: "proposer".into(),
            base_fee: 1,
            gas_used: 0,
            gas_limit: 10_000_000,
            timestamp_ms: 1000,
            coherence: 1.0,
        };
        assert!(header.validate().is_ok());

        header.gas_limit = 0;
        assert!(header.validate().is_err());

        header.gas_limit = MAX_GAS_LIMIT + 1;
        assert!(header.validate().is_err());

        header.gas_limit = 10_000_000;
        header.gas_used = 20_000_000;
        assert!(header.validate().is_err());

        header.gas_used = 0;
        header.base_fee = 0;
        assert!(header.validate().is_err());

        header.base_fee = 1;
        header.proposer_pk = vec![0u8; 31];
        assert!(header.validate().is_err());
    }

    #[test]
    fn test_tx_root_empty() {
        let root = tx_root(&[]);
        assert!(root.is_zero());
    }

    #[test]
    fn test_tx_root_deterministic() {
        let tx1 = vec![1, 2, 3];
        let tx2 = vec![4, 5, 6];
        let txs = vec![tx1.clone(), tx2.clone()];
        let root1 = tx_root(&txs);
        let txs2 = vec![tx2, tx1];
        let root2 = tx_root(&txs2);
        assert_ne!(root1, root2);
    }

    // ── Quantum tests ──────────────────────────────────────────────────
    #[test]
    fn test_quantum_state_initialization() {
        let state = QuantumProtocolState::new();
        assert!((state.purity - 1.0).abs() < 1e-10);
        assert!((state.entropy - 0.0).abs() < 1e-10);
        assert!(state.is_valid);
    }

    #[test]
    fn test_record_pass_decoheres() {
        let mut state = QuantumProtocolState::new();
        let initial_purity = state.purity;
        state.record_pass();
        assert!(state.purity < initial_purity);
        assert_eq!(state.total_checks, 1);
    }

    #[test]
    fn test_record_failure_stronger() {
        let mut state1 = QuantumProtocolState::new();
        let mut state2 = QuantumProtocolState::new();
        state1.record_pass();
        state2.record_failure();
        assert!(state2.purity < state1.purity);
        assert_eq!(state2.checks_failed, 1);
    }

    #[test]
    fn test_header_validate_quantum_ok() {
        let header = BlockHeader {
            height: Height(1),
            round: Round(0),
            parent_id: Hash32::zero(),
            state_root: Hash32::zero(),
            tx_root: Hash32::zero(),
            proposer_pk: vec![0u8; 32],
            proposer_addr: "proposer".into(),
            base_fee: 1,
            gas_used: 0,
            gas_limit: 10_000_000,
            timestamp_ms: 1000,
            coherence: 1.0,
        };
        let (result, qstate) = header.validate_quantum();
        assert!(result.is_ok());
        assert!(qstate.total_checks > 0);
        assert!(qstate.purity < 1.0);
    }

    #[test]
    fn test_header_validate_quantum_failure() {
        let header = BlockHeader {
            height: Height(0),
            round: Round(0),
            parent_id: Hash32([1u8; HASH_SIZE]),
            state_root: Hash32::zero(),
            tx_root: Hash32::zero(),
            proposer_pk: vec![0u8; 32],
            proposer_addr: "proposer".into(),
            base_fee: 1,
            gas_used: 0,
            gas_limit: 10_000_000,
            timestamp_ms: 1000,
            coherence: 1.0,
        };
        let (result, qstate) = header.validate_quantum();
        assert!(result.is_err());
        assert!(qstate.checks_failed > 0);
    }

    #[test]
    fn test_block_validate_quantum() {
        let header = BlockHeader {
            height: Height(1),
            round: Round(0),
            parent_id: Hash32::zero(),
            state_root: Hash32::zero(),
            tx_root: tx_root(&[vec![1, 2, 3]]),
            proposer_pk: vec![0u8; 32],
            proposer_addr: "proposer".into(),
            base_fee: 1,
            gas_used: 0,
            gas_limit: 10_000_000,
            timestamp_ms: 1000,
            coherence: 1.0,
        };
        let block = Block {
            header,
            txs: vec![vec![1, 2, 3]],
            coherence: 1.0,
        };
        let (result, qstate) = block.validate_quantum();
        assert!(result.is_ok());
        assert!(qstate.total_checks > 0);
    }

    #[test]
    fn test_id_quantum() {
        let header = BlockHeader {
            height: Height(1),
            round: Round(0),
            parent_id: Hash32::zero(),
            state_root: Hash32::zero(),
            tx_root: Hash32::zero(),
            proposer_pk: vec![0u8; 32],
            proposer_addr: "proposer".into(),
            base_fee: 1,
            gas_used: 0,
            gas_limit: 10_000_000,
            timestamp_ms: 1000,
            coherence: 1.0,
        };
        let (id, qstate) = header.id_quantum();
        assert!(!id.is_zero());
        assert!(qstate.crypto_coherence < 1.0);
    }

    #[test]
    fn test_hash_fidelity() {
        let a = Hash32([1u8; HASH_SIZE]);
        let b = Hash32([1u8; HASH_SIZE]);
        let c = Hash32([2u8; HASH_SIZE]);
        assert!((hash_fidelity(&a, &b) - 1.0).abs() < 1e-10);
        assert!((hash_fidelity(&a, &c) - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_receipt_validate_quantum() {
        let receipt = Receipt {
            tx_hash: Hash32::zero(),
            success: true,
            gas_used: 21000,
            logs: vec![],
            output: vec![],
            coherence: 1.0,
        };
        let (result, qstate) = receipt.validate_quantum();
        assert!(result.is_ok());
        assert!(qstate.total_checks > 0);
    }

    #[test]
    fn test_manager_parse() {
        let mgr = TypeManager::default();
        let h = mgr.parse_height("42").unwrap();
        assert_eq!(h.as_u64(), 42);
        let r = mgr.parse_round("5").unwrap();
        assert_eq!(r.as_u32(), 5);
        let hash = mgr.parse_hash("0x0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        assert!(hash.is_zero());
    }

    #[test]
    fn test_manager_quantum() {
        let mgr = TypeManager::default();
        let mut state = mgr.new_quantum_state();
        assert!((state.purity - 1.0).abs() < 1e-10);
        mgr.record_pass(&mut state);
        assert!(state.purity < 1.0);
        mgr.apply_crypto_decoherence(&mut state);
        assert!(state.crypto_coherence < 1.0);
        let snap = mgr.metrics_snapshot();
        assert!(snap.quantum_states_created > 0);
        assert!(snap.quantum_checks_passed > 0);
    }
}
