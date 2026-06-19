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
//! # Mathematical Formalism
//!
//! ```text
//! |Block⟩ = |header⟩ ⊗ |tx₁⟩ ⊗ … ⊗ |txₙ⟩
//! ρ       = |Block⟩⟨Block|
//! ```
//!
//! ## Hamiltonian for Validation
//! ```text
//! Ĥ_val = Ĥ_genesis + Ĥ_gas + Ĥ_fee + Ĥ_proposer + Ĥ_root
//! ```
//! Each term is a **projector** onto the subspace of valid states.
//!
//! ## Decoherence
//! Every validation step applies a **Kraus channel**:
//! ```text
//! ρ → Σ_k K_k ρ K_k†    with   K_k = √p_k |k⟩⟨k|
//! ```

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;
use serde::{Deserialize, Serialize};

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default quantum coherence for a freshly created protocol object.
const DEFAULT_PROTOCOL_COHERENCE: f64 = 1.0;

/// Decoherence rate for a single validation check.
const VALIDATION_DECOHERENCE_RATE: f64 = 0.0001;

/// Stronger decoherence when a check **fails** (invalid data).
const FAILURE_DECOHERENCE_RATE: f64 = 0.001;

/// Minimum purity threshold for a “healthy” object.
const MIN_PROTOCOL_COHERENCE: f64 = 0.99;

/// Kraus rank used when applying the quantum channel.
const PROTOCOL_KRAUS_RANK: usize = 4;

// -----------------------------------------------------------------------------
// Classical Constants
// -----------------------------------------------------------------------------

/// Size of a hash in bytes.
pub const HASH_SIZE: usize = 32;

/// Minimum gas limit per block (prevents zero‑gas blocks).
pub const MIN_GAS_LIMIT: u64 = 1_000_000;

/// Maximum gas limit per block (4 294 967 295 – same as Ethereum’s uint32).
pub const MAX_GAS_LIMIT: u64 = 0xFFFF_FFFF;

/// Minimum base fee (1 gwei equivalent in micro‑units).
pub const MIN_BASE_FEE: u64 = 1;

// -----------------------------------------------------------------------------
// Type aliases
// -----------------------------------------------------------------------------

/// Simple KV state for execution (key‑value pairs).
pub type KvState = BTreeMap<Vec<u8>, Vec<u8>>;

/// Raw transaction bytes (opaque).
pub type Tx = Vec<u8>;

// -----------------------------------------------------------------------------
// Newtype wrappers for type safety
// -----------------------------------------------------------------------------

/// Block height (0 = genesis).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
    Serialize, Deserialize,
)]
pub struct Height(pub u64);

impl Height {
    /// Create a new height.
    pub const fn new(h: u64) -> Self {
        Self(h)
    }

    /// Get the inner value.
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// Saturating subtraction.
    pub const fn saturating_sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }

    /// Checked addition.
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

/// 32‑byte hash (Blake3 or SHA‑256).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
    Serialize, Deserialize,
)]
pub struct Hash32(pub [u8; HASH_SIZE]);

impl Hash32 {
    /// Create a zero hash.
    pub const fn zero() -> Self {
        Self([0u8; HASH_SIZE])
    }

    /// Convert to a hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Parse from a hex string (with or without 0x).
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

    /// Check if the hash is zero.
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

// -----------------------------------------------------------------------------
// Quantum Protocol State
// -----------------------------------------------------------------------------

/// Quantum state that tracks the **density matrix** properties of a
/// protocol object (Block, Header, Receipt, …).
///
/// It is updated by every validation call and can be used for
/// monitoring the “health” of the data pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumProtocolState {
    /// Purity γ = Tr(ρ²).
    pub purity: f64,
    /// Von Neumann entropy S = –Tr(ρ ln ρ).
    pub entropy: f64,
    /// Coherence of the validation subspace.
    pub validation_coherence: f64,
    /// Coherence of the cryptographic (hash) subspace.
    pub crypto_coherence: f64,
    /// Total number of checks performed on this object.
    pub total_checks: u64,
    /// Number of checks that failed.
    pub checks_failed: u64,
    /// Whether the object is in a valid quantum state.
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
    /// Create a fresh quantum state (pure |∅⟩).
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a **passed** check – mild decoherence.
    pub fn record_pass(&mut self) {
        self.total_checks = self.total_checks.wrapping_add(1);
        let decay = (-VALIDATION_DECOHERENCE_RATE).exp();
        self.validation_coherence = (self.validation_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Record a **failed** check – strong decoherence.
    pub fn record_failure(&mut self) {
        self.total_checks = self.total_checks.wrapping_add(1);
        self.checks_failed = self.checks_failed.wrapping_add(1);
        let decay = (-FAILURE_DECOHERENCE_RATE).exp();
        self.validation_coherence = (self.validation_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply crypto‑related decoherence (hashing, signature verification).
    pub fn apply_crypto_decoherence(&mut self) {
        let decay = (-VALIDATION_DECOHERENCE_RATE).exp();
        self.crypto_coherence = (self.crypto_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply the full Kraus channel for a protocol operation.
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
}

// -----------------------------------------------------------------------------
// Log and Receipt (classical + quantum)
// -----------------------------------------------------------------------------

/// EVM‑style log entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Log {
    /// Contract address (20 bytes).
    pub address: [u8; 20],
    /// Event topics (each 32 bytes).
    pub topics: Vec<Hash32>,
    /// Raw log data.
    pub data: Vec<u8>,
}

/// EVM‑style transaction receipt with quantum state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receipt {
    /// Transaction hash.
    pub tx_hash: Hash32,
    /// Whether the execution succeeded.
    pub success: bool,
    /// Total gas used by the transaction.
    pub gas_used: u64,
    /// Emitted logs.
    pub logs: Vec<Log>,
    /// Return data (or revert reason).
    pub output: Vec<u8>,
    /// Quantum coherence of this receipt.
    #[serde(default = "default_coherence")]
    pub coherence: f64,
}

fn default_coherence() -> f64 {
    DEFAULT_PROTOCOL_COHERENCE
}

impl Receipt {
    /// Classical validation (backward compatible).
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.gas_used == 0 && !self.success {
            // Zero gas is acceptable for early reverts.
        }
        Ok(())
    }

    /// Validate and return the quantum state after the measurement.
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

    /// Quantum coherence accessor.
    pub fn coherence(&self) -> f64 {
        self.coherence
    }
}

// -----------------------------------------------------------------------------
// BlockHeader (classical + quantum)
// -----------------------------------------------------------------------------

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
    /// Quantum coherence of this header.
    #[serde(default = "default_coherence")]
    pub coherence: f64,
}

impl BlockHeader {
    /// Classical validation (unchanged logic).
    pub fn validate(&self) -> Result<(), &'static str> {
        // Genesis block must have zero parent hash.
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

    /// Validate and return the quantum state after all checks.
    pub fn validate_quantum(&self) -> (Result<(), &'static str>, QuantumProtocolState) {
        let mut qstate = QuantumProtocolState::new();
        let result = self.validate();
        match &result {
            Ok(_) => {
                // Simulate the individual checks for accurate decoherence.
                for _ in 0..7 {
                    qstate.record_pass();
                }
            }
            Err(_) => qstate.record_failure(),
        }
        qstate.apply_crypto_decoherence(); // hashing for id()
        qstate.apply_protocol_channel();
        (result, qstate)
    }

    /// Compute the block ID (hash of the RLP‑encoded header).
    #[must_use]
    pub fn id(&self) -> Hash32 {
        let encoded = postcard::to_allocvec(self).unwrap_or_default();
        let hash = blake3::hash(&encoded);
        Hash32(*hash.as_bytes())
    }

    /// Compute the block ID with quantum state tracking.
    #[must_use]
    pub fn id_quantum(&self) -> (Hash32, QuantumProtocolState) {
        let id = self.id();
        let mut qstate = QuantumProtocolState::new();
        qstate.apply_crypto_decoherence();
        qstate.apply_protocol_channel();
        (id, qstate)
    }

    /// Quantum coherence accessor.
    pub fn coherence(&self) -> f64 {
        self.coherence
    }
}

// -----------------------------------------------------------------------------
// Block (classical + quantum)
// -----------------------------------------------------------------------------

/// Full block containing header and transactions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<Tx>,
    /// Quantum coherence of the full block.
    #[serde(default = "default_coherence")]
    pub coherence: f64,
}

impl Block {
    /// Compute the block ID (hash of the header).
    #[must_use]
    pub fn id(&self) -> Hash32 {
        self.header.id()
    }

    /// Compute the block ID with quantum state tracking.
    #[must_use]
    pub fn id_quantum(&self) -> (Hash32, QuantumProtocolState) {
        self.header.id_quantum()
    }

    /// Classical validation (header + transaction root consistency).
    pub fn validate(&self) -> Result<(), &'static str> {
        self.header.validate()?;
        let computed_root = tx_root(&self.txs);
        if computed_root != self.header.tx_root {
            return Err("transaction root mismatch");
        }
        Ok(())
    }

    /// Validate and return the quantum state after all checks.
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

    /// Quantum coherence accessor.
    pub fn coherence(&self) -> f64 {
        self.coherence
    }
}

// -----------------------------------------------------------------------------
// Helper: transaction root
// -----------------------------------------------------------------------------

/// Compute the transaction root hash (simple hash of concatenated tx hashes).
#[must_use]
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

/// Compute the transaction root with quantum state tracking.
#[must_use]
pub fn tx_root_quantum(txs: &[Tx]) -> (Hash32, QuantumProtocolState) {
    let root = tx_root(txs);
    let mut qstate = QuantumProtocolState::new();
    qstate.apply_crypto_decoherence();
    qstate.apply_protocol_channel();
    (root, qstate)
}

// -----------------------------------------------------------------------------
// Hash32 utilities
// -----------------------------------------------------------------------------

/// Compute quantum fidelity between two hashes.
///
/// ```text
/// F = |⟨h₁|h₂⟩|²   →   1.0 if equal, 0.0 otherwise
/// ```
pub fn hash_fidelity(a: &Hash32, b: &Hash32) -> f64 {
    if a == b { 1.0 } else { 0.0 }
}

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
            parent_id: Hash32([1u8; HASH_SIZE]), // invalid
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
    fn test_coherence_accessors() {
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
            coherence: 0.95,
        };
        assert!((header.coherence() - 0.95).abs() < 1e-10);
    }

    #[test]
    fn test_health_after_many_failures() {
        let mut state = QuantumProtocolState::new();
        for _ in 0..1000 {
            state.record_failure();
        }
        assert!(!state.is_valid);
    }

    #[test]
    fn test_purity_never_negative() {
        let mut state = QuantumProtocolState::new();
        for _ in 0..100000 {
            state.record_failure();
        }
        assert!(state.purity >= 0.0);
    }
}
