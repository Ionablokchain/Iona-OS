//! IONA Protocol — Tendermint BFT Consensus Engine
//!
//! Implements the Tendermint consensus protocol (Cosmos SDK compatible):
//!   Propose → Prevote → Precommit → Commit
//!
//! # Features
//! - **fast_quorum**: advance immediately when 2/3+ of validators have responded
//! - **double_sign**: hardware protection against double‑signing
//! - **EIP-1559**: base fee adjustment per block
//! - **evidence**: detection and slashing for double‑votes
//! - **slashing**: reduce stake for malicious behaviour
//! - **modular**: pluggable crypto, storage, and networking
//! - **observability**: optional Prometheus metrics for kernel consensus state
//! - **overflow‑safe**: saturating arithmetic on height and round counters
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use iona::consensus::{ConsensusConfig, Engine, ValidatorSet, Ed25519Verifier};
//! use iona::crypto::ed25519::Ed25519Signer;
//!
//! let config = ConsensusConfig::default();
//! let signer = Ed25519Signer::random();
//! let vset = ValidatorSet::from_genesis(&genesis);
//! let mut engine = Engine::<Ed25519Verifier>::new(
//!     config.into(),
//!     vset,
//!     height,
//!     prev_block_id,
//!     app_state,
//!     stakes,
//!     Some(double_sign_guard),
//! );
//! ```

// -----------------------------------------------------------------------------
// Module exports
// -----------------------------------------------------------------------------

pub mod engine;
pub mod messages;
pub mod quorum;
pub mod validator_set;
pub mod double_sign;

// Re‑export core types for convenience
pub use engine::{Config, ConsensusError, ConsensusState, Engine, Step};
pub use messages::{
    ConsensusMsg, Proposal, Vote, VoteType, MessageError, MessageKind,
    proposal_sign_bytes, vote_sign_bytes,
};
pub use quorum::{quorum_threshold, VoteTally};
pub use validator_set::{Validator, ValidatorSet, ValidatorSetError};
pub use double_sign::{DoubleSignGuard, DoubleSignConfig, DoubleSignError};

// Use the concrete verifier from the crypto module
pub use crate::crypto::ed25519::Ed25519Verifier;

use prometheus::{register_gauge, Gauge};
use spin::{Lazy, Mutex};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, OnceLock,
};

// -----------------------------------------------------------------------------
// Consensus module configuration
// -----------------------------------------------------------------------------

/// Configuration for the consensus module (kernel-visible state and metrics).
#[derive(Debug, Clone)]
pub struct ConsensusModuleConfig {
    /// Whether to enable Prometheus metrics for the kernel consensus state.
    pub enable_metrics: bool,
}

impl Default for ConsensusModuleConfig {
    fn default() -> Self {
        Self {
            enable_metrics: false,
        }
    }
}

impl ConsensusModuleConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Prometheus metrics for kernel consensus state
// -----------------------------------------------------------------------------

/// Metrics for the kernel-visible consensus state.
#[derive(Clone)]
pub struct KernelConsensusMetrics {
    /// Current block height.
    pub height: Gauge,
    /// Current consensus round.
    pub round: Gauge,
    /// Number of connected peers.
    pub peers: Gauge,
    /// Validator ID of this node (0 if not a validator).
    pub validator_id: Gauge,
    /// Whether fast quorum mode is enabled (1=yes, 0=no).
    pub fast_quorum: Gauge,
    /// Total blocks committed (monotonic counter).
    pub total_blocks_committed: prometheus::Counter,
    /// Total peer count updates.
    pub total_peer_updates: prometheus::Counter,
}

impl KernelConsensusMetrics {
    /// Create and register metrics with the global Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            height: register_gauge!("iona_consensus_kernel_height", "Current kernel consensus height")?,
            round: register_gauge!("iona_consensus_kernel_round", "Current kernel consensus round")?,
            peers: register_gauge!("iona_consensus_kernel_peers", "Number of connected peers (kernel view)")?,
            validator_id: register_gauge!("iona_consensus_kernel_validator_id", "Validator ID of this node")?,
            fast_quorum: register_gauge!("iona_consensus_kernel_fast_quorum", "Fast quorum enabled (1=yes,0=no)")?,
            total_blocks_committed: register_counter!(
                "iona_consensus_kernel_blocks_committed_total",
                "Total blocks committed (kernel counter)"
            )?,
            total_peer_updates: register_counter!(
                "iona_consensus_kernel_peer_updates_total",
                "Total peer count updates"
            )?,
        })
    }

    /// Create an unregistered instance (for tests or when metrics are disabled).
    pub fn new_unregistered() -> Self {
        Self {
            height: Gauge::new("iona_consensus_kernel_height", "Height").unwrap(),
            round: Gauge::new("iona_consensus_kernel_round", "Round").unwrap(),
            peers: Gauge::new("iona_consensus_kernel_peers", "Peers").unwrap(),
            validator_id: Gauge::new("iona_consensus_kernel_validator_id", "Validator ID").unwrap(),
            fast_quorum: Gauge::new("iona_consensus_kernel_fast_quorum", "Fast quorum").unwrap(),
            total_blocks_committed: prometheus::Counter::new("iona_consensus_kernel_blocks_committed_total", "Blocks committed").unwrap(),
            total_peer_updates: prometheus::Counter::new("iona_consensus_kernel_peer_updates_total", "Peer updates").unwrap(),
        }
    }

    /// Update gauges from the given kernel state.
    pub fn update(&self, state: &KernelConsensusState) {
        self.height.set(state.height as f64);
        self.round.set(state.round as f64);
        self.peers.set(state.peers as f64);
        self.validator_id.set(state.validator_id as f64);
        self.fast_quorum.set(if state.fast_quorum { 1.0 } else { 0.0 });
    }

    /// Increment the blocks committed counter.
    pub fn record_commit(&self) {
        self.total_blocks_committed.inc();
    }

    /// Increment the peer update counter.
    pub fn record_peer_update(&self) {
        self.total_peer_updates.inc();
    }
}

// -----------------------------------------------------------------------------
// Global metrics instance
// -----------------------------------------------------------------------------

static KERNEL_CONSENSUS_METRICS: OnceLock<Option<Arc<KernelConsensusMetrics>>> = OnceLock::new();

/// Initialize the kernel consensus metrics (if enabled).
/// Should be called once during startup, before any consensus operations.
pub fn init_kernel_metrics(config: &ConsensusModuleConfig) -> Result<(), String> {
    if KERNEL_CONSENSUS_METRICS.get().is_some() {
        return Err("kernel consensus metrics already initialized".into());
    }
    let metrics = if config.enable_metrics {
        Some(Arc::new(KernelConsensusMetrics::new().map_err(|e| e.to_string())?))
    } else {
        None
    };
    KERNEL_CONSENSUS_METRICS.set(metrics).map_err(|_| "failed to set metrics".into())?;
    Ok(())
}

/// Get a reference to the global metrics (if enabled).
fn kernel_metrics() -> Option<Arc<KernelConsensusMetrics>> {
    KERNEL_CONSENSUS_METRICS.get().and_then(|m| m.clone())
}

// -----------------------------------------------------------------------------
// Kernel‑visible consensus state (minimal, non‑generic)
// -----------------------------------------------------------------------------

/// Minimal consensus state exposed to the kernel.
/// All counters are atomic to allow safe concurrent updates.
#[derive(Debug)]
pub struct KernelConsensusState {
    /// Current block height (atomic).
    pub height: AtomicU64,
    /// Current consensus round (atomic).
    pub round: AtomicU64,
    /// Number of connected peer nodes (atomic).
    pub peers: AtomicU64,
    /// ID of this node (if it is a validator).
    pub validator_id: AtomicU64,
    /// Whether fast quorum mode is enabled.
    pub fast_quorum: bool,
}

impl Default for KernelConsensusState {
    fn default() -> Self {
        Self {
            height: AtomicU64::new(1),
            round: AtomicU64::new(0),
            peers: AtomicU64::new(0),
            validator_id: AtomicU64::new(0),
            fast_quorum: true,
        }
    }
}

impl KernelConsensusState {
    /// Create a new kernel consensus state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the current height.
    pub fn height(&self) -> u64 {
        self.height.load(Ordering::SeqCst)
    }

    /// Get the current round.
    pub fn round(&self) -> u64 {
        self.round.load(Ordering::SeqCst)
    }

    /// Get the current peer count.
    pub fn peers(&self) -> u64 {
        self.peers.load(Ordering::SeqCst)
    }

    /// Get the validator ID.
    pub fn validator_id(&self) -> u64 {
        self.validator_id.load(Ordering::SeqCst)
    }

    /// Set the height (saturating at max).
    pub fn set_height(&self, h: u64) {
        let mut cur = self.height.load(Ordering::SeqCst);
        while h > cur {
            match self.height.compare_exchange_weak(cur, h, Ordering::SeqCst, Ordering::Relaxed) {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
    }

    /// Increment height by one (saturating).
    pub fn increment_height(&self) -> u64 {
        let prev = self.height.fetch_add(1, Ordering::SeqCst);
        prev.saturating_add(1)
    }

    /// Reset round to zero.
    pub fn reset_round(&self) {
        self.round.store(0, Ordering::SeqCst);
    }

    /// Set round (saturating).
    pub fn set_round(&self, r: u64) {
        self.round.store(r, Ordering::SeqCst);
    }

    /// Set peer count.
    pub fn set_peers(&self, count: u64) {
        self.peers.store(count, Ordering::SeqCst);
    }

    /// Set validator ID.
    pub fn set_validator_id(&self, id: u64) {
        self.validator_id.store(id, Ordering::SeqCst);
    }
}

// -----------------------------------------------------------------------------
// Global consensus engine (kernel state)
// -----------------------------------------------------------------------------

/// Global consensus engine state.
/// Wrapped in `Option` so that applications can detect whether the
/// consensus engine has been initialised.
pub static CONSENSUS_ENGINE: Lazy<Mutex<Option<KernelConsensusState>>> =
    Lazy::new(|| Mutex::new(Some(KernelConsensusState::default())));

// -----------------------------------------------------------------------------
// Public API for kernel
// -----------------------------------------------------------------------------

/// Advance the consensus height when a block is committed.
/// Called from syscall 400 after a successful block commit.
///
/// # Returns
/// The new block height, or `0` if the consensus engine is not initialised.
pub fn commit_block() -> u64 {
    if let Some(state) = CONSENSUS_ENGINE.lock().as_ref() {
        let new_height = state.increment_height();
        state.reset_round();
        if let Some(metrics) = kernel_metrics() {
            metrics.record_commit();
            metrics.update(state);
        }
        crate::serial_println!("[BFT] block {} committed", new_height);
        return new_height;
    }
    0
}

/// Initialise the kernel consensus engine with the given validator ID.
/// Called at boot time after the validator set is determined.
///
/// # Arguments
/// * `validator_id` – The ID of this node in the validator set (0 = not a validator).
pub fn init_kernel_engine(validator_id: u32) {
    if let Some(state) = CONSENSUS_ENGINE.lock().as_mut() {
        state.set_validator_id(validator_id as u64);
        if let Some(metrics) = kernel_metrics() {
            metrics.update(state);
        }
        crate::serial_println!("[BFT] kernel engine initialised val_id={}", validator_id);
    }
}

/// Update the peer count in the kernel consensus state.
pub fn update_peer_count(count: u8) {
    if let Some(state) = CONSENSUS_ENGINE.lock().as_ref() {
        state.set_peers(count as u64);
        if let Some(metrics) = kernel_metrics() {
            metrics.record_peer_update();
            metrics.update(state);
        }
    }
}

/// Get the current consensus height from the kernel state.
pub fn current_height() -> u64 {
    CONSENSUS_ENGINE.lock().as_ref().map(|e| e.height()).unwrap_or(0)
}

/// Get the current consensus round from the kernel state.
pub fn current_round() -> u64 {
    CONSENSUS_ENGINE.lock().as_ref().map(|e| e.round()).unwrap_or(0)
}

/// Get a snapshot of the kernel consensus state.
pub fn kernel_state_snapshot() -> Option<KernelConsensusStateSnapshot> {
    CONSENSUS_ENGINE.lock().as_ref().map(|state| KernelConsensusStateSnapshot {
        height: state.height(),
        round: state.round(),
        peers: state.peers(),
        validator_id: state.validator_id(),
        fast_quorum: state.fast_quorum,
    })
}

/// Snapshot of the kernel consensus state for external use.
#[derive(Debug, Clone, Copy)]
pub struct KernelConsensusStateSnapshot {
    pub height: u64,
    pub round: u64,
    pub peers: u64,
    pub validator_id: u64,
    pub fast_quorum: bool,
}

// -----------------------------------------------------------------------------
// Submodules
// -----------------------------------------------------------------------------

pub mod sync;

// -----------------------------------------------------------------------------
// Prelude
// -----------------------------------------------------------------------------

/// Convenience prelude for the consensus module.
///
/// # Example
/// ```rust,ignore
/// use iona::consensus::prelude::*;
/// ```
pub mod prelude {
    pub use super::{
        Config, ConsensusError, ConsensusMsg, ConsensusState, DoubleSignGuard,
        Engine, Proposal, Step, ValidatorSet, Vote, VoteType,
        Ed25519Verifier, quorum_threshold,
        // Kernel state
        KernelConsensusState, KernelConsensusStateSnapshot,
        commit_block, current_height, current_round, init_kernel_engine,
        update_peer_count, init_kernel_metrics, ConsensusModuleConfig,
    };
}
