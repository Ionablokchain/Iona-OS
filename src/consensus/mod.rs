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

// -----------------------------------------------------------------------------
// Kernel‑visible consensus state (minimal, non‑generic)
// -----------------------------------------------------------------------------

/// Minimal consensus state exposed to the kernel.
/// GUI applications can read the current height via:
/// `CONSENSUS_ENGINE.lock().as_ref().map(|e| e.height)`
#[derive(Debug, Clone)]
pub struct KernelConsensusState {
    /// Current block height.
    pub height: u64,
    /// Current consensus round (0, 1, 2, ...).
    pub round: u32,
    /// Number of connected peer nodes.
    pub peers: u8,
    /// ID of this node (if it is a validator).
    pub validator_id: u32,
    /// Whether fast quorum mode is enabled.
    pub fast_quorum: bool,
}

impl Default for KernelConsensusState {
    fn default() -> Self {
        Self {
            height: 1,
            round: 0,
            peers: 0,
            validator_id: 0,
            fast_quorum: true,
        }
    }
}

// -----------------------------------------------------------------------------
// Global consensus engine
// -----------------------------------------------------------------------------

use spin::{Lazy, Mutex};

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
    if let Some(ref mut e) = *CONSENSUS_ENGINE.lock() {
        e.height += 1;
        e.round = 0;
        crate::serial_println!("[BFT] block {} committed", e.height);
        return e.height;
    }
    0
}

/// Initialise the kernel consensus engine with the given validator ID.
/// Called at boot time after the validator set is determined.
///
/// # Arguments
/// * `validator_id` – The ID of this node in the validator set (0 = not a validator).
pub fn init_kernel_engine(validator_id: u32) {
    if let Some(ref mut e) = *CONSENSUS_ENGINE.lock() {
        e.validator_id = validator_id;
        crate::serial_println!("[BFT] kernel engine initialised val_id={}", validator_id);
    }
}

/// Update the peer count in the kernel consensus state.
pub fn update_peer_count(count: u8) {
    if let Some(ref mut e) = *CONSENSUS_ENGINE.lock() {
        e.peers = count;
    }
}

/// Get the current consensus height from the kernel state.
pub fn current_height() -> u64 {
    CONSENSUS_ENGINE.lock().as_ref().map(|e| e.height).unwrap_or(0)
}

/// Get the current consensus round from the kernel state.
pub fn current_round() -> u32 {
    CONSENSUS_ENGINE.lock().as_ref().map(|e| e.round).unwrap_or(0)
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
    };
}
