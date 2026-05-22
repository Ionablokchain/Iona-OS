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

pub mod engine;
pub mod messages;
pub mod quorum;
pub mod validator_set;
pub mod double_sign;

use spin::{Lazy, Mutex};

// -----------------------------------------------------------------------------
// Kernel‑visible consensus state (minimal, non‑generic)
// -----------------------------------------------------------------------------

/// Minimal consensus state exposed to the kernel.
/// GUI applications can read the current height via:
/// `CONSENSUS_ENGINE.lock().as_ref().map(|e| e.height)`
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

impl KernelConsensusState {
    /// Create a new consensus state with default values.
    pub fn new() -> Self {
        Self {
            height: 1,
            round: 0,
            peers: 0,
            validator_id: 0,
            fast_quorum: true,
        }
    }
}

/// Global consensus engine state.
/// Wrapped in `Option` so that applications can detect whether the
/// consensus engine has been initialised.
pub static CONSENSUS_ENGINE: Lazy<Mutex<Option<KernelConsensusState>>> =
    Lazy::new(|| Mutex::new(Some(KernelConsensusState::new())));

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

// -----------------------------------------------------------------------------
// Submodules
// -----------------------------------------------------------------------------

pub mod sync;
