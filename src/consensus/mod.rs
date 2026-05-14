//! IONA Protocol — Tendermint BFT Consensus Engine
//!
//! Implementează protocolul Tendermint (Cosmos SDK compatible):
//!   Propose → Prevote → Precommit → Commit
//!
//! Features:
//!   fast_quorum: avanseaza imediat cand 2/3+ validatori au raspuns
//!   double_sign: protectie hardware impotriva double-signing
//!   EIP-1559: base fee adjustment per bloc
//!   evidence: detectie si penalizare double-vote
//!   slashing: reducere stake pentru comportament malitios

pub mod engine;
pub mod messages;
pub mod quorum;
pub mod validator_set;
pub mod double_sign;

use spin::{Lazy, Mutex};

/// Kernel-visible consensus state — minimal, non-generic
/// All GUI apps read height via: CONSENSUS_ENGINE.lock().as_ref().map(|e| e.height)
pub struct KernelConsensusState {
    pub height:       u64,
    pub round:        u32,
    pub peers:        u8,
    pub validator_id: u32,
    pub fast_quorum:  bool,
}
impl KernelConsensusState {
    pub fn new() -> Self {
        Self { height: 1, round: 0, peers: 0, validator_id: 0, fast_quorum: true }
    }
}

/// Global consensus engine state — Option so apps detect if initialized
pub static CONSENSUS_ENGINE: Lazy<Mutex<Option<KernelConsensusState>>> =
    Lazy::new(|| Mutex::new(Some(KernelConsensusState::new())));

/// Advance height on block commit — called from syscall 400
pub fn commit_block() -> u64 {
    if let Some(ref mut e) = *CONSENSUS_ENGINE.lock() {
        e.height += 1; e.round = 0;
        crate::serial_println!("[BFT] block {} committed", e.height);
        return e.height;
    }
    0
}

/// Initialize with validator config — called at boot
pub fn init_kernel_engine(validator_id: u32) {
    if let Some(ref mut e) = *CONSENSUS_ENGINE.lock() {
        e.validator_id = validator_id;
        crate::serial_println!("[BFT] kernel engine initialized val_id={}", validator_id);
    }
}

pub mod sync;
