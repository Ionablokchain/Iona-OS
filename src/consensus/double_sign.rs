//! Double‑sign guard — prevents signing two conflicting messages at the same height/round.
//!
//! This module provides a persistent guard that records every signed consensus message
//! (proposals and votes). Before signing a new message, the guard checks whether a
//! conflicting message has already been signed for the same height and round.
//!
//! The state is persisted to IONAFS, so protection survives node restarts.
//!
//! # Usage
//!
//! ```rust,ignore
//! let mut guard = DoubleSignGuard::new("/data/consensus/double_sign_guard.bin");
//! guard.check_proposal(height, round, &block_id)?;
//! let signature = sign_proposal(...);
//! guard.record_proposal(height, round, &block_id)?;
//! ```

use alloc::{collections::BTreeSet, format, string::String, vec::Vec};
use core::cmp::Ordering;
use serde::{Serialize, Deserialize};
use crate::types::{Hash32, Height, Round};
use super::messages::VoteType;

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

#[derive(Debug, thiserror_no_std::Error)]
pub enum DoubleSignError {
    #[error("double‑sign detected: already signed a conflicting message for this height/round")]
    Conflict,
    #[error("I/O error while persisting guard state: {0}")]
    Io(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

// -----------------------------------------------------------------------------
// Signed key: what we have already signed
// -----------------------------------------------------------------------------

/// Uniquely identifies a signed consensus message.
/// Used to detect conflicts: two messages at the same height and round
/// with different block hashes are a double‑sign.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
enum SignedKey {
    Proposal {
        height: Height,
        round: Round,
        block_id: Hash32,
    },
    Vote {
        vote_type: u8,          // VoteType as u8 (0: prevote, 1: precommit)
        height: Height,
        round: Round,
        block_id: Option<Hash32>, // None = nil vote
    },
}

impl SignedKey {
    /// Returns the height and round for this key.
    fn height_round(&self) -> (Height, Round) {
        match self {
            SignedKey::Proposal { height, round, .. } => (*height, *round),
            SignedKey::Vote { height, round, .. } => (*height, *round),
        }
    }

    /// Returns the block hash (if any) for this key.
    fn block_hash(&self) -> Option<&Hash32> {
        match self {
            SignedKey::Proposal { block_id, .. } => Some(block_id),
            SignedKey::Vote { block_id, .. } => block_id.as_ref(),
        }
    }
}

// -----------------------------------------------------------------------------
// Double‑sign guard
// -----------------------------------------------------------------------------

/// Persistent guard that prevents double‑signing.
pub struct DoubleSignGuard {
    /// Set of all keys already signed.
    signed: BTreeSet<SignedKey>,
    /// Path in IONAFS where the guard state is persisted.
    path: String,
}

impl DoubleSignGuard {
    /// Create a new guard, loading any previously persisted state.
    pub fn new(path: &str) -> Self {
        let mut guard = Self {
            signed: BTreeSet::new(),
            path: path.into(),
        };
        guard.load().unwrap_or_else(|e| {
            crate::serial_println!("[DS_GUARD] warning: could not load previous state: {}", e);
        });
        guard
    }

    /// Load persisted state from IONAFS.
    fn load(&mut self) -> Result<(), DoubleSignError> {
        let data = crate::fs::ionafs::read(&self.path);
        let data = match data {
            Some(d) => d,
            None => return Ok(()), // no previous state
        };
        self.signed = postcard::from_bytes(&data)
            .map_err(|e| DoubleSignError::Serialization(e.to_string()))?;
        crate::serial_println!("[DS_GUARD] loaded {} guard entries", self.signed.len());
        Ok(())
    }

    /// Persist the current guard state to IONAFS.
    fn persist(&self) -> Result<(), DoubleSignError> {
        let data = postcard::to_vec(&self.signed)
            .map_err(|e| DoubleSignError::Serialization(e.to_string()))?;
        crate::fs::ionafs::write(&self.path, &data);
        Ok(())
    }

    /// Check whether signing a proposal would cause a double‑sign.
    pub fn check_proposal(&self, height: Height, round: Round, block_id: &Hash32) -> Result<(), DoubleSignError> {
        let new_key = SignedKey::Proposal {
            height,
            round,
            block_id: block_id.clone(),
        };
        // Look for any existing proposal at same height/round with a different block.
        for existing in &self.signed {
            if let SignedKey::Proposal { height: h, round: r, block_id: b } = existing {
                if *h == height && *r == round && b != block_id {
                    return Err(DoubleSignError::Conflict);
                }
            }
        }
        Ok(())
    }

    /// Record a signed proposal. Must be called **after** signing.
    pub fn record_proposal(&mut self, height: Height, round: Round, block_id: &Hash32) -> Result<(), DoubleSignError> {
        let key = SignedKey::Proposal {
            height,
            round,
            block_id: block_id.clone(),
        };
        self.signed.insert(key);
        self.persist()
    }

    /// Check whether signing a vote would cause a double‑sign.
    pub fn check_vote(&self, vote_type: VoteType, height: Height, round: Round, block_id: &Option<Hash32>) -> Result<(), DoubleSignError> {
        let new_key = SignedKey::Vote {
            vote_type: vote_type as u8,
            height,
            round,
            block_id: block_id.clone(),
        };
        for existing in &self.signed {
            if let SignedKey::Vote { vote_type: vt, height: h, round: r, block_id: b } = existing {
                if *vt == vote_type as u8 && *h == height && *r == round && b != block_id {
                    return Err(DoubleSignError::Conflict);
                }
            }
        }
        Ok(())
    }

    /// Record a signed vote. Must be called **after** signing.
    pub fn record_vote(&mut self, vote_type: VoteType, height: Height, round: Round, block_id: &Option<Hash32>) -> Result<(), DoubleSignError> {
        let key = SignedKey::Vote {
            vote_type: vote_type as u8,
            height,
            round,
            block_id: block_id.clone(),
        };
        self.signed.insert(key);
        self.persist()
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Hash32;

    fn dummy_hash(val: u8) -> Hash32 {
        let mut h = [0u8; 32];
        h[0] = val;
        Hash32(h)
    }

    #[test]
    fn proposal_conflict_detected() {
        let mut guard = DoubleSignGuard::new("/test/ds_guard.bin");
        let h = Height::new(1);
        let r = Round::new(0);
        let block_a = dummy_hash(1);
        let block_b = dummy_hash(2);

        assert!(guard.check_proposal(h, r, &block_a).is_ok());
        guard.record_proposal(h, r, &block_a).unwrap();

        // Same block is allowed (idempotent)
        assert!(guard.check_proposal(h, r, &block_a).is_ok());
        // Different block at same height/round -> conflict
        assert!(guard.check_proposal(h, r, &block_b).is_err());
    }

    #[test]
    fn vote_conflict_detected() {
        let mut guard = DoubleSignGuard::new("/test/ds_guard.bin");
        let h = Height::new(1);
        let r = Round::new(0);
        let block_a = Some(dummy_hash(1));
        let block_b = Some(dummy_hash(2));
        let nil = None;

        assert!(guard.check_vote(VoteType::Prevote, h, r, &block_a).is_ok());
        guard.record_vote(VoteType::Prevote, h, r, &block_a).unwrap();

        // Same vote is allowed (idempotent)
        assert!(guard.check_vote(VoteType::Prevote, h, r, &block_a).is_ok());
        // Different prevote at same height/round -> conflict
        assert!(guard.check_vote(VoteType::Prevote, h, r, &block_b).is_err());

        // Nil vote is also a different block_id
        assert!(guard.check_vote(VoteType::Prevote, h, r, &nil).is_err());

        // Different vote type (precommit) at same height/round is allowed
        assert!(guard.check_vote(VoteType::Precommit, h, r, &block_a).is_ok());
    }
}
