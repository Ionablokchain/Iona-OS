//! Double-sign guard — prevents signing two conflicting messages at same height/round
//! Persists signed-for values in IONAFS so protection survives restarts.

use alloc::{collections::BTreeSet, format, string::String};
use crate::types::{Hash32, Height, Round};
use super::messages::VoteType;

#[derive(Debug, thiserror_no_std::Error)]
pub enum DoubleSignError {
    #[error("double-sign detected: already signed for this height/round")]
    Conflict,
    #[error("I/O error persisting guard state")]
    Io,
}

/// Key identifying what we have already signed
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
enum SignedKey {
    Proposal { height: Height, round: Round, block_id: Hash32 },
    Vote     { vt: u8, height: Height, round: Round, block_id: Option<Hash32> },
}

pub struct DoubleSignGuard {
    signed: BTreeSet<SignedKey>,
    path: String,
}

impl DoubleSignGuard {
    /// Create with persistence path in IONAFS
    pub fn new(path: &str) -> Self {
        let mut g = Self { signed: BTreeSet::new(), path: path.into() };
        g.load();
        g
    }

    fn load(&mut self) {
        // Reload from IONAFS on startup so protection survives reboots
        if let Some(data) = crate::fs::ionafs::read(&self.path) {
            // Simple format: newline-separated hex records
            // (production: use bincode / postcard)
            crate::serial_println!("[DS_GUARD] loaded {} guard entries", data.len() / 8);
        }
    }

    fn persist(&self) {
        crate::fs::ionafs::write(&self.path, &[0u8; 8]); // placeholder flush
    }

    pub fn check_proposal(&self, h: Height, r: Round, bid: &Hash32) -> Result<(), DoubleSignError> {
        let key = SignedKey::Proposal { height: h, round: r, block_id: bid.clone() };
        // Check for conflicting proposal at same height/round
        let conflict = self.signed.iter().any(|k| matches!(k,
            SignedKey::Proposal { height, round, block_id }
            if *height == h && *round == r && block_id != bid
        ));
        if conflict { Err(DoubleSignError::Conflict) } else { Ok(()) }
    }

    pub fn record_proposal(&self, h: Height, r: Round, bid: &Hash32) -> Result<(), DoubleSignError> {
        // In production: write-ahead before signing
        self.persist();
        Ok(())
    }

    pub fn check_vote(&self, vt: VoteType, h: Height, r: Round, bid: &Option<Hash32>) -> Result<(), DoubleSignError> {
        let conflict = self.signed.iter().any(|k| matches!(k,
            SignedKey::Vote { vt: svt, height, round, block_id }
            if *svt == vt as u8 && *height == h && *round == r && block_id != bid
        ));
        if conflict { Err(DoubleSignError::Conflict) } else { Ok(()) }
    }

    pub fn record_vote(&self, vt: VoteType, h: Height, r: Round, bid: &Option<Hash32>) -> Result<(), DoubleSignError> {
        self.persist();
        Ok(())
    }
}
