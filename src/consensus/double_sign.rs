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
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info, warn};

use crate::consensus::messages::VoteType;
use crate::types::{Hash32, Height, Round};

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the double‑sign guard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoubleSignConfig {
    /// Whether to persist state to disk (default: true).
    pub persist: bool,
    /// Maximum number of entries to keep (0 = unlimited).
    /// Older entries are pruned when exceeding this limit.
    pub max_entries: usize,
    /// Prune entries older than this many heights below the current height (0 = disabled).
    pub prune_below: u64,
    /// Whether to log every check (default: false, use for debugging).
    pub verbose_logging: bool,
}

impl Default for DoubleSignConfig {
    fn default() -> Self {
        Self {
            persist: true,
            max_entries: 10_000,
            prune_below: 1000,
            verbose_logging: false,
        }
    }
}

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

/// Errors that can occur during double‑sign guard operations.
#[derive(Debug, Error)]
pub enum DoubleSignError {
    #[error("double‑sign detected: already signed a conflicting message for height {height}, round {round}")]
    Conflict { height: Height, round: Round },

    #[error("I/O error while persisting guard state: {0}")]
    Io(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("configuration error: {0}")]
    Config(String),
}

pub type DoubleSignResult<T> = Result<T, DoubleSignError>;

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

    /// Returns the height.
    fn height(&self) -> Height {
        match self {
            SignedKey::Proposal { height, .. } => *height,
            SignedKey::Vote { height, .. } => *height,
        }
    }
}

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

/// Metrics for the double‑sign guard.
#[derive(Debug, Default, Clone)]
pub struct DoubleSignMetrics {
    /// Number of `check` calls.
    pub checks: u64,
    /// Number of conflicts detected.
    pub conflicts: u64,
    /// Number of successful records.
    pub records: u64,
    /// Number of times the state was loaded.
    pub loads: u64,
    /// Number of times the state was persisted.
    pub persists: u64,
    /// Number of entries pruned.
    pub pruned: u64,
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
    /// Configuration.
    config: DoubleSignConfig,
    /// Metrics.
    metrics: DoubleSignMetrics,
    /// Highest height seen (for pruning).
    highest_height: Height,
}

impl DoubleSignGuard {
    /// Create a new guard with default configuration.
    pub fn new(path: &str) -> Self {
        Self::with_config(path, DoubleSignConfig::default())
    }

    /// Create a new guard with the given configuration.
    pub fn with_config(path: &str, config: DoubleSignConfig) -> Self {
        let mut guard = Self {
            signed: BTreeSet::new(),
            path: path.into(),
            config,
            metrics: DoubleSignMetrics::default(),
            highest_height: Height::new(0),
        };
        if guard.config.persist {
            guard.load().unwrap_or_else(|e| {
                warn!(error = %e, "could not load previous double‑sign state, starting fresh");
            });
        }
        guard
    }

    /// Load persisted state from IONAFS.
    fn load(&mut self) -> DoubleSignResult<()> {
        let data = crate::fs::ionafs::read(&self.path);
        let data = match data {
            Some(d) => d,
            None => {
                debug!("no previous double‑sign state found at {}", self.path);
                return Ok(());
            }
        };
        self.signed = postcard::from_bytes(&data)
            .map_err(|e| DoubleSignError::Serialization(e.to_string()))?;
        self.metrics.loads += 1;
        // Find highest height
        if let Some(last) = self.signed.iter().last() {
            self.highest_height = last.height();
        }
        info!(
            path = %self.path,
            entries = self.signed.len(),
            "loaded double‑sign guard state"
        );
        Ok(())
    }

    /// Persist the current guard state to IONAFS.
    fn persist(&self) -> DoubleSignResult<()> {
        if !self.config.persist {
            return Ok(());
        }
        let data = postcard::to_vec(&self.signed)
            .map_err(|e| DoubleSignError::Serialization(e.to_string()))?;
        crate::fs::ionafs::write(&self.path, &data);
        debug!(
            path = %self.path,
            entries = self.signed.len(),
            "persisted double‑sign guard state"
        );
        Ok(())
    }

    /// Reload the state from disk (useful after manual recovery).
    pub fn reload(&mut self) -> DoubleSignResult<()> {
        self.load()
    }

    /// Get the current metrics.
    pub fn metrics(&self) -> &DoubleSignMetrics {
        &self.metrics
    }

    /// Get the number of entries currently stored.
    pub fn entry_count(&self) -> usize {
        self.signed.len()
    }

    /// Prune entries older than `height - prune_below` if configured.
    /// Returns the number of entries pruned.
    pub fn prune(&mut self, current_height: Height) -> usize {
        if self.config.prune_below == 0 {
            return 0;
        }
        let threshold = current_height.saturating_sub(self.config.prune_below);
        let before = self.signed.len();
        self.signed.retain(|key| key.height() >= threshold);
        let pruned = before - self.signed.len();
        if pruned > 0 {
            self.metrics.pruned += pruned as u64;
            if self.config.persist {
                let _ = self.persist();
            }
            debug!(
                current_height,
                threshold,
                pruned,
                remaining = self.signed.len(),
                "pruned old double‑sign entries"
            );
        }
        pruned
    }

    /// Ensure the set does not exceed `max_entries` by removing the oldest entries.
    fn enforce_max_entries(&mut self) {
        if self.config.max_entries == 0 {
            return;
        }
        while self.signed.len() > self.config.max_entries {
            if let Some(&first) = self.signed.iter().next() {
                self.signed.remove(&first);
            } else {
                break;
            }
        }
    }

    /// Check whether signing a proposal would cause a double‑sign.
    pub fn check_proposal(
        &mut self,
        height: Height,
        round: Round,
        block_id: &Hash32,
    ) -> DoubleSignResult<()> {
        self.metrics.checks += 1;
        if self.config.verbose_logging {
            debug!(height, round, block_hash = %hex::encode(&block_id.0[..4]), "checking proposal");
        }

        // Update highest height
        if height > self.highest_height {
            self.highest_height = height;
            // Prune if configured
            if self.config.prune_below > 0 {
                self.prune(height);
            }
        }

        let new_key = SignedKey::Proposal {
            height,
            round,
            block_id: block_id.clone(),
        };

        // Look for any existing proposal at same height/round with a different block.
        for existing in &self.signed {
            if let SignedKey::Proposal {
                height: h,
                round: r,
                block_id: b,
            } = existing
            {
                if *h == height && *r == round && b != block_id {
                    self.metrics.conflicts += 1;
                    warn!(
                        height,
                        round,
                        existing_block = %hex::encode(&b.0[..4]),
                        requested_block = %hex::encode(&block_id.0[..4]),
                        "double‑sign proposal conflict detected"
                    );
                    return Err(DoubleSignError::Conflict { height, round });
                }
            }
        }
        Ok(())
    }

    /// Record a signed proposal. Must be called **after** signing.
    pub fn record_proposal(
        &mut self,
        height: Height,
        round: Round,
        block_id: &Hash32,
    ) -> DoubleSignResult<()> {
        let key = SignedKey::Proposal {
            height,
            round,
            block_id: block_id.clone(),
        };
        self.signed.insert(key);
        self.metrics.records += 1;
        self.enforce_max_entries();
        if self.config.persist {
            self.persist()?;
        }
        if self.config.verbose_logging {
            debug!(height, round, "recorded proposal");
        }
        Ok(())
    }

    /// Check whether signing a vote would cause a double‑sign.
    pub fn check_vote(
        &mut self,
        vote_type: VoteType,
        height: Height,
        round: Round,
        block_id: &Option<Hash32>,
    ) -> DoubleSignResult<()> {
        self.metrics.checks += 1;
        if self.config.verbose_logging {
            debug!(
                vote_type = ?vote_type,
                height,
                round,
                block_hash = %block_id.as_ref().map(|h| hex::encode(&h.0[..4])).unwrap_or_else(|| "nil".into()),
                "checking vote"
            );
        }

        // Update highest height
        if height > self.highest_height {
            self.highest_height = height;
            if self.config.prune_below > 0 {
                self.prune(height);
            }
        }

        let new_key = SignedKey::Vote {
            vote_type: vote_type as u8,
            height,
            round,
            block_id: block_id.clone(),
        };

        for existing in &self.signed {
            if let SignedKey::Vote {
                vote_type: vt,
                height: h,
                round: r,
                block_id: b,
            } = existing
            {
                if *vt == vote_type as u8 && *h == height && *r == round && b != block_id {
                    self.metrics.conflicts += 1;
                    let existing_block = b.as_ref().map(|h| hex::encode(&h.0[..4])).unwrap_or_else(|| "nil".into());
                    let requested_block = block_id
                        .as_ref()
                        .map(|h| hex::encode(&h.0[..4]))
                        .unwrap_or_else(|| "nil".into());
                    warn!(
                        height,
                        round,
                        vote_type = ?vote_type,
                        existing_block,
                        requested_block,
                        "double‑sign vote conflict detected"
                    );
                    return Err(DoubleSignError::Conflict { height, round });
                }
            }
        }
        Ok(())
    }

    /// Record a signed vote. Must be called **after** signing.
    pub fn record_vote(
        &mut self,
        vote_type: VoteType,
        height: Height,
        round: Round,
        block_id: &Option<Hash32>,
    ) -> DoubleSignResult<()> {
        let key = SignedKey::Vote {
            vote_type: vote_type as u8,
            height,
            round,
            block_id: block_id.clone(),
        };
        self.signed.insert(key);
        self.metrics.records += 1;
        self.enforce_max_entries();
        if self.config.persist {
            self.persist()?;
        }
        if self.config.verbose_logging {
            debug!(
                vote_type = ?vote_type,
                height,
                round,
                "recorded vote"
            );
        }
        Ok(())
    }

    /// Reset the guard state (clears all entries).
    /// This should be used with extreme care, e.g., when recovering from a known safe state.
    pub fn reset(&mut self) -> DoubleSignResult<()> {
        self.signed.clear();
        self.highest_height = Height::new(0);
        if self.config.persist {
            self.persist()?;
        }
        info!("double‑sign guard reset");
        Ok(())
    }

    /// Check if a proposal has already been signed at this height/round.
    pub fn has_proposal(&self, height: Height, round: Round) -> bool {
        self.signed.iter().any(|key| {
            if let SignedKey::Proposal { height: h, round: r, .. } = key {
                *h == height && *r == round
            } else {
                false
            }
        })
    }

    /// Check if a vote has already been signed at this height/round for the given vote type.
    pub fn has_vote(&self, vote_type: VoteType, height: Height, round: Round) -> bool {
        self.signed.iter().any(|key| {
            if let SignedKey::Vote { vote_type: vt, height: h, round: r, .. } = key {
                *vt == vote_type as u8 && *h == height && *r == round
            } else {
                false
            }
        })
    }

    /// Get the block hash signed for a proposal at this height/round, if any.
    pub fn proposal_block(&self, height: Height, round: Round) -> Option<&Hash32> {
        self.signed.iter().find_map(|key| {
            if let SignedKey::Proposal { height: h, round: r, block_id } = key {
                if *h == height && *r == round {
                    Some(block_id)
                } else {
                    None
                }
            } else {
                None
            }
        })
    }

    /// Get the block hash signed for a vote at this height/round, if any.
    pub fn vote_block(&self, vote_type: VoteType, height: Height, round: Round) -> Option<&Option<Hash32>> {
        self.signed.iter().find_map(|key| {
            if let SignedKey::Vote { vote_type: vt, height: h, round: r, block_id } = key {
                if *vt == vote_type as u8 && *h == height && *r == round {
                    Some(block_id)
                } else {
                    None
                }
            } else {
                None
            }
        })
    }

    /// Export the current state as a byte vector (for backup or inspection).
    pub fn export_state(&self) -> DoubleSignResult<Vec<u8>> {
        postcard::to_vec(&self.signed)
            .map_err(|e| DoubleSignError::Serialization(e.to_string()))
    }

    /// Import a previously exported state.
    /// This replaces the current state entirely.
    pub fn import_state(&mut self, data: &[u8]) -> DoubleSignResult<()> {
        self.signed = postcard::from_bytes(data)
            .map_err(|e| DoubleSignError::Serialization(e.to_string()))?;
        if self.config.persist {
            self.persist()?;
        }
        info!(entries = self.signed.len(), "imported double‑sign guard state");
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_hash(val: u8) -> Hash32 {
        let mut h = [0u8; 32];
        h[0] = val;
        Hash32(h)
    }

    #[test]
    fn test_proposal_conflict_detected() {
        let mut guard = DoubleSignGuard::with_config(
            "/test/ds_guard.bin",
            DoubleSignConfig {
                persist: false,
                ..Default::default()
            },
        );
        let h = Height::new(1);
        let r = Round::new(0);
        let block_a = dummy_hash(1);
        let block_b = dummy_hash(2);

        assert!(guard.check_proposal(h, r, &block_a).is_ok());
        guard.record_proposal(h, r, &block_a).unwrap();

        // Same block is allowed (idempotent)
        assert!(guard.check_proposal(h, r, &block_a).is_ok());
        // Different block at same height/round -> conflict
        let err = guard.check_proposal(h, r, &block_b).unwrap_err();
        assert!(matches!(err, DoubleSignError::Conflict { height, round } if height == h && round == r));
    }

    #[test]
    fn test_vote_conflict_detected() {
        let mut guard = DoubleSignGuard::with_config(
            "/test/ds_guard.bin",
            DoubleSignConfig {
                persist: false,
                ..Default::default()
            },
        );
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

    #[test]
    fn test_max_entries_enforcement() {
        let mut guard = DoubleSignGuard::with_config(
            "/test/ds_guard.bin",
            DoubleSignConfig {
                persist: false,
                max_entries: 3,
                ..Default::default()
            },
        );
        let h = Height::new(1);
        let r = Round::new(0);
        let block = dummy_hash(1);

        for i in 0..5 {
            let round = Round::new(i as u64);
            guard.record_vote(VoteType::Prevote, h, round, &Some(block)).unwrap();
        }
        assert!(guard.signed.len() <= 3);
    }

    #[test]
    fn test_prune_old_entries() {
        let mut guard = DoubleSignGuard::with_config(
            "/test/ds_guard.bin",
            DoubleSignConfig {
                persist: false,
                prune_below: 2,
                ..Default::default()
            },
        );
        let block = dummy_hash(1);

        for i in 1..=5 {
            let height = Height::new(i);
            guard.record_vote(VoteType::Prevote, height, Round::new(0), &Some(block)).unwrap();
        }

        // Prune at height 5: keep heights >= 3
        guard.prune(Height::new(5));
        assert_eq!(guard.signed.len(), 3);
        // The remaining heights should be 3,4,5
        let heights: Vec<Height> = guard.signed.iter().map(|k| k.height()).collect();
        assert_eq!(heights, vec![Height::new(3), Height::new(4), Height::new(5)]);
    }

    #[test]
    fn test_has_proposal_and_vote() {
        let mut guard = DoubleSignGuard::new("/test/ds_guard.bin");
        let h = Height::new(1);
        let r = Round::new(0);
        let block = dummy_hash(1);

        assert!(!guard.has_proposal(h, r));
        guard.record_proposal(h, r, &block).unwrap();
        assert!(guard.has_proposal(h, r));

        assert!(!guard.has_vote(VoteType::Prevote, h, r));
        guard.record_vote(VoteType::Prevote, h, r, &Some(block)).unwrap();
        assert!(guard.has_vote(VoteType::Prevote, h, r));
        assert!(!guard.has_vote(VoteType::Precommit, h, r));
    }

    #[test]
    fn test_export_import() -> DoubleSignResult<()> {
        let mut guard = DoubleSignGuard::with_config(
            "/test/ds_guard.bin",
            DoubleSignConfig {
                persist: false,
                ..Default::default()
            },
        );
        let h = Height::new(1);
        let r = Round::new(0);
        let block = dummy_hash(1);
        guard.record_proposal(h, r, &block)?;

        let exported = guard.export_state()?;
        let mut guard2 = DoubleSignGuard::with_config(
            "/test/ds_guard2.bin",
            DoubleSignConfig {
                persist: false,
                ..Default::default()
            },
        );
        guard2.import_state(&exported)?;
        assert_eq!(guard2.signed.len(), 1);
        assert!(guard2.has_proposal(h, r));
        Ok(())
    }
}
