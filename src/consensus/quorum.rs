//! Quorum threshold + vote tally for Tendermint BFT
//!
//! This module provides helper functions and structures for vote aggregation
//! and quorum calculation in the Tendermint consensus algorithm.
//!
//! # Overview
//!
//! - `quorum_threshold` computes the minimum voting power required for a decision.
//! - `VoteTally` accumulates votes from validators and finds the most supported block.
//! - `TallyConfig` allows configuration of duplicate vote handling.
//! - `TallyMetrics` tracks tally operations for monitoring.
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::consensus::quorum::{VoteTally, TallyConfig, quorum_threshold};
//!
//! let mut tally = VoteTally::new(TallyConfig::default());
//! tally.add_vote(&vset, &pk, &Some(block_id))?;
//! let (best, power) = tally.best().unwrap();
//! if power >= quorum_threshold(vset.total_power()) {
//!     // decision reached
//! }
//! ```

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::PublicKeyBytes;
use crate::types::Hash32;
use super::validator_set::ValidatorSet;

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

/// Errors that can occur during vote tallying.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TallyError {
    #[error("duplicate vote detected from validator {0}")]
    DuplicateVote(String),

    #[error("validator not found in validator set")]
    ValidatorNotFound,

    #[error("no votes recorded")]
    NoVotes,

    #[error("configuration error: {0}")]
    Config(String),
}

pub type TallyResult<T> = Result<T, TallyError>;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for vote tallying.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TallyConfig {
    /// Whether to allow duplicate votes from the same validator (default: false).
    pub allow_duplicate_votes: bool,
    /// Whether to log warnings on duplicate votes (default: true).
    pub log_duplicate_warnings: bool,
    /// Whether to track metrics (default: true).
    pub track_metrics: bool,
}

impl Default for TallyConfig {
    fn default() -> Self {
        Self {
            allow_duplicate_votes: false,
            log_duplicate_warnings: true,
            track_metrics: true,
        }
    }
}

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

/// Metrics for vote tallying.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TallyMetrics {
    /// Number of votes added.
    pub votes_added: u64,
    /// Number of duplicate votes rejected.
    pub duplicate_votes_rejected: u64,
    /// Number of duplicate votes allowed (if config allows).
    pub duplicate_votes_allowed: u64,
    /// Number of times `best()` was called.
    pub best_calls: u64,
    /// Number of times `clear()` was called.
    pub clear_calls: u64,
}

impl fmt::Display for TallyMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Tally Metrics:")?;
        writeln!(f, "  votes_added: {}", self.votes_added)?;
        writeln!(f, "  duplicate_votes_rejected: {}", self.duplicate_votes_rejected)?;
        writeln!(f, "  duplicate_votes_allowed: {}", self.duplicate_votes_allowed)?;
        writeln!(f, "  best_calls: {}", self.best_calls)?;
        writeln!(f, "  clear_calls: {}", self.clear_calls)?;
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Quorum threshold
// -----------------------------------------------------------------------------

/// Compute the quorum threshold for Tendermint consensus.
///
/// The threshold is defined as **strictly more than 2/3** of the total voting power.
/// This matches the formula used in Tendermint/Cosmos SDK.
///
/// # Arguments
/// * `total` – Total voting power of all validators.
///
/// # Returns
/// The minimum power required to reach quorum.
///
/// # Example
/// ```
/// assert_eq!(quorum_threshold(100), 67);   // 100 * 2/3 = 66.66 → +1 = 67
/// assert_eq!(quorum_threshold(3), 3);      // 3 * 2/3 = 2 → +1 = 3
/// ```
#[inline]
pub const fn quorum_threshold(total: u64) -> u64 {
    if total == 0 {
        0
    } else {
        total * 2 / 3 + 1
    }
}

/// Check if a given power meets the quorum threshold.
#[inline]
pub const fn meets_quorum(power: u64, total: u64) -> bool {
    power >= quorum_threshold(total)
}

// -----------------------------------------------------------------------------
// Vote tally
// -----------------------------------------------------------------------------

/// Accumulates votes and determines the best (most supported) block candidate.
///
/// Votes are weighted by the voter's voting power (stake). The tally tracks
/// the total power for each block hash (including `None` for nil votes).
#[derive(Clone)]
pub struct VoteTally {
    /// Map from block hash (or `None` for nil) to accumulated voting power.
    buckets: BTreeMap<Option<Hash32>, u64>,
    /// Track which validators have already voted (for duplicate detection).
    voters: BTreeMap<PublicKeyBytes, (VoteKey, u64)>,
    /// Configuration.
    config: TallyConfig,
    /// Metrics.
    metrics: TallyMetrics,
}

/// Key used to identify a vote (for duplicate detection).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct VoteKey {
    pub block_id: Option<Hash32>,
}

impl VoteTally {
    /// Create a new tally with the given configuration.
    pub fn new(config: TallyConfig) -> Self {
        Self {
            buckets: BTreeMap::new(),
            voters: BTreeMap::new(),
            config,
            metrics: TallyMetrics::default(),
        }
    }

    /// Create a new tally with default configuration.
    pub fn default() -> Self {
        Self::new(TallyConfig::default())
    }

    /// Add a vote to the tally.
    ///
    /// # Arguments
    /// * `vset` – Validator set used to look up the voter's power.
    /// * `voter` – Public key of the voter.
    /// * `bid` – Block hash being voted for (`None` = nil vote).
    ///
    /// # Errors
    /// Returns `TallyError::ValidatorNotFound` if the voter is not in the validator set.
    /// Returns `TallyError::DuplicateVote` if the voter has already voted and
    /// `allow_duplicate_votes` is false.
    pub fn add_vote(
        &mut self,
        vset: &dyn ValidatorSet,
        voter: &PublicKeyBytes,
        bid: &Option<Hash32>,
    ) -> TallyResult<()> {
        // Look up the voter's power.
        let power = vset.power_of(voter).ok_or(TallyError::ValidatorNotFound)?;

        // Check for duplicate votes.
        if let Some((prev_key, prev_power)) = self.voters.get(voter) {
            // The voter has already voted.
            if self.config.allow_duplicate_votes {
                // Update the vote if the block ID differs (or we allow duplicates).
                // For simplicity, we just add the new vote as an additional one,
                // but we could replace or accumulate. We'll add a new vote entry.
                // However, this could double-count power. Let's decide: we replace
                // the previous vote with the new one, but we also add a metric.
                // In practice, we want to replace the vote (since the validator
                // changed its mind). We'll remove the old vote's power and add the new.
                let old_key = VoteKey {
                    block_id: prev_key.block_id.clone(),
                };
                // Remove old vote's power from bucket.
                if let Some(old_power) = self.buckets.get(&old_key.block_id) {
                    let new_power = old_power.saturating_sub(prev_power);
                    if new_power == 0 {
                        self.buckets.remove(&old_key.block_id);
                    } else {
                        self.buckets.insert(old_key.block_id.clone(), new_power);
                    }
                }
                // Update the voter record.
                self.voters.insert(
                    voter.clone(),
                    (VoteKey { block_id: bid.clone() }, power),
                );
                // Add the new vote's power to bucket.
                *self.buckets.entry(bid.clone()).or_insert(0) += power;
                self.metrics.duplicate_votes_allowed += 1;
                return Ok(());
            } else {
                // Duplicate vote not allowed.
                if self.config.log_duplicate_warnings {
                    // Log a warning (using tracing or serial_println).
                    #[cfg(feature = "tracing")]
                    tracing::warn!(
                        voter = ?voter,
                        prev_block = ?prev_key.block_id,
                        new_block = ?bid,
                        "duplicate vote detected"
                    );
                    #[cfg(not(feature = "tracing"))]
                    crate::serial_println!(
                        "[TALLY] duplicate vote from voter {:?}",
                        voter
                    );
                }
                self.metrics.duplicate_votes_rejected += 1;
                return Err(TallyError::DuplicateVote(
                    hex::encode(&voter.0).chars().take(8).collect(),
                ));
            }
        }

        // First vote from this validator.
        self.voters.insert(
            voter.clone(),
            (VoteKey { block_id: bid.clone() }, power),
        );
        *self.buckets.entry(bid.clone()).or_insert(0) += power;
        self.metrics.votes_added += 1;
        Ok(())
    }

    /// Find the block (or nil) with the highest accumulated power.
    ///
    /// # Returns
    /// `Ok((block_id, power))` if there is at least one vote, otherwise `Err(TallyError::NoVotes)`.
    /// If multiple blocks have the same power, the first in iteration order is returned.
    pub fn best(&self) -> TallyResult<(Option<Hash32>, u64)> {
        self.metrics.best_calls += 1;
        self.buckets
            .iter()
            .max_by_key(|(_, &power)| power)
            .map(|(bid, &power)| (bid.clone(), power))
            .ok_or(TallyError::NoVotes)
    }

    /// Get the total power accumulated for a specific block (or nil).
    pub fn power_for(&self, bid: &Option<Hash32>) -> u64 {
        self.buckets.get(bid).copied().unwrap_or(0)
    }

    /// Get the total number of votes (validators that have voted).
    pub fn vote_count(&self) -> usize {
        self.voters.len()
    }

    /// Get all block candidates with their powers.
    pub fn candidates(&self) -> Vec<(Option<Hash32>, u64)> {
        self.buckets.iter().map(|(bid, &power)| (bid.clone(), power)).collect()
    }

    /// Check if a quorum is reached for any candidate.
    pub fn has_quorum(&self, total_power: u64) -> bool {
        let threshold = quorum_threshold(total_power);
        self.buckets.values().any(|&power| power >= threshold)
    }

    /// Get the candidate that meets quorum, if any.
    pub fn quorum_candidate(&self, total_power: u64) -> Option<(Option<Hash32>, u64)> {
        let threshold = quorum_threshold(total_power);
        self.buckets
            .iter()
            .find(|(_, &power)| power >= threshold)
            .map(|(bid, &power)| (bid.clone(), power))
    }

    /// Clear all votes.
    pub fn clear(&mut self) {
        self.metrics.clear_calls += 1;
        self.buckets.clear();
        self.voters.clear();
    }

    /// Merge another tally into this one.
    pub fn merge(&mut self, other: &VoteTally, vset: &dyn ValidatorSet) -> TallyResult<()> {
        for (voter, (key, power)) in other.voters.iter() {
            // We need to re-add the vote with the same block_id and power.
            // But we must use the add_vote method to respect duplicate checks.
            // However, that would re-check duplicates and maybe reject.
            // For merging, we can bypass duplicates by adding the power directly.
            // We'll add to buckets directly and track voters if not present.
            if self.voters.contains_key(voter) {
                // Duplicate validator across tallies: we need to decide what to do.
                // For merging, we could overwrite or add. We'll overwrite with the latest.
                // We'll remove the old power and add the new.
                if let Some((old_key, old_power)) = self.voters.get(voter) {
                    // Remove old power.
                    if let Some(old_power_val) = self.buckets.get(&old_key.block_id) {
                        let new_val = old_power_val.saturating_sub(*old_power);
                        if new_val == 0 {
                            self.buckets.remove(&old_key.block_id);
                        } else {
                            self.buckets.insert(old_key.block_id.clone(), new_val);
                        }
                    }
                }
                self.voters.insert(voter.clone(), (key.clone(), *power));
                *self.buckets.entry(key.block_id.clone()).or_insert(0) += power;
            } else {
                self.voters.insert(voter.clone(), (key.clone(), *power));
                *self.buckets.entry(key.block_id.clone()).or_insert(0) += power;
            }
        }
        self.metrics.votes_added += other.voters.len() as u64;
        Ok(())
    }

    /// Get a reference to the metrics.
    pub fn metrics(&self) -> &TallyMetrics {
        &self.metrics
    }

    /// Reset metrics.
    pub fn reset_metrics(&mut self) {
        self.metrics = TallyMetrics::default();
    }

    /// Check if the tally is empty.
    pub fn is_empty(&self) -> bool {
        self.voters.is_empty()
    }
}

impl fmt::Display for VoteTally {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "VoteTally ({} voters, {} candidates):", self.voters.len(), self.buckets.len())?;
        for (bid, power) in &self.buckets {
            let bid_str = bid
                .as_ref()
                .map(|h| hex::encode(&h.0[..4]))
                .unwrap_or_else(|| "nil".into());
            writeln!(f, "  {}: {}", bid_str, power)?;
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Default implementation
// -----------------------------------------------------------------------------

impl Default for VoteTally {
    fn default() -> Self {
        Self::new(TallyConfig::default())
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PublicKeyBytes;

    // Minimal validator set implementation for testing.
    struct TestValidatorSet {
        powers: BTreeMap<PublicKeyBytes, u64>,
    }

    impl TestValidatorSet {
        fn new() -> Self {
            Self { powers: BTreeMap::new() }
        }
        fn add_validator(&mut self, pk: PublicKeyBytes, power: u64) {
            self.powers.insert(pk, power);
        }
    }

    impl ValidatorSet for TestValidatorSet {
        fn total_power(&self) -> u64 {
            self.powers.values().sum()
        }
        fn power_of(&self, pk: &PublicKeyBytes) -> Option<u64> {
            self.powers.get(pk).copied()
        }
        fn len(&self) -> usize {
            self.powers.len()
        }
        fn is_empty(&self) -> bool {
            self.powers.is_empty()
        }
        fn iter(&self) -> alloc::collections::btree_map::Iter<PublicKeyBytes, u64> {
            self.powers.iter()
        }
    }

    fn dummy_pk(id: u8) -> PublicKeyBytes {
        let mut pk = [0u8; 32];
        pk[0] = id;
        PublicKeyBytes(pk.to_vec())
    }

    fn dummy_hash(val: u8) -> Hash32 {
        let mut h = [0u8; 32];
        h[0] = val;
        Hash32(h)
    }

    #[test]
    fn test_quorum_threshold() {
        assert_eq!(quorum_threshold(0), 0);
        assert_eq!(quorum_threshold(1), 1);
        assert_eq!(quorum_threshold(2), 2);
        assert_eq!(quorum_threshold(3), 3);
        assert_eq!(quorum_threshold(100), 67);
        assert!(meets_quorum(67, 100));
        assert!(!meets_quorum(66, 100));
    }

    #[test]
    fn test_tally_basic() {
        let mut vset = TestValidatorSet::new();
        let pk1 = dummy_pk(1);
        let pk2 = dummy_pk(2);
        let pk3 = dummy_pk(3);
        vset.add_validator(pk1, 30);
        vset.add_validator(pk2, 30);
        vset.add_validator(pk3, 40);

        let mut tally = VoteTally::default();
        let hash_a = Some(dummy_hash(1));
        let hash_b = Some(dummy_hash(2));

        tally.add_vote(&vset, &pk1, &hash_a).unwrap();
        tally.add_vote(&vset, &pk2, &hash_a).unwrap();
        tally.add_vote(&vset, &pk3, &hash_b).unwrap();

        let (best, power) = tally.best().unwrap();
        assert_eq!(best, hash_a);
        assert_eq!(power, 60);
        assert_eq!(tally.power_for(&hash_a), 60);
        assert_eq!(tally.power_for(&hash_b), 40);
        assert_eq!(tally.vote_count(), 3);
    }

    #[test]
    fn test_duplicate_vote_rejection() {
        let mut vset = TestValidatorSet::new();
        let pk1 = dummy_pk(1);
        vset.add_validator(pk1.clone(), 100);

        let mut tally = VoteTally::default();
        let hash_a = Some(dummy_hash(1));
        let hash_b = Some(dummy_hash(2));

        tally.add_vote(&vset, &pk1, &hash_a).unwrap();
        let err = tally.add_vote(&vset, &pk1, &hash_b).unwrap_err();
        assert!(matches!(err, TallyError::DuplicateVote(_)));
        assert_eq!(tally.vote_count(), 1);
        assert_eq!(tally.power_for(&hash_a), 100);
        assert_eq!(tally.power_for(&hash_b), 0);
    }

    #[test]
    fn test_duplicate_vote_allow() {
        let config = TallyConfig {
            allow_duplicate_votes: true,
            log_duplicate_warnings: false,
            track_metrics: true,
        };
        let mut vset = TestValidatorSet::new();
        let pk1 = dummy_pk(1);
        vset.add_validator(pk1.clone(), 100);

        let mut tally = VoteTally::new(config);
        let hash_a = Some(dummy_hash(1));
        let hash_b = Some(dummy_hash(2));

        tally.add_vote(&vset, &pk1, &hash_a).unwrap();
        tally.add_vote(&vset, &pk1, &hash_b).unwrap();

        // Since we allowed duplicates, the tally should have updated to the new vote.
        assert_eq!(tally.vote_count(), 1);
        assert_eq!(tally.power_for(&hash_a), 0);
        assert_eq!(tally.power_for(&hash_b), 100);
        assert_eq!(tally.metrics().duplicate_votes_allowed, 1);
    }

    #[test]
    fn test_has_quorum() {
        let mut vset = TestValidatorSet::new();
        let pk1 = dummy_pk(1);
        let pk2 = dummy_pk(2);
        let pk3 = dummy_pk(3);
        vset.add_validator(pk1, 30);
        vset.add_validator(pk2, 30);
        vset.add_validator(pk3, 40);
        let total = vset.total_power(); // 100

        let mut tally = VoteTally::default();
        let hash_a = Some(dummy_hash(1));

        tally.add_vote(&vset, &pk1, &hash_a).unwrap();
        tally.add_vote(&vset, &pk2, &hash_a).unwrap();
        assert!(!tally.has_quorum(total)); // 60 < 67

        tally.add_vote(&vset, &pk3, &hash_a).unwrap();
        assert!(tally.has_quorum(total)); // 100 >= 67

        let (bid, power) = tally.quorum_candidate(total).unwrap();
        assert_eq!(bid, hash_a);
        assert_eq!(power, 100);
    }

    #[test]
    fn test_merge() {
        let mut vset = TestValidatorSet::new();
        let pk1 = dummy_pk(1);
        let pk2 = dummy_pk(2);
        let pk3 = dummy_pk(3);
        vset.add_validator(pk1.clone(), 30);
        vset.add_validator(pk2.clone(), 30);
        vset.add_validator(pk3.clone(), 40);

        let hash_a = Some(dummy_hash(1));
        let hash_b = Some(dummy_hash(2));

        let mut tally1 = VoteTally::default();
        tally1.add_vote(&vset, &pk1, &hash_a).unwrap();
        tally1.add_vote(&vset, &pk2, &hash_a).unwrap();

        let mut tally2 = VoteTally::default();
        tally2.add_vote(&vset, &pk3, &hash_b).unwrap();

        tally1.merge(&tally2, &vset).unwrap();
        assert_eq!(tally1.vote_count(), 3);
        assert_eq!(tally1.power_for(&hash_a), 60);
        assert_eq!(tally1.power_for(&hash_b), 40);
    }

    #[test]
    fn test_metrics() {
        let mut vset = TestValidatorSet::new();
        let pk1 = dummy_pk(1);
        vset.add_validator(pk1.clone(), 100);

        let mut tally = VoteTally::default();
        let hash_a = Some(dummy_hash(1));

        tally.add_vote(&vset, &pk1, &hash_a).unwrap();
        tally.best().unwrap();
        tally.clear();

        let metrics = tally.metrics();
        assert_eq!(metrics.votes_added, 1);
        assert_eq!(metrics.best_calls, 1);
        assert_eq!(metrics.clear_calls, 1);
    }
}
