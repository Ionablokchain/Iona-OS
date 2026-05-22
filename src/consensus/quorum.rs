//! Quorum threshold + vote tally for Tendermint BFT
//!
//! This module provides helper functions and structures for vote aggregation
//! and quorum calculation in the Tendermint consensus algorithm.
//!
//! # Overview
//!
//! - `quorum_threshold` computes the minimum voting power required for a decision.
//! - `VoteTally` accumulates votes from validators and finds the most supported block.

use alloc::collections::BTreeMap;
use crate::types::Hash32;
use crate::crypto::PublicKeyBytes;
use super::validator_set::ValidatorSet;

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
    total * 2 / 3 + 1
}

// -----------------------------------------------------------------------------
// Vote tally
// -----------------------------------------------------------------------------

/// Accumulates votes and determines the best (most supported) block candidate.
///
/// Votes are weighted by the voter's voting power (stake). The tally tracks
/// the total power for each block hash (including `None` for nil votes).
#[derive(Default)]
pub struct VoteTally {
    /// Map from block hash (or `None` for nil) to accumulated voting power.
    buckets: BTreeMap<Option<Hash32>, u64>,
}

impl VoteTally {
    /// Create a new empty tally.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a vote to the tally.
    ///
    /// # Arguments
    /// * `vset` – Validator set used to look up the voter's power.
    /// * `voter` – Public key of the voter.
    /// * `bid` – Block hash being voted for (`None` = nil vote).
    pub fn add_vote(&mut self, vset: &ValidatorSet, voter: &PublicKeyBytes, bid: &Option<Hash32>) {
        let power = vset.power_of(voter).unwrap_or(0);
        *self.buckets.entry(bid.clone()).or_insert(0) += power;
    }

    /// Find the block (or nil) with the highest accumulated power.
    ///
    /// # Returns
    /// `Some((block_id, power))` if there is at least one vote, otherwise `None`.
    /// If multiple blocks have the same power, the first in iteration order is returned.
    pub fn best(&self) -> Option<(Option<Hash32>, u64)> {
        self.buckets
            .iter()
            .max_by_key(|(_, &power)| power)
            .map(|(bid, &power)| (bid.clone(), power))
    }

    /// Get the total power accumulated for a specific block (or nil).
    pub fn power_for(&self, bid: &Option<Hash32>) -> u64 {
        self.buckets.get(bid).copied().unwrap_or(0)
    }

    /// Clear all votes.
    pub fn clear(&mut self) {
        self.buckets.clear();
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PublicKeyBytes;

    fn dummy_pk(id: u8) -> PublicKeyBytes {
        let mut pk = [0u8; 32];
        pk[0] = id;
        pk
    }

    // A minimal validator set for testing
    struct TestValidatorSet {
        powers: alloc::collections::BTreeMap<PublicKeyBytes, u64>,
    }

    impl TestValidatorSet {
        fn new() -> Self {
            Self { powers: alloc::collections::BTreeMap::new() }
        }
        fn add_validator(&mut self, pk: PublicKeyBytes, power: u64) {
            self.powers.insert(pk, power);
        }
        fn power_of(&self, pk: &PublicKeyBytes) -> Option<u64> {
            self.powers.get(pk).copied()
        }
    }

    impl super::ValidatorSet for TestValidatorSet {
        fn total_power(&self) -> u64 {
            self.powers.values().sum()
        }
        fn power_of(&self, pk: &PublicKeyBytes) -> Option<u64> {
            self.powers.get(pk).copied()
        }
        // Other methods can be stubbed; we only need power_of.
        fn len(&self) -> usize { self.powers.len() }
        fn is_empty(&self) -> bool { self.powers.is_empty() }
        fn iter(&self) -> alloc::collections::btree_map::Iter<PublicKeyBytes, u64> {
            self.powers.iter()
        }
    }

    #[test]
    fn quorum_threshold_correct() {
        assert_eq!(quorum_threshold(0), 1);
        assert_eq!(quorum_threshold(1), 1);
        assert_eq!(quorum_threshold(2), 2);
        assert_eq!(quorum_threshold(3), 3);
        assert_eq!(quorum_threshold(100), 67);
        assert_eq!(quorum_threshold(150), 101);
    }

    #[test]
    fn tally_best_candidate() {
        let mut vset = TestValidatorSet::new();
        let pk1 = dummy_pk(1);
        let pk2 = dummy_pk(2);
        let pk3 = dummy_pk(3);
        vset.add_validator(pk1, 30);
        vset.add_validator(pk2, 30);
        vset.add_validator(pk3, 40);

        let mut tally = VoteTally::new();
        let hash_a = Some(Hash32([1u8; 32]));
        let hash_b = Some(Hash32([2u8; 32]));
        let nil = None;

        tally.add_vote(&vset, &pk1, &hash_a);
        tally.add_vote(&vset, &pk2, &hash_a);
        tally.add_vote(&vset, &pk3, &hash_b);
        tally.add_vote(&vset, &pk1, &nil); // voter already voted? but fine

        let (best, power) = tally.best().unwrap();
        assert_eq!(best, hash_a);
        assert_eq!(power, 60);
        assert_eq!(tally.power_for(&hash_a), 60);
        assert_eq!(tally.power_for(&hash_b), 40);
        assert_eq!(tally.power_for(&nil), 30);
    }
}
