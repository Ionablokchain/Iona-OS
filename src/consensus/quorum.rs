//! Quorum threshold + vote tally for Tendermint BFT

use alloc::collections::BTreeMap;
use crate::types::Hash32;
use crate::crypto::PublicKeyBytes;
use super::validator_set::ValidatorSet;

/// Quorum threshold: strictly more than 2/3 of total power
#[inline]
pub fn quorum_threshold(total: u64) -> u64 {
    total * 2 / 3 + 1
}

/// Accumulates votes and computes the best candidate
#[derive(Default)]
pub struct VoteTally {
    /// block_id (None=nil) → accumulated power
    buckets: BTreeMap<Option<Hash32>, u64>,
}

impl VoteTally {
    pub fn add_vote(&mut self, vset: &ValidatorSet, voter: &PublicKeyBytes, bid: &Option<Hash32>) {
        let power = vset.power_of(voter).unwrap_or(0);
        *self.buckets.entry(bid.clone()).or_insert(0) += power;
    }

    /// Returns (best_bid, power) if any block has the most votes; (None, nil_power) for nil
    pub fn best(&self) -> Option<(Option<Hash32>, u64)> {
        self.buckets.iter()
            .max_by_key(|(_,p)| *p)
            .map(|(b,&p)| (b.clone(), p))
    }
}
