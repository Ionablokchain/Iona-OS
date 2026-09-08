//! Quorum threshold + vote tally for Tendermint BFT
//!
//! This module provides helper functions and structures for vote aggregation
//! and quorum calculation in the Tendermint consensus algorithm.
//!
//! # Overview
//!
//! - `quorum_threshold` computes the minimum voting power required for a decision.
//! - `VoteTally` accumulates votes from validators and finds the most supported block.
//! - `TallyConfig` allows configuration of duplicate vote handling and metrics.
//! - `PrometheusTallyMetrics` provides optional Prometheus instrumentation.
//! - `AtomicTallyMetrics` provides atomic counters for environments without Prometheus.
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::consensus::quorum::{VoteTally, TallyConfig, quorum_threshold};
//!
//! let config = TallyConfig::default();
//! let mut tally = VoteTally::new(config);
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
use parking_lot::Mutex;
use prometheus::{register_counter, register_gauge, Counter, Gauge};
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
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

    #[error("metrics error: {0}")]
    Metrics(String),
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
    /// Whether to track atomic metrics (default: true).
    pub track_metrics: bool,
    /// Whether to enable Prometheus metrics (default: false).
    pub enable_prometheus: bool,
}

impl Default for TallyConfig {
    fn default() -> Self {
        Self {
            allow_duplicate_votes: false,
            log_duplicate_warnings: true,
            track_metrics: true,
            enable_prometheus: false,
        }
    }
}

impl TallyConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), TallyError> {
        // No invalid combinations currently, but placeholder for future.
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Atomic metrics (always available)
// -----------------------------------------------------------------------------

/// Atomic counters for vote tally metrics.
#[derive(Debug, Default)]
pub struct AtomicTallyMetrics {
    /// Number of votes added.
    pub votes_added: AtomicU64,
    /// Number of duplicate votes rejected.
    pub duplicate_votes_rejected: AtomicU64,
    /// Number of duplicate votes allowed (if config allows).
    pub duplicate_votes_allowed: AtomicU64,
    /// Number of times `best()` was called.
    pub best_calls: AtomicU64,
    /// Number of times `clear()` was called.
    pub clear_calls: AtomicU64,
}

impl AtomicTallyMetrics {
    fn inc_votes_added(&self) {
        self.votes_added.fetch_add(1, Ordering::Relaxed);
    }
    fn inc_duplicate_rejected(&self) {
        self.duplicate_votes_rejected.fetch_add(1, Ordering::Relaxed);
    }
    fn inc_duplicate_allowed(&self) {
        self.duplicate_votes_allowed.fetch_add(1, Ordering::Relaxed);
    }
    fn inc_best_calls(&self) {
        self.best_calls.fetch_add(1, Ordering::Relaxed);
    }
    fn inc_clear_calls(&self) {
        self.clear_calls.fetch_add(1, Ordering::Relaxed);
    }

    /// Get a snapshot of the metrics.
    pub fn snapshot(&self) -> TallyMetricsSnapshot {
        TallyMetricsSnapshot {
            votes_added: self.votes_added.load(Ordering::Relaxed),
            duplicate_votes_rejected: self.duplicate_votes_rejected.load(Ordering::Relaxed),
            duplicate_votes_allowed: self.duplicate_votes_allowed.load(Ordering::Relaxed),
            best_calls: self.best_calls.load(Ordering::Relaxed),
            clear_calls: self.clear_calls.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of tally metrics (for external consumption).
#[derive(Debug, Clone, Default)]
pub struct TallyMetricsSnapshot {
    pub votes_added: u64,
    pub duplicate_votes_rejected: u64,
    pub duplicate_votes_allowed: u64,
    pub best_calls: u64,
    pub clear_calls: u64,
}

// -----------------------------------------------------------------------------
// Prometheus metrics (optional)
// -----------------------------------------------------------------------------

/// Prometheus metrics for vote tallying.
#[derive(Clone)]
pub struct PrometheusTallyMetrics {
    /// Current number of voters (gauge).
    pub voters: Gauge,
    /// Total votes added (counter).
    pub votes_added_total: Counter,
    /// Total duplicate votes rejected (counter).
    pub duplicate_votes_rejected_total: Counter,
    /// Total duplicate votes allowed (counter).
    pub duplicate_votes_allowed_total: Counter,
    /// Total best calls (counter).
    pub best_calls_total: Counter,
    /// Total clear calls (counter).
    pub clear_calls_total: Counter,
}

impl PrometheusTallyMetrics {
    /// Create and register metrics with the global Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            voters: register_gauge!(
                "iona_consensus_tally_voters",
                "Current number of voters in the tally"
            )?,
            votes_added_total: register_counter!(
                "iona_consensus_tally_votes_added_total",
                "Total votes added to tally"
            )?,
            duplicate_votes_rejected_total: register_counter!(
                "iona_consensus_tally_duplicate_rejected_total",
                "Total duplicate votes rejected"
            )?,
            duplicate_votes_allowed_total: register_counter!(
                "iona_consensus_tally_duplicate_allowed_total",
                "Total duplicate votes allowed"
            )?,
            best_calls_total: register_counter!(
                "iona_consensus_tally_best_calls_total",
                "Total calls to best()"
            )?,
            clear_calls_total: register_counter!(
                "iona_consensus_tally_clear_calls_total",
                "Total calls to clear()"
            )?,
        })
    }

    /// Create an unregistered instance (for tests or disabled metrics).
    pub fn new_unregistered() -> Self {
        Self {
            voters: Gauge::new("iona_consensus_tally_voters", "Voters").unwrap(),
            votes_added_total: Counter::new("iona_consensus_tally_votes_added_total", "Votes added").unwrap(),
            duplicate_votes_rejected_total: Counter::new("iona_consensus_tally_duplicate_rejected_total", "Dup rejected").unwrap(),
            duplicate_votes_allowed_total: Counter::new("iona_consensus_tally_duplicate_allowed_total", "Dup allowed").unwrap(),
            best_calls_total: Counter::new("iona_consensus_tally_best_calls_total", "Best calls").unwrap(),
            clear_calls_total: Counter::new("iona_consensus_tally_clear_calls_total", "Clear calls").unwrap(),
        }
    }

    /// Update gauges from current state.
    pub fn update_voters(&self, count: usize) {
        self.voters.set(count as f64);
    }

    /// Increment counters based on event.
    pub fn record_vote_added(&self) {
        self.votes_added_total.inc();
    }

    pub fn record_duplicate_rejected(&self) {
        self.duplicate_votes_rejected_total.inc();
    }

    pub fn record_duplicate_allowed(&self) {
        self.duplicate_votes_allowed_total.inc();
    }

    pub fn record_best_call(&self) {
        self.best_calls_total.inc();
    }

    pub fn record_clear_call(&self) {
        self.clear_calls_total.inc();
    }
}

// -----------------------------------------------------------------------------
// Quorum threshold
// -----------------------------------------------------------------------------

/// Compute the quorum threshold for Tendermint consensus.
///
/// The threshold is defined as **strictly more than 2/3** of the total voting power.
///
/// # Arguments
/// * `total` – Total voting power of all validators.
///
/// # Returns
/// The minimum power required to reach quorum.
///
/// # Example
/// ```
/// assert_eq!(quorum_threshold(100), 67);
/// assert_eq!(quorum_threshold(3), 3);
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
#[derive(Clone)]
pub struct VoteTally {
    /// Map from block hash (or `None` for nil) to accumulated voting power.
    buckets: BTreeMap<Option<Hash32>, u64>,
    /// Track which validators have already voted (for duplicate detection).
    voters: BTreeMap<PublicKeyBytes, (VoteKey, u64)>,
    /// Configuration.
    config: TallyConfig,
    /// Atomic metrics (if tracking enabled).
    atomic_metrics: Arc<AtomicTallyMetrics>,
    /// Prometheus metrics (if enabled).
    prometheus: Option<Arc<PrometheusTallyMetrics>>,
}

/// Key used to identify a vote (for duplicate detection).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct VoteKey {
    pub block_id: Option<Hash32>,
}

impl VoteTally {
    /// Create a new tally with the given configuration.
    pub fn new(config: TallyConfig) -> Result<Self, TallyError> {
        config.validate()?;
        let atomic_metrics = if config.track_metrics {
            Arc::new(AtomicTallyMetrics::default())
        } else {
            Arc::new(AtomicTallyMetrics::default()) // still provide, but ignore updates
        };
        let prometheus = if config.enable_prometheus {
            Some(Arc::new(PrometheusTallyMetrics::new().map_err(|e| TallyError::Metrics(e.to_string()))?))
        } else {
            None
        };
        Ok(Self {
            buckets: BTreeMap::new(),
            voters: BTreeMap::new(),
            config,
            atomic_metrics,
            prometheus,
        })
    }

    /// Create a new tally with default configuration.
    pub fn default() -> Self {
        Self::new(TallyConfig::default()).expect("default tally config should be valid")
    }

    /// Add a vote to the tally.
    ///
    /// # Arguments
    /// * `vset` – Validator set used to look up the voter's power.
    /// * `voter` – Public key of the voter.
    /// * `bid` – Block hash being voted for (`None` = nil vote).
    pub fn add_vote(
        &mut self,
        vset: &dyn ValidatorSet,
        voter: &PublicKeyBytes,
        bid: &Option<Hash32>,
    ) -> TallyResult<()> {
        let power = vset.power_of(voter).ok_or(TallyError::ValidatorNotFound)?;

        if let Some((prev_key, prev_power)) = self.voters.get(voter) {
            if self.config.allow_duplicate_votes {
                // Replace the old vote with the new one.
                let old_key = VoteKey {
                    block_id: prev_key.block_id.clone(),
                };
                if let Some(old_power) = self.buckets.get(&old_key.block_id) {
                    let new_power = old_power.saturating_sub(*prev_power);
                    if new_power == 0 {
                        self.buckets.remove(&old_key.block_id);
                    } else {
                        self.buckets.insert(old_key.block_id.clone(), new_power);
                    }
                }
                self.voters.insert(voter.clone(), (VoteKey { block_id: bid.clone() }, power));
                *self.buckets.entry(bid.clone()).or_insert(0) = self.buckets.get(bid).copied().unwrap_or(0).saturating_add(power);

                if self.config.track_metrics {
                    self.atomic_metrics.inc_duplicate_allowed();
                }
                if let Some(pm) = &self.prometheus {
                    pm.record_duplicate_allowed();
                    pm.update_voters(self.voters.len());
                }
                return Ok(());
            } else {
                if self.config.log_duplicate_warnings {
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
                if self.config.track_metrics {
                    self.atomic_metrics.inc_duplicate_rejected();
                }
                if let Some(pm) = &self.prometheus {
                    pm.record_duplicate_rejected();
                }
                return Err(TallyError::DuplicateVote(
                    hex::encode(&voter.0).chars().take(8).collect(),
                ));
            }
        }

        // First vote from this validator.
        self.voters.insert(voter.clone(), (VoteKey { block_id: bid.clone() }, power));
        *self.buckets.entry(bid.clone()).or_insert(0) = self.buckets.get(bid).copied().unwrap_or(0).saturating_add(power);

        if self.config.track_metrics {
            self.atomic_metrics.inc_votes_added();
        }
        if let Some(pm) = &self.prometheus {
            pm.record_vote_added();
            pm.update_voters(self.voters.len());
        }
        Ok(())
    }

    /// Find the block (or nil) with the highest accumulated power.
    pub fn best(&self) -> TallyResult<(Option<Hash32>, u64)> {
        if self.config.track_metrics {
            self.atomic_metrics.inc_best_calls();
        }
        if let Some(pm) = &self.prometheus {
            pm.record_best_call();
        }
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
        if self.config.track_metrics {
            self.atomic_metrics.inc_clear_calls();
        }
        if let Some(pm) = &self.prometheus {
            pm.record_clear_call();
            pm.update_voters(0);
        }
        self.buckets.clear();
        self.voters.clear();
    }

    /// Merge another tally into this one.
    pub fn merge(&mut self, other: &VoteTally, vset: &dyn ValidatorSet) -> TallyResult<()> {
        for (voter, (key, power)) in other.voters.iter() {
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
            *self.buckets.entry(key.block_id.clone()).or_insert(0) = self.buckets.get(&key.block_id).copied().unwrap_or(0).saturating_add(*power);
        }
        if self.config.track_metrics {
            self.atomic_metrics.inc_votes_added();
        }
        if let Some(pm) = &self.prometheus {
            pm.record_vote_added();
            pm.update_voters(self.voters.len());
        }
        Ok(())
    }

    /// Get a snapshot of the atomic metrics.
    pub fn metrics_snapshot(&self) -> TallyMetricsSnapshot {
        self.atomic_metrics.snapshot()
    }

    /// Get a reference to the atomic metrics.
    pub fn atomic_metrics(&self) -> &AtomicTallyMetrics {
        &self.atomic_metrics
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

impl Default for VoteTally {
    fn default() -> Self {
        Self::new(TallyConfig::default()).expect("default config should be valid")
    }
}

// -----------------------------------------------------------------------------
// Thread‑safe manager (optional)
// -----------------------------------------------------------------------------

/// Thread‑safe wrapper for `VoteTally`.
#[derive(Clone)]
pub struct VoteTallyManager {
    inner: Arc<Mutex<VoteTally>>,
}

impl VoteTallyManager {
    /// Create a new manager with the given configuration.
    pub fn new(config: TallyConfig) -> Result<Self, TallyError> {
        Ok(Self {
            inner: Arc::new(Mutex::new(VoteTally::new(config)?)),
        })
    }

    /// Delegate to `add_vote`.
    pub fn add_vote(
        &self,
        vset: &dyn ValidatorSet,
        voter: &PublicKeyBytes,
        bid: &Option<Hash32>,
    ) -> TallyResult<()> {
        self.inner.lock().add_vote(vset, voter, bid)
    }

    /// Delegate to `best`.
    pub fn best(&self) -> TallyResult<(Option<Hash32>, u64)> {
        self.inner.lock().best()
    }

    /// Delegate to `power_for`.
    pub fn power_for(&self, bid: &Option<Hash32>) -> u64 {
        self.inner.lock().power_for(bid)
    }

    /// Delegate to `has_quorum`.
    pub fn has_quorum(&self, total_power: u64) -> bool {
        self.inner.lock().has_quorum(total_power)
    }

    /// Delegate to `clear`.
    pub fn clear(&self) {
        self.inner.lock().clear();
    }

    /// Delegate to `metrics_snapshot`.
    pub fn metrics_snapshot(&self) -> TallyMetricsSnapshot {
        self.inner.lock().metrics_snapshot()
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
        vset.add_validator(pk1.clone(), 30);
        vset.add_validator(pk2.clone(), 30);
        vset.add_validator(pk3.clone(), 40);

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
            enable_prometheus: false,
        };
        let mut vset = TestValidatorSet::new();
        let pk1 = dummy_pk(1);
        vset.add_validator(pk1.clone(), 100);

        let mut tally = VoteTally::new(config).unwrap();
        let hash_a = Some(dummy_hash(1));
        let hash_b = Some(dummy_hash(2));

        tally.add_vote(&vset, &pk1, &hash_a).unwrap();
        tally.add_vote(&vset, &pk1, &hash_b).unwrap();

        assert_eq!(tally.vote_count(), 1);
        assert_eq!(tally.power_for(&hash_a), 0);
        assert_eq!(tally.power_for(&hash_b), 100);
        let snap = tally.metrics_snapshot();
        assert_eq!(snap.duplicate_votes_allowed, 1);
    }

    #[test]
    fn test_has_quorum() {
        let mut vset = TestValidatorSet::new();
        let pk1 = dummy_pk(1);
        let pk2 = dummy_pk(2);
        let pk3 = dummy_pk(3);
        vset.add_validator(pk1.clone(), 30);
        vset.add_validator(pk2.clone(), 30);
        vset.add_validator(pk3.clone(), 40);
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
    fn test_metrics_snapshot() {
        let mut vset = TestValidatorSet::new();
        let pk1 = dummy_pk(1);
        vset.add_validator(pk1.clone(), 100);

        let mut tally = VoteTally::default();
        let hash_a = Some(dummy_hash(1));

        tally.add_vote(&vset, &pk1, &hash_a).unwrap();
        tally.best().unwrap();
        tally.clear();

        let snap = tally.metrics_snapshot();
        assert_eq!(snap.votes_added, 1);
        assert_eq!(snap.best_calls, 1);
        assert_eq!(snap.clear_calls, 1);
    }

    #[test]
    fn test_manager() -> TallyResult<()> {
        let manager = VoteTallyManager::new(TallyConfig::default())?;
        let mut vset = TestValidatorSet::new();
        let pk1 = dummy_pk(1);
        vset.add_validator(pk1.clone(), 100);
        let hash_a = Some(dummy_hash(1));
        manager.add_vote(&vset, &pk1, &hash_a)?;
        assert_eq!(manager.power_for(&hash_a), 100);
        Ok(())
    }
}
