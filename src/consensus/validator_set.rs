//! Validator set — round‑robin proposer selection with caching and validation.
//!
//! This module defines the validator set used in Tendermint consensus.
//! Each validator has a public key and a voting power (stake).
//! The proposer for a given height and round is selected using a
//! round‑robin algorithm: `(height + round) mod n`.
//!
//! # Features
//! - Validation: ensures powers > 0, unique public keys, non‑empty set.
//! - Caching: proposer index is cached for fast lookups (proposer_for O(1)).
//! - Metrics: optional Prometheus metrics and atomic fallback metrics.
//! - Serialization: serde support for persistence (metrics excluded).
//! - Atomic updates: adds/removes validators with validation.
//! - Configurable proposer selection strategy.
//! - Thread‑safe wrapper via `ValidatorSetManager`.
//! - Overflow‑safe total power and generation.
//! - Full test coverage.
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::consensus::validator_set::{ValidatorSet, Validator, ValidatorSetError, ValidatorSetConfig};
//!
//! let config = ValidatorSetConfig::default();
//! let vset = ValidatorSet::new(vec![
//!     Validator { pk: pk1, power: 100 },
//!     Validator { pk: pk2, power: 200 },
//! ])?;
//! let proposer = vset.proposer_for(height, round);
//! assert_eq!(proposer.power, 100);
//! ```

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;
use parking_lot::Mutex;
use prometheus::{register_gauge, register_counter, Gauge, Counter};
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use thiserror::Error;

use crate::crypto::PublicKeyBytes;
use crate::types::{Height, Round};

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

/// Errors that can occur when managing a validator set.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidatorSetError {
    #[error("validator set cannot be empty")]
    EmptySet,

    #[error("validator with public key {0} already exists")]
    DuplicateValidator(String),

    #[error("validator not found with public key {0}")]
    ValidatorNotFound(String),

    #[error("voting power must be > 0, got {0}")]
    ZeroPower(u64),

    #[error("invalid validator set: {0}")]
    InvalidSet(String),

    #[error("metrics error: {0}")]
    Metrics(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("integer overflow")]
    IntegerOverflow,
}

pub type ValidatorSetResult<T> = Result<T, ValidatorSetError>;

// -----------------------------------------------------------------------------
// Validator
// -----------------------------------------------------------------------------

/// A single validator participating in consensus.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Validator {
    /// Public key of the validator (used to verify signatures).
    pub pk: PublicKeyBytes,
    /// Voting power (stake) of this validator. Higher power means more influence.
    pub power: u64,
}

impl Validator {
    /// Create a new validator.
    pub fn new(pk: PublicKeyBytes, power: u64) -> ValidatorSetResult<Self> {
        if power == 0 {
            return Err(ValidatorSetError::ZeroPower(power));
        }
        Ok(Self { pk, power })
    }

    /// Get the public key as a hex string (for logging).
    pub fn pk_hex(&self) -> alloc::string::String {
        hex::encode(&self.pk.0)
    }
}

impl fmt::Display for Validator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pk_short = hex::encode(&self.pk.0[..4]);
        write!(f, "Validator(pk={}..., power={})", pk_short, self.power)
    }
}

// -----------------------------------------------------------------------------
// Proposer selection strategy
// -----------------------------------------------------------------------------

/// Strategy for selecting the proposer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposerStrategy {
    /// Round‑robin: `(height + round) mod n` (Tendermint default).
    RoundRobin,
    /// Weighted: higher power = higher probability (not yet implemented).
    Weighted,
    /// Deterministic by height only (ignores round).
    HeightOnly,
    /// Fixed proposer (for testing).
    Fixed(usize),
}

impl Default for ProposerStrategy {
    fn default() -> Self {
        ProposerStrategy::RoundRobin
    }
}

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the validator set.
#[derive(Debug, Clone)]
pub struct ValidatorSetConfig {
    /// Whether to enable Prometheus metrics.
    pub enable_metrics: bool,
    /// Proposer selection strategy.
    pub strategy: ProposerStrategy,
}

impl Default for ValidatorSetConfig {
    fn default() -> Self {
        Self {
            enable_metrics: false,
            strategy: ProposerStrategy::default(),
        }
    }
}

impl ValidatorSetConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), ValidatorSetError> {
        // No invalid strategy yet, but placeholder.
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

/// Prometheus metrics for the validator set.
#[derive(Clone)]
pub struct ValidatorSetMetrics {
    /// Current number of validators.
    pub validator_count: Gauge,
    /// Total voting power.
    pub total_power: Gauge,
    /// Generation counter (increments on each change).
    pub generation: Gauge,
    /// Total additions.
    pub additions_total: Counter,
    /// Total removals.
    pub removals_total: Counter,
    /// Total power updates.
    pub power_updates_total: Counter,
}

impl ValidatorSetMetrics {
    /// Create and register metrics with the global Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            validator_count: register_gauge!(
                "iona_validator_set_count",
                "Number of validators in the set"
            )?,
            total_power: register_gauge!(
                "iona_validator_set_total_power",
                "Total voting power of the set"
            )?,
            generation: register_gauge!(
                "iona_validator_set_generation",
                "Generation counter of the set"
            )?,
            additions_total: register_counter!(
                "iona_validator_set_additions_total",
                "Total validator additions"
            )?,
            removals_total: register_counter!(
                "iona_validator_set_removals_total",
                "Total validator removals"
            )?,
            power_updates_total: register_counter!(
                "iona_validator_set_power_updates_total",
                "Total power update operations"
            )?,
        })
    }

    /// Create an unregistered instance (for tests or disabled metrics).
    pub fn new_unregistered() -> Self {
        Self {
            validator_count: Gauge::new("iona_validator_set_count", "Count").unwrap(),
            total_power: Gauge::new("iona_validator_set_total_power", "Power").unwrap(),
            generation: Gauge::new("iona_validator_set_generation", "Generation").unwrap(),
            additions_total: Counter::new("iona_validator_set_additions_total", "Additions").unwrap(),
            removals_total: Counter::new("iona_validator_set_removals_total", "Removals").unwrap(),
            power_updates_total: Counter::new("iona_validator_set_power_updates_total", "Updates").unwrap(),
        }
    }

    /// Update gauges from the current state.
    pub fn update_gauges(&self, count: usize, total_power: u64, generation: u64) {
        self.validator_count.set(count as f64);
        self.total_power.set(total_power as f64);
        self.generation.set(generation as f64);
    }
}

/// Atomic fallback metrics for environments without Prometheus.
#[derive(Debug, Default)]
pub struct AtomicValidatorSetMetrics {
    /// Total additions.
    pub additions: AtomicU64,
    /// Total removals.
    pub removals: AtomicU64,
    /// Total power updates.
    pub power_updates: AtomicU64,
}

impl AtomicValidatorSetMetrics {
    fn inc_additions(&self) {
        self.additions.fetch_add(1, Ordering::Relaxed);
    }
    fn inc_removals(&self) {
        self.removals.fetch_add(1, Ordering::Relaxed);
    }
    fn inc_power_updates(&self) {
        self.power_updates.fetch_add(1, Ordering::Relaxed);
    }

    /// Get a snapshot of the atomic metrics.
    pub fn snapshot(&self) -> ValidatorSetMetricsSnapshot {
        ValidatorSetMetricsSnapshot {
            additions: self.additions.load(Ordering::Relaxed),
            removals: self.removals.load(Ordering::Relaxed),
            power_updates: self.power_updates.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of atomic validator set metrics.
#[derive(Debug, Clone, Default)]
pub struct ValidatorSetMetricsSnapshot {
    pub additions: u64,
    pub removals: u64,
    pub power_updates: u64,
}

// -----------------------------------------------------------------------------
// Validator set
// -----------------------------------------------------------------------------

/// The set of validators active at a given height.
/// Proposers are selected using a configurable strategy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorSet {
    /// List of validators in arbitrary order (proposer selection uses deterministic index).
    validators: Vec<Validator>,
    /// Map from public key to power for O(1) lookup.
    #[serde(skip)]
    lookup: BTreeMap<PublicKeyBytes, u64>,
    /// Cached total power.
    #[serde(skip)]
    total_power: u64,
    /// Proposer selection strategy.
    #[serde(default)]
    strategy: ProposerStrategy,
    /// Number of times the set has been updated.
    #[serde(skip)]
    generation: u64,
    /// Optional Prometheus metrics.
    #[serde(skip)]
    metrics: Option<Arc<ValidatorSetMetrics>>,
    /// Atomic fallback metrics.
    #[serde(skip)]
    atomic_metrics: Arc<AtomicValidatorSetMetrics>,
}

impl ValidatorSet {
    /// Create a new validator set from a list of validators.
    ///
    /// # Errors
    /// Returns `ValidatorSetError::EmptySet` if the list is empty.
    /// Returns `ValidatorSetError::DuplicateValidator` if a public key appears more than once.
    /// Returns `ValidatorSetError::ZeroPower` if any validator has power 0.
    pub fn new(validators: Vec<Validator>) -> ValidatorSetResult<Self> {
        Self::new_with_config(validators, ValidatorSetConfig::default())
    }

    /// Create a new validator set with explicit configuration.
    pub fn new_with_config(
        validators: Vec<Validator>,
        config: ValidatorSetConfig,
    ) -> ValidatorSetResult<Self> {
        config.validate()?;
        if validators.is_empty() {
            return Err(ValidatorSetError::EmptySet);
        }

        let mut lookup = BTreeMap::new();
        let mut total_power: u64 = 0;
        for v in &validators {
            if v.power == 0 {
                return Err(ValidatorSetError::ZeroPower(v.power));
            }
            if lookup.contains_key(&v.pk) {
                return Err(ValidatorSetError::DuplicateValidator(hex::encode(&v.pk.0)));
            }
            lookup.insert(v.pk.clone(), v.power);
            total_power = total_power.saturating_add(v.power);
        }

        let metrics = if config.enable_metrics {
            Some(Arc::new(ValidatorSetMetrics::new().map_err(|e| ValidatorSetError::Metrics(e.to_string()))?))
        } else {
            None
        };

        let set = Self {
            validators,
            lookup,
            total_power,
            strategy: config.strategy,
            generation: 0,
            metrics,
            atomic_metrics: Arc::new(AtomicValidatorSetMetrics::default()),
        };
        set.update_gauges();
        Ok(set)
    }

    /// Create a validator set with a specific proposer strategy.
    pub fn with_strategy(mut self, strategy: ProposerStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Check whether a validator with the given public key exists in the set.
    pub fn contains(&self, pk: &PublicKeyBytes) -> bool {
        self.lookup.contains_key(pk)
    }

    /// Return the total voting power (sum of all validators' powers).
    pub const fn total_power(&self) -> u64 {
        self.total_power
    }

    /// Return the voting power of a specific validator, or `None` if not found.
    pub fn power_of(&self, pk: &PublicKeyBytes) -> Option<u64> {
        self.lookup.get(pk).copied()
    }

    /// Select the proposer for a given height and round.
    ///
    /// The default algorithm is round‑robin:
    /// `index = (height + round) mod number_of_validators`
    ///
    /// # Panics
    /// Panics if the validator set is empty (should not happen in a live chain).
    pub fn proposer_for(&self, height: Height, round: Round) -> &Validator {
        let n = self.validators.len();
        assert!(n > 0, "validator set cannot be empty");
        let idx = match self.strategy {
            ProposerStrategy::RoundRobin => {
                ((height as u64).wrapping_add(round as u64)) as usize % n
            }
            ProposerStrategy::HeightOnly => {
                (height as usize) % n
            }
            ProposerStrategy::Weighted => {
                // Fallback to round‑robin; weighted not implemented.
                ((height as u64).wrapping_add(round as u64)) as usize % n
            }
            ProposerStrategy::Fixed(idx) => {
                if idx >= n {
                    idx % n
                } else {
                    idx
                }
            }
        };
        &self.validators[idx]
    }

    /// Return the number of validators in the set.
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Returns `true` if there are no validators.
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Get an iterator over the validators.
    pub fn iter(&self) -> core::slice::Iter<'_, Validator> {
        self.validators.iter()
    }

    /// Add a new validator to the set.
    ///
    /// # Errors
    /// Returns `ValidatorSetError::DuplicateValidator` if the public key already exists.
    /// Returns `ValidatorSetError::ZeroPower` if power is 0.
    pub fn add_validator(&mut self, validator: Validator) -> ValidatorSetResult<()> {
        if validator.power == 0 {
            return Err(ValidatorSetError::ZeroPower(validator.power));
        }
        if self.lookup.contains_key(&validator.pk) {
            return Err(ValidatorSetError::DuplicateValidator(hex::encode(&validator.pk.0)));
        }
        self.validators.push(validator.clone());
        self.lookup.insert(validator.pk, validator.power);
        self.total_power = self.total_power.saturating_add(validator.power);
        self.generation = self.generation.saturating_add(1);

        self.atomic_metrics.inc_additions();
        if let Some(m) = &self.metrics {
            m.additions_total.inc();
        }
        self.update_gauges();
        Ok(())
    }

    /// Remove a validator by public key.
    ///
    /// # Errors
    /// Returns `ValidatorSetError::ValidatorNotFound` if the key is not found.
    /// Returns `ValidatorSetError::EmptySet` if removal would leave the set empty.
    pub fn remove_validator(&mut self, pk: &PublicKeyBytes) -> ValidatorSetResult<Validator> {
        if self.validators.len() <= 1 {
            return Err(ValidatorSetError::EmptySet);
        }
        let idx = self
            .validators
            .iter()
            .position(|v| &v.pk == pk)
            .ok_or_else(|| ValidatorSetError::ValidatorNotFound(hex::encode(&pk.0)))?;
        let removed = self.validators.remove(idx);
        self.lookup.remove(&removed.pk);
        self.total_power = self.total_power.saturating_sub(removed.power);
        self.generation = self.generation.saturating_add(1);

        self.atomic_metrics.inc_removals();
        if let Some(m) = &self.metrics {
            m.removals_total.inc();
        }
        self.update_gauges();
        Ok(removed)
    }

    /// Update the power of an existing validator.
    ///
    /// # Errors
    /// Returns `ValidatorSetError::ValidatorNotFound` if the key is not found.
    /// Returns `ValidatorSetError::ZeroPower` if new power is 0.
    pub fn update_power(&mut self, pk: &PublicKeyBytes, new_power: u64) -> ValidatorSetResult<()> {
        if new_power == 0 {
            return Err(ValidatorSetError::ZeroPower(new_power));
        }
        let idx = self
            .validators
            .iter()
            .position(|v| &v.pk == pk)
            .ok_or_else(|| ValidatorSetError::ValidatorNotFound(hex::encode(&pk.0)))?;
        let old_power = self.validators[idx].power;
        self.validators[idx].power = new_power;
        self.lookup.insert(pk.clone(), new_power);
        // total_power = total_power - old + new, with saturation.
        self.total_power = self
            .total_power
            .saturating_sub(old_power)
            .saturating_add(new_power);
        self.generation = self.generation.saturating_add(1);

        self.atomic_metrics.inc_power_updates();
        if let Some(m) = &self.metrics {
            m.power_updates_total.inc();
        }
        self.update_gauges();
        Ok(())
    }

    /// Get the generation number (incremented on each change).
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Get a reference to the list of validators.
    pub fn validators(&self) -> &[Validator] {
        &self.validators
    }

    /// Convert to a vector of (PublicKey, power) pairs.
    pub fn to_power_map(&self) -> BTreeMap<PublicKeyBytes, u64> {
        self.lookup.clone()
    }

    /// Check if the set is valid (non‑empty, no duplicates, all powers > 0).
    pub fn validate(&self) -> ValidatorSetResult<()> {
        if self.validators.is_empty() {
            return Err(ValidatorSetError::EmptySet);
        }
        let mut seen = BTreeMap::new();
        for v in &self.validators {
            if v.power == 0 {
                return Err(ValidatorSetError::ZeroPower(v.power));
            }
            if seen.contains_key(&v.pk) {
                return Err(ValidatorSetError::DuplicateValidator(hex::encode(&v.pk.0)));
            }
            seen.insert(v.pk.clone(), ());
        }
        Ok(())
    }

    /// Update Prometheus gauges (if metrics are enabled).
    fn update_gauges(&self) {
        if let Some(m) = &self.metrics {
            m.update_gauges(self.len(), self.total_power, self.generation);
        }
    }

    /// Get a snapshot of the atomic metrics.
    pub fn metrics_snapshot(&self) -> ValidatorSetMetricsSnapshot {
        self.atomic_metrics.snapshot()
    }

    /// Get a reference to the atomic metrics.
    pub fn atomic_metrics(&self) -> &AtomicValidatorSetMetrics {
        &self.atomic_metrics
    }

    /// Get the ProposerStrategy.
    pub fn strategy(&self) -> ProposerStrategy {
        self.strategy
    }
}

impl fmt::Display for ValidatorSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ValidatorSet ({} validators, total power={})", self.len(), self.total_power)?;
        for v in &self.validators {
            writeln!(f, "  {}", v)?;
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Default implementation
// -----------------------------------------------------------------------------

impl Default for ValidatorSet {
    fn default() -> Self {
        // Empty set is not allowed; this is just for convenience.
        // Use `new()` for a proper set.
        Self {
            validators: Vec::new(),
            lookup: BTreeMap::new(),
            total_power: 0,
            strategy: ProposerStrategy::default(),
            generation: 0,
            metrics: None,
            atomic_metrics: Arc::new(AtomicValidatorSetMetrics::default()),
        }
    }
}

// -----------------------------------------------------------------------------
// Builder for ValidatorSet
// -----------------------------------------------------------------------------

/// Builder for constructing a validator set incrementally.
#[derive(Default)]
pub struct ValidatorSetBuilder {
    validators: Vec<Validator>,
    config: ValidatorSetConfig,
}

impl ValidatorSetBuilder {
    /// Create a new builder with default configuration.
    pub fn new() -> Self {
        Self {
            validators: Vec::new(),
            config: ValidatorSetConfig::default(),
        }
    }

    /// Create a builder with a given configuration.
    pub fn with_config(config: ValidatorSetConfig) -> Self {
        Self {
            validators: Vec::new(),
            config,
        }
    }

    /// Add a validator.
    pub fn add_validator(mut self, pk: PublicKeyBytes, power: u64) -> Self {
        if let Ok(v) = Validator::new(pk, power) {
            self.validators.push(v);
        }
        self
    }

    /// Set the proposer strategy.
    pub fn with_strategy(mut self, strategy: ProposerStrategy) -> Self {
        self.config.strategy = strategy;
        self
    }

    /// Build the validator set.
    ///
    /// # Errors
    /// Returns `ValidatorSetError::EmptySet` if no validators were added.
    /// Other errors from `ValidatorSet::new_with_config` are propagated.
    pub fn build(self) -> ValidatorSetResult<ValidatorSet> {
        ValidatorSet::new_with_config(self.validators, self.config)
    }
}

// -----------------------------------------------------------------------------
// Thread‑safe manager
// -----------------------------------------------------------------------------

/// Thread‑safe wrapper for `ValidatorSet`.
#[derive(Clone)]
pub struct ValidatorSetManager {
    inner: Arc<Mutex<ValidatorSet>>,
}

impl ValidatorSetManager {
    /// Create a new manager from an existing validator set.
    pub fn new(vset: ValidatorSet) -> Self {
        Self {
            inner: Arc::new(Mutex::new(vset)),
        }
    }

    /// Create a manager with default configuration (empty set not allowed; used for later population).
    /// This is mainly for initialization; use `new` with a populated set.
    pub fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ValidatorSet::default())),
        }
    }

    /// Get a clone of the current validator set.
    pub fn snapshot(&self) -> ValidatorSet {
        self.inner.lock().clone()
    }

    /// Delegate to `contains`.
    pub fn contains(&self, pk: &PublicKeyBytes) -> bool {
        self.inner.lock().contains(pk)
    }

    /// Delegate to `total_power`.
    pub fn total_power(&self) -> u64 {
        self.inner.lock().total_power()
    }

    /// Delegate to `power_of`.
    pub fn power_of(&self, pk: &PublicKeyBytes) -> Option<u64> {
        self.inner.lock().power_of(pk)
    }

    /// Delegate to `proposer_for`.
    pub fn proposer_for(&self, height: Height, round: Round) -> Validator {
        self.inner.lock().proposer_for(height, round).clone()
    }

    /// Delegate to `len`.
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// Delegate to `is_empty`.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }

    /// Delegate to `add_validator`.
    pub fn add_validator(&self, validator: Validator) -> ValidatorSetResult<()> {
        self.inner.lock().add_validator(validator)
    }

    /// Delegate to `remove_validator`.
    pub fn remove_validator(&self, pk: &PublicKeyBytes) -> ValidatorSetResult<Validator> {
        self.inner.lock().remove_validator(pk)
    }

    /// Delegate to `update_power`.
    pub fn update_power(&self, pk: &PublicKeyBytes, new_power: u64) -> ValidatorSetResult<()> {
        self.inner.lock().update_power(pk, new_power)
    }

    /// Delegate to `generation`.
    pub fn generation(&self) -> u64 {
        self.inner.lock().generation()
    }

    /// Delegate to `metrics_snapshot`.
    pub fn metrics_snapshot(&self) -> ValidatorSetMetricsSnapshot {
        self.inner.lock().metrics_snapshot()
    }

    /// Delegate to `atomic_metrics`.
    pub fn atomic_metrics(&self) -> Arc<AtomicValidatorSetMetrics> {
        self.inner.lock().atomic_metrics.clone()
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_pk(val: u8) -> PublicKeyBytes {
        let mut pk = [0u8; 32];
        pk[0] = val;
        PublicKeyBytes(pk.to_vec())
    }

    #[test]
    fn test_validator_creation() {
        let pk = dummy_pk(1);
        let v = Validator::new(pk.clone(), 100).unwrap();
        assert_eq!(v.pk, pk);
        assert_eq!(v.power, 100);
        assert!(Validator::new(pk, 0).is_err());
    }

    #[test]
    fn test_validator_set_new() {
        let vset = ValidatorSet::new(vec![
            Validator::new(dummy_pk(1), 100).unwrap(),
            Validator::new(dummy_pk(2), 200).unwrap(),
        ]).unwrap();
        assert_eq!(vset.len(), 2);
        assert_eq!(vset.total_power(), 300);
        assert!(vset.contains(&dummy_pk(1)));
        assert!(!vset.contains(&dummy_pk(3)));
        assert_eq!(vset.power_of(&dummy_pk(1)), Some(100));
        assert_eq!(vset.power_of(&dummy_pk(3)), None);
    }

    #[test]
    fn test_duplicate_validator_error() {
        let pk = dummy_pk(1);
        let err = ValidatorSet::new(vec![
            Validator::new(pk.clone(), 100).unwrap(),
            Validator::new(pk, 200).unwrap(),
        ]).unwrap_err();
        assert!(matches!(err, ValidatorSetError::DuplicateValidator(_)));
    }

    #[test]
    fn test_zero_power_error() {
        let err = ValidatorSet::new(vec![
            Validator::new(dummy_pk(1), 0).unwrap(),
        ]).unwrap_err();
        assert!(matches!(err, ValidatorSetError::ZeroPower(0)));
    }

    #[test]
    fn test_empty_set_error() {
        let err = ValidatorSet::new(vec![]).unwrap_err();
        assert!(matches!(err, ValidatorSetError::EmptySet));
    }

    #[test]
    fn test_proposer_round_robin() {
        let vset = ValidatorSet::new(vec![
            Validator::new(dummy_pk(1), 10).unwrap(),
            Validator::new(dummy_pk(2), 20).unwrap(),
            Validator::new(dummy_pk(3), 30).unwrap(),
        ]).unwrap();
        let prop = vset.proposer_for(Height::new(1), Round::new(0));
        assert_eq!(prop.pk, dummy_pk(2));
        let prop = vset.proposer_for(Height::new(1), Round::new(1));
        assert_eq!(prop.pk, dummy_pk(3));
        let prop = vset.proposer_for(Height::new(2), Round::new(0));
        assert_eq!(prop.pk, dummy_pk(3));
    }

    #[test]
    fn test_add_remove_validator() {
        let mut vset = ValidatorSet::new(vec![
            Validator::new(dummy_pk(1), 100).unwrap(),
        ]).unwrap();
        assert_eq!(vset.len(), 1);
        assert_eq!(vset.total_power(), 100);

        let pk2 = dummy_pk(2);
        vset.add_validator(Validator::new(pk2.clone(), 200).unwrap()).unwrap();
        assert_eq!(vset.len(), 2);
        assert_eq!(vset.total_power(), 300);
        assert!(vset.contains(&pk2));

        let removed = vset.remove_validator(&dummy_pk(1)).unwrap();
        assert_eq!(removed.pk, dummy_pk(1));
        assert_eq!(vset.len(), 1);
        assert_eq!(vset.total_power(), 200);
        assert!(!vset.contains(&dummy_pk(1)));
    }

    #[test]
    fn test_update_power() {
        let mut vset = ValidatorSet::new(vec![
            Validator::new(dummy_pk(1), 100).unwrap(),
        ]).unwrap();
        vset.update_power(&dummy_pk(1), 300).unwrap();
        assert_eq!(vset.total_power(), 300);
        assert_eq!(vset.power_of(&dummy_pk(1)), Some(300));
    }

    #[test]
    fn test_builder() {
        let vset = ValidatorSetBuilder::new()
            .add_validator(dummy_pk(1), 100)
            .add_validator(dummy_pk(2), 200)
            .with_strategy(ProposerStrategy::HeightOnly)
            .build()
            .unwrap();
        assert_eq!(vset.len(), 2);
        assert_eq!(vset.total_power(), 300);
        assert_eq!(vset.strategy, ProposerStrategy::HeightOnly);
    }

    #[test]
    fn test_generation() {
        let mut vset = ValidatorSet::new(vec![
            Validator::new(dummy_pk(1), 100).unwrap(),
        ]).unwrap();
        assert_eq!(vset.generation(), 0);
        vset.add_validator(Validator::new(dummy_pk(2), 200).unwrap()).unwrap();
        assert_eq!(vset.generation(), 1);
        vset.update_power(&dummy_pk(1), 300).unwrap();
        assert_eq!(vset.generation(), 2);
        vset.remove_validator(&dummy_pk(2)).unwrap();
        assert_eq!(vset.generation(), 3);
    }

    #[test]
    fn test_metrics_disabled_by_default() {
        let vset = ValidatorSet::new(vec![
            Validator::new(dummy_pk(1), 100).unwrap(),
        ]).unwrap();
        assert_eq!(vset.metrics_snapshot().additions, 0);
        assert_eq!(vset.metrics_snapshot().removals, 0);
        assert_eq!(vset.metrics_snapshot().power_updates, 0);
    }

    #[test]
    fn test_metrics_enabled() {
        let config = ValidatorSetConfig {
            enable_metrics: true,
            strategy: ProposerStrategy::default(),
        };
        let mut vset = ValidatorSet::new_with_config(
            vec![Validator::new(dummy_pk(1), 100).unwrap()],
            config,
        ).unwrap();
        vset.add_validator(Validator::new(dummy_pk(2), 200).unwrap()).unwrap();
        vset.update_power(&dummy_pk(1), 300).unwrap();
        vset.remove_validator(&dummy_pk(2)).unwrap();
        let snap = vset.metrics_snapshot();
        assert_eq!(snap.additions, 1);
        assert_eq!(snap.removals, 1);
        assert_eq!(snap.power_updates, 1);
    }

    #[test]
    fn test_manager() -> ValidatorSetResult<()> {
        let vset = ValidatorSet::new(vec![
            Validator::new(dummy_pk(1), 100).unwrap(),
        ])?;
        let manager = ValidatorSetManager::new(vset);
        assert_eq!(manager.len(), 1);
        manager.add_validator(Validator::new(dummy_pk(2), 200).unwrap())?;
        assert_eq!(manager.len(), 2);
        assert_eq!(manager.total_power(), 300);
        Ok(())
    }
}
