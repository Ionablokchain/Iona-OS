//! Stake ledger and slashing logic.
//!
//! Tracks each validator's stake, status (active, jailed, tombstoned), and applies
//! slashing penalties for misbehaviour (double-vote, double-proposal, downtime).
//!
//! # Slashing Rules
//!
//! - **Double-vote**: 5% of stake (configurable).
//! - **Double-proposal**: 5% of stake (configurable).
//! - **Downtime**: 1% of stake (configurable).
//! - After slashing, if stake drops below `min_stake_after_slash`, validator is removed.
//! - Repeated offences lead to tombstoning (permanent removal).
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                          Slashing Module                               │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   Config    │    Error     │    Metrics    │         Types            │
//! │ (SlashCfg)  │ (SlashErr)   │ (SlashMetr)  │ (Status, Record)         │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   Ledger    │   Manager    │    Legacy     │                          │
//! │ (StakeLedger)│ (SlashMgr)  │ (global fns)  │                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::slashing::{SlashingManager, SlashingConfig};
//!
//! let config = SlashingConfig::default();
//! let mut manager = SlashingManager::new(config);
//! manager.add_validator(pk, 1000);
//! manager.apply_evidence(&evidence)?;
//! assert_eq!(manager.get_stake(&pk), 950);
//! ```

#![allow(dead_code)]

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

use crate::crypto::PublicKeyBytes;
use crate::evidence::Evidence;
use crate::types::Height;

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for slashing.
    use serde::{Deserialize, Serialize};
    use super::constants::*;

    /// Configuration for slashing.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SlashingConfig {
        pub slash_double_vote: u64,
        pub slash_double_proposal: u64,
        pub slash_downtime: u64,
        pub min_stake_after_slash: u64,
        pub unjail_delay: Height,
        pub downtime_window: u64,
        pub min_signed: u64,
        pub tombstone_after_repeated: bool,
    }

    impl Default for SlashingConfig {
        fn default() -> Self {
            Self {
                slash_double_vote: super::constants::DEFAULT_SLASH_DOUBLE_VOTE,
                slash_double_proposal: super::constants::DEFAULT_SLASH_DOUBLE_PROPOSAL,
                slash_downtime: super::constants::DEFAULT_SLASH_DOWNTIME,
                min_stake_after_slash: super::constants::DEFAULT_MIN_STAKE_AFTER_SLASH,
                unjail_delay: super::constants::DEFAULT_UNJAIL_DELAY,
                downtime_window: super::constants::DEFAULT_DOWNTIME_WINDOW,
                min_signed: super::constants::DEFAULT_MIN_SIGNED,
                tombstone_after_repeated: true,
            }
        }
    }

    impl SlashingConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.slash_double_vote == 0 {
                return Err("slash_double_vote must be > 0");
            }
            if self.slash_double_proposal == 0 {
                return Err("slash_double_proposal must be > 0");
            }
            if self.slash_downtime == 0 {
                return Err("slash_downtime must be > 0");
            }
            if self.min_stake_after_slash == 0 {
                return Err("min_stake_after_slash must be > 0");
            }
            if self.unjail_delay == 0 {
                return Err("unjail_delay must be > 0");
            }
            if self.downtime_window == 0 {
                return Err("downtime_window must be > 0");
            }
            if self.min_signed == 0 {
                return Err("min_signed must be > 0");
            }
            Ok(())
        }

        pub fn with_metrics(mut self) -> Self {
            // Metrics are handled by the manager.
            self
        }
    }
}

pub mod constants {
    //! Constants for slashing.

    /// Default slash fraction denominator for double-vote (1/20 = 5%).
    pub const DEFAULT_SLASH_DOUBLE_VOTE: u64 = 20;

    /// Default slash fraction denominator for double-proposal (1/20 = 5%).
    pub const DEFAULT_SLASH_DOUBLE_PROPOSAL: u64 = 20;

    /// Default slash fraction denominator for downtime (1/100 = 1%).
    pub const DEFAULT_SLASH_DOWNTIME: u64 = 100;

    /// Default minimum stake after slashing (1 unit).
    pub const DEFAULT_MIN_STAKE_AFTER_SLASH: u64 = 1;

    /// Default unjail delay (1000 blocks).
    pub const DEFAULT_UNJAIL_DELAY: Height = 1000;

    /// Default downtime window (200 blocks).
    pub const DEFAULT_DOWNTIME_WINDOW: u64 = 200;

    /// Default minimum signed blocks in window (100).
    pub const DEFAULT_MIN_SIGNED: u64 = 100;
}

pub mod error {
    //! Error types for slashing.
    use super::types::Height;
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum SlashingError {
        #[error("validator not found")]
        ValidatorNotFound,

        #[error("validator is already active")]
        AlreadyActive,

        #[error("validator is tombstoned")]
        Tombstoned,

        #[error("unjail delay not elapsed (remaining {remaining} blocks)")]
        UnjailDelayNotElapsed { remaining: Height },

        #[error("stake too low to slash: {stake}")]
        StakeTooLow { stake: u64 },

        #[error("invalid evidence: {0}")]
        InvalidEvidence(String),

        #[error("internal error: {0}")]
        Internal(String),
    }

    pub type SlashingResult<T> = Result<T, SlashingError>;
}

pub mod types {
    //! Core types for slashing.
    use super::constants::DEFAULT_UNJAIL_DELAY;
    use crate::crypto::PublicKeyBytes;
    use crate::types::Height;
    use serde::{Deserialize, Serialize};

    /// Status of a validator.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub enum ValidatorStatus {
        Active,
        Jailed {
            since_height: Height,
            slash_count: u32,
        },
        Tombstoned,
    }

    /// Full record for a validator.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ValidatorRecord {
        pub stake: u64,
        pub slashed_total: u64,
        pub status: ValidatorStatus,
        pub jailed_at: Option<Height>,
    }

    impl ValidatorRecord {
        pub fn new(stake: u64) -> Self {
            Self {
                stake,
                slashed_total: 0,
                status: ValidatorStatus::Active,
                jailed_at: None,
            }
        }

        pub const fn is_active(&self) -> bool {
            matches!(self.status, ValidatorStatus::Active)
        }

        pub const fn is_jailed(&self) -> bool {
            matches!(self.status, ValidatorStatus::Jailed { .. })
        }

        pub const fn is_tombstoned(&self) -> bool {
            matches!(self.status, ValidatorStatus::Tombstoned)
        }

        pub fn can_unjail(&self, current_height: Height, unjail_delay: Height) -> bool {
            match self.status {
                ValidatorStatus::Jailed { since_height, .. } => {
                    current_height >= since_height + unjail_delay
                }
                _ => false,
            }
        }
    }
}

pub mod metrics {
    //! Metrics for slashing.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct SlashingMetrics {
        pub slashes_applied: AtomicU64,
        pub slash_double_vote: AtomicU64,
        pub slash_double_proposal: AtomicU64,
        pub slash_downtime: AtomicU64,
        pub total_slashed: AtomicU64,
        pub validators_jailed: AtomicU64,
        pub validators_tombstoned: AtomicU64,
        pub unjails: AtomicU64,
        pub community_pool: AtomicU64,
    }

    impl SlashingMetrics {
        pub fn inc_slash(&self, ev_type: &str, amount: u64) {
            self.slashes_applied.fetch_add(1, Ordering::Relaxed);
            self.total_slashed.fetch_add(amount, Ordering::Relaxed);
            match ev_type {
                "double_vote" => self.slash_double_vote.fetch_add(1, Ordering::Relaxed),
                "double_proposal" => self.slash_double_proposal.fetch_add(1, Ordering::Relaxed),
                "downtime" => self.slash_downtime.fetch_add(1, Ordering::Relaxed),
                _ => 0,
            };
        }

        pub fn inc_jailed(&self) {
            self.validators_jailed.fetch_add(1, Ordering::Relaxed);
        }

        pub fn inc_tombstoned(&self) {
            self.validators_tombstoned.fetch_add(1, Ordering::Relaxed);
        }

        pub fn inc_unjail(&self) {
            self.unjails.fetch_add(1, Ordering::Relaxed);
        }

        pub fn set_community_pool(&self, amount: u64) {
            self.community_pool.store(amount, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> SlashingMetricsSnapshot {
            SlashingMetricsSnapshot {
                slashes_applied: self.slashes_applied.load(Ordering::Relaxed),
                slash_double_vote: self.slash_double_vote.load(Ordering::Relaxed),
                slash_double_proposal: self.slash_double_proposal.load(Ordering::Relaxed),
                slash_downtime: self.slash_downtime.load(Ordering::Relaxed),
                total_slashed: self.total_slashed.load(Ordering::Relaxed),
                validators_jailed: self.validators_jailed.load(Ordering::Relaxed),
                validators_tombstoned: self.validators_tombstoned.load(Ordering::Relaxed),
                unjails: self.unjails.load(Ordering::Relaxed),
                community_pool: self.community_pool.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SlashingMetricsSnapshot {
        pub slashes_applied: u64,
        pub slash_double_vote: u64,
        pub slash_double_proposal: u64,
        pub slash_downtime: u64,
        pub total_slashed: u64,
        pub validators_jailed: u64,
        pub validators_tombstoned: u64,
        pub unjails: u64,
        pub community_pool: u64,
    }
}

pub mod ledger {
    //! Core stake ledger.
    use super::{
        config::SlashingConfig,
        error::{SlashingError, SlashingResult},
        types::{ValidatorRecord, ValidatorStatus},
        metrics::SlashingMetrics,
    };
    use crate::crypto::PublicKeyBytes;
    use crate::evidence::Evidence;
    use crate::types::Height;
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;
    use tracing::{info, warn};

    /// Stake ledger tracking all validators and their status.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct StakeLedger {
        pub validators: BTreeMap<PublicKeyBytes, ValidatorRecord>,
        pub community_pool: u64,
        pub current_height: Height,
        #[serde(skip)]
        config: SlashingConfig,
    }

    impl StakeLedger {
        pub fn new(config: SlashingConfig) -> Self {
            Self {
                validators: BTreeMap::new(),
                community_pool: 0,
                current_height: 0,
                config,
            }
        }

        pub fn default() -> Self {
            Self::new(SlashingConfig::default())
        }

        pub fn add_validator(&mut self, pk: PublicKeyBytes, stake: u64) -> SlashingResult<()> {
            if self.validators.contains_key(&pk) {
                return Err(SlashingError::Internal("validator already exists".into()));
            }
            self.validators.insert(pk, ValidatorRecord::new(stake));
            Ok(())
        }

        pub fn remove_validator(&mut self, pk: &PublicKeyBytes) -> Option<ValidatorRecord> {
            self.validators.remove(pk)
        }

        pub fn get_validator(&self, pk: &PublicKeyBytes) -> Option<&ValidatorRecord> {
            self.validators.get(pk)
        }

        pub fn get_validator_mut(&mut self, pk: &PublicKeyBytes) -> Option<&mut ValidatorRecord> {
            self.validators.get_mut(pk)
        }

        pub fn get_stake(&self, pk: &PublicKeyBytes) -> u64 {
            self.validators.get(pk).map(|r| r.stake).unwrap_or(0)
        }

        pub fn get_slashed(&self, pk: &PublicKeyBytes) -> u64 {
            self.validators.get(pk).map(|r| r.slashed_total).unwrap_or(0)
        }

        pub const fn community_pool(&self) -> u64 {
            self.community_pool
        }

        pub fn set_height(&mut self, height: Height) {
            self.current_height = height;
        }

        pub fn total_power(&self) -> u64 {
            self.validators
                .values()
                .filter(|r| r.is_active())
                .map(|r| r.stake)
                .sum()
        }

        pub fn apply_evidence(
            &mut self,
            evidence: &Evidence,
            metrics: &SlashingMetrics,
        ) -> SlashingResult<()> {
            let offender = evidence.offender().clone();
            let height = evidence.height();

            let record = self
                .validators
                .get_mut(&offender)
                .ok_or(SlashingError::ValidatorNotFound)?;

            if record.is_tombstoned() {
                return Err(SlashingError::Tombstoned);
            }

            let (fraction, ev_type) = match evidence {
                Evidence::DoubleVote { .. } => {
                    (self.config.slash_double_vote, "double_vote")
                }
                Evidence::DoubleProposal { .. } => {
                    (self.config.slash_double_proposal, "double_proposal")
                }
            };

            let slash_amount = (record.stake / fraction).max(1);
            if slash_amount == 0 {
                return Err(SlashingError::StakeTooLow { stake: record.stake });
            }

            let new_stake = record.stake.saturating_sub(slash_amount);

            record.slashed_total += slash_amount;
            self.community_pool += slash_amount;
            metrics.set_community_pool(self.community_pool);

            let slash_count = match &record.status {
                ValidatorStatus::Jailed { slash_count, .. } => *slash_count + 1,
                _ => 1,
            };

            if self.config.tombstone_after_repeated && slash_count >= 2 {
                record.status = ValidatorStatus::Tombstoned;
                record.stake = 0;
                metrics.inc_tombstoned();
                info!(offender = ?offender, "validator tombstoned");
            } else if new_stake < self.config.min_stake_after_slash {
                record.status = ValidatorStatus::Tombstoned;
                record.stake = 0;
                metrics.inc_tombstoned();
                info!(offender = ?offender, "validator removed (stake below minimum)");
            } else {
                record.status = ValidatorStatus::Jailed {
                    since_height: self.current_height,
                    slash_count,
                };
                record.stake = new_stake;
                record.jailed_at = Some(self.current_height);
                metrics.inc_jailed();
                info!(
                    offender = ?offender,
                    slashed = slash_amount,
                    remaining = new_stake,
                    "validator jailed"
                );
            }

            metrics.inc_slash(ev_type, slash_amount);
            Ok(())
        }

        pub fn unjail(&mut self, pk: &PublicKeyBytes, metrics: &SlashingMetrics) -> SlashingResult<()> {
            let record = self
                .validators
                .get_mut(pk)
                .ok_or(SlashingError::ValidatorNotFound)?;

            match &record.status {
                ValidatorStatus::Tombstoned => return Err(SlashingError::Tombstoned),
                ValidatorStatus::Active => return Err(SlashingError::AlreadyActive),
                ValidatorStatus::Jailed { since_height, .. } => {
                    let remaining = (since_height + self.config.unjail_delay)
                        .saturating_sub(self.current_height);
                    if remaining > 0 {
                        return Err(SlashingError::UnjailDelayNotElapsed { remaining });
                    }
                }
            }

            record.status = ValidatorStatus::Active;
            record.jailed_at = None;
            metrics.inc_unjail();
            Ok(())
        }

        pub fn slash_downtime(&mut self, pk: &PublicKeyBytes, metrics: &SlashingMetrics) -> SlashingResult<()> {
            let record = self
                .validators
                .get_mut(pk)
                .ok_or(SlashingError::ValidatorNotFound)?;

            if !record.is_active() {
                return Err(SlashingError::Internal("validator not active".into()));
            }

            let slash_amount = (record.stake / self.config.slash_downtime).max(1);
            let new_stake = record.stake.saturating_sub(slash_amount);

            record.slashed_total += slash_amount;
            self.community_pool += slash_amount;
            metrics.set_community_pool(self.community_pool);

            if new_stake < self.config.min_stake_after_slash {
                record.status = ValidatorStatus::Tombstoned;
                record.stake = 0;
                metrics.inc_tombstoned();
                info!(offender = ?pk, "validator removed for downtime");
            } else {
                record.status = ValidatorStatus::Jailed {
                    since_height: self.current_height,
                    slash_count: 1,
                };
                record.stake = new_stake;
                record.jailed_at = Some(self.current_height);
                metrics.inc_jailed();
                info!(
                    offender = ?pk,
                    slashed = slash_amount,
                    remaining = new_stake,
                    "validator jailed for downtime"
                );
            }

            metrics.inc_slash("downtime", slash_amount);
            Ok(())
        }

        pub fn active_validators(&self) -> Vec<(&PublicKeyBytes, &ValidatorRecord)> {
            self.validators
                .iter()
                .filter(|(_, r)| r.is_active())
                .collect()
        }

        pub fn jailed_validators(&self) -> Vec<(&PublicKeyBytes, &ValidatorRecord)> {
            self.validators
                .iter()
                .filter(|(_, r)| r.is_jailed())
                .collect()
        }

        pub fn tombstoned_validators(&self) -> Vec<(&PublicKeyBytes, &ValidatorRecord)> {
            self.validators
                .iter()
                .filter(|(_, r)| r.is_tombstoned())
                .collect()
        }

        pub const fn config(&self) -> &SlashingConfig {
            &self.config
        }

        pub fn set_config(&mut self, config: SlashingConfig) {
            self.config = config;
        }

        pub fn apply_evidence_batch(
            &mut self,
            evidence_list: &[Evidence],
            metrics: &SlashingMetrics,
        ) -> Vec<SlashingResult<()>> {
            evidence_list.iter().map(|ev| self.apply_evidence(ev, metrics)).collect()
        }
    }

    impl Default for StakeLedger {
        fn default() -> Self {
            Self::new(SlashingConfig::default())
        }
    }
}

pub mod manager {
    //! Centralised manager for slashing.
    use super::{
        config::SlashingConfig,
        error::{SlashingError, SlashingResult},
        ledger::StakeLedger,
        metrics::SlashingMetrics,
        types::{ValidatorRecord, ValidatorStatus},
    };
    use crate::crypto::PublicKeyBytes;
    use crate::evidence::Evidence;
    use crate::types::Height;
    use alloc::collections::BTreeMap;
    use core::sync::atomic::Ordering;
    use tracing::{debug, info};

    /// Manager for slashing.
    pub struct SlashingManager {
        ledger: StakeLedger,
        metrics: SlashingMetrics,
        initialised: bool,
    }

    impl SlashingManager {
        pub fn new(config: SlashingConfig) -> Self {
            config.validate().expect("invalid SlashingConfig");
            let ledger = StakeLedger::new(config);
            Self {
                ledger,
                metrics: SlashingMetrics::default(),
                initialised: false,
            }
        }

        pub fn default() -> Self {
            Self::new(SlashingConfig::default())
        }

        pub fn config(&self) -> &SlashingConfig {
            self.ledger.config()
        }

        pub fn metrics(&self) -> &SlashingMetrics {
            &self.metrics
        }

        pub fn init(&mut self) {
            self.initialised = true;
            info!("slashing manager initialised");
        }

        pub fn add_validator(&mut self, pk: PublicKeyBytes, stake: u64) -> SlashingResult<()> {
            self.ledger.add_validator(pk, stake)
        }

        pub fn remove_validator(&mut self, pk: &PublicKeyBytes) -> Option<ValidatorRecord> {
            self.ledger.remove_validator(pk)
        }

        pub fn get_validator(&self, pk: &PublicKeyBytes) -> Option<&ValidatorRecord> {
            self.ledger.get_validator(pk)
        }

        pub fn get_stake(&self, pk: &PublicKeyBytes) -> u64 {
            self.ledger.get_stake(pk)
        }

        pub fn get_slashed(&self, pk: &PublicKeyBytes) -> u64 {
            self.ledger.get_slashed(pk)
        }

        pub fn community_pool(&self) -> u64 {
            self.ledger.community_pool()
        }

        pub fn set_height(&mut self, height: Height) {
            self.ledger.set_height(height);
        }

        pub fn total_power(&self) -> u64 {
            self.ledger.total_power()
        }

        pub fn apply_evidence(&mut self, evidence: &Evidence) -> SlashingResult<()> {
            self.ledger.apply_evidence(evidence, &self.metrics)
        }

        pub fn unjail(&mut self, pk: &PublicKeyBytes) -> SlashingResult<()> {
            self.ledger.unjail(pk, &self.metrics)
        }

        pub fn slash_downtime(&mut self, pk: &PublicKeyBytes) -> SlashingResult<()> {
            self.ledger.slash_downtime(pk, &self.metrics)
        }

        pub fn active_validators(&self) -> Vec<(&PublicKeyBytes, &ValidatorRecord)> {
            self.ledger.active_validators()
        }

        pub fn jailed_validators(&self) -> Vec<(&PublicKeyBytes, &ValidatorRecord)> {
            self.ledger.jailed_validators()
        }

        pub fn tombstoned_validators(&self) -> Vec<(&PublicKeyBytes, &ValidatorRecord)> {
            self.ledger.tombstoned_validators()
        }

        pub fn apply_evidence_batch(&mut self, evidence_list: &[Evidence]) -> Vec<SlashingResult<()>> {
            self.ledger.apply_evidence_batch(evidence_list, &self.metrics)
        }

        pub fn metrics_snapshot(&self) -> super::metrics::SlashingMetricsSnapshot {
            self.metrics.snapshot()
        }

        pub fn reset_metrics(&self) {
            *self.metrics = SlashingMetrics::default();
        }

        pub fn is_initialised(&self) -> bool {
            self.initialised
        }

        /// Serialize the ledger for persistence.
        pub fn serialize(&self) -> Result<Vec<u8>, String> {
            serde_json::to_vec(&self.ledger).map_err(|e| e.to_string())
        }

        /// Deserialize and replace the ledger.
        pub fn deserialize(&mut self, data: &[u8]) -> Result<(), String> {
            let ledger: StakeLedger = serde_json::from_slice(data).map_err(|e| e.to_string())?;
            // Preserve the config from the current manager (the serialized one may have outdated config).
            let config = self.ledger.config().clone();
            self.ledger = ledger;
            self.ledger.set_config(config);
            self.ledger.set_height(self.ledger.current_height);
            Ok(())
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::SlashingConfig;
pub use constants::*;
pub use error::{SlashingError, SlashingResult};
pub use types::{ValidatorStatus, ValidatorRecord};
pub use metrics::{SlashingMetrics, SlashingMetricsSnapshot};
pub use ledger::StakeLedger;
pub use manager::SlashingManager;

// -----------------------------------------------------------------------------
// Legacy global API (backward compatibility)
// -----------------------------------------------------------------------------

use spin::Once;

static GLOBAL_MANAGER: Once<SlashingManager> = Once::new();

/// Get the global manager (initialises with defaults if not yet set).
fn global_manager() -> &'static SlashingManager {
    GLOBAL_MANAGER.get_or_init(|| {
        let mut mgr = SlashingManager::new(SlashingConfig::default());
        mgr.init();
        mgr
    })
}

/// Add a validator (legacy).
pub fn add_validator(pk: PublicKeyBytes, stake: u64) -> SlashingResult<()> {
    // We need mutable access, so we'll use a static mutex.
    static MUTEX: spin::Mutex<Option<SlashingManager>> = spin::Mutex::new(None);
    let mut guard = MUTEX.lock();
    if guard.is_none() {
        *guard = Some(SlashingManager::new(SlashingConfig::default()));
    }
    let mgr = guard.as_mut().unwrap();
    mgr.add_validator(pk, stake)
}

/// Apply evidence (legacy).
pub fn apply_evidence(evidence: &Evidence) -> SlashingResult<()> {
    static MUTEX: spin::Mutex<Option<SlashingManager>> = spin::Mutex::new(None);
    let mut guard = MUTEX.lock();
    if guard.is_none() {
        *guard = Some(SlashingManager::new(SlashingConfig::default()));
    }
    let mgr = guard.as_mut().unwrap();
    mgr.apply_evidence(evidence)
}

/// Unjail (legacy).
pub fn unjail(pk: &PublicKeyBytes) -> SlashingResult<()> {
    static MUTEX: spin::Mutex<Option<SlashingManager>> = spin::Mutex::new(None);
    let mut guard = MUTEX.lock();
    if guard.is_none() {
        *guard = Some(SlashingManager::new(SlashingConfig::default()));
    }
    let mgr = guard.as_mut().unwrap();
    mgr.unjail(pk)
}

/// Get stake (legacy).
pub fn get_stake(pk: &PublicKeyBytes) -> u64 {
    static MUTEX: spin::Mutex<Option<SlashingManager>> = spin::Mutex::new(None);
    let guard = MUTEX.lock();
    if let Some(mgr) = guard.as_ref() {
        mgr.get_stake(pk)
    } else {
        0
    }
}

/// Get community pool (legacy).
pub fn community_pool() -> u64 {
    static MUTEX: spin::Mutex<Option<SlashingManager>> = spin::Mutex::new(None);
    let guard = MUTEX.lock();
    if let Some(mgr) = guard.as_ref() {
        mgr.community_pool()
    } else {
        0
    }
}

/// Set height (legacy).
pub fn set_height(height: Height) {
    static MUTEX: spin::Mutex<Option<SlashingManager>> = spin::Mutex::new(None);
    let mut guard = MUTEX.lock();
    if guard.is_none() {
        *guard = Some(SlashingManager::new(SlashingConfig::default()));
    }
    let mgr = guard.as_mut().unwrap();
    mgr.set_height(height);
}

// -----------------------------------------------------------------------------
// Tests (expanded)
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PublicKeyBytes;
    use crate::types::Hash32;

    fn dummy_pk(id: u8) -> PublicKeyBytes {
        PublicKeyBytes(vec![id; 32])
    }

    fn dummy_evidence(pk: PublicKeyBytes, height: Height) -> Evidence {
        use crate::consensus::messages::{Vote, VoteType};
        use crate::crypto::SignatureBytes;

        let vote_a = Vote {
            vote_type: VoteType::Prevote,
            height,
            round: 0,
            voter: pk.clone(),
            block_id: Some(Hash32([1; 32])),
            signature: SignatureBytes(vec![1; 64]),
        };
        let vote_b = Vote {
            vote_type: VoteType::Prevote,
            height,
            round: 0,
            voter: pk.clone(),
            block_id: Some(Hash32([2; 32])),
            signature: SignatureBytes(vec![2; 64]),
        };
        Evidence::DoubleVote {
            voter: pk,
            height,
            round: 0,
            vote_type: VoteType::Prevote,
            a: Some(Hash32([1; 32])),
            b: Some(Hash32([2; 32])),
            vote_a,
            vote_b,
        }
    }

    #[test]
    fn test_add_and_get_validator() {
        let mut ledger = StakeLedger::default();
        let pk = dummy_pk(1);
        ledger.add_validator(pk.clone(), 1000).unwrap();
        assert_eq!(ledger.get_stake(&pk), 1000);
        assert!(ledger.get_validator(&pk).unwrap().is_active());
    }

    #[test]
    fn test_slashing_double_vote() {
        let config = SlashingConfig {
            slash_double_vote: 20, // 5%
            ..Default::default()
        };
        let mut ledger = StakeLedger::new(config);
        let pk = dummy_pk(1);
        ledger.add_validator(pk.clone(), 1000).unwrap();
        let ev = dummy_evidence(pk.clone(), 10);
        ledger.set_height(10);
        let metrics = SlashingMetrics::default();
        ledger.apply_evidence(&ev, &metrics).unwrap();
        assert_eq!(ledger.get_stake(&pk), 950);
        assert_eq!(ledger.get_slashed(&pk), 50);
        assert_eq!(ledger.community_pool, 50);
        let record = ledger.get_validator(&pk).unwrap();
        assert!(record.is_jailed());
    }

    #[test]
    fn test_unjail() {
        let config = SlashingConfig {
            unjail_delay: 10,
            ..Default::default()
        };
        let mut ledger = StakeLedger::new(config);
        let pk = dummy_pk(2);
        ledger.add_validator(pk.clone(), 1000).unwrap();
        let ev = dummy_evidence(pk.clone(), 5);
        ledger.set_height(5);
        let metrics = SlashingMetrics::default();
        ledger.apply_evidence(&ev, &metrics).unwrap();
        assert!(ledger.get_validator(&pk).unwrap().is_jailed());

        ledger.set_height(10);
        let err = ledger.unjail(&pk, &metrics).unwrap_err();
        assert!(matches!(err, SlashingError::UnjailDelayNotElapsed { remaining: 5 }));

        ledger.set_height(20);
        ledger.unjail(&pk, &metrics).unwrap();
        assert!(ledger.get_validator(&pk).unwrap().is_active());
    }

    #[test]
    fn test_tombstoning_after_repeated() {
        let config = SlashingConfig {
            tombstone_after_repeated: true,
            ..Default::default()
        };
        let mut ledger = StakeLedger::new(config);
        let pk = dummy_pk(3);
        ledger.add_validator(pk.clone(), 1000).unwrap();
        let metrics = SlashingMetrics::default();

        ledger.set_height(10);
        let ev1 = dummy_evidence(pk.clone(), 10);
        ledger.apply_evidence(&ev1, &metrics).unwrap();
        assert!(ledger.get_validator(&pk).unwrap().is_jailed());

        ledger.set_height(100);
        ledger.unjail(&pk, &metrics).unwrap();
        assert!(ledger.get_validator(&pk).unwrap().is_active());

        ledger.set_height(200);
        let ev2 = dummy_evidence(pk.clone(), 200);
        ledger.apply_evidence(&ev2, &metrics).unwrap();
        assert!(ledger.get_validator(&pk).unwrap().is_tombstoned());
        assert_eq!(ledger.get_stake(&pk), 0);
    }

    #[test]
    fn test_downtime_slashing() {
        let mut ledger = StakeLedger::default();
        let pk = dummy_pk(4);
        ledger.add_validator(pk.clone(), 1000).unwrap();
        ledger.set_height(100);
        let metrics = SlashingMetrics::default();
        ledger.slash_downtime(&pk, &metrics).unwrap();
        assert!(ledger.get_validator(&pk).unwrap().is_jailed());
        assert_eq!(ledger.get_stake(&pk), 1000 - 10);
        assert_eq!(ledger.community_pool, 10);
    }

    #[test]
    fn test_total_power() {
        let mut ledger = StakeLedger::default();
        let pk1 = dummy_pk(1);
        let pk2 = dummy_pk(2);
        ledger.add_validator(pk1.clone(), 100).unwrap();
        ledger.add_validator(pk2.clone(), 200).unwrap();
        assert_eq!(ledger.total_power(), 300);
        ledger.set_height(10);
        let metrics = SlashingMetrics::default();
        let ev = dummy_evidence(pk1.clone(), 10);
        ledger.apply_evidence(&ev, &metrics).unwrap();
        assert_eq!(ledger.total_power(), 200);
    }

    #[test]
    fn test_stake_below_min_removes_validator() {
        let config = SlashingConfig {
            min_stake_after_slash: 50,
            slash_double_vote: 2, // 50% slash
            ..Default::default()
        };
        let mut ledger = StakeLedger::new(config);
        let pk = dummy_pk(5);
        ledger.add_validator(pk.clone(), 60).unwrap();
        let metrics = SlashingMetrics::default();
        let ev = dummy_evidence(pk.clone(), 10);
        ledger.set_height(10);
        ledger.apply_evidence(&ev, &metrics).unwrap();
        assert!(ledger.get_validator(&pk).unwrap().is_tombstoned());
        assert_eq!(ledger.get_stake(&pk), 0);
    }

    #[test]
    fn test_manager() {
        let mut manager = SlashingManager::new(SlashingConfig::default());
        manager.init();
        let pk = dummy_pk(6);
        manager.add_validator(pk.clone(), 1000).unwrap();
        let ev = dummy_evidence(pk.clone(), 10);
        manager.set_height(10);
        manager.apply_evidence(&ev).unwrap();
        assert_eq!(manager.get_stake(&pk), 950);
        assert_eq!(manager.community_pool(), 50);
        let snap = manager.metrics_snapshot();
        assert_eq!(snap.slashes_applied, 1);
        assert_eq!(snap.total_slashed, 50);
    }
}
