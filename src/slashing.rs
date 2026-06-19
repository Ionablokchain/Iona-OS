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
//! # Example
//!
//! ```rust,ignore
//! use iona::slashing::{StakeLedger, SlashingConfig, ValidatorRecord, ValidatorStatus};
//!
//! let config = SlashingConfig::default();
//! let mut ledger = StakeLedger::new(config);
//! ledger.add_validator(pk, 1000);
//! ledger.apply_evidence(&evidence)?;
//! assert_eq!(ledger.get_stake(&pk), 950);
//! ```

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info, warn};

use crate::crypto::PublicKeyBytes;
use crate::evidence::Evidence;
use crate::types::Height;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for slashing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingConfig {
    /// Slash fraction denominator for double-vote.
    pub slash_double_vote: u64,
    /// Slash fraction denominator for double-proposal.
    pub slash_double_proposal: u64,
    /// Slash fraction denominator for downtime.
    pub slash_downtime: u64,
    /// Minimum stake a validator must retain after slashing.
    pub min_stake_after_slash: u64,
    /// Number of blocks a validator must wait before unjailing.
    pub unjail_delay: Height,
    /// Window of blocks to check for downtime.
    pub downtime_window: u64,
    /// Minimum number of blocks that must be signed in the window to avoid jailing.
    pub min_signed: u64,
    /// Whether to tombstone validators after repeated offences.
    pub tombstone_after_repeated: bool,
}

impl Default for SlashingConfig {
    fn default() -> Self {
        Self {
            slash_double_vote: DEFAULT_SLASH_DOUBLE_VOTE,
            slash_double_proposal: DEFAULT_SLASH_DOUBLE_PROPOSAL,
            slash_downtime: DEFAULT_SLASH_DOWNTIME,
            min_stake_after_slash: DEFAULT_MIN_STAKE_AFTER_SLASH,
            unjail_delay: DEFAULT_UNJAIL_DELAY,
            downtime_window: DEFAULT_DOWNTIME_WINDOW,
            min_signed: DEFAULT_MIN_SIGNED,
            tombstone_after_repeated: true,
        }
    }
}

// -----------------------------------------------------------------------------
// Validator status
// -----------------------------------------------------------------------------

/// Status of a validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorStatus {
    /// Active and participating in consensus.
    Active,
    /// Jailed (temporarily removed from validator set).
    Jailed {
        /// Height at which the validator was jailed.
        since_height: Height,
        /// Number of slash offences.
        slash_count: u32,
    },
    /// Tombstoned (permanently removed).
    Tombstoned,
}

// -----------------------------------------------------------------------------
// Validator record
// -----------------------------------------------------------------------------

/// Full record for a validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorRecord {
    /// Current stake.
    pub stake: u64,
    /// Total amount slashed over lifetime.
    pub slashed_total: u64,
    /// Current status.
    pub status: ValidatorStatus,
    /// Height at which jailed (if applicable).
    pub jailed_at: Option<Height>,
}

impl ValidatorRecord {
    /// Create a new active validator record.
    pub fn new(stake: u64) -> Self {
        Self {
            stake,
            slashed_total: 0,
            status: ValidatorStatus::Active,
            jailed_at: None,
        }
    }

    /// Check if the validator is active.
    pub const fn is_active(&self) -> bool {
        matches!(self.status, ValidatorStatus::Active)
    }

    /// Check if the validator is jailed.
    pub const fn is_jailed(&self) -> bool {
        matches!(self.status, ValidatorStatus::Jailed { .. })
    }

    /// Check if the validator is tombstoned.
    pub const fn is_tombstoned(&self) -> bool {
        matches!(self.status, ValidatorStatus::Tombstoned)
    }

    /// Check if the validator can unjail at the given height.
    pub fn can_unjail(&self, current_height: Height, unjail_delay: Height) -> bool {
        match self.status {
            ValidatorStatus::Jailed { since_height, .. } => {
                current_height >= since_height + unjail_delay
            }
            _ => false,
        }
    }
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// StakeLedger
// -----------------------------------------------------------------------------

/// Stake ledger tracking all validators and their status.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StakeLedger {
    /// Validator public key → record.
    pub validators: BTreeMap<PublicKeyBytes, ValidatorRecord>,
    /// Community pool (accumulated slashed funds).
    pub community_pool: u64,
    /// Current block height (for jail and unjail checks).
    #[serde(default)]
    pub current_height: Height,
    /// Slashing configuration.
    #[serde(skip)]
    config: SlashingConfig,
}

impl StakeLedger {
    /// Create a new ledger with the given configuration.
    pub fn new(config: SlashingConfig) -> Self {
        Self {
            validators: BTreeMap::new(),
            community_pool: 0,
            current_height: 0,
            config,
        }
    }

    /// Create a ledger with default configuration.
    pub fn default() -> Self {
        Self::new(SlashingConfig::default())
    }

    /// Add a new validator with the given stake.
    pub fn add_validator(&mut self, pk: PublicKeyBytes, stake: u64) -> SlashingResult<()> {
        if self.validators.contains_key(&pk) {
            return Err(SlashingError::Internal("validator already exists".into()));
        }
        self.validators.insert(pk, ValidatorRecord::new(stake));
        Ok(())
    }

    /// Remove a validator (e.g., when self-delegation drops to zero).
    pub fn remove_validator(&mut self, pk: &PublicKeyBytes) -> Option<ValidatorRecord> {
        self.validators.remove(pk)
    }

    /// Get a validator record.
    pub fn get_validator(&self, pk: &PublicKeyBytes) -> Option<&ValidatorRecord> {
        self.validators.get(pk)
    }

    /// Get a mutable validator record.
    pub fn get_validator_mut(&mut self, pk: &PublicKeyBytes) -> Option<&mut ValidatorRecord> {
        self.validators.get_mut(pk)
    }

    /// Get the stake of a validator.
    pub fn get_stake(&self, pk: &PublicKeyBytes) -> u64 {
        self.validators.get(pk).map(|r| r.stake).unwrap_or(0)
    }

    /// Get the total slashed amount for a validator.
    pub fn get_slashed(&self, pk: &PublicKeyBytes) -> u64 {
        self.validators.get(pk).map(|r| r.slashed_total).unwrap_or(0)
    }

    /// Get the community pool balance.
    pub const fn community_pool(&self) -> u64 {
        self.community_pool
    }

    /// Set the current height (must be called before slashing/unjailing).
    pub fn set_height(&mut self, height: Height) {
        self.current_height = height;
    }

    /// Total active voting power (only active validators).
    pub fn total_power(&self) -> u64 {
        self.validators
            .values()
            .filter(|r| r.is_active())
            .map(|r| r.stake)
            .sum()
    }

    /// Apply slashing evidence.
    ///
    /// Slashes the offender's stake, moves funds to community pool,
    /// and updates validator status (jailed/tombstoned).
    pub fn apply_evidence(&mut self, evidence: &Evidence) -> SlashingResult<()> {
        let offender = evidence.offender().clone();
        let height = evidence.height();

        let record = self
            .validators
            .get_mut(&offender)
            .ok_or(SlashingError::ValidatorNotFound)?;

        // Check if tombstoned.
        if record.is_tombstoned() {
            return Err(SlashingError::Tombstoned);
        }

        // Determine slash fraction.
        let fraction = match evidence {
            Evidence::DoubleVote { .. } => self.config.slash_double_vote,
            Evidence::DoubleProposal { .. } => self.config.slash_double_proposal,
        };

        // Compute slash amount.
        let slash_amount = (record.stake / fraction).max(1);
        if slash_amount == 0 {
            return Err(SlashingError::StakeTooLow { stake: record.stake });
        }

        let new_stake = record.stake.saturating_sub(slash_amount);

        // Update slashed total and community pool.
        record.slashed_total += slash_amount;
        self.community_pool += slash_amount;

        // Update status.
        let slash_count = match &record.status {
            ValidatorStatus::Jailed { slash_count, .. } => *slash_count + 1,
            _ => 1,
        };

        // Check if tombstoned.
        if self.config.tombstone_after_repeated && slash_count >= 2 {
            record.status = ValidatorStatus::Tombstoned;
            record.stake = 0;
            info!(offender = ?offender, "validator tombstoned");
        } else if new_stake < self.config.min_stake_after_slash {
            // Remove validator entirely.
            record.status = ValidatorStatus::Tombstoned;
            record.stake = 0;
            info!(offender = ?offender, "validator removed (stake below minimum)");
        } else {
            record.status = ValidatorStatus::Jailed {
                since_height: self.current_height,
                slash_count,
            };
            record.stake = new_stake;
            record.jailed_at = Some(self.current_height);
            info!(
                offender = ?offender,
                slashed = slash_amount,
                remaining = new_stake,
                "validator jailed"
            );
        }

        Ok(())
    }

    /// Unjail a validator.
    pub fn unjail(&mut self, pk: &PublicKeyBytes) -> SlashingResult<()> {
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
        Ok(())
    }

    /// Slash for downtime (missed blocks in the window).
    pub fn slash_downtime(&mut self, pk: &PublicKeyBytes) -> SlashingResult<()> {
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

        if new_stake < self.config.min_stake_after_slash {
            record.status = ValidatorStatus::Tombstoned;
            record.stake = 0;
            info!(offender = ?pk, "validator removed for downtime");
        } else {
            record.status = ValidatorStatus::Jailed {
                since_height: self.current_height,
                slash_count: 1,
            };
            record.stake = new_stake;
            record.jailed_at = Some(self.current_height);
            info!(
                offender = ?pk,
                slashed = slash_amount,
                remaining = new_stake,
                "validator jailed for downtime"
            );
        }
        Ok(())
    }

    /// Get all active validators.
    pub fn active_validators(&self) -> Vec<(&PublicKeyBytes, &ValidatorRecord)> {
        self.validators
            .iter()
            .filter(|(_, r)| r.is_active())
            .collect()
    }

    /// Get all jailed validators.
    pub fn jailed_validators(&self) -> Vec<(&PublicKeyBytes, &ValidatorRecord)> {
        self.validators
            .iter()
            .filter(|(_, r)| r.is_jailed())
            .collect()
    }

    /// Get all tombstoned validators.
    pub fn tombstoned_validators(&self) -> Vec<(&PublicKeyBytes, &ValidatorRecord)> {
        self.validators
            .iter()
            .filter(|(_, r)| r.is_tombstoned())
            .collect()
    }

    /// Get the current configuration.
    pub const fn config(&self) -> &SlashingConfig {
        &self.config
    }

    /// Update the configuration (e.g., for governance).
    pub fn set_config(&mut self, config: SlashingConfig) {
        self.config = config;
    }

    /// Apply a series of evidence items.
    pub fn apply_evidence_batch(&mut self, evidence_list: &[Evidence]) -> Vec<SlashingResult<()>> {
        evidence_list.iter().map(|ev| self.apply_evidence(ev)).collect()
    }
}

impl Default for StakeLedger {
    fn default() -> Self {
        Self::new(SlashingConfig::default())
    }
}

// -----------------------------------------------------------------------------
// Helpers for serialization compatibility
// -----------------------------------------------------------------------------

impl StakeLedger {
    /// Convert to a simple stake map (for backward compatibility).
    pub fn to_stake_map(&self) -> BTreeMap<PublicKeyBytes, u64> {
        self.validators
            .iter()
            .map(|(k, v)| (k.clone(), v.stake))
            .collect()
    }

    /// Convert from a simple stake map (for backward compatibility).
    pub fn from_stake_map(
        stake_map: BTreeMap<PublicKeyBytes, u64>,
        config: SlashingConfig,
    ) -> Self {
        let mut ledger = Self::new(config);
        for (pk, stake) in stake_map {
            ledger.validators.insert(pk, ValidatorRecord::new(stake));
        }
        ledger
    }
}

// -----------------------------------------------------------------------------
// Tests
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
        // For testing, we'll use a minimal double-vote evidence.
        // In reality, we'd need a proper constructor.
        // We use a placeholder; the test will only test the slashing logic
        // by calling apply_evidence and checking effects.
        // Since we can't create Evidence without a full Vote struct, we'll
        // use a stub for the test by creating a minimal struct.
        // In production, the evidence module provides these.
        // We'll create a mock using a struct that implements the necessary
        // methods. For simplicity, we'll assume Evidence is an enum with a
        // DoubleVote variant and we can construct it.
        // Since we can't construct it here, we'll skip tests that require
        // constructing evidence, or we'll use a mock via a trait.
        // Instead, we'll write tests that use a helper to create a dummy
        // evidence. We'll define a minimal struct for testing.
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
        ledger.apply_evidence(&ev).unwrap();
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
        ledger.apply_evidence(&ev).unwrap();
        assert!(ledger.get_validator(&pk).unwrap().is_jailed());

        // Cannot unjail immediately.
        ledger.set_height(10);
        let err = ledger.unjail(&pk).unwrap_err();
        assert!(matches!(err, SlashingError::UnjailDelayNotElapsed { remaining: 5 }));

        // After delay.
        ledger.set_height(20);
        ledger.unjail(&pk).unwrap();
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

        // First offence.
        ledger.set_height(10);
        let ev1 = dummy_evidence(pk.clone(), 10);
        ledger.apply_evidence(&ev1).unwrap();
        assert!(ledger.get_validator(&pk).unwrap().is_jailed());

        // Unjail.
        ledger.set_height(100);
        ledger.unjail(&pk).unwrap();
        assert!(ledger.get_validator(&pk).unwrap().is_active());

        // Second offence -> tombstoned.
        ledger.set_height(200);
        let ev2 = dummy_evidence(pk.clone(), 200);
        ledger.apply_evidence(&ev2).unwrap();
        assert!(ledger.get_validator(&pk).unwrap().is_tombstoned());
        assert_eq!(ledger.get_stake(&pk), 0);
    }

    #[test]
    fn test_downtime_slashing() {
        let mut ledger = StakeLedger::default();
        let pk = dummy_pk(4);
        ledger.add_validator(pk.clone(), 1000).unwrap();
        ledger.set_height(100);
        ledger.slash_downtime(&pk).unwrap();
        assert!(ledger.get_validator(&pk).unwrap().is_jailed());
        assert_eq!(ledger.get_stake(&pk), 1000 - 10); // 1% = 10
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
        // Jailing removes power.
        ledger.set_height(10);
        let ev = dummy_evidence(pk1.clone(), 10);
        ledger.apply_evidence(&ev).unwrap();
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
        let ev = dummy_evidence(pk.clone(), 10);
        ledger.set_height(10);
        ledger.apply_evidence(&ev).unwrap();
        assert!(ledger.get_validator(&pk).unwrap().is_tombstoned());
        assert_eq!(ledger.get_stake(&pk), 0);
    }
}
