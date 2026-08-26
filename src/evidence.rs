//! Evidence of validator misbehaviour for slashing.
//!
//! This module defines evidence structures that can be submitted to the chain
//! to slash validators who equivocate (double‑vote or double‑propose).
//!
//! # Slashing Rules
//!
//! - **Double‑vote**: A validator signs two different blocks (or a block and nil)
//!   in the same height/round for the same vote type. Slash fraction is
//!   configurable (default 5% = 1/20).
//! - **Double‑proposal**: A validator proposes two different blocks at the same
//!   height/round. Slash fraction is also configurable (default 5%).
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                         Evidence Module                                │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   Config    │    Error     │    Metrics    │         Types            │
//! │ (EvCfg)     │ (EvError)    │ (EvMetrics)   │ (Evidence, Id, Outcome)  │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │ Validation  │  Application │   Manager     │        Legacy            │
//! │ (validate)  │ (apply)      │ (EvManager)   │ (global functions)       │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::evidence::{EvidenceManager, EvidenceConfig};
//!
//! let config = EvidenceConfig::default();
//! let mut manager = EvidenceManager::new(config);
//! let outcome = manager.apply_evidence(&evidence, &mut ledger)?;
//! if outcome.slashed {
//!     println!("Slashed {} tokens", outcome.slashed_amount);
//! }
//! ```

#![allow(dead_code)]

use crate::consensus::messages::{Proposal, Vote, VoteType};
use crate::crypto::{PublicKeyBytes, SignatureBytes, Verifier, CryptoError};
use crate::slashing::StakeLedger;
use crate::types::{Height, Hash32, Round};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for evidence handling.
    use serde::{Deserialize, Serialize};
    use super::types::{Height, Round};

    /// Configuration for evidence handling.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct EvidenceConfig {
        pub max_age: Height,
        pub slash_fraction_double_vote: u64,
        pub slash_fraction_double_proposal: u64,
        pub tombstone_period: Height,
        pub verify_signatures: bool,
        pub allow_nil_equivocation: bool,
    }

    impl Default for EvidenceConfig {
        fn default() -> Self {
            Self {
                max_age: super::constants::DEFAULT_EVIDENCE_MAX_AGE,
                slash_fraction_double_vote: super::constants::DEFAULT_SLASH_FRACTION_DOUBLE_VOTE,
                slash_fraction_double_proposal: super::constants::DEFAULT_SLASH_FRACTION_DOUBLE_PROPOSAL,
                tombstone_period: super::constants::DEFAULT_TOMBSTONE_PERIOD,
                verify_signatures: true,
                allow_nil_equivocation: true,
            }
        }
    }

    impl EvidenceConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.max_age == 0 {
                return Err("max_age must be > 0");
            }
            if self.slash_fraction_double_vote == 0 {
                return Err("slash_fraction_double_vote must be > 0");
            }
            if self.slash_fraction_double_proposal == 0 {
                return Err("slash_fraction_double_proposal must be > 0");
            }
            if self.tombstone_period == 0 {
                return Err("tombstone_period must be > 0");
            }
            Ok(())
        }

        pub fn with_verify(mut self, verify: bool) -> Self {
            self.verify_signatures = verify;
            self
        }
    }
}

pub mod error {
    //! Errors that can occur during evidence validation or application.
    use super::types::{Height, Round, VoteType};
    use crate::crypto::CryptoError;
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum EvidenceError {
        #[error("duplicate evidence: both messages are identical")]
        DuplicateMessages,

        #[error("mismatched height: expected {expected}, got {actual}")]
        HeightMismatch { expected: Height, actual: Height },

        #[error("mismatched round: expected {expected}, got {actual}")]
        RoundMismatch { expected: Round, actual: Round },

        #[error("mismatched vote type: expected {:?}, got {:?}", expected, actual)]
        VoteTypeMismatch { expected: VoteType, actual: VoteType },

        #[error("mismatched offender: expected public key mismatch")]
        OffenderMismatch,

        #[error("invalid signature in evidence")]
        InvalidSignature(#[from] CryptoError),

        #[error("both votes refer to the same block (not equivocation)")]
        SameBlock,

        #[error("both proposals refer to the same block (not equivocation)")]
        SameProposal,

        #[error("evidence is stale: height {height} older than max age {max_age}")]
        StaleEvidence { height: Height, max_age: Height },

        #[error("validator not found in validator set")]
        ValidatorNotFound,

        #[error("validator already tombstoned")]
        AlreadyTombstoned,

        #[error("evidence already processed (duplicate)")]
        AlreadyProcessed,

        #[error("incomplete evidence: missing required fields")]
        IncompleteEvidence,

        #[error("internal error: {0}")]
        Internal(String),
    }

    pub type EvidenceResult<T> = Result<T, EvidenceError>;
}

pub mod constants {
    //! Constants for evidence handling.

    /// Minimum signature length for a valid vote signature (Ed25519).
    pub const MIN_SIGNATURE_LEN: usize = 64;

    /// Default slash fraction for double‑vote (5% = 1/20).
    pub const DEFAULT_SLASH_FRACTION_DOUBLE_VOTE: u64 = 20;

    /// Default slash fraction for double‑proposal (5% = 1/20).
    pub const DEFAULT_SLASH_FRACTION_DOUBLE_PROPOSAL: u64 = 20;

    /// Default evidence age limit (blocks) – evidence older than this is rejected.
    pub const DEFAULT_EVIDENCE_MAX_AGE: Height = 100_000;

    /// Default tombstone period (blocks) – after this, validator cannot unjail.
    pub const DEFAULT_TOMBSTONE_PERIOD: Height = 1_000_000;
}

pub mod types {
    //! Core types for evidence.
    use super::{constants::*, error::EvidenceError};
    use crate::consensus::messages::{Proposal, Vote, VoteType};
    use crate::crypto::PublicKeyBytes;
    use crate::types::{Height, Hash32, Round};
    use serde::{Deserialize, Serialize};

    /// Evidence of validator misbehaviour for slashing.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub enum Evidence {
        /// Validator signed two different blocks in the same prevote/precommit round.
        DoubleVote {
            voter: PublicKeyBytes,
            height: Height,
            round: Round,
            vote_type: VoteType,
            #[serde(default)]
            a: Option<Hash32>,
            #[serde(default)]
            b: Option<Hash32>,
            vote_a: Vote,
            vote_b: Vote,
        },
        /// Validator proposed two different blocks at the same height/round.
        DoubleProposal {
            proposer: PublicKeyBytes,
            height: Height,
            round: Round,
            #[serde(default)]
            a: Option<Hash32>,
            #[serde(default)]
            b: Option<Hash32>,
            #[serde(default)]
            proposal_a: Option<Proposal>,
            #[serde(default)]
            proposal_b: Option<Proposal>,
        },
    }

    impl Evidence {
        /// Returns the public key of the offending validator.
        pub fn offender(&self) -> &PublicKeyBytes {
            match self {
                Evidence::DoubleVote { voter, .. } => voter,
                Evidence::DoubleProposal { proposer, .. } => proposer,
            }
        }

        /// Returns the height at which the offence occurred.
        pub fn height(&self) -> Height {
            match self {
                Evidence::DoubleVote { height, .. } => *height,
                Evidence::DoubleProposal { height, .. } => *height,
            }
        }

        /// Returns the round.
        pub fn round(&self) -> Round {
            match self {
                Evidence::DoubleVote { round, .. } => *round,
                Evidence::DoubleProposal { round, .. } => *round,
            }
        }

        /// Returns the slash fraction denominator for this evidence type.
        pub fn slash_fraction(&self, config: &super::config::EvidenceConfig) -> u64 {
            match self {
                Evidence::DoubleVote { .. } => config.slash_fraction_double_vote,
                Evidence::DoubleProposal { .. } => config.slash_fraction_double_proposal,
            }
        }

        /// Validate internal consistency and signatures.
        pub fn validate<V: crate::crypto::Verifier>(
            &self,
            verifier: &V,
            config: &super::config::EvidenceConfig,
        ) -> super::error::EvidenceResult<()> {
            match self {
                Evidence::DoubleVote {
                    voter,
                    height,
                    round,
                    vote_type,
                    a,
                    b,
                    vote_a,
                    vote_b,
                } => {
                    if vote_a.voter != *voter || vote_b.voter != *voter {
                        return Err(super::error::EvidenceError::OffenderMismatch);
                    }
                    if vote_a.height != *height || vote_b.height != *height {
                        return Err(super::error::EvidenceError::HeightMismatch {
                            expected: *height,
                            actual: vote_a.height,
                        });
                    }
                    if vote_a.round != *round || vote_b.round != *round {
                        return Err(super::error::EvidenceError::RoundMismatch {
                            expected: *round,
                            actual: vote_a.round,
                        });
                    }
                    if vote_a.vote_type != *vote_type || vote_b.vote_type != *vote_type {
                        return Err(super::error::EvidenceError::VoteTypeMismatch {
                            expected: *vote_type,
                            actual: vote_a.vote_type,
                        });
                    }
                    if vote_a == vote_b {
                        return Err(super::error::EvidenceError::DuplicateMessages);
                    }
                    if a == b {
                        return Err(super::error::EvidenceError::SameBlock);
                    }
                    if !config.allow_nil_equivocation && (a.is_none() || b.is_none()) {
                        return Err(super::error::EvidenceError::Internal(
                            "nil equivocation not allowed".into(),
                        ));
                    }
                    if config.verify_signatures {
                        let msg_a = crate::consensus::messages::vote_sign_bytes(
                            *vote_type,
                            *height,
                            *round,
                            &vote_a.block_id,
                        );
                        let msg_b = crate::consensus::messages::vote_sign_bytes(
                            *vote_type,
                            *height,
                            *round,
                            &vote_b.block_id,
                        );
                        verifier.verify(voter, &msg_a, &vote_a.signature)?;
                        verifier.verify(voter, &msg_b, &vote_b.signature)?;
                    }
                    Ok(())
                }
                Evidence::DoubleProposal {
                    proposer,
                    height,
                    round,
                    a,
                    b,
                    proposal_a,
                    proposal_b,
                } => {
                    let (prop_a, prop_b) = match (proposal_a, proposal_b) {
                        (Some(p1), Some(p2)) => (p1, p2),
                        _ => return Err(super::error::EvidenceError::IncompleteEvidence),
                    };
                    if prop_a.proposer != *proposer || prop_b.proposer != *proposer {
                        return Err(super::error::EvidenceError::OffenderMismatch);
                    }
                    if prop_a.height != *height || prop_b.height != *height {
                        return Err(super::error::EvidenceError::HeightMismatch {
                            expected: *height,
                            actual: prop_a.height,
                        });
                    }
                    if prop_a.round != *round || prop_b.round != *round {
                        return Err(super::error::EvidenceError::RoundMismatch {
                            expected: *round,
                            actual: prop_a.round,
                        });
                    }
                    if prop_a == prop_b {
                        return Err(super::error::EvidenceError::DuplicateMessages);
                    }
                    if a == b {
                        return Err(super::error::EvidenceError::SameProposal);
                    }
                    if config.verify_signatures {
                        let msg_a = crate::consensus::messages::proposal_sign_bytes(
                            *height,
                            *round,
                            &prop_a.block_id,
                            prop_a.pol_round,
                        );
                        let msg_b = crate::consensus::messages::proposal_sign_bytes(
                            *height,
                            *round,
                            &prop_b.block_id,
                            prop_b.pol_round,
                        );
                        verifier.verify(proposer, &msg_a, &prop_a.signature)?;
                        verifier.verify(proposer, &msg_b, &prop_b.signature)?;
                    }
                    Ok(())
                }
            }
        }

        /// Check if the evidence is still fresh (not older than `max_age` blocks).
        pub fn is_fresh(&self, current_height: Height, max_age: Height) -> bool {
            current_height.saturating_sub(self.height()) <= max_age
        }

        /// Returns a unique identifier for this evidence (for deduplication).
        pub fn id(&self) -> EvidenceId {
            EvidenceId {
                offender: self.offender().clone(),
                height: self.height(),
                round: self.round(),
                ev_type: match self {
                    Evidence::DoubleVote { .. } => EvidenceType::DoubleVote,
                    Evidence::DoubleProposal { .. } => EvidenceType::DoubleProposal,
                },
            }
        }
    }

    /// Unique identifier for an evidence (used for deduplication).
    #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct EvidenceId {
        pub offender: PublicKeyBytes,
        pub height: Height,
        pub round: Round,
        pub ev_type: EvidenceType,
    }

    /// Type of evidence.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub enum EvidenceType {
        DoubleVote,
        DoubleProposal,
    }

    /// Result of applying evidence.
    #[derive(Debug, Clone)]
    pub struct SlashingOutcome {
        pub slashed: bool,
        pub slashed_amount: u64,
        pub remaining_stake: u64,
        pub jailed: bool,
        pub tombstoned: bool,
        pub slash_height: Height,
    }
}

pub mod metrics {
    //! Metrics for evidence processing.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct EvidenceMetrics {
        pub evidence_received: AtomicU64,
        pub evidence_validated: AtomicU64,
        pub evidence_applied: AtomicU64,
        pub evidence_rejected: AtomicU64,
        pub total_slashed: AtomicU64,
    }

    impl EvidenceMetrics {
        pub fn inc_received(&self) {
            self.evidence_received.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_validated(&self) {
            self.evidence_validated.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_applied(&self) {
            self.evidence_applied.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_rejected(&self) {
            self.evidence_rejected.fetch_add(1, Ordering::Relaxed);
        }
        pub fn add_slashed(&self, amount: u64) {
            self.total_slashed.fetch_add(amount, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> EvidenceMetricsSnapshot {
            EvidenceMetricsSnapshot {
                evidence_received: self.evidence_received.load(Ordering::Relaxed),
                evidence_validated: self.evidence_validated.load(Ordering::Relaxed),
                evidence_applied: self.evidence_applied.load(Ordering::Relaxed),
                evidence_rejected: self.evidence_rejected.load(Ordering::Relaxed),
                total_slashed: self.total_slashed.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct EvidenceMetricsSnapshot {
        pub evidence_received: u64,
        pub evidence_validated: u64,
        pub evidence_applied: u64,
        pub evidence_rejected: u64,
        pub total_slashed: u64,
    }
}

pub mod application {
    //! Applying evidence to the stake ledger.
    use super::{
        config::EvidenceConfig,
        error::{EvidenceError, EvidenceResult},
        types::{Evidence, EvidenceId, SlashingOutcome},
        metrics::EvidenceMetrics,
    };
    use crate::slashing::StakeLedger;
    use std::collections::HashSet;
    use tracing::{info, warn};

    /// Apply evidence to a stake ledger, slashing the offending validator.
    pub fn apply_evidence(
        evidence: &Evidence,
        ledger: &mut StakeLedger,
        config: &EvidenceConfig,
        processed_set: &mut HashSet<EvidenceId>,
        metrics: &EvidenceMetrics,
    ) -> EvidenceResult<SlashingOutcome> {
        let offender = evidence.offender().clone();
        let height = evidence.height();

        // Deduplication.
        let id = evidence.id();
        if processed_set.contains(&id) {
            warn!(?id, "evidence already processed");
            metrics.inc_rejected();
            return Err(EvidenceError::AlreadyProcessed);
        }

        // Check if validator exists.
        let record = ledger
            .validators
            .get_mut(&offender)
            .ok_or(EvidenceError::ValidatorNotFound)?;

        // Check if already tombstoned.
        if matches!(record.status, crate::slashing::ValidatorStatus::Tombstoned) {
            metrics.inc_rejected();
            return Err(EvidenceError::AlreadyTombstoned);
        }

        // Check freshness.
        let current_height = ledger.current_height().unwrap_or(0);
        if !evidence.is_fresh(current_height, config.max_age) {
            metrics.inc_rejected();
            return Err(EvidenceError::StaleEvidence {
                height: evidence.height(),
                max_age: config.max_age,
            });
        }

        // Compute slash amount.
        let fraction = evidence.slash_fraction(config);
        let slash_amount = (record.stake / fraction).max(1);
        let new_stake = record.stake.saturating_sub(slash_amount);

        // Update record.
        record.stake = new_stake;
        record.slashed_total += slash_amount;
        metrics.add_slashed(slash_amount);

        // Determine if tombstoned.
        let tombstoned = matches!(&record.status, crate::slashing::ValidatorStatus::Jailed { slash_count, .. } if *slash_count >= 2);
        if tombstoned {
            record.status = crate::slashing::ValidatorStatus::Tombstoned;
            info!(offender = ?offender, "validator tombstoned");
        } else {
            let slash_count = match &record.status {
                crate::slashing::ValidatorStatus::Jailed { slash_count, .. } => *slash_count + 1,
                _ => 1,
            };
            record.status = crate::slashing::ValidatorStatus::Jailed {
                since_height: current_height,
                slash_count,
            };
            info!(offender = ?offender, slashed = slash_amount, remaining = new_stake, "validator jailed");
        }

        // Mark as processed.
        processed_set.insert(id);
        metrics.inc_applied();

        Ok(SlashingOutcome {
            slashed: true,
            slashed_amount: slash_amount,
            remaining_stake: new_stake,
            jailed: true,
            tombstoned,
            slash_height: current_height,
        })
    }
}

pub mod validation {
    //! Validation of evidence (stateless).
    use super::{
        config::EvidenceConfig,
        error::EvidenceResult,
        types::Evidence,
    };
    use crate::crypto::Verifier;

    /// Validate evidence using the given verifier and config.
    pub fn validate_evidence<V: Verifier>(
        evidence: &Evidence,
        verifier: &V,
        config: &EvidenceConfig,
    ) -> EvidenceResult<()> {
        evidence.validate(verifier, config)
    }
}

pub mod manager {
    //! Centralised manager for evidence handling.
    use super::{
        config::EvidenceConfig,
        error::{EvidenceError, EvidenceResult},
        types::{Evidence, EvidenceId, SlashingOutcome},
        metrics::EvidenceMetrics,
        application::apply_evidence,
        validation::validate_evidence,
    };
    use crate::crypto::Verifier;
    use crate::slashing::StakeLedger;
    use std::collections::HashSet;
    use std::sync::RwLock;
    use tracing::{debug, info};

    /// Manager for evidence handling.
    pub struct EvidenceManager {
        config: EvidenceConfig,
        metrics: EvidenceMetrics,
        processed: RwLock<HashSet<EvidenceId>>,
        initialised: bool,
    }

    impl EvidenceManager {
        /// Create a new evidence manager with the given configuration.
        pub fn new(config: EvidenceConfig) -> Self {
            config.validate().expect("invalid EvidenceConfig");
            Self {
                config,
                metrics: EvidenceMetrics::default(),
                processed: RwLock::new(HashSet::new()),
                initialised: false,
            }
        }

        /// Create a manager with default configuration.
        pub fn default() -> Self {
            Self::new(EvidenceConfig::default())
        }

        pub fn config(&self) -> &EvidenceConfig {
            &self.config
        }

        pub fn metrics(&self) -> &EvidenceMetrics {
            &self.metrics
        }

        /// Initialise the manager (e.g., load persisted processed evidence).
        pub fn init(&mut self) {
            self.initialised = true;
            info!("evidence manager initialised");
        }

        /// Validate evidence using the manager's config and a verifier.
        pub fn validate<V: Verifier>(
            &self,
            evidence: &Evidence,
            verifier: &V,
        ) -> EvidenceResult<()> {
            self.metrics.inc_received();
            let result = validate_evidence(evidence, verifier, &self.config);
            if result.is_ok() {
                self.metrics.inc_validated();
            } else {
                self.metrics.inc_rejected();
            }
            result
        }

        /// Apply evidence to the stake ledger, using the manager's config and
        /// internal processed set for deduplication.
        pub fn apply(
            &self,
            evidence: &Evidence,
            ledger: &mut StakeLedger,
            verifier: &impl Verifier,
        ) -> EvidenceResult<SlashingOutcome> {
            // Validate first.
            self.validate(evidence, verifier)?;
            // Apply.
            let mut processed = self.processed.write().unwrap();
            let outcome = apply_evidence(
                evidence,
                ledger,
                &self.config,
                &mut processed,
                &self.metrics,
            )?;
            // The outcome already includes slashed_amount; we've already recorded metrics.
            Ok(outcome)
        }

        /// Check if evidence has already been processed.
        pub fn is_processed(&self, id: &EvidenceId) -> bool {
            let processed = self.processed.read().unwrap();
            processed.contains(id)
        }

        /// Get the number of processed evidence entries.
        pub fn processed_count(&self) -> usize {
            let processed = self.processed.read().unwrap();
            processed.len()
        }

        /// Get a metrics snapshot.
        pub fn metrics_snapshot(&self) -> super::metrics::EvidenceMetricsSnapshot {
            self.metrics.snapshot()
        }

        /// Reset metrics.
        pub fn reset_metrics(&self) {
            *self.metrics = EvidenceMetrics::default();
        }

        /// Check if the manager is initialised.
        pub fn is_initialised(&self) -> bool {
            self.initialised
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::EvidenceConfig;
pub use error::{EvidenceError, EvidenceResult};
pub use types::{Evidence, EvidenceId, EvidenceType, SlashingOutcome};
pub use metrics::{EvidenceMetrics, EvidenceMetricsSnapshot};
pub use validation::validate_evidence;
pub use application::apply_evidence;
pub use manager::EvidenceManager;

// Re‑export constants for backward compatibility.
pub use constants::*;

// -----------------------------------------------------------------------------
// Legacy global functions (backward compatibility)
// -----------------------------------------------------------------------------

use spin::Once;

static GLOBAL_MANAGER: Once<EvidenceManager> = Once::new();

/// Get the global manager (initialises with defaults if not yet set).
fn global_manager() -> &'static EvidenceManager {
    GLOBAL_MANAGER.get_or_init(|| {
        let mut mgr = EvidenceManager::new(EvidenceConfig::default());
        mgr.init();
        mgr
    })
}

/// Apply evidence to a stake ledger (legacy).
///
/// This is the original function signature; it now uses the global manager's
/// internal processed set and config.
pub fn apply_evidence_legacy(
    evidence: &Evidence,
    ledger: &mut StakeLedger,
    config: &EvidenceConfig,
    processed_set: &mut HashSet<EvidenceId>,
) -> EvidenceResult<SlashingOutcome> {
    let manager = global_manager();
    // We need to use the provided config and processed_set, not the manager's.
    // So we call the raw application function directly.
    // But we also want to use the manager's metrics? We'll just call the raw function.
    // To avoid confusion, we'll keep the old function signature and call the raw apply.
    // We'll also update metrics manually.
    let metrics = manager.metrics();
    metrics.inc_received();
    let result = application::apply_evidence(
        evidence,
        ledger,
        config,
        processed_set,
        metrics,
    );
    if result.is_ok() {
        metrics.inc_validated();
    } else {
        metrics.inc_rejected();
    }
    result
}

/// Validate evidence (legacy).
pub fn validate_evidence_legacy<V: Verifier>(
    evidence: &Evidence,
    verifier: &V,
    config: &EvidenceConfig,
) -> EvidenceResult<()> {
    evidence.validate(verifier, config)
}

// -----------------------------------------------------------------------------
// Tests (expanded)
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::{Ed25519Signer, Ed25519Verifier};
    use crate::slashing::ValidatorRecord;

    fn dummy_vote(
        signer: &Ed25519Signer,
        height: Height,
        round: Round,
        vote_type: VoteType,
        block: Option<Hash32>,
    ) -> Vote {
        let msg = crate::consensus::messages::vote_sign_bytes(vote_type, height, round, &block);
        let sig = signer.sign(&msg);
        Vote {
            vote_type,
            height,
            round,
            voter: signer.public_key(),
            block_id: block,
            signature: sig,
        }
    }

    fn dummy_proposal(
        signer: &Ed25519Signer,
        height: Height,
        round: Round,
        block: Hash32,
        pol_round: Option<Round>,
    ) -> Proposal {
        let msg = crate::consensus::messages::proposal_sign_bytes(height, round, &block, pol_round);
        let sig = signer.sign(&msg);
        Proposal {
            height,
            round,
            proposer: signer.public_key(),
            block_id: block,
            block: None,
            pol_round,
            signature: sig,
        }
    }

    #[test]
    fn test_double_vote_validation_ok() {
        let signer = Ed25519Signer::random();
        let pk = signer.public_key();
        let h = 10;
        let r = 0;
        let block_a = Some(Hash32([1; 32]));
        let block_b = Some(Hash32([2; 32]));
        let vote_a = dummy_vote(&signer, h, r, VoteType::Prevote, block_a);
        let vote_b = dummy_vote(&signer, h, r, VoteType::Prevote, block_b);
        let ev = Evidence::DoubleVote {
            voter: pk,
            height: h,
            round: r,
            vote_type: VoteType::Prevote,
            a: block_a,
            b: block_b,
            vote_a,
            vote_b,
        };
        let verifier = Ed25519Verifier;
        let config = EvidenceConfig::default();
        assert!(ev.validate(&verifier, &config).is_ok());
    }

    #[test]
    fn test_double_vote_duplicate() {
        let signer = Ed25519Signer::random();
        let pk = signer.public_key();
        let h = 10;
        let r = 0;
        let block = Some(Hash32([1; 32]));
        let vote_a = dummy_vote(&signer, h, r, VoteType::Prevote, block);
        let vote_b = dummy_vote(&signer, h, r, VoteType::Prevote, block);
        let ev = Evidence::DoubleVote {
            voter: pk,
            height: h,
            round: r,
            vote_type: VoteType::Prevote,
            a: block,
            b: block,
            vote_a,
            vote_b,
        };
        let verifier = Ed25519Verifier;
        let config = EvidenceConfig::default();
        assert!(matches!(
            ev.validate(&verifier, &config),
            Err(EvidenceError::DuplicateMessages)
        ));
    }

    #[test]
    fn test_offender_mismatch() {
        let signer1 = Ed25519Signer::random();
        let signer2 = Ed25519Signer::random();
        let h = 10;
        let r = 0;
        let block_a = Some(Hash32([1; 32]));
        let block_b = Some(Hash32([2; 32]));
        let vote_a = dummy_vote(&signer1, h, r, VoteType::Prevote, block_a);
        let vote_b = dummy_vote(&signer2, h, r, VoteType::Prevote, block_b);
        let ev = Evidence::DoubleVote {
            voter: signer1.public_key(),
            height: h,
            round: r,
            vote_type: VoteType::Prevote,
            a: block_a,
            b: block_b,
            vote_a,
            vote_b,
        };
        let verifier = Ed25519Verifier;
        let config = EvidenceConfig::default();
        assert!(matches!(
            ev.validate(&verifier, &config),
            Err(EvidenceError::OffenderMismatch)
        ));
    }

    #[test]
    fn test_is_fresh() {
        let signer = Ed25519Signer::random();
        let pk = signer.public_key();
        let ev = Evidence::DoubleVote {
            voter: pk,
            height: 10,
            round: 0,
            vote_type: VoteType::Prevote,
            a: None,
            b: Some(Hash32([1; 32])),
            vote_a: dummy_vote(&signer, 10, 0, VoteType::Prevote, None),
            vote_b: dummy_vote(&signer, 10, 0, VoteType::Prevote, Some(Hash32([1; 32]))),
        };
        assert!(ev.is_fresh(15, 10));
        assert!(!ev.is_fresh(25, 10));
    }

    #[test]
    fn test_apply_evidence() {
        let signer = Ed25519Signer::random();
        let pk = signer.public_key();
        let h = 10;
        let r = 0;
        let block_a = Some(Hash32([1; 32]));
        let block_b = Some(Hash32([2; 32]));
        let vote_a = dummy_vote(&signer, h, r, VoteType::Prevote, block_a);
        let vote_b = dummy_vote(&signer, h, r, VoteType::Prevote, block_b);
        let ev = Evidence::DoubleVote {
            voter: pk.clone(),
            height: h,
            round: r,
            vote_type: VoteType::Prevote,
            a: block_a,
            b: block_b,
            vote_a,
            vote_b,
        };

        let mut ledger = StakeLedger::default();
        ledger.validators.insert(
            pk.clone(),
            ValidatorRecord::new(1000),
        );
        ledger.current_height = Some(15);

        let config = EvidenceConfig::default();
        let mut processed = HashSet::new();
        let metrics = EvidenceMetrics::default();
        let outcome = application::apply_evidence(&ev, &mut ledger, &config, &mut processed, &metrics).unwrap();
        assert!(outcome.slashed);
        assert!(outcome.slashed_amount > 0);
        assert_eq!(outcome.remaining_stake, 1000 - outcome.slashed_amount);
        assert!(outcome.jailed);
        assert!(!outcome.tombstoned);

        let record = ledger.validators.get(&pk).unwrap();
        assert!(matches!(
            record.status,
            crate::slashing::ValidatorStatus::Jailed { .. }
        ));
        assert!(record.stake < 1000);
        assert_eq!(record.slashed_total, outcome.slashed_amount);
        assert_eq!(metrics.evidence_applied.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_duplicate_evidence_rejected() {
        let signer = Ed25519Signer::random();
        let pk = signer.public_key();
        let h = 10;
        let r = 0;
        let block_a = Some(Hash32([1; 32]));
        let block_b = Some(Hash32([2; 32]));
        let vote_a = dummy_vote(&signer, h, r, VoteType::Prevote, block_a);
        let vote_b = dummy_vote(&signer, h, r, VoteType::Prevote, block_b);
        let ev = Evidence::DoubleVote {
            voter: pk.clone(),
            height: h,
            round: r,
            vote_type: VoteType::Prevote,
            a: block_a,
            b: block_b,
            vote_a,
            vote_b,
        };
        let mut ledger = StakeLedger::default();
        ledger.validators.insert(
            pk.clone(),
            ValidatorRecord::new(1000),
        );
        ledger.current_height = Some(15);
        let config = EvidenceConfig::default();
        let mut processed = HashSet::new();
        let metrics = EvidenceMetrics::default();
        let _ = application::apply_evidence(&ev, &mut ledger, &config, &mut processed, &metrics).unwrap();
        let err = application::apply_evidence(&ev, &mut ledger, &config, &mut processed, &metrics).unwrap_err();
        assert!(matches!(err, EvidenceError::AlreadyProcessed));
        assert_eq!(metrics.evidence_rejected.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_manager() {
        let config = EvidenceConfig::default();
        let mut manager = EvidenceManager::new(config);
        manager.init();

        let signer = Ed25519Signer::random();
        let pk = signer.public_key();
        let h = 10;
        let r = 0;
        let block_a = Some(Hash32([1; 32]));
        let block_b = Some(Hash32([2; 32]));
        let vote_a = dummy_vote(&signer, h, r, VoteType::Prevote, block_a);
        let vote_b = dummy_vote(&signer, h, r, VoteType::Prevote, block_b);
        let ev = Evidence::DoubleVote {
            voter: pk.clone(),
            height: h,
            round: r,
            vote_type: VoteType::Prevote,
            a: block_a,
            b: block_b,
            vote_a,
            vote_b,
        };

        let mut ledger = StakeLedger::default();
        ledger.validators.insert(pk.clone(), ValidatorRecord::new(1000));
        ledger.current_height = Some(15);

        let verifier = Ed25519Verifier;
        let outcome = manager.apply(&ev, &mut ledger, &verifier).unwrap();
        assert!(outcome.slashed);
        assert_eq!(manager.processed_count(), 1);
        let metrics = manager.metrics_snapshot();
        assert_eq!(metrics.evidence_applied, 1);
        assert_eq!(metrics.total_slashed, outcome.slashed_amount);
    }
}
