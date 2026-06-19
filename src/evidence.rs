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
//! # Evidence Lifecycle
//!
//! 1. Evidence is submitted (from P2P or RPC).
//! 2. It is validated (signatures, internal consistency).
//! 3. If valid, it is applied to the stake ledger (slashing the validator).
//! 4. The validator is jailed (and possibly tombstoned).
//! 5. Evidence is persisted to prevent double‑processing.
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::evidence::{Evidence, EvidenceConfig, apply_evidence};
//!
//! let config = EvidenceConfig::default();
//! let (outcome, new_ledger) = apply_evidence(&evidence, &ledger, &verifier, &config)?;
//! if outcome.slashed {
//!     println!("Slashed {} tokens", outcome.slashed_amount);
//! }
//! ```

use crate::consensus::messages::{Proposal, Vote, VoteType};
use crate::crypto::{PublicKeyBytes, SignatureBytes, Verifier, CryptoError};
use crate::slashing::StakeLedger;
use crate::types::{Height, Hash32, Round};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Minimum signature length for a valid vote signature (Ed25519).
pub const MIN_SIGNATURE_LEN: usize = 64;

/// Default slash fraction for double‑vote (5% = 1/20).
pub const DEFAULT_SLASH_FRACTION_DOUBLE_VOTE: u64 = 20; // 1/20

/// Default slash fraction for double‑proposal (5% = 1/20).
pub const DEFAULT_SLASH_FRACTION_DOUBLE_PROPOSAL: u64 = 20;

/// Default evidence age limit (blocks) – evidence older than this is rejected.
pub const DEFAULT_EVIDENCE_MAX_AGE: Height = 100_000;

/// Default tombstone period (blocks) – after this, validator cannot unjail.
pub const DEFAULT_TOMBSTONE_PERIOD: Height = 1_000_000;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur when validating or applying evidence.
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

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for evidence handling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceConfig {
    /// Maximum age (in blocks) for evidence to be accepted.
    pub max_age: Height,
    /// Slash fraction denominator for double‑vote (e.g., 20 = 5%).
    pub slash_fraction_double_vote: u64,
    /// Slash fraction denominator for double‑proposal.
    pub slash_fraction_double_proposal: u64,
    /// Tombstone period (blocks) after which a validator cannot unjail.
    pub tombstone_period: Height,
    /// Whether to enable evidence verification (signature checks).
    pub verify_signatures: bool,
    /// Whether to allow nil votes in double‑vote evidence.
    pub allow_nil_equivocation: bool,
}

impl Default for EvidenceConfig {
    fn default() -> Self {
        Self {
            max_age: DEFAULT_EVIDENCE_MAX_AGE,
            slash_fraction_double_vote: DEFAULT_SLASH_FRACTION_DOUBLE_VOTE,
            slash_fraction_double_proposal: DEFAULT_SLASH_FRACTION_DOUBLE_PROPOSAL,
            tombstone_period: DEFAULT_TOMBSTONE_PERIOD,
            verify_signatures: true,
            allow_nil_equivocation: true,
        }
    }
}

// -----------------------------------------------------------------------------
// Evidence enum
// -----------------------------------------------------------------------------

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
    pub fn slash_fraction(&self, config: &EvidenceConfig) -> u64 {
        match self {
            Evidence::DoubleVote { .. } => config.slash_fraction_double_vote,
            Evidence::DoubleProposal { .. } => config.slash_fraction_double_proposal,
        }
    }

    /// Validate internal consistency and signatures.
    ///
    /// # Arguments
    /// * `verifier` – A `Verifier` implementation for checking signatures.
    /// * `config` – Evidence configuration.
    ///
    /// # Returns
    /// `Ok(())` if the evidence is valid, `Err(EvidenceError)` otherwise.
    pub fn validate<V: Verifier>(
        &self,
        verifier: &V,
        config: &EvidenceConfig,
    ) -> EvidenceResult<()> {
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
                // Check that the two votes are from the same validator.
                if vote_a.voter != *voter || vote_b.voter != *voter {
                    return Err(EvidenceError::OffenderMismatch);
                }
                // Check height and round match.
                if vote_a.height != *height || vote_b.height != *height {
                    return Err(EvidenceError::HeightMismatch {
                        expected: *height,
                        actual: vote_a.height,
                    });
                }
                if vote_a.round != *round || vote_b.round != *round {
                    return Err(EvidenceError::RoundMismatch {
                        expected: *round,
                        actual: vote_a.round,
                    });
                }
                // Check vote type matches.
                if vote_a.vote_type != *vote_type || vote_b.vote_type != *vote_type {
                    return Err(EvidenceError::VoteTypeMismatch {
                        expected: *vote_type,
                        actual: vote_a.vote_type,
                    });
                }
                // Check that the two votes are not identical.
                if vote_a == vote_b {
                    return Err(EvidenceError::DuplicateMessages);
                }
                // Check that they refer to different blocks (equivocation).
                if a == b {
                    return Err(EvidenceError::SameBlock);
                }
                // If nil equivocation is not allowed, ensure at least one is non‑nil.
                if !config.allow_nil_equivocation && (a.is_none() || b.is_none()) {
                    return Err(EvidenceError::Internal(
                        "nil equivocation not allowed".into(),
                    ));
                }
                // Verify signatures if enabled.
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
                // Require both proposals to be present.
                let (prop_a, prop_b) = match (proposal_a, proposal_b) {
                    (Some(p1), Some(p2)) => (p1, p2),
                    _ => return Err(EvidenceError::IncompleteEvidence),
                };
                // Same proposer.
                if prop_a.proposer != *proposer || prop_b.proposer != *proposer {
                    return Err(EvidenceError::OffenderMismatch);
                }
                // Same height and round.
                if prop_a.height != *height || prop_b.height != *height {
                    return Err(EvidenceError::HeightMismatch {
                        expected: *height,
                        actual: prop_a.height,
                    });
                }
                if prop_a.round != *round || prop_b.round != *round {
                    return Err(EvidenceError::RoundMismatch {
                        expected: *round,
                        actual: prop_a.round,
                    });
                }
                // Not identical.
                if prop_a == prop_b {
                    return Err(EvidenceError::DuplicateMessages);
                }
                // Different block IDs.
                if a == b {
                    return Err(EvidenceError::SameProposal);
                }
                // Verify signatures if enabled.
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

// -----------------------------------------------------------------------------
// Evidence identifier
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// Slashing outcome
// -----------------------------------------------------------------------------

/// Result of applying evidence.
#[derive(Debug, Clone)]
pub struct SlashingOutcome {
    /// Whether the validator was slashed.
    pub slashed: bool,
    /// Amount of tokens slashed (in native units).
    pub slashed_amount: u64,
    /// Remaining stake after slashing.
    pub remaining_stake: u64,
    /// Whether the validator was jailed.
    pub jailed: bool,
    /// Whether the validator was tombstoned.
    pub tombstoned: bool,
    /// Height at which the slash occurred.
    pub slash_height: Height,
}

// -----------------------------------------------------------------------------
// Apply evidence to stake ledger
// -----------------------------------------------------------------------------

/// Apply evidence to a stake ledger, slashing the offending validator.
///
/// # Arguments
/// * `evidence` – The evidence to apply.
/// * `ledger` – The stake ledger (will be mutated).
/// * `config` – Evidence configuration.
/// * `processed_set` – Set of already‑processed evidence IDs (for deduplication).
///
/// # Returns
/// A `SlashingOutcome` describing the result.
pub fn apply_evidence(
    evidence: &Evidence,
    ledger: &mut StakeLedger,
    config: &EvidenceConfig,
    processed_set: &mut HashSet<EvidenceId>,
) -> EvidenceResult<SlashingOutcome> {
    let offender = evidence.offender().clone();
    let height = evidence.height();

    // Deduplication.
    let id = evidence.id();
    if processed_set.contains(&id) {
        warn!(?id, "evidence already processed");
        return Err(EvidenceError::AlreadyProcessed);
    }

    // Check if validator exists.
    let record = ledger
        .validators
        .get_mut(&offender)
        .ok_or(EvidenceError::ValidatorNotFound)?;

    // Check if already tombstoned.
    if matches!(record.status, crate::slashing::ValidatorStatus::Tombstoned) {
        return Err(EvidenceError::AlreadyTombstoned);
    }

    // Check freshness.
    let current_height = ledger.current_height().unwrap_or(0);
    if !evidence.is_fresh(current_height, config.max_age) {
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

    Ok(SlashingOutcome {
        slashed: true,
        slashed_amount: slash_amount,
        remaining_stake: new_stake,
        jailed: true,
        tombstoned,
        slash_height: current_height,
    })
}

// -----------------------------------------------------------------------------
// Metrics (optional)
// -----------------------------------------------------------------------------

/// Metrics for evidence processing.
#[derive(Debug, Clone, Default)]
pub struct EvidenceMetrics {
    pub evidence_received: u64,
    pub evidence_validated: u64,
    pub evidence_applied: u64,
    pub evidence_rejected: u64,
    pub total_slashed: u64,
}

// -----------------------------------------------------------------------------
// Tests
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
            crate::slashing::ValidatorRecord::new(1000),
        );
        ledger.current_height = Some(15);

        let config = EvidenceConfig::default();
        let mut processed = HashSet::new();
        let outcome = apply_evidence(&ev, &mut ledger, &config, &mut processed).unwrap();
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
            crate::slashing::ValidatorRecord::new(1000),
        );
        ledger.current_height = Some(15);
        let config = EvidenceConfig::default();
        let mut processed = HashSet::new();
        let _ = apply_evidence(&ev, &mut ledger, &config, &mut processed).unwrap();
        let err = apply_evidence(&ev, &mut ledger, &config, &mut processed).unwrap_err();
        assert!(matches!(err, EvidenceError::AlreadyProcessed));
    }
}
