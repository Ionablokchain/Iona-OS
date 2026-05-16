//! Evidence of validator misbehavior for slashing
//!
//! This module defines evidence structures that can be submitted to the chain
//! to slash validators who equivocate (double‑vote or double‑propose).

use crate::types::{Height, Round};
use crate::crypto::PublicKeyBytes;
use crate::consensus::messages::{Vote, VoteType};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Minimum signature length for a valid vote signature.
pub const MIN_SIGNATURE_LEN: usize = 64;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur when validating evidence.
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
    #[error("invalid signature length in evidence")]
    InvalidSignatureLength,
    #[error("evidence is incomplete (missing fields)")]
    IncompleteEvidence,
    #[error("both votes refer to the same block (not equivocation)")]
    SameBlock,
    #[error("both proposals refer to the same block (not equivocation)")]
    SameProposal,
    #[error("evidence is stale: height {height} too old")]
    StaleEvidence { height: Height, current_height: Height },
}

pub type EvidenceResult<T> = Result<T, EvidenceError>;

// -----------------------------------------------------------------------------
// Evidence enum
// -----------------------------------------------------------------------------

/// Evidence of validator misbehaviour for slashing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Evidence {
    /// Validator signed two different blocks in the same prevote/precommit round.
    DoubleVote {
        voter: PublicKeyBytes,
        height: Height,
        round: Round,
        vote_type: VoteType,
        a: Option<crate::types::Hash32>,
        b: Option<crate::types::Hash32>,
        vote_a: Vote,
        vote_b: Vote,
    },
    /// Validator proposed two different blocks at the same height/round.
    DoubleProposal {
        proposer: PublicKeyBytes,
        height: Height,
        round: Round,
        #[serde(default)]
        a: Option<crate::types::Hash32>,
        #[serde(default)]
        b: Option<crate::types::Hash32>,
        #[serde(default)]
        proposal_a: Option<crate::consensus::messages::Proposal>,
        #[serde(default)]
        proposal_b: Option<crate::consensus::messages::Proposal>,
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

    /// Validate internal consistency of the evidence.
    ///
    /// Checks:
    /// - Heights and rounds match within the evidence.
    /// - The two votes/proposals are from the same validator.
    /// - They are not identical (duplicate).
    /// - For double‑vote: vote types match.
    /// - For double‑vote: the block IDs are different (or one is nil and the other is not).
    pub fn validate(&self) -> EvidenceResult<()> {
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
                // Validate signature lengths (basic sanity).
                if vote_a.signature.0.len() < MIN_SIGNATURE_LEN
                    || vote_b.signature.0.len() < MIN_SIGNATURE_LEN
                {
                    return Err(EvidenceError::InvalidSignatureLength);
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
                // Signature length check (optional, depends on implementation).
                if prop_a.signature.0.len() < MIN_SIGNATURE_LEN
                    || prop_b.signature.0.len() < MIN_SIGNATURE_LEN
                {
                    return Err(EvidenceError::InvalidSignatureLength);
                }
                Ok(())
            }
        }
    }

    /// Check if the evidence is still fresh (not older than `max_age` blocks).
    pub fn is_fresh(&self, current_height: Height, max_age: Height) -> bool {
        current_height.saturating_sub(self.height()) <= max_age
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Hash32;
    use crate::crypto::SignatureBytes;

    fn dummy_vote(seed: u8, height: Height, round: Round, block: Option<Hash32>) -> Vote {
        Vote {
            vote_type: VoteType::Prevote,
            height,
            round,
            voter: PublicKeyBytes(vec![seed; 32]),
            block_id: block,
            signature: SignatureBytes(vec![seed; 64]),
        }
    }

    fn dummy_proposal(seed: u8, height: Height, round: Round, block: Hash32) -> crate::consensus::messages::Proposal {
        use crate::crypto::SignatureBytes;
        crate::consensus::messages::Proposal {
            height,
            round,
            proposer: PublicKeyBytes(vec![seed; 32]),
            block_id: block,
            block: None,
            pol_round: None,
            signature: SignatureBytes(vec![seed; 64]),
        }
    }

    #[test]
    fn test_double_vote_valid() {
        let voter = PublicKeyBytes(vec![1; 32]);
        let h = 10;
        let r = 0;
        let block_a = Some(Hash32([1; 32]));
        let block_b = Some(Hash32([2; 32]));
        let vote_a = dummy_vote(1, h, r, block_a);
        let vote_b = dummy_vote(1, h, r, block_b);
        let ev = Evidence::DoubleVote {
            voter: voter.clone(),
            height: h,
            round: r,
            vote_type: VoteType::Prevote,
            a: block_a,
            b: block_b,
            vote_a,
            vote_b,
        };
        assert!(ev.validate().is_ok());
    }

    #[test]
    fn test_double_vote_duplicate() {
        let voter = PublicKeyBytes(vec![1; 32]);
        let h = 10;
        let r = 0;
        let block_a = Some(Hash32([1; 32]));
        let vote_a = dummy_vote(1, h, r, block_a);
        let vote_b = vote_a.clone();
        let ev = Evidence::DoubleVote {
            voter,
            height: h,
            round: r,
            vote_type: VoteType::Prevote,
            a: block_a,
            b: block_a,
            vote_a,
            vote_b,
        };
        assert!(matches!(ev.validate(), Err(EvidenceError::DuplicateMessages)));
    }

    #[test]
    fn test_offender_mismatch() {
        let voter = PublicKeyBytes(vec![1; 32]);
        let h = 10;
        let r = 0;
        let block_a = Some(Hash32([1; 32]));
        let block_b = Some(Hash32([2; 32]));
        let vote_a = dummy_vote(1, h, r, block_a);
        let vote_b = dummy_vote(2, h, r, block_b); // different voter
        let ev = Evidence::DoubleVote {
            voter,
            height: h,
            round: r,
            vote_type: VoteType::Prevote,
            a: block_a,
            b: block_b,
            vote_a,
            vote_b,
        };
        assert!(matches!(ev.validate(), Err(EvidenceError::OffenderMismatch)));
    }

    #[test]
    fn test_is_fresh() {
        let voter = PublicKeyBytes(vec![1; 32]);
        let ev = Evidence::DoubleVote {
            voter,
            height: 10,
            round: 0,
            vote_type: VoteType::Prevote,
            a: None,
            b: None,
            vote_a: dummy_vote(1, 10, 0, None),
            vote_b: dummy_vote(1, 10, 0, Some(Hash32([1; 32]))),
        };
        assert!(ev.is_fresh(15, 10));
        assert!(!ev.is_fresh(25, 10));
    }
}
