//! Consensus wire messages: Proposal, Vote, Evidence
//!
//! This module defines the core message types exchanged between consensus
//! participants. These messages are serialized and sent over the network,
//! and are also persisted in the blockchain.
//!
//! # Message types
//! - `Proposal`: A block proposal for a specific height and round.
//! - `Vote`: A prevote or precommit vote for a block (or nil).
//! - `Evidence`: Proof of misbehaviour (equivocation, etc.).
//!
//! # Serialization
//! All messages implement `serde::Serialize` and `serde::Deserialize`.
//! The recommended wire format is `postcard` or `bincode` for compactness.
//!
//! # Validation
//! Each message type provides a `validate` method to check its internal
//! consistency before processing.

use crate::crypto::PublicKeyBytes;
use crate::evidence::Evidence;
use crate::types::{Hash32, Height, Round};
use alloc::vec::Vec;
use core::fmt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum size of a serialized message (1 MiB) to prevent DoS.
pub const MAX_MESSAGE_SIZE: usize = 1_048_576;

/// Message type identifiers for protocol discrimination.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    Proposal = 0x01,
    Vote = 0x02,
    Evidence = 0x03,
}

impl TryFrom<u8> for MessageKind {
    type Error = MessageError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(MessageKind::Proposal),
            0x02 => Ok(MessageKind::Vote),
            0x03 => Ok(MessageKind::Evidence),
            _ => Err(MessageError::UnknownMessageKind(value)),
        }
    }
}

// -----------------------------------------------------------------------------
// Vote type
// -----------------------------------------------------------------------------

/// Type of vote in Tendermint consensus.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VoteType {
    /// First step of consensus: vote for a block or nil.
    Prevote,
    /// Second step: commit to a block after receiving enough prevotes.
    Precommit,
}

impl VoteType {
    /// Convert to a byte representation.
    pub const fn as_u8(self) -> u8 {
        match self {
            VoteType::Prevote => 0,
            VoteType::Precommit => 1,
        }
    }

    /// Try to parse from a byte.
    pub fn from_u8(val: u8) -> Result<Self, MessageError> {
        match val {
            0 => Ok(VoteType::Prevote),
            1 => Ok(VoteType::Precommit),
            _ => Err(MessageError::InvalidVoteType(val)),
        }
    }

    /// Human‑readable name.
    pub const fn name(self) -> &'static str {
        match self {
            VoteType::Prevote => "prevote",
            VoteType::Precommit => "precommit",
        }
    }
}

impl fmt::Display for VoteType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur when validating or parsing consensus messages.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MessageError {
    #[error("invalid vote type: {0}")]
    InvalidVoteType(u8),

    #[error("proposal signature is empty or invalid")]
    InvalidProposalSignature,

    #[error("vote signature is empty or invalid")]
    InvalidVoteSignature,

    #[error("proposal block ID is zero")]
    ZeroBlockId,

    #[error("proposer public key is empty")]
    EmptyProposerKey,

    #[error("voter public key is empty")]
    EmptyVoterKey,

    #[error("invalid height: {0} (must be > 0)")]
    InvalidHeight(u64),

    #[error("invalid round: {0} (must be >= 0)")]
    InvalidRound(u64),

    #[error("message size {0} exceeds max {1}")]
    MessageTooLarge(usize, usize),

    #[error("unknown message kind: {0}")]
    UnknownMessageKind(u8),

    #[error("evidence is empty")]
    EmptyEvidence,
}

pub type MessageResult<T> = Result<T, MessageError>;

// -----------------------------------------------------------------------------
// Proposal message
// -----------------------------------------------------------------------------

/// A proposal for a new block at a given height and round.
/// The proposer is determined by the consensus algorithm.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    /// Height at which this proposal is made.
    pub height: Height,
    /// Round number (0, 1, 2, ...).
    pub round: Round,
    /// Public key of the proposer (used to verify signature).
    pub proposer: PublicKeyBytes,
    /// Hash of the proposed block.
    pub block_id: Hash32,
    /// Full block data (optional – may be sent separately or omitted in
    /// some protocols).
    pub block: Option<crate::types::Block>,
    /// `POL` (Proof‑of‑Lock) round: the round in which a sufficient number
    /// of prevotes were received for this block (or `None` if none).
    pub pol_round: Option<Round>,
    /// Signature over the canonical proposal bytes (see `proposal_sign_bytes`).
    pub signature: Vec<u8>,
}

impl Proposal {
    /// Validate the proposal's internal consistency.
    pub fn validate(&self) -> MessageResult<()> {
        if self.height == 0 {
            return Err(MessageError::InvalidHeight(self.height));
        }
        if self.proposer.0.is_empty() {
            return Err(MessageError::EmptyProposerKey);
        }
        if self.block_id.is_zero() {
            return Err(MessageError::ZeroBlockId);
        }
        if self.signature.is_empty() {
            return Err(MessageError::InvalidProposalSignature);
        }
        Ok(())
    }

    /// Compute the canonical signing bytes for this proposal.
    pub fn sign_bytes(&self) -> Vec<u8> {
        proposal_sign_bytes(self.height, self.round, &self.block_id, self.pol_round)
    }

    /// Get the message kind.
    pub const fn kind() -> MessageKind {
        MessageKind::Proposal
    }

    /// Check if the proposal includes a full block.
    pub fn has_block(&self) -> bool {
        self.block.is_some()
    }

    /// Get the block ID as a hex string (for logging).
    pub fn block_id_hex(&self) -> alloc::string::String {
        hex::encode(&self.block_id.0)
    }
}

// -----------------------------------------------------------------------------
// Vote message
// -----------------------------------------------------------------------------

/// A consensus vote (prevote or precommit) for a specific block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    /// Whether this is a prevote or a precommit.
    pub vote_type: VoteType,
    /// Height at which this vote is cast.
    pub height: Height,
    /// Round number.
    pub round: Round,
    /// Public key of the voter (used to verify signature).
    pub voter: PublicKeyBytes,
    /// Block hash being voted for. `None` means a "nil" vote (no block).
    pub block_id: Option<Hash32>,
    /// Signature over the canonical vote bytes (see `vote_sign_bytes`).
    pub signature: Vec<u8>,
}

impl Vote {
    /// Validate the vote's internal consistency.
    pub fn validate(&self) -> MessageResult<()> {
        if self.height == 0 {
            return Err(MessageError::InvalidHeight(self.height));
        }
        if self.voter.0.is_empty() {
            return Err(MessageError::EmptyVoterKey);
        }
        if self.signature.is_empty() {
            return Err(MessageError::InvalidVoteSignature);
        }
        Ok(())
    }

    /// Compute the canonical signing bytes for this vote.
    pub fn sign_bytes(&self) -> Vec<u8> {
        vote_sign_bytes(self.vote_type, self.height, self.round, &self.block_id)
    }

    /// Get the message kind.
    pub const fn kind() -> MessageKind {
        MessageKind::Vote
    }

    /// Check if this is a nil vote (no block).
    pub fn is_nil(&self) -> bool {
        self.block_id.is_none()
    }

    /// Get the block ID as a hex string (or "nil" if none).
    pub fn block_id_hex(&self) -> alloc::string::String {
        self.block_id
            .as_ref()
            .map(|h| hex::encode(&h.0))
            .unwrap_or_else(|| "nil".into())
    }
}

// -----------------------------------------------------------------------------
// Top-level message enum
// -----------------------------------------------------------------------------

/// All message types that can be exchanged over the consensus gossip network.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ConsensusMsg {
    Proposal(Proposal),
    Vote(Vote),
    Evidence(Evidence),
}

impl ConsensusMsg {
    /// Validate the message.
    pub fn validate(&self) -> MessageResult<()> {
        match self {
            ConsensusMsg::Proposal(p) => p.validate(),
            ConsensusMsg::Vote(v) => v.validate(),
            ConsensusMsg::Evidence(e) => {
                if e.is_empty() {
                    Err(MessageError::EmptyEvidence)
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Get the message kind.
    pub fn kind(&self) -> MessageKind {
        match self {
            ConsensusMsg::Proposal(_) => MessageKind::Proposal,
            ConsensusMsg::Vote(_) => MessageKind::Vote,
            ConsensusMsg::Evidence(_) => MessageKind::Evidence,
        }
    }

    /// Get the height of the message (if applicable).
    pub fn height(&self) -> Option<Height> {
        match self {
            ConsensusMsg::Proposal(p) => Some(p.height),
            ConsensusMsg::Vote(v) => Some(v.height),
            ConsensusMsg::Evidence(e) => e.height(),
        }
    }

    /// Get the round of the message (if applicable).
    pub fn round(&self) -> Option<Round> {
        match self {
            ConsensusMsg::Proposal(p) => Some(p.round),
            ConsensusMsg::Vote(v) => Some(v.round),
            ConsensusMsg::Evidence(_) => None,
        }
    }

    /// Get the block hash of the message (if applicable).
    pub fn block_id(&self) -> Option<&Hash32> {
        match self {
            ConsensusMsg::Proposal(p) => Some(&p.block_id),
            ConsensusMsg::Vote(v) => v.block_id.as_ref(),
            ConsensusMsg::Evidence(_) => None,
        }
    }

    /// Get the public key of the signer (proposer or voter).
    pub fn signer_key(&self) -> Option<&PublicKeyBytes> {
        match self {
            ConsensusMsg::Proposal(p) => Some(&p.proposer),
            ConsensusMsg::Vote(v) => Some(&v.voter),
            ConsensusMsg::Evidence(_) => None,
        }
    }

    /// Get the signature bytes.
    pub fn signature(&self) -> Option<&[u8]> {
        match self {
            ConsensusMsg::Proposal(p) => Some(&p.signature),
            ConsensusMsg::Vote(v) => Some(&v.signature),
            ConsensusMsg::Evidence(_) => None,
        }
    }

    /// Compute the canonical signing bytes (for proposal or vote).
    pub fn sign_bytes(&self) -> Option<Vec<u8>> {
        match self {
            ConsensusMsg::Proposal(p) => Some(p.sign_bytes()),
            ConsensusMsg::Vote(v) => Some(v.sign_bytes()),
            ConsensusMsg::Evidence(_) => None,
        }
    }

    /// Check if the message is a nil vote.
    pub fn is_nil(&self) -> bool {
        matches!(self, ConsensusMsg::Vote(v) if v.is_nil())
    }

    /// Get the message size (approximate, for rate limiting).
    pub fn approximate_size(&self) -> usize {
        match self {
            ConsensusMsg::Proposal(p) => {
                let block_size = p.block.as_ref().map(|b| b.encoded_len()).unwrap_or(0);
                32 + 8 + 8 + p.proposer.0.len() + 32 + block_size + p.signature.len() + 8
            }
            ConsensusMsg::Vote(v) => {
                1 + 8 + 8 + v.voter.0.len() + v.block_id.as_ref().map(|_| 32).unwrap_or(0) + v.signature.len()
            }
            ConsensusMsg::Evidence(e) => e.encoded_len(),
        }
    }
}

// -----------------------------------------------------------------------------
// Canonical signing helpers
// -----------------------------------------------------------------------------

/// Generate the canonical bytes that must be signed for a proposal.
/// These bytes uniquely identify the proposal for signature verification.
///
/// # Arguments
/// * `height` – Consensus height.
/// * `round` – Round number.
/// * `block_id` – Hash of the proposed block.
/// * `pol_round` – Proof‑of‑Lock round (if any).
pub fn proposal_sign_bytes(
    height: Height,
    round: Round,
    block_id: &Hash32,
    pol_round: Option<Round>,
) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + 8 + 32 + 1 + 8);
    v.extend_from_slice(&height.to_le_bytes());
    v.extend_from_slice(&round.to_le_bytes());
    v.extend_from_slice(block_id);
    if let Some(pr) = pol_round {
        v.push(1);
        v.extend_from_slice(&pr.to_le_bytes());
    } else {
        v.push(0);
    }
    v
}

/// Generate the canonical bytes that must be signed for a vote.
///
/// # Arguments
/// * `vote_type` – Precommit or Prevote.
/// * `height` – Consensus height.
/// * `round` – Round number.
/// * `block_id` – Hash of the block being voted for (or `None` for nil).
pub fn vote_sign_bytes(
    vote_type: VoteType,
    height: Height,
    round: Round,
    block_id: &Option<Hash32>,
) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + 8 + 8 + 32);
    v.push(vote_type.as_u8());
    v.extend_from_slice(&height.to_le_bytes());
    v.extend_from_slice(&round.to_le_bytes());
    if let Some(bid) = block_id {
        v.extend_from_slice(bid);
    }
    v
}

// -----------------------------------------------------------------------------
// From/Into implementations
// -----------------------------------------------------------------------------

impl TryFrom<&[u8]> for ConsensusMsg {
    type Error = MessageError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(MessageError::MessageTooLarge(bytes.len(), MAX_MESSAGE_SIZE));
        }
        // First byte is the message kind.
        let kind = bytes.first().ok_or(MessageError::UnknownMessageKind(0))?;
        let payload = &bytes[1..];
        match *kind {
            0x01 => {
                let msg: Proposal = postcard::from_bytes(payload)
                    .map_err(|_| MessageError::UnknownMessageKind(*kind))?;
                Ok(ConsensusMsg::Proposal(msg))
            }
            0x02 => {
                let msg: Vote = postcard::from_bytes(payload)
                    .map_err(|_| MessageError::UnknownMessageKind(*kind))?;
                Ok(ConsensusMsg::Vote(msg))
            }
            0x03 => {
                let msg: Evidence = postcard::from_bytes(payload)
                    .map_err(|_| MessageError::UnknownMessageKind(*kind))?;
                Ok(ConsensusMsg::Evidence(msg))
            }
            _ => Err(MessageError::UnknownMessageKind(*kind)),
        }
    }
}

impl From<&ConsensusMsg> for Vec<u8> {
    fn from(msg: &ConsensusMsg) -> Self {
        let kind = msg.kind() as u8;
        let payload = match msg {
            ConsensusMsg::Proposal(p) => postcard::to_allocvec(p).unwrap_or_default(),
            ConsensusMsg::Vote(v) => postcard::to_allocvec(v).unwrap_or_default(),
            ConsensusMsg::Evidence(e) => postcard::to_allocvec(e).unwrap_or_default(),
        };
        let mut bytes = Vec::with_capacity(1 + payload.len());
        bytes.push(kind);
        bytes.extend_from_slice(&payload);
        bytes
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Hash32;

    fn dummy_hash(val: u8) -> Hash32 {
        let mut h = [0u8; 32];
        h[0] = val;
        Hash32(h)
    }

    #[test]
    fn test_vote_type_conversion() {
        let vt = VoteType::Prevote;
        assert_eq!(vt.as_u8(), 0);
        assert_eq!(VoteType::from_u8(0).unwrap(), VoteType::Prevote);
        assert!(VoteType::from_u8(2).is_err());
    }

    #[test]
    fn test_proposal_validation() {
        let p = Proposal {
            height: 1,
            round: 0,
            proposer: PublicKeyBytes(vec![1u8; 32]),
            block_id: dummy_hash(1),
            block: None,
            pol_round: None,
            signature: vec![1u8; 64],
        };
        assert!(p.validate().is_ok());

        let mut bad = p.clone();
        bad.height = 0;
        assert!(bad.validate().is_err());

        let mut bad2 = p;
        bad2.signature.clear();
        assert!(bad2.validate().is_err());
    }

    #[test]
    fn test_vote_validation() {
        let v = Vote {
            vote_type: VoteType::Prevote,
            height: 1,
            round: 0,
            voter: PublicKeyBytes(vec![1u8; 32]),
            block_id: Some(dummy_hash(1)),
            signature: vec![1u8; 64],
        };
        assert!(v.validate().is_ok());

        let mut bad = v;
        bad.voter.0.clear();
        assert!(bad.validate().is_err());
    }

    #[test]
    fn test_sign_bytes() {
        let h = dummy_hash(0xAA);
        let bytes = proposal_sign_bytes(1, 2, &h, Some(3));
        assert!(!bytes.is_empty());

        let bytes2 = vote_sign_bytes(VoteType::Prevote, 1, 2, &Some(h));
        assert!(!bytes2.is_empty());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let p = Proposal {
            height: 1,
            round: 0,
            proposer: PublicKeyBytes(vec![1u8; 32]),
            block_id: dummy_hash(1),
            block: None,
            pol_round: None,
            signature: vec![1u8; 64],
        };
        let msg = ConsensusMsg::Proposal(p);
        let bytes: Vec<u8> = (&msg).into();
        let decoded = ConsensusMsg::try_from(&bytes[..]).unwrap();
        match decoded {
            ConsensusMsg::Proposal(dp) => {
                assert_eq!(dp.height, 1);
                assert_eq!(dp.round, 0);
            }
            _ => panic!("wrong type"),
        }
    }
}
