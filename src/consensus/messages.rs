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

use crate::types::{Hash32, Height, Round};
use crate::crypto::PublicKeyBytes;
use crate::evidence::Evidence;

// -----------------------------------------------------------------------------
// Vote type
// -----------------------------------------------------------------------------

/// Type of vote in Tendermint consensus.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord,
         serde::Serialize, serde::Deserialize)]
pub enum VoteType {
    /// First step of consensus: vote for a block or nil.
    Prevote,
    /// Second step: commit to a block after receiving enough prevotes.
    Precommit,
}

// -----------------------------------------------------------------------------
// Proposal message
// -----------------------------------------------------------------------------

/// A proposal for a new block at a given height and round.
/// The proposer is determined by the consensus algorithm.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
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
    pub signature: alloc::vec::Vec<u8>,
}

// -----------------------------------------------------------------------------
// Vote message
// -----------------------------------------------------------------------------

/// A consensus vote (prevote or precommit) for a specific block.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
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
    pub signature: alloc::vec::Vec<u8>,
}

// -----------------------------------------------------------------------------
// Top-level message enum
// -----------------------------------------------------------------------------

/// All message types that can be exchanged over the consensus gossip network.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum ConsensusMsg {
    Proposal(Proposal),
    Vote(Vote),
    Evidence(Evidence),
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
) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec::Vec::new();
    v.extend_from_slice(&height.to_le_bytes());
    v.extend_from_slice(&round.to_le_bytes());
    v.extend_from_slice(block_id);
    v.push(if pol_round.is_some() { 1 } else { 0 });
    if let Some(pr) = pol_round {
        v.extend_from_slice(&pr.to_le_bytes());
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
) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec::Vec::new();
    v.push(vote_type as u8);
    v.extend_from_slice(&height.to_le_bytes());
    v.extend_from_slice(&round.to_le_bytes());
    if let Some(bid) = block_id {
        v.extend_from_slice(bid);
    }
    v
}
