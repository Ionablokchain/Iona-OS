//! Consensus wire messages: Proposal, Vote, Evidence

use crate::types::{Hash32, Height, Round};
use crate::crypto::PublicKeyBytes;
use crate::evidence::Evidence;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord,
         serde::Serialize, serde::Deserialize)]
pub enum VoteType { Prevote, Precommit }

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Proposal {
    pub height:    Height,
    pub round:     Round,
    pub proposer:  PublicKeyBytes,
    pub block_id:  Hash32,
    pub block:     Option<crate::types::Block>,
    pub pol_round: Option<Round>,
    pub signature: alloc::vec::Vec<u8>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Vote {
    pub vote_type: VoteType,
    pub height:    Height,
    pub round:     Round,
    pub voter:     PublicKeyBytes,
    pub block_id:  Option<Hash32>,
    pub signature: alloc::vec::Vec<u8>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum ConsensusMsg {
    Proposal(Proposal),
    Vote(Vote),
    Evidence(Evidence),
}

/// Canonical bytes to sign for a proposal
pub fn proposal_sign_bytes(
    height: Height, round: Round, block_id: &Hash32, pol_round: Option<Round>,
) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec::Vec::new();
    v.extend_from_slice(&height.to_le_bytes());
    v.extend_from_slice(&round.to_le_bytes());
    v.extend_from_slice(block_id);
    v.push(if pol_round.is_some() { 1 } else { 0 });
    if let Some(pr) = pol_round { v.extend_from_slice(&pr.to_le_bytes()); }
    v
}

/// Canonical bytes to sign for a vote
pub fn vote_sign_bytes(
    vt: VoteType, height: Height, round: Round, block_id: &Option<Hash32>,
) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec::Vec::new();
    v.push(vt as u8);
    v.extend_from_slice(&height.to_le_bytes());
    v.extend_from_slice(&round.to_le_bytes());
    if let Some(bid) = block_id { v.extend_from_slice(bid); }
    v
}
