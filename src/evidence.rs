//! Evidence of validator misbehavior for slashing

use crate::types::{Height, Round};
use crate::crypto::PublicKeyBytes;
use crate::consensus::messages::{Vote, VoteType};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum Evidence {
    /// Validator signed two different blocks in the same prevote/precommit round
    DoubleVote {
        voter:     PublicKeyBytes,
        height:    Height,
        round:     Round,
        vote_type: VoteType,
        a:         Option<crate::types::Hash32>,
        b:         Option<crate::types::Hash32>,
        vote_a:    Vote,
        vote_b:    Vote,
    },
    /// Validator proposed two different blocks at same height/round
    DoubleProposal {
        proposer:  PublicKeyBytes,
        height:    Height,
        round:     Round,
    },
}

impl Evidence {
    pub fn offender(&self) -> &PublicKeyBytes {
        match self {
            Evidence::DoubleVote { voter, .. }      => voter,
            Evidence::DoubleProposal { proposer, .. } => proposer,
        }
    }
}
