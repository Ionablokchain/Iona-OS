//! Core protocol types shared across consensus, execution, and networking

use alloc::{vec::Vec, string::String};

pub type Height  = u64;
pub type Round   = u32;
pub type Hash32  = [u8; 32];

/// Raw transaction bytes
pub type Tx = Vec<u8>;

/// EVM-style transaction receipt
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Receipt {
    pub tx_hash:     Hash32,
    pub success:     bool,
    pub gas_used:    u64,
    pub logs:        Vec<Log>,
    pub output:      Vec<u8>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Log {
    pub address: [u8; 20],
    pub topics:  Vec<Hash32>,
    pub data:    Vec<u8>,
}

/// Block header
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BlockHeader {
    pub height:       Height,
    pub round:        Round,
    pub parent_id:    Hash32,
    pub state_root:   Hash32,
    pub tx_root:      Hash32,
    pub proposer_pk:  Vec<u8>,
    pub proposer_addr: String,
    pub base_fee:     u64,
    pub gas_used:     u64,
    pub gas_limit:    u64,
    pub timestamp_ms: u64,
}

/// Block
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub txs:    Vec<Tx>,
}

impl Block {
    pub fn id(&self) -> Hash32 {
        // Hash the header deterministically
        let encoded = postcard::to_allocvec(&self.header).unwrap_or_default();
        crate::consensus::engine::sha256_hash(&encoded)
    }
}

/// Simple kv state for execution
pub type KvState = alloc::collections::BTreeMap<Vec<u8>, Vec<u8>>;
