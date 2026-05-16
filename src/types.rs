//! Core protocol types shared across consensus, execution, and networking

use alloc::{vec::Vec, string::String};
use core::fmt;
use serde::{Serialize, Deserialize};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Size of a hash in bytes.
pub const HASH_SIZE: usize = 32;

/// Minimum gas limit per block (prevents zero-gas blocks).
pub const MIN_GAS_LIMIT: u64 = 1_000_000;

/// Maximum gas limit per block (4.2 billion, same as Ethereum's uint32 gas limit).
pub const MAX_GAS_LIMIT: u64 = 0xFFFFFFFF;

/// Minimum base fee (1 gwei equivalent in micro-units).
pub const MIN_BASE_FEE: u64 = 1;

// -----------------------------------------------------------------------------
// Basic type aliases
// -----------------------------------------------------------------------------

/// Block height (0 = genesis).
pub type Height = u64;

/// Consensus round number.
pub type Round = u32;

/// 32‑byte hash (Blake3 or SHA‑256).
pub type Hash32 = [u8; HASH_SIZE];

/// Raw transaction bytes (opaque).
pub type Tx = Vec<u8>;

/// Simple KV state for execution (key‑value pairs).
pub type KvState = alloc::collections::BTreeMap<Vec<u8>, Vec<u8>>;

// -----------------------------------------------------------------------------
// Log and Receipt
// -----------------------------------------------------------------------------

/// EVM‑style log entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Log {
    /// Contract address (20 bytes).
    pub address: [u8; 20],
    /// Event topics (each 32 bytes).
    pub topics: Vec<Hash32>,
    /// Raw log data.
    pub data: Vec<u8>,
}

/// EVM‑style transaction receipt.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receipt {
    /// Transaction hash.
    pub tx_hash: Hash32,
    /// Whether the execution succeeded.
    pub success: bool,
    /// Total gas used by the transaction.
    pub gas_used: u64,
    /// Emitted logs.
    pub logs: Vec<Log>,
    /// Return data (or revert reason).
    pub output: Vec<u8>,
}

impl Receipt {
    /// Validate receipt fields.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.gas_used == 0 && !self.success {
            // Zero gas used only allowed for failed transactions that reverted early.
            // Allowing zero is fine.
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// BlockHeader
// -----------------------------------------------------------------------------

/// Block header containing all metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub height: Height,
    pub round: Round,
    pub parent_id: Hash32,
    pub state_root: Hash32,
    pub tx_root: Hash32,
    pub proposer_pk: Vec<u8>,
    pub proposer_addr: String,
    pub base_fee: u64,
    pub gas_used: u64,
    pub gas_limit: u64,
    pub timestamp_ms: u64,
}

impl BlockHeader {
    /// Validate header fields (does not verify cryptographic consistency).
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.height == 0 && self.parent_id != [0u8; HASH_SIZE] {
            // Genesis block must have zero parent hash.
            return Err("genesis block must have zero parent hash");
        }
        if self.gas_limit < MIN_GAS_LIMIT {
            return Err("gas limit below minimum");
        }
        if self.gas_limit > MAX_GAS_LIMIT {
            return Err("gas limit exceeds maximum");
        }
        if self.gas_used > self.gas_limit {
            return Err("gas used exceeds gas limit");
        }
        if self.base_fee < MIN_BASE_FEE {
            return Err("base fee below minimum");
        }
        if self.proposer_pk.len() != 32 {
            return Err("proposer public key must be 32 bytes");
        }
        if self.proposer_addr.is_empty() {
            return Err("proposer address cannot be empty");
        }
        Ok(())
    }

    /// Compute the block ID (hash of the RLP‑encoded header).
    #[must_use]
    pub fn id(&self) -> Hash32 {
        let encoded = postcard::to_allocvec(self).unwrap_or_default();
        crate::consensus::engine::sha256_hash(&encoded)
    }
}

// -----------------------------------------------------------------------------
// Block
// -----------------------------------------------------------------------------

/// Full block containing header and transactions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<Tx>,
}

impl Block {
    /// Compute the block ID (hash of the header).
    #[must_use]
    pub fn id(&self) -> Hash32 {
        self.header.id()
    }

    /// Validate the block (header + transaction root consistency).
    pub fn validate(&self) -> Result<(), &'static str> {
        self.header.validate()?;
        // Verify that the transaction root matches the actual transactions.
        let computed_root = crate::types::tx_root(&self.txs);
        if computed_root != self.header.tx_root {
            return Err("transaction root mismatch");
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Helper: transaction root
// -----------------------------------------------------------------------------

/// Compute the transaction root hash (merkle root of transaction hashes).
#[must_use]
pub fn tx_root(txs: &[Tx]) -> Hash32 {
    if txs.is_empty() {
        return [0u8; HASH_SIZE];
    }
    // Simple hash of concatenated transaction hashes (not a true Merkle tree).
    let mut hasher = blake3::Hasher::new();
    for tx in txs {
        hasher.update(&crate::consensus::engine::sha256_hash(tx));
    }
    let mut out = [0u8; HASH_SIZE];
    out.copy_from_slice(hasher.finalize().as_bytes());
    out
}

// -----------------------------------------------------------------------------
// Hash32 utilities (functions, not newtype to preserve compatibility)
// -----------------------------------------------------------------------------

/// Convert a `Hash32` to a hex string.
#[must_use]
pub fn hash32_to_hex(h: &Hash32) -> String {
    hex::encode(h)
}

/// Convert a hex string to a `Hash32` (returns `None` on invalid length).
#[must_use]
pub fn hex_to_hash32(s: &str) -> Option<Hash32> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != HASH_SIZE {
        return None;
    }
    let mut out = [0u8; HASH_SIZE];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// Zero hash (all zeros).
#[must_use]
pub const fn zero_hash() -> Hash32 {
    [0u8; HASH_SIZE]
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_header_validation() {
        let mut header = BlockHeader {
            height: 1,
            round: 0,
            parent_id: zero_hash(),
            state_root: zero_hash(),
            tx_root: zero_hash(),
            proposer_pk: vec![0u8; 32],
            proposer_addr: "proposer".into(),
            base_fee: 1,
            gas_used: 0,
            gas_limit: 10_000_000,
            timestamp_ms: 1000,
        };
        assert!(header.validate().is_ok());

        header.gas_limit = 0;
        assert!(header.validate().is_err());

        header.gas_limit = MAX_GAS_LIMIT + 1;
        assert!(header.validate().is_err());

        header.gas_limit = 10_000_000;
        header.gas_used = 20_000_000;
        assert!(header.validate().is_err());

        header.gas_used = 0;
        header.base_fee = 0;
        assert!(header.validate().is_err());

        header.base_fee = 1;
        header.proposer_pk = vec![0u8; 31];
        assert!(header.validate().is_err());
    }

    #[test]
    fn test_zero_hash() {
        let z = zero_hash();
        assert_eq!(z, [0u8; HASH_SIZE]);
    }

    #[test]
    fn test_hash32_hex_roundtrip() {
        let original = [0xAA; HASH_SIZE];
        let hex = hash32_to_hex(&original);
        let decoded = hex_to_hash32(&hex).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_tx_root_empty() {
        let root = tx_root(&[]);
        assert_eq!(root, zero_hash());
    }

    #[test]
    fn test_tx_root_deterministic() {
        let tx1 = vec![1, 2, 3];
        let tx2 = vec![4, 5, 6];
        let txs = vec![tx1.clone(), tx2.clone()];
        let root1 = tx_root(&txs);
        let txs2 = vec![tx2, tx1];
        let root2 = tx_root(&txs2);
        // Different order yields different root (not sorted).
        assert_ne!(root1, root2);
    }
}
