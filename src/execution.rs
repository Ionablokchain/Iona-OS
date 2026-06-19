//! Block execution: build blocks from transactions, verify blocks, apply state transitions.
//!
//! Integrates with the IONA EVM (via `evm::kv_state_db`) for contract execution.
//! Handles transaction validation (signatures, nonces, balances, gas),
//! EIP-1559 fee calculation, state root computation, and block building.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                           Block Execution                                 │
//! ├─────────────────┬─────────────────┬───────────────────────────────────────┤
//! │  apply_tx()     │  build_block()  │  verify_block()                     │
//! │  (single tx)    │  (produce       │  (validate block from peer)         │
//! │                 │   new block)    │                                      │
//! └─────────────────┴─────────────────┴───────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                        EVM Integration                                     │
//! │  `evm::kv_state_db::execute_evm_on_state`                                 │
//! │  (unified EVM backend backed by KvState)                                  │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::execution::{apply_tx, build_block, verify_block, ExecutionConfig};
//!
//! let config = ExecutionConfig::default();
//! let (receipt, new_state) = apply_tx(&state, &tx, base_fee, proposer_addr)?;
//! ```

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use alloc::string::String;
use core::fmt;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

use crate::crypto::{PublicKeyBytes, SignatureBytes, Signer, Verifier};
use crate::crypto::ed25519::Ed25519Verifier;
use crate::crypto::tx::{derive_address, tx_sign_bytes};
use crate::evm::kv_state_db::{execute_evm_on_state, KvStateDb, UnifiedEvmResult};
use crate::evm::types::{EvmTx, AccessListItem};
use crate::types::{
    Block, BlockHeader, Hash32, Height, KvState, Receipt, Round, Tx, Log,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default gas limit per block (86 million, same as Ethereum mainnet).
pub const DEFAULT_GAS_LIMIT: u64 = 86_000_000;

/// Minimum gas for a transaction (intrinsic cost).
pub const INTRINSIC_GAS: u64 = 21_000;

/// Gas cost per byte of transaction payload.
pub const GAS_PER_BYTE: u64 = 10;

/// Minimum base fee (1 gwei equivalent in micro-units).
pub const MIN_BASE_FEE: u64 = 1;

/// EIP-1559 elasticity denominator (8 as per Ethereum).
const ELASTICITY_DENOM: u64 = 8;

/// Maximum payload size for a transaction (256 KiB).
pub const MAX_PAYLOAD_SIZE: usize = 262_144;

/// Default chain ID for IONA.
pub const DEFAULT_CHAIN_ID: u64 = 6126151;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the execution engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionConfig {
    /// Block gas limit.
    pub gas_limit: u64,
    /// Default chain ID.
    pub chain_id: u64,
    /// Minimum base fee.
    pub min_base_fee: u64,
    /// Whether to verify transaction signatures.
    pub verify_signatures: bool,
    /// Whether to verify state roots.
    pub verify_state_roots: bool,
    /// Whether to verify transaction roots.
    pub verify_tx_roots: bool,
    /// Maximum payload size.
    pub max_payload_size: usize,
    /// Enable EVM execution (if false, only KV operations are allowed).
    pub enable_evm: bool,
    /// EVM gas limit per transaction.
    pub evm_gas_limit: u64,
    /// Enable detailed tracing of EVM execution.
    pub evm_tracing: bool,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            gas_limit: DEFAULT_GAS_LIMIT,
            chain_id: DEFAULT_CHAIN_ID,
            min_base_fee: MIN_BASE_FEE,
            verify_signatures: true,
            verify_state_roots: true,
            verify_tx_roots: true,
            max_payload_size: MAX_PAYLOAD_SIZE,
            enable_evm: true,
            evm_gas_limit: 15_000_000,
            evm_tracing: false,
        }
    }
}

impl ExecutionConfig {
    /// Create a config for testing (fast, no verification).
    pub fn test() -> Self {
        Self {
            verify_signatures: false,
            verify_state_roots: false,
            verify_tx_roots: false,
            enable_evm: true,
            ..Default::default()
        }
    }

    /// Create a config for production (all checks enabled).
    pub fn production() -> Self {
        Self::default()
    }
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during transaction execution.
#[derive(Debug, Error)]
pub enum ExecutionError {
    #[error("invalid transaction signature")]
    InvalidSignature,

    #[error("sender address mismatch: expected {expected}, got {actual}")]
    AddressMismatch { expected: String, actual: String },

    #[error("nonce mismatch: expected {expected}, got {actual}")]
    NonceMismatch { expected: u64, actual: u64 },

    #[error("insufficient balance: needed {needed}, available {available}")]
    InsufficientBalance { needed: u64, available: u64 },

    #[error("gas limit too low: limit {limit} < intrinsic {intrinsic}")]
    GasLimitTooLow { limit: u64, intrinsic: u64 },

    #[error("max fee per gas {max_fee} < base fee {base_fee}")]
    FeeTooLow { max_fee: u64, base_fee: u64 },

    #[error("payload too large: {len} bytes (max {max})")]
    PayloadTooLarge { len: usize, max: usize },

    #[error("EVM execution failed: {0}")]
    EvmError(String),

    #[error("state root mismatch: expected {expected}, got {actual}")]
    StateRootMismatch { expected: String, actual: String },

    #[error("transaction root mismatch: expected {expected}, got {actual}")]
    TxRootMismatch { expected: String, actual: String },

    #[error("gas used mismatch: expected {expected}, got {actual}")]
    GasUsedMismatch { expected: u64, actual: u64 },

    #[error("proposer mismatch: expected {expected}, got {actual}")]
    ProposerMismatch { expected: String, actual: String },

    #[error("block verification failed: {0}")]
    VerificationFailed(String),

    #[error("chain ID mismatch: expected {expected}, got {actual}")]
    ChainIdMismatch { expected: u64, actual: u64 },

    #[error("internal error: {0}")]
    Internal(String),
}

pub type ExecutionResult<T> = Result<T, ExecutionError>;

// -----------------------------------------------------------------------------
// EIP-1559 base fee adjustment
// -----------------------------------------------------------------------------

/// Compute the next block's base fee per gas according to EIP-1559.
/// If `gas_used == gas_target`, fee unchanged.
/// If `gas_used > gas_target`, fee increases up to 12.5%.
/// If `gas_used < gas_target`, fee decreases.
pub fn next_base_fee(current: u64, gas_used: u64, gas_target: u64) -> u64 {
    if gas_target == 0 {
        return current.max(MIN_BASE_FEE);
    }
    let current = current.max(MIN_BASE_FEE);
    if gas_used == gas_target {
        return current;
    }
    let delta = if gas_used > gas_target {
        let excess = gas_used - gas_target;
        (current * excess / gas_target / ELASTICITY_DENOM).max(1)
    } else {
        let shortage = gas_target - gas_used;
        current * shortage / gas_target / ELASTICITY_DENOM
    };
    if gas_used > gas_target {
        current.saturating_add(delta).max(MIN_BASE_FEE)
    } else {
        current.saturating_sub(delta).max(MIN_BASE_FEE)
    }
}

// -----------------------------------------------------------------------------
// Transaction intrinsic gas
// -----------------------------------------------------------------------------

/// Compute the intrinsic gas cost for a transaction (signature + payload).
pub fn intrinsic_gas(tx: &Tx, config: &ExecutionConfig) -> u64 {
    let base = INTRINSIC_GAS;
    let payload_gas = (tx.payload.len() as u64) * GAS_PER_BYTE;
    base + payload_gas
}

// -----------------------------------------------------------------------------
// Signature verification
// -----------------------------------------------------------------------------

/// Verify transaction signature and return the sender address.
pub fn verify_tx_signature(tx: &Tx) -> ExecutionResult<String> {
    let derived_addr = derive_address(&tx.pubkey);
    if tx.from != derived_addr {
        return Err(ExecutionError::AddressMismatch {
            expected: derived_addr,
            actual: tx.from.clone(),
        });
    }
    let pk = PublicKeyBytes(tx.pubkey.clone());
    let msg = tx_sign_bytes(tx);
    Ed25519Verifier::verify(&pk, &msg, &SignatureBytes(tx.signature.clone()))
        .map_err(|_| ExecutionError::InvalidSignature)?;
    Ok(derived_addr)
}

// -----------------------------------------------------------------------------
// Single transaction application
// -----------------------------------------------------------------------------

/// Apply a single transaction to the state, returning receipt and new state.
/// Does **not** commit VM state changes on revert (they are discarded).
pub fn apply_tx(
    state: &KvState,
    tx: &Tx,
    base_fee_per_gas: u64,
    proposer_addr: &str,
    config: &ExecutionConfig,
) -> ExecutionResult<(Receipt, KvState)> {
    // 1. Verify signature and get sender.
    let from_addr = if config.verify_signatures {
        verify_tx_signature(tx)?
    } else {
        derive_address(&tx.pubkey)
    };

    let mut working = state.clone();

    // 2. Check chain ID.
    if config.chain_id != tx.chain_id {
        return Err(ExecutionError::ChainIdMismatch {
            expected: config.chain_id,
            actual: tx.chain_id,
        });
    }

    // 3. Check nonce.
    let expected_nonce = working.nonces.get(&from_addr).copied().unwrap_or(0);
    if tx.nonce != expected_nonce {
        return Err(ExecutionError::NonceMismatch {
            expected: expected_nonce,
            actual: tx.nonce,
        });
    }

    // 4. Payload size check.
    if tx.payload.len() > config.max_payload_size {
        return Err(ExecutionError::PayloadTooLarge {
            len: tx.payload.len(),
            max: config.max_payload_size,
        });
    }

    // 5. Intrinsic gas.
    let intrinsic = intrinsic_gas(tx, config);
    if tx.gas_limit < intrinsic {
        return Err(ExecutionError::GasLimitTooLow {
            limit: tx.gas_limit,
            intrinsic,
        });
    }

    // 6. Fee check (EIP-1559).
    if tx.max_fee_per_gas < base_fee_per_gas {
        return Err(ExecutionError::FeeTooLow {
            max_fee: tx.max_fee_per_gas,
            base_fee: base_fee_per_gas,
        });
    }

    // 7. Calculate effective gas price and tip.
    let max_tip = tx.max_fee_per_gas.saturating_sub(base_fee_per_gas);
    let priority_fee = tx.max_priority_fee_per_gas.min(max_tip);
    let effective_gas_price = base_fee_per_gas + priority_fee;

    let total_gas_cost = intrinsic * effective_gas_price;
    let burned = intrinsic * base_fee_per_gas;
    let tip = intrinsic * priority_fee;

    // 8. Check balance.
    let balance = working.balances.get(&from_addr).copied().unwrap_or(0);
    if balance < total_gas_cost {
        return Err(ExecutionError::InsufficientBalance {
            needed: total_gas_cost,
            available: balance,
        });
    }

    // 9. Deduct gas cost, increase nonce, update burned and proposer tip.
    *working.balances.entry(from_addr.clone()).or_insert(0) = balance - total_gas_cost;
    *working.burned.entry(()).or_insert(0) += burned;
    *working.balances.entry(proposer_addr.to_string()).or_insert(0) += tip;
    *working.nonces.entry(from_addr.clone()).or_insert(0) = expected_nonce + 1;

    // 10. Execute payload.
    let (success, output, logs, gas_used_extra) = if tx.payload.starts_with(b"evm_unified ") {
        if !config.enable_evm {
            return Err(ExecutionError::EvmError("EVM execution disabled".into()));
        }
        let hex_payload = tx.payload.strip_prefix(b"evm_unified ").unwrap_or(b"");
        let evm_tx = match hex::decode(hex_payload).ok().and_then(|bytes| bincode::deserialize(&bytes).ok()) {
            Some(t) => t,
            None => return Err(ExecutionError::EvmError("failed to decode EVM transaction".into())),
        };

        // Execute via unified EVM backend.
        let result = execute_evm_on_state(
            &mut working,
            evm_tx,
            // We need block number and timestamp. These are not in the Tx, so we use defaults.
            // In practice, the block builder would provide these.
            0, // block_number
            0, // block_timestamp
            base_fee_per_gas,
            config.chain_id,
            Some(config.evm_gas_limit),
        );

        match result {
            UnifiedEvmResult { success, gas_used, return_data, logs, error, .. } => {
                let gas_used_extra = gas_used.saturating_sub(intrinsic);
                (success, return_data, logs, gas_used_extra)
            }
            _ => (false, vec![], vec![], 0),
        }
    } else {
        // Simple KV operation (for testing).
        match apply_kv_payload(&mut working.kv, &tx.payload) {
            Ok(_) => (true, vec![], vec![], 0),
            Err(e) => (false, vec![], vec![], 0),
        }
    };

    let gas_used = intrinsic + gas_used_extra;
    let receipt = Receipt {
        tx_hash: crate::types::tx_hash(tx),
        success,
        gas_used,
        intrinsic_gas_used: intrinsic,
        exec_gas_used: gas_used_extra,
        // These are not used in simple receipt; we set to 0.
        vm_gas_used: 0,
        evm_gas_used: if success { gas_used_extra } else { 0 },
        effective_gas_price,
        burned,
        tip,
        error: if success { None } else { Some("execution failed".into()) },
        data: Some(output),
    };

    Ok((receipt, working))
}

/// Apply a simple KV payload (for testing purposes).
fn apply_kv_payload(kv: &mut BTreeMap<Vec<u8>, Vec<u8>>, payload: &[u8]) -> Result<(), String> {
    let s = core::str::from_utf8(payload).map_err(|_| "invalid UTF-8".to_string())?;
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.is_empty() {
        return Err("empty payload".into());
    }
    match parts[0] {
        "set" if parts.len() >= 3 => {
            let key = parts[1].as_bytes().to_vec();
            let value = parts[2..].join(" ").into_bytes();
            kv.insert(key, value);
            Ok(())
        }
        "del" if parts.len() == 2 => {
            let key = parts[1].as_bytes().to_vec();
            kv.remove(&key);
            Ok(())
        }
        _ => Err(format!("unknown KV command: {}", parts[0])),
    }
}

// -----------------------------------------------------------------------------
// Block building
// -----------------------------------------------------------------------------

/// Build a new block from pending transactions.
pub fn build_block(
    height: Height,
    round: Round,
    parent_id: Hash32,
    proposer_pk: PublicKeyBytes,
    proposer_addr: &str,
    state: &KvState,
    base_fee: u64,
    txs: Vec<Tx>,
    config: &ExecutionConfig,
) -> ExecutionResult<(Block, KvState, Vec<Receipt>)> {
    let mut new_state = state.clone();
    let mut receipts = Vec::with_capacity(txs.len());
    let mut gas_used = 0u64;
    let mut successful_txs = 0;

    for tx in txs.iter() {
        let (receipt, next_state) = apply_tx(&new_state, tx, base_fee, proposer_addr, config)?;
        gas_used += receipt.gas_used;
        if receipt.success {
            successful_txs += 1;
        }
        receipts.push(receipt);
        new_state = next_state;
    }

    let state_root = compute_state_root(&new_state);
    let tx_root = compute_tx_root(&txs);
    let timestamp = crate::arch::x86_64::timer::uptime_ms();

    let header = BlockHeader {
        height,
        round,
        prev: parent_id,
        proposer_pk: proposer_pk.0,
        proposer_addr: proposer_addr.to_string(),
        tx_root,
        receipts_root: compute_receipts_root(&receipts),
        state_root,
        base_fee_per_gas: base_fee,
        gas_used,
        intrinsic_gas_used: receipts.iter().map(|r| r.intrinsic_gas_used).sum(),
        exec_gas_used: receipts.iter().map(|r| r.exec_gas_used).sum(),
        vm_gas_used: receipts.iter().map(|r| r.vm_gas_used).sum(),
        evm_gas_used: receipts.iter().map(|r| r.evm_gas_used).sum(),
        chain_id: config.chain_id,
        timestamp,
        protocol_version: crate::protocol::version::CURRENT_PROTOCOL_VERSION,
    };

    debug!(
        height,
        round,
        txs = txs.len(),
        gas_used,
        successful_txs,
        "block built"
    );

    Ok((Block { header, txs }, new_state, receipts))
}

// -----------------------------------------------------------------------------
// Block verification
// -----------------------------------------------------------------------------

/// Verify a block against the expected proposer public key and state.
pub fn verify_block(
    state: &KvState,
    block: &Block,
    expected_proposer_pk: &PublicKeyBytes,
    proposer_addr: &str,
    config: &ExecutionConfig,
) -> ExecutionResult<(KvState, Vec<Receipt>)> {
    // 1. Check proposer matches.
    if block.header.proposer_pk != expected_proposer_pk.0 {
        return Err(ExecutionError::ProposerMismatch {
            expected: hex::encode(&expected_proposer_pk.0),
            actual: hex::encode(&block.header.proposer_pk),
        });
    }
    if block.header.proposer_addr != proposer_addr {
        return Err(ExecutionError::ProposerMismatch {
            expected: proposer_addr.to_string(),
            actual: block.header.proposer_addr.clone(),
        });
    }

    // 2. Check chain ID.
    if block.header.chain_id != config.chain_id {
        return Err(ExecutionError::ChainIdMismatch {
            expected: config.chain_id,
            actual: block.header.chain_id,
        });
    }

    // 3. Re-execute transactions.
    let mut new_state = state.clone();
    let mut receipts = Vec::with_capacity(block.txs.len());
    let mut gas_used = 0u64;
    let mut successful_txs = 0;

    for tx in block.txs.iter() {
        let (receipt, next_state) = apply_tx(
            &new_state,
            tx,
            block.header.base_fee_per_gas,
            proposer_addr,
            config,
        )?;
        gas_used += receipt.gas_used;
        if receipt.success {
            successful_txs += 1;
        }
        receipts.push(receipt);
        new_state = next_state;
    }

    // 4. Verify gas used.
    if config.verify_state_roots && gas_used != block.header.gas_used {
        return Err(ExecutionError::GasUsedMismatch {
            expected: block.header.gas_used,
            actual: gas_used,
        });
    }

    // 5. Verify transaction root.
    if config.verify_tx_roots {
        let computed_tx_root = compute_tx_root(&block.txs);
        if computed_tx_root != block.header.tx_root {
            return Err(ExecutionError::TxRootMismatch {
                expected: hex::encode(block.header.tx_root.0),
                actual: hex::encode(computed_tx_root.0),
            });
        }
    }

    // 6. Verify receipts root.
    let computed_receipts_root = compute_receipts_root(&receipts);
    if computed_receipts_root != block.header.receipts_root {
        return Err(ExecutionError::VerificationFailed(
            format!("receipts root mismatch: expected {}, got {}",
                hex::encode(block.header.receipts_root.0),
                hex::encode(computed_receipts_root.0))
        ));
    }

    // 7. Verify state root.
    if config.verify_state_roots {
        let computed_root = compute_state_root(&new_state);
        if computed_root != block.header.state_root {
            return Err(ExecutionError::StateRootMismatch {
                expected: hex::encode(block.header.state_root.0),
                actual: hex::encode(computed_root.0),
            });
        }
    }

    debug!(
        height = block.header.height,
        txs = block.txs.len(),
        gas_used,
        successful_txs,
        "block verified"
    );

    Ok((new_state, receipts))
}

// -----------------------------------------------------------------------------
// State and root helpers
// -----------------------------------------------------------------------------

/// Compute state root (deterministic Merkle root of all key‑value pairs).
/// Uses Blake3 for speed and determinism.
pub fn compute_state_root(state: &KvState) -> Hash32 {
    // Deterministic: sort keys, hash concatenation of key+value.
    let mut data = Vec::new();
    let mut sorted: Vec<(&Vec<u8>, &Vec<u8>)> = state.kv.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    for (k, v) in sorted {
        data.extend_from_slice(k);
        data.extend_from_slice(v);
    }
    // Also include balances and nonces.
    let mut balances_sorted: Vec<(&String, &u64)> = state.balances.iter().collect();
    balances_sorted.sort_by(|a, b| a.0.cmp(b.0));
    for (addr, bal) in balances_sorted {
        data.extend_from_slice(addr.as_bytes());
        data.extend_from_slice(&bal.to_le_bytes());
    }
    let mut nonces_sorted: Vec<(&String, &u64)> = state.nonces.iter().collect();
    nonces_sorted.sort_by(|a, b| a.0.cmp(b.0));
    for (addr, nonce) in nonces_sorted {
        data.extend_from_slice(addr.as_bytes());
        data.extend_from_slice(&nonce.to_le_bytes());
    }
    // Include burned amount.
    data.extend_from_slice(&state.burned.to_le_bytes());

    // Hash with Blake3 (32 bytes).
    let hash = blake3::hash(&data);
    Hash32(hash.as_bytes().try_into().unwrap())
}

/// Compute transaction root (hash of concatenated transaction hashes).
pub fn compute_tx_root(txs: &[Tx]) -> Hash32 {
    let mut data = Vec::new();
    for tx in txs {
        data.extend_from_slice(&crate::types::tx_hash(tx));
    }
    let hash = blake3::hash(&data);
    Hash32(hash.as_bytes().try_into().unwrap())
}

/// Compute receipts root (hash of concatenated receipts).
pub fn compute_receipts_root(receipts: &[Receipt]) -> Hash32 {
    let mut data = Vec::new();
    for r in receipts {
        // Serialize receipt to bytes for hashing.
        let serialized = postcard::to_allocvec(r).unwrap_or_default();
        data.extend_from_slice(&serialized);
    }
    let hash = blake3::hash(&data);
    Hash32(hash.as_bytes().try_into().unwrap())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Tx;

    fn dummy_tx(from: &str, nonce: u64, payload: &str) -> Tx {
        Tx {
            pubkey: vec![0u8; 32],
            from: from.to_string(),
            nonce,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 10,
            gas_limit: 100_000,
            payload: payload.as_bytes().to_vec(),
            signature: vec![0u8; 64],
            chain_id: DEFAULT_CHAIN_ID,
        }
    }

    #[test]
    fn test_next_base_fee() {
        assert_eq!(next_base_fee(100, 0, 1_000_000), 99);
        assert_eq!(next_base_fee(100, 2_000_000, 1_000_000), 125);
        assert_eq!(next_base_fee(1, 0, 1_000_000), 1);
    }

    #[test]
    fn test_intrinsic_gas() {
        let config = ExecutionConfig::default();
        let tx = dummy_tx("alice", 0, "set key value");
        let gas = intrinsic_gas(&tx, &config);
        assert!(gas >= INTRINSIC_GAS);
        assert_eq!(gas, INTRINSIC_GAS + 13 * GAS_PER_BYTE);
    }

    #[test]
    fn test_apply_kv_payload() {
        let mut kv = BTreeMap::new();
        let payload = b"set key value";
        assert!(apply_kv_payload(&mut kv, payload).is_ok());
        assert_eq!(kv.get(b"key".as_slice()), Some(&b"value".to_vec()));

        let payload2 = b"del key";
        assert!(apply_kv_payload(&mut kv, payload2).is_ok());
        assert!(!kv.contains_key(b"key".as_slice()));
    }

    #[test]
    fn test_apply_tx_kv() -> ExecutionResult<()> {
        let config = ExecutionConfig::test();
        let mut state = KvState::default();
        state.balances.insert("alice".into(), 1_000_000);
        let tx = Tx {
            pubkey: vec![0u8; 32],
            from: "alice".into(),
            nonce: 0,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 10,
            gas_limit: 100_000,
            payload: b"set key value".to_vec(),
            signature: vec![0u8; 64],
            chain_id: DEFAULT_CHAIN_ID,
        };
        let (receipt, new_state) = apply_tx(&state, &tx, 10, "proposer", &config)?;
        assert!(receipt.success);
        assert!(receipt.gas_used > 0);
        assert_eq!(new_state.kv.get(b"key".as_slice()), Some(&b"value".to_vec()));
        assert_eq!(new_state.balances.get("alice"), Some(&(1_000_000 - 100_000 * 100)));
        Ok(())
    }

    #[test]
    fn test_build_block() -> ExecutionResult<()> {
        let config = ExecutionConfig::test();
        let mut state = KvState::default();
        state.balances.insert("alice".into(), 1_000_000);
        let tx = Tx {
            pubkey: vec![0u8; 32],
            from: "alice".into(),
            nonce: 0,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 10,
            gas_limit: 100_000,
            payload: b"set key value".to_vec(),
            signature: vec![0u8; 64],
            chain_id: DEFAULT_CHAIN_ID,
        };
        let pk = PublicKeyBytes(vec![0u8; 32]);
        let (block, new_state, receipts) = build_block(
            1, 0, Hash32::zero(), pk, "proposer", &state, 10, vec![tx], &config,
        )?;
        assert_eq!(block.txs.len(), 1);
        assert!(!receipts.is_empty());
        assert!(receipts[0].success);
        assert_eq!(new_state.kv.get(b"key".as_slice()), Some(&b"value".to_vec()));
        Ok(())
    }

    #[test]
    fn test_verify_block() -> ExecutionResult<()> {
        let config = ExecutionConfig::test();
        let mut state = KvState::default();
        state.balances.insert("alice".into(), 1_000_000);
        let tx = Tx {
            pubkey: vec![0u8; 32],
            from: "alice".into(),
            nonce: 0,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 10,
            gas_limit: 100_000,
            payload: b"set key value".to_vec(),
            signature: vec![0u8; 64],
            chain_id: DEFAULT_CHAIN_ID,
        };
        let pk = PublicKeyBytes(vec![0u8; 32]);
        let (block, _, _) = build_block(
            1, 0, Hash32::zero(), pk.clone(), "proposer", &state, 10, vec![tx], &config,
        )?;
        let (new_state, receipts) = verify_block(&state, &block, &pk, "proposer", &config)?;
        assert!(!receipts.is_empty());
        assert_eq!(new_state.kv.get(b"key".as_slice()), Some(&b"value".to_vec()));
        Ok(())
    }
}
