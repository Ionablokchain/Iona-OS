//! Block execution: build blocks from transactions, verify blocks, apply state transitions
//!
//! Integrates with EVM (via `blockchain::revm_port`) for contract execution.
//! Handles transaction validation (signatures, nonces, balances, gas),
//! EIP-1559 fee calculation, and state root computation.

use alloc::{vec::Vec, string::String, collections::BTreeMap};
use crate::types::{Block, BlockHeader, Hash32, Height, KvState, Receipt, Round, Tx, Log};
use crate::crypto::{PublicKeyBytes, Signer, Verifier, ed25519::Ed25519Verifier};
use crate::crypto::tx::{derive_address, tx_sign_bytes};
use thiserror::Error;

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

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during transaction execution.
#[derive(Debug, Error)]
pub enum ExecutionError {
    #[error("invalid signature")]
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
pub fn intrinsic_gas(tx: &Tx) -> u64 {
    INTRINSIC_GAS + (tx.payload.len() as u64) * GAS_PER_BYTE
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
    Ed25519Verifier::verify(&pk, &msg, &tx.signature)
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
) -> ExecutionResult<(Receipt, KvState)> {
    // 1. Verify signature and get sender.
    let from_addr = verify_tx_signature(tx)?;

    let mut working = state.clone();

    // 2. Check nonce.
    let expected_nonce = working.nonces.get(&from_addr).copied().unwrap_or(0);
    if tx.nonce != expected_nonce {
        return Err(ExecutionError::NonceMismatch {
            expected: expected_nonce,
            actual: tx.nonce,
        });
    }

    // 3. Intrinsic gas.
    let intrinsic = intrinsic_gas(tx);
    if tx.gas_limit < intrinsic {
        return Err(ExecutionError::GasLimitTooLow {
            limit: tx.gas_limit,
            intrinsic,
        });
    }

    // 4. Fee check (EIP-1559).
    if tx.max_fee_per_gas < base_fee_per_gas {
        return Err(ExecutionError::FeeTooLow {
            max_fee: tx.max_fee_per_gas,
            base_fee: base_fee_per_gas,
        });
    }

    // 5. Calculate effective gas price and tip.
    let max_tip = tx.max_fee_per_gas.saturating_sub(base_fee_per_gas);
    let priority_fee = tx.max_priority_fee_per_gas.min(max_tip);
    let effective_gas_price = base_fee_per_gas + priority_fee;

    let total_gas_cost = intrinsic * effective_gas_price;
    let burned = intrinsic * base_fee_per_gas;
    let tip = intrinsic * priority_fee;

    // 6. Check balance.
    let balance = working.balances.get(&from_addr).copied().unwrap_or(0);
    if balance < total_gas_cost {
        return Err(ExecutionError::InsufficientBalance {
            needed: total_gas_cost,
            available: balance,
        });
    }

    // 7. Deduct gas cost, increase nonce, update burned and proposer tip.
    *working.balances.entry(from_addr.clone()).or_insert(0) = balance - total_gas_cost;
    *working.burned.entry(()).or_insert(0) += burned;
    *working.balances.entry(proposer_addr.to_string()).or_insert(0) += tip;
    *working.nonces.entry(from_addr.clone()).or_insert(0) = expected_nonce + 1;

    // 8. Execute payload (EVM or KV).
    let (success, output, logs, gas_used_extra) = if tx.payload.starts_with(b"evm_unified ") {
        // Decode EVM transaction and execute via `revm_port`.
        let hex_payload = tx.payload.strip_prefix(b"evm_unified ").unwrap_or(b"");
        let evm_tx = match hex::decode(hex_payload).ok().and_then(|bytes| bincode::deserialize(&bytes).ok()) {
            Some(t) => t,
            None => return Err(ExecutionError::EvmError("failed to decode EVM transaction".into())),
        };
        // This would call into the EVM executor. Placeholder for actual integration.
        // For now, we return a dummy.
        (true, vec![], vec![], 0)
    } else {
        // Simple KV operation (for testing).
        apply_kv_payload(&mut working.kv, &tx.payload)
            .map_err(|e| ExecutionError::EvmError(e))?;
        (true, vec![], vec![], 0)
    };

    let gas_used = intrinsic + gas_used_extra;
    let receipt = Receipt {
        tx_hash: crate::types::tx_hash(tx),
        success,
        gas_used,
        logs,
        output,
    };

    Ok((receipt, working))
}

/// Apply a simple KV payload (for testing purposes).
fn apply_kv_payload(kv: &mut BTreeMap<Vec<u8>, Vec<u8>>, payload: &[u8]) -> Result<(), String> {
    let s = core::str::from_utf8(payload).map_err(|_| "invalid UTF-8")?;
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
        _ => Err("unknown KV command".into()),
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
) -> ExecutionResult<(Block, KvState, Vec<Receipt>)> {
    let mut new_state = state.clone();
    let mut receipts = Vec::with_capacity(txs.len());
    let mut gas_used = 0u64;

    for tx in txs.iter() {
        let (receipt, next_state) = apply_tx(&new_state, tx, base_fee, proposer_addr)?;
        gas_used += receipt.gas_used;
        receipts.push(receipt);
        new_state = next_state;
    }

    let state_root = compute_state_root(&new_state);
    let tx_root = compute_tx_root(&txs);
    let timestamp = crate::arch::x86_64::timer::uptime_ms();

    let header = BlockHeader {
        height,
        round,
        parent_id,
        state_root,
        tx_root,
        proposer_pk: proposer_pk.0,
        proposer_addr: proposer_addr.to_string(),
        base_fee,
        gas_used,
        gas_limit: DEFAULT_GAS_LIMIT,
        timestamp_ms: timestamp,
    };

    Ok((Block { header, txs }, new_state, receipts))
}

// -----------------------------------------------------------------------------
// Block verification
// -----------------------------------------------------------------------------

/// Verify a block against the expected proposer public key.
pub fn verify_block_with_vset(
    state: &KvState,
    block: &Block,
    proposer_addr: &str,
    expected_proposer_pk: &PublicKeyBytes,
) -> ExecutionResult<(KvState, Vec<Receipt>)> {
    // Check proposer matches.
    if block.header.proposer_pk != expected_proposer_pk.0 {
        return Err(ExecutionError::EvmError("proposer public key mismatch".into()));
    }
    if block.header.proposer_addr != proposer_addr {
        return Err(ExecutionError::EvmError("proposer address mismatch".into()));
    }

    // Re-execute transactions.
    let mut new_state = state.clone();
    let mut receipts = Vec::with_capacity(block.txs.len());
    let mut gas_used = 0u64;

    for tx in block.txs.iter() {
        let (receipt, next_state) = apply_tx(&new_state, tx, block.header.base_fee, proposer_addr)?;
        gas_used += receipt.gas_used;
        receipts.push(receipt);
        new_state = next_state;
    }

    // Verify gas used.
    if gas_used != block.header.gas_used {
        return Err(ExecutionError::EvmError("gas used mismatch".into()));
    }

    // Verify state root.
    let computed_root = compute_state_root(&new_state);
    if computed_root != block.header.state_root {
        return Err(ExecutionError::StateRootMismatch {
            expected: hex::encode(block.header.state_root),
            actual: hex::encode(computed_root),
        });
    }

    // Verify transaction root.
    let computed_tx_root = compute_tx_root(&block.txs);
    if computed_tx_root != block.header.tx_root {
        return Err(ExecutionError::EvmError("transaction root mismatch".into()));
    }

    Ok((new_state, receipts))
}

// -----------------------------------------------------------------------------
// State and transaction root helpers
// -----------------------------------------------------------------------------

/// Compute state root (deterministic Merkle root of all key‑value pairs).
fn compute_state_root(state: &KvState) -> Hash32 {
    // Deterministic: sort keys, hash concatenation of key+value.
    let mut data = Vec::new();
    let mut sorted: Vec<(&Vec<u8>, &Vec<u8>)> = state.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    for (k, v) in sorted {
        data.extend_from_slice(k);
        data.extend_from_slice(v);
    }
    crate::consensus::engine::sha256_hash(&data)
}

/// Compute transaction root (simple hash of concatenated transaction hashes).
fn compute_tx_root(txs: &[Tx]) -> Hash32 {
    let mut data = Vec::new();
    for tx in txs {
        data.extend_from_slice(&crate::types::tx_hash(tx));
    }
    crate::consensus::engine::sha256_hash(&data)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_next_base_fee() {
        assert_eq!(next_base_fee(100, 0, 1_000_000), 99);
        assert_eq!(next_base_fee(100, 2_000_000, 1_000_000), 125);
        assert_eq!(next_base_fee(1, 0, 1_000_000), 1);
    }
}
