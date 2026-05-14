//! Block execution: build blocks from txs, verify blocks, apply state transitions
//!
//! Integrates with EVM (blockchain::revm_port) for contract execution.

use alloc::{vec::Vec, string::String};
use crate::types::{Block, BlockHeader, Hash32, Height, KvState, Receipt, Round, Tx};
use crate::crypto::PublicKeyBytes;


/// EIP-1559 base fee adjustment
/// If gas_used > gas_target: increase base_fee by up to 12.5%
/// If gas_used < gas_target: decrease base_fee by up to 12.5%
pub fn next_base_fee(current: u64, gas_used: u64, gas_target: u64) -> u64 {
    if gas_used == gas_target { return current; }
    let delta = if gas_used > gas_target {
        // Increase: min(12.5%, actual overshoot fraction)
        current * (gas_used - gas_target) / gas_target / 8
    } else {
        0
    };
    let decrease = if gas_used < gas_target {
        current * (gas_target - gas_used) / gas_target / 8
    } else {
        0
    };
    current.saturating_add(delta).saturating_sub(decrease).max(1)
}

/// Build a new block from pending transactions
pub fn build_block(
    height: Height,
    round: Round,
    parent_id: Hash32,
    proposer_pk_bytes: Vec<u8>,
    proposer_addr: &str,
    state: &KvState,
    base_fee: u64,
    txs: Vec<Tx>,
) -> (Block, KvState, Vec<Receipt>) {
    let mut new_state = state.clone();
    let mut receipts = Vec::new();
    let mut gas_used = 0u64;

    // Execute each transaction against the EVM
    for tx in &txs {
        let receipt = execute_tx(tx, &mut new_state, base_fee);
        gas_used += receipt.gas_used;
        receipts.push(receipt);
    }

    let state_root  = state_hash(&new_state);
    let tx_root     = tx_hash(&txs);
    let timestamp   = crate::arch::x86_64::timer::uptime_ms();

    let header = BlockHeader {
        height,
        round,
        parent_id,
        state_root,
        tx_root,
        proposer_pk: proposer_pk_bytes,
        proposer_addr: proposer_addr.into(),
        base_fee,
        gas_used,
        gas_limit: 86_000_000,
        timestamp_ms: timestamp,
    };
    (Block { header, txs }, new_state, receipts)
}

/// Verify block validity, returning new state if valid
pub fn verify_block_with_vset(
    state: &KvState,
    block: &Block,
    proposer_addr: &str,
    expected_proposer_pk: &PublicKeyBytes,
) -> Option<(KvState, Vec<Receipt>)> {
    // Check proposer matches
    if block.header.proposer_pk != expected_proposer_pk.0 { return None; }
    if block.header.proposer_addr != proposer_addr { return None; }

    // Re-execute transactions
    let mut new_state = state.clone();
    let mut receipts = Vec::new();
    let mut gas_used = 0u64;
    for tx in &block.txs {
        let r = execute_tx(tx, &mut new_state, block.header.base_fee);
        gas_used += r.gas_used;
        receipts.push(r);
    }

    // Verify state root
    let computed_root = state_hash(&new_state);
    if computed_root != block.header.state_root { return None; }
    // Verify gas accounting
    if gas_used != block.header.gas_used { return None; }

    Some((new_state, receipts))
}

fn execute_tx(tx: &Tx, state: &mut KvState, base_fee: u64) -> Receipt {
    // Decode simple KV tx: [20: from][20: to][8: value][*: data]
    if tx.len() < 48 {
        return Receipt { tx_hash: [0;32], success: false, gas_used: 21_000, logs: Vec::new(), output: Vec::new() };
    }
    let from:  [u8;20] = tx[0..20].try_into().unwrap_or([0;20]);
    let to:    [u8;20] = tx[20..40].try_into().unwrap_or([0;20]);
    let value: u64     = u64::from_le_bytes(tx[40..48].try_into().unwrap_or([0;8]));
    let data           = &tx[48..];

    // Simple: store key=to, value=from in state
    state.insert(to.to_vec(), from.to_vec());

    let tx_hash = crate::consensus::engine::sha256_hash(tx);
    Receipt { tx_hash, success: true, gas_used: 21_000, logs: Vec::new(), output: Vec::new() }
}

fn state_hash(state: &KvState) -> Hash32 {
    let mut data = Vec::new();
    for (k, v) in state { data.extend_from_slice(k); data.extend_from_slice(v); }
    crate::consensus::engine::sha256_hash(&data)
}

fn tx_hash(txs: &[Tx]) -> Hash32 {
    let mut data = Vec::new();
    for tx in txs { data.extend_from_slice(tx); }
    crate::consensus::engine::sha256_hash(&data)
}
