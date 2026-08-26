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
//! use iona::execution::{ExecutionManager, ExecutionConfig};
//!
//! let config = ExecutionConfig::default();
//! let manager = ExecutionManager::new(config);
//! let (receipt, new_state) = manager.apply_tx(&state, &tx, base_fee, proposer_addr)?;
//! ```

#![allow(dead_code)]

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use alloc::string::String;
use core::fmt;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for the execution engine.
    use serde::{Deserialize, Serialize};
    use super::constants::*;

    /// Configuration for the execution engine.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ExecutionConfig {
        pub gas_limit: u64,
        pub chain_id: u64,
        pub min_base_fee: u64,
        pub verify_signatures: bool,
        pub verify_state_roots: bool,
        pub verify_tx_roots: bool,
        pub max_payload_size: usize,
        pub enable_evm: bool,
        pub evm_gas_limit: u64,
        pub evm_tracing: bool,
        pub collect_metrics: bool,
    }

    impl Default for ExecutionConfig {
        fn default() -> Self {
            Self {
                gas_limit: super::constants::DEFAULT_GAS_LIMIT,
                chain_id: super::constants::DEFAULT_CHAIN_ID,
                min_base_fee: super::constants::MIN_BASE_FEE,
                verify_signatures: true,
                verify_state_roots: true,
                verify_tx_roots: true,
                max_payload_size: super::constants::MAX_PAYLOAD_SIZE,
                enable_evm: true,
                evm_gas_limit: 15_000_000,
                evm_tracing: false,
                collect_metrics: true,
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

        pub fn validate(&self) -> Result<(), &'static str> {
            if self.gas_limit == 0 {
                return Err("gas_limit must be > 0");
            }
            if self.chain_id == 0 {
                return Err("chain_id must be > 0");
            }
            if self.min_base_fee == 0 {
                return Err("min_base_fee must be > 0");
            }
            if self.max_payload_size == 0 {
                return Err("max_payload_size must be > 0");
            }
            if self.evm_gas_limit == 0 {
                return Err("evm_gas_limit must be > 0");
            }
            Ok(())
        }

        pub fn with_metrics(mut self) -> Self {
            self.collect_metrics = true;
            self
        }
    }
}

pub mod constants {
    //! Constants for the execution engine.
    /// Default gas limit per block (86 million, same as Ethereum mainnet).
    pub const DEFAULT_GAS_LIMIT: u64 = 86_000_000;

    /// Minimum gas for a transaction (intrinsic cost).
    pub const INTRINSIC_GAS: u64 = 21_000;

    /// Gas cost per byte of transaction payload.
    pub const GAS_PER_BYTE: u64 = 10;

    /// Minimum base fee (1 gwei equivalent in micro-units).
    pub const MIN_BASE_FEE: u64 = 1;

    /// EIP-1559 elasticity denominator (8 as per Ethereum).
    pub const ELASTICITY_DENOM: u64 = 8;

    /// Maximum payload size for a transaction (256 KiB).
    pub const MAX_PAYLOAD_SIZE: usize = 262_144;

    /// Default chain ID for IONA.
    pub const DEFAULT_CHAIN_ID: u64 = 6126151;
}

pub mod error {
    //! Errors that can occur during transaction execution.
    use super::types::{Receipt, Tx};
    use thiserror::Error;

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
}

pub mod types {
    //! Types used in execution.
    use super::constants::INTRINSIC_GAS;
    use crate::types::{KvState, Receipt, Tx};
    use serde::{Deserialize, Serialize};

    /// Extended receipt with gas breakdown.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct ExecutionReceipt {
        pub tx_hash: [u8; 32],
        pub success: bool,
        pub gas_used: u64,
        pub intrinsic_gas_used: u64,
        pub exec_gas_used: u64,
        pub vm_gas_used: u64,
        pub evm_gas_used: u64,
        pub effective_gas_price: u64,
        pub burned: u64,
        pub tip: u64,
        pub error: Option<String>,
        pub data: Option<Vec<u8>>,
    }

    impl From<Receipt> for ExecutionReceipt {
        fn from(r: Receipt) -> Self {
            Self {
                tx_hash: r.tx_hash,
                success: r.success,
                gas_used: r.gas_used,
                intrinsic_gas_used: r.intrinsic_gas_used,
                exec_gas_used: r.exec_gas_used,
                vm_gas_used: r.vm_gas_used,
                evm_gas_used: r.evm_gas_used,
                effective_gas_price: r.effective_gas_price,
                burned: r.burned,
                tip: r.tip,
                error: r.error,
                data: r.data,
            }
        }
    }

    impl ExecutionReceipt {
        pub fn intrinsic_gas(tx: &Tx) -> u64 {
            INTRINSIC_GAS + (tx.payload.len() as u64) * super::constants::GAS_PER_BYTE
        }
    }
}

pub mod metrics {
    //! Metrics for execution operations.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct ExecutionMetrics {
        pub txs_applied: AtomicU64,
        pub txs_failed: AtomicU64,
        pub blocks_built: AtomicU64,
        pub blocks_verified: AtomicU64,
        pub gas_used_total: AtomicU64,
        pub gas_refunded_total: AtomicU64,
        pub state_roots_computed: AtomicU64,
    }

    impl ExecutionMetrics {
        pub fn inc_tx_applied(&self) {
            self.txs_applied.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_tx_failed(&self) {
            self.txs_failed.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_block_built(&self) {
            self.blocks_built.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_block_verified(&self) {
            self.blocks_verified.fetch_add(1, Ordering::Relaxed);
        }
        pub fn add_gas_used(&self, gas: u64) {
            self.gas_used_total.fetch_add(gas, Ordering::Relaxed);
        }
        pub fn add_gas_refunded(&self, gas: u64) {
            self.gas_refunded_total.fetch_add(gas, Ordering::Relaxed);
        }
        pub fn inc_state_root(&self) {
            self.state_roots_computed.fetch_add(1, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> ExecutionMetricsSnapshot {
            ExecutionMetricsSnapshot {
                txs_applied: self.txs_applied.load(Ordering::Relaxed),
                txs_failed: self.txs_failed.load(Ordering::Relaxed),
                blocks_built: self.blocks_built.load(Ordering::Relaxed),
                blocks_verified: self.blocks_verified.load(Ordering::Relaxed),
                gas_used_total: self.gas_used_total.load(Ordering::Relaxed),
                gas_refunded_total: self.gas_refunded_total.load(Ordering::Relaxed),
                state_roots_computed: self.state_roots_computed.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ExecutionMetricsSnapshot {
        pub txs_applied: u64,
        pub txs_failed: u64,
        pub blocks_built: u64,
        pub blocks_verified: u64,
        pub gas_used_total: u64,
        pub gas_refunded_total: u64,
        pub state_roots_computed: u64,
    }
}

pub mod gas {
    //! Gas-related utilities.
    use super::constants::{INTRINSIC_GAS, GAS_PER_BYTE, ELASTICITY_DENOM, MIN_BASE_FEE};
    use crate::types::Tx;

    /// Compute intrinsic gas cost.
    pub fn intrinsic_gas(tx: &Tx) -> u64 {
        INTRINSIC_GAS + (tx.payload.len() as u64) * GAS_PER_BYTE
    }

    /// Compute next base fee according to EIP-1559.
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

    /// Calculate effective gas price and tip for EIP-1559.
    pub fn effective_prices(base_fee: u64, max_fee: u64, max_priority: u64) -> (u64, u64, u64) {
        let max_tip = max_fee.saturating_sub(base_fee);
        let priority = max_priority.min(max_tip);
        let effective = base_fee + priority;
        (effective, base_fee, priority)
    }
}

pub mod verify {
    //! Signature and transaction verification.
    use super::{
        error::{ExecutionError, ExecutionResult},
        types::Tx,
    };
    use crate::crypto::{PublicKeyBytes, SignatureBytes, Verifier};
    use crate::crypto::ed25519::Ed25519Verifier;
    use crate::crypto::tx::{derive_address, tx_sign_bytes};

    /// Verify transaction signature and return sender address.
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
}

pub mod kv {
    //! Simple KV operations (for testing).
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;
    use alloc::string::String;

    /// Apply a simple KV payload (for testing purposes).
    pub fn apply_kv_payload(kv: &mut BTreeMap<Vec<u8>, Vec<u8>>, payload: &[u8]) -> Result<(), String> {
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
}

pub mod evm {
    //! EVM integration via `evm::kv_state_db`.
    use super::{
        config::ExecutionConfig,
        error::{ExecutionError, ExecutionResult},
        types::ExecutionReceipt,
        gas::intrinsic_gas,
    };
    use crate::evm::kv_state_db::{execute_evm_on_state, UnifiedEvmResult};
    use crate::evm::types::EvmTx;
    use crate::types::{KvState, Tx};
    use tracing::trace;

    /// Execute an EVM transaction payload.
    pub fn execute_evm_payload(
        state: &mut KvState,
        tx: &Tx,
        base_fee_per_gas: u64,
        chain_id: u64,
        config: &ExecutionConfig,
    ) -> ExecutionResult<UnifiedEvmResult> {
        if !config.enable_evm {
            return Err(ExecutionError::EvmError("EVM execution disabled".into()));
        }
        let hex_payload = tx.payload.strip_prefix(b"evm_unified ").unwrap_or(b"");
        let evm_tx: EvmTx = match hex::decode(hex_payload)
            .ok()
            .and_then(|bytes| bincode::deserialize(&bytes).ok())
        {
            Some(t) => t,
            None => return Err(ExecutionError::EvmError("failed to decode EVM transaction".into())),
        };

        if config.evm_tracing {
            trace!(tx_hash = ?tx.hash(), "executing EVM transaction");
        }

        let result = execute_evm_on_state(
            state,
            evm_tx,
            0, // block_number (provided by block builder)
            0, // block_timestamp (provided by block builder)
            base_fee_per_gas,
            chain_id,
            Some(config.evm_gas_limit),
        );
        Ok(result)
    }
}

pub mod block {
    //! Block building and verification.
    use super::{
        config::ExecutionConfig,
        error::{ExecutionError, ExecutionResult},
        types::{ExecutionReceipt, Tx},
        gas::{intrinsic_gas, effective_prices},
        verify::verify_tx_signature,
        evm::execute_evm_payload,
        kv::apply_kv_payload,
        metrics::ExecutionMetrics,
        root::compute_state_root,
    };
    use crate::types::{Block, BlockHeader, Hash32, Height, KvState, Receipt, Round};
    use crate::crypto::PublicKeyBytes;
    use alloc::vec::Vec;
    use tracing::{debug, info};

    /// Apply a single transaction to the state.
    pub fn apply_tx(
        state: &KvState,
        tx: &Tx,
        base_fee_per_gas: u64,
        proposer_addr: &str,
        config: &ExecutionConfig,
        metrics: &ExecutionMetrics,
    ) -> ExecutionResult<(ExecutionReceipt, KvState)> {
        // 1. Verify signature.
        let from_addr = if config.verify_signatures {
            verify_tx_signature(tx)?
        } else {
            crate::crypto::tx::derive_address(&tx.pubkey)
        };

        let mut working = state.clone();

        // 2. Chain ID check.
        if config.chain_id != tx.chain_id {
            return Err(ExecutionError::ChainIdMismatch {
                expected: config.chain_id,
                actual: tx.chain_id,
            });
        }

        // 3. Nonce check.
        let expected_nonce = working.nonces.get(&from_addr).copied().unwrap_or(0);
        if tx.nonce != expected_nonce {
            return Err(ExecutionError::NonceMismatch {
                expected: expected_nonce,
                actual: tx.nonce,
            });
        }

        // 4. Payload size.
        if tx.payload.len() > config.max_payload_size {
            return Err(ExecutionError::PayloadTooLarge {
                len: tx.payload.len(),
                max: config.max_payload_size,
            });
        }

        // 5. Intrinsic gas.
        let intrinsic = intrinsic_gas(tx);
        if tx.gas_limit < intrinsic {
            return Err(ExecutionError::GasLimitTooLow {
                limit: tx.gas_limit,
                intrinsic,
            });
        }

        // 6. Fee check.
        if tx.max_fee_per_gas < base_fee_per_gas {
            return Err(ExecutionError::FeeTooLow {
                max_fee: tx.max_fee_per_gas,
                base_fee: base_fee_per_gas,
            });
        }

        // 7. Effective prices.
        let (effective_gas_price, burned_per_gas, tip_per_gas) =
            effective_prices(base_fee_per_gas, tx.max_fee_per_gas, tx.max_priority_fee_per_gas);

        let total_gas_cost = intrinsic * effective_gas_price;
        let burned = intrinsic * base_fee_per_gas;
        let tip = intrinsic * tip_per_gas;

        // 8. Balance check.
        let balance = working.balances.get(&from_addr).copied().unwrap_or(0);
        if balance < total_gas_cost {
            return Err(ExecutionError::InsufficientBalance {
                needed: total_gas_cost,
                available: balance,
            });
        }

        // 9. Deduct gas cost, update nonce, add burned and tip.
        *working.balances.entry(from_addr.clone()).or_insert(0) = balance - total_gas_cost;
        *working.burned.entry(()).or_insert(0) += burned;
        *working.balances.entry(proposer_addr.to_string()).or_insert(0) += tip;
        *working.nonces.entry(from_addr.clone()).or_insert(0) = expected_nonce + 1;

        // 10. Execute payload (EVM or KV).
        let (success, output, logs, exec_gas_used) = if tx.payload.starts_with(b"evm_unified ") {
            match execute_evm_payload(&mut working, tx, base_fee_per_gas, config.chain_id, config) {
                Ok(result) => {
                    let gas_used_extra = result.gas_used.saturating_sub(intrinsic);
                    (result.success, result.return_data, result.logs, gas_used_extra)
                }
                Err(e) => (false, vec![], vec![], 0),
            }
        } else {
            match apply_kv_payload(&mut working.kv, &tx.payload) {
                Ok(_) => (true, vec![], vec![], 0),
                Err(_) => (false, vec![], vec![], 0),
            }
        };

        let total_gas_used = intrinsic + exec_gas_used;
        // Refund unused gas.
        let refund = tx.gas_limit.saturating_sub(total_gas_used);
        if refund > 0 {
            let refund_amount = refund * effective_gas_price;
            *working.balances.entry(from_addr.clone()).or_insert(0) += refund_amount;
        }

        // Record metrics.
        if success {
            metrics.inc_tx_applied();
        } else {
            metrics.inc_tx_failed();
        }
        metrics.add_gas_used(total_gas_used);
        metrics.add_gas_refunded(refund);

        let receipt = ExecutionReceipt {
            tx_hash: crate::types::tx_hash(tx),
            success,
            gas_used: total_gas_used,
            intrinsic_gas_used: intrinsic,
            exec_gas_used,
            vm_gas_used: 0,
            evm_gas_used: if success { exec_gas_used } else { 0 },
            effective_gas_price,
            burned,
            tip,
            error: if success { None } else { Some("execution failed".into()) },
            data: Some(output),
        };

        Ok((receipt, working))
    }

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
        metrics: &ExecutionMetrics,
    ) -> ExecutionResult<(Block, KvState, Vec<ExecutionReceipt>)> {
        let mut new_state = state.clone();
        let mut receipts = Vec::with_capacity(txs.len());
        let mut gas_used = 0u64;
        let mut successful_txs = 0;

        for tx in txs.iter() {
            let (receipt, next_state) = apply_tx(&new_state, tx, base_fee, proposer_addr, config, metrics)?;
            gas_used += receipt.gas_used;
            if receipt.success {
                successful_txs += 1;
            }
            receipts.push(receipt);
            new_state = next_state;
        }

        let state_root = crate::root::compute_state_root(&new_state);
        let tx_root = crate::root::compute_tx_root(&txs);
        let receipts_root = crate::root::compute_receipts_root(&receipts);
        let timestamp = crate::arch::x86_64::timer::uptime_ms();

        let header = BlockHeader {
            height,
            round,
            prev: parent_id,
            proposer_pk: proposer_pk.0,
            proposer_addr: proposer_addr.to_string(),
            tx_root,
            receipts_root,
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

        metrics.inc_block_built();
        debug!(
            height,
            round,
            txs = txs.len(),
            gas_used,
            successful_txs,
            "block built"
        );

        // Convert receipts to standard Receipt for compatibility.
        let std_receipts: Vec<Receipt> = receipts.iter().map(|r| Receipt {
            tx_hash: r.tx_hash,
            success: r.success,
            gas_used: r.gas_used,
            intrinsic_gas_used: r.intrinsic_gas_used,
            exec_gas_used: r.exec_gas_used,
            vm_gas_used: r.vm_gas_used,
            evm_gas_used: r.evm_gas_used,
            effective_gas_price: r.effective_gas_price,
            burned: r.burned,
            tip: r.tip,
            error: r.error.clone(),
            data: r.data.clone(),
        }).collect();

        Ok((Block { header, txs }, new_state, std_receipts))
    }

    /// Verify a block against the expected proposer public key and state.
    pub fn verify_block(
        state: &KvState,
        block: &Block,
        expected_proposer_pk: &PublicKeyBytes,
        proposer_addr: &str,
        config: &ExecutionConfig,
        metrics: &ExecutionMetrics,
    ) -> ExecutionResult<(KvState, Vec<ExecutionReceipt>)> {
        // 1. Check proposer.
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

        // 2. Chain ID.
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
                metrics,
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

        // 5. Verify tx root.
        if config.verify_tx_roots {
            let computed_tx_root = crate::root::compute_tx_root(&block.txs);
            if computed_tx_root != block.header.tx_root {
                return Err(ExecutionError::TxRootMismatch {
                    expected: hex::encode(block.header.tx_root.0),
                    actual: hex::encode(computed_tx_root.0),
                });
            }
        }

        // 6. Verify receipts root.
        let computed_receipts_root = crate::root::compute_receipts_root_from_receipts(&receipts);
        if computed_receipts_root != block.header.receipts_root {
            return Err(ExecutionError::VerificationFailed(
                format!("receipts root mismatch: expected {}, got {}",
                    hex::encode(block.header.receipts_root.0),
                    hex::encode(computed_receipts_root.0))
            ));
        }

        // 7. Verify state root.
        if config.verify_state_roots {
            let computed_root = crate::root::compute_state_root(&new_state);
            if computed_root != block.header.state_root {
                return Err(ExecutionError::StateRootMismatch {
                    expected: hex::encode(block.header.state_root.0),
                    actual: hex::encode(computed_root.0),
                });
            }
        }

        metrics.inc_block_verified();
        debug!(
            height = block.header.height,
            txs = block.txs.len(),
            gas_used,
            successful_txs,
            "block verified"
        );

        Ok((new_state, receipts))
    }
}

pub mod root {
    //! State, transaction, and receipts root computation.
    use super::types::ExecutionReceipt;
    use crate::types::{Hash32, KvState, Receipt, Tx};
    use alloc::vec::Vec;
    use alloc::collections::BTreeMap;

    /// Compute state root (deterministic Merkle root of all key‑value pairs).
    pub fn compute_state_root(state: &KvState) -> Hash32 {
        let mut data = Vec::new();
        let mut sorted: Vec<(&Vec<u8>, &Vec<u8>)> = state.kv.iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        for (k, v) in sorted {
            data.extend_from_slice(k);
            data.extend_from_slice(v);
        }
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
        data.extend_from_slice(&state.burned.to_le_bytes());

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

    /// Compute receipts root from execution receipts.
    pub fn compute_receipts_root_from_receipts(receipts: &[ExecutionReceipt]) -> Hash32 {
        let mut data = Vec::new();
        for r in receipts {
            let serialized = postcard::to_allocvec(r).unwrap_or_default();
            data.extend_from_slice(&serialized);
        }
        let hash = blake3::hash(&data);
        Hash32(hash.as_bytes().try_into().unwrap())
    }

    /// Compute receipts root from standard receipts (compatibility).
    pub fn compute_receipts_root(receipts: &[Receipt]) -> Hash32 {
        let mut data = Vec::new();
        for r in receipts {
            let serialized = postcard::to_allocvec(r).unwrap_or_default();
            data.extend_from_slice(&serialized);
        }
        let hash = blake3::hash(&data);
        Hash32(hash.as_bytes().try_into().unwrap())
    }
}

pub mod manager {
    //! Centralised manager for execution.
    use super::{
        config::ExecutionConfig,
        error::ExecutionResult,
        metrics::ExecutionMetrics,
        block::{apply_tx, build_block, verify_block},
        types::ExecutionReceipt,
    };
    use crate::types::{Block, Hash32, Height, KvState, Round, Tx};
    use crate::crypto::PublicKeyBytes;
    use core::sync::atomic::Ordering;
    use tracing::{debug, info};

    /// Manager for execution.
    pub struct ExecutionManager {
        config: ExecutionConfig,
        metrics: ExecutionMetrics,
        initialised: bool,
    }

    impl ExecutionManager {
        pub fn new(config: ExecutionConfig) -> Self {
            config.validate().expect("invalid ExecutionConfig");
            Self {
                config,
                metrics: ExecutionMetrics::default(),
                initialised: false,
            }
        }

        pub fn default() -> Self {
            Self::new(ExecutionConfig::default())
        }

        pub fn config(&self) -> &ExecutionConfig {
            &self.config
        }

        pub fn metrics(&self) -> &ExecutionMetrics {
            &self.metrics
        }

        pub fn init(&mut self) {
            self.initialised = true;
            info!("execution manager initialised");
        }

        pub fn apply_tx(
            &self,
            state: &KvState,
            tx: &Tx,
            base_fee_per_gas: u64,
            proposer_addr: &str,
        ) -> ExecutionResult<(ExecutionReceipt, KvState)> {
            block::apply_tx(state, tx, base_fee_per_gas, proposer_addr, &self.config, &self.metrics)
        }

        pub fn build_block(
            &self,
            height: Height,
            round: Round,
            parent_id: Hash32,
            proposer_pk: PublicKeyBytes,
            proposer_addr: &str,
            state: &KvState,
            base_fee: u64,
            txs: Vec<Tx>,
        ) -> ExecutionResult<(Block, KvState, Vec<ExecutionReceipt>)> {
            block::build_block(
                height, round, parent_id, proposer_pk, proposer_addr,
                state, base_fee, txs, &self.config, &self.metrics,
            )
        }

        pub fn verify_block(
            &self,
            state: &KvState,
            block: &Block,
            expected_proposer_pk: &PublicKeyBytes,
            proposer_addr: &str,
        ) -> ExecutionResult<(KvState, Vec<ExecutionReceipt>)> {
            block::verify_block(
                state, block, expected_proposer_pk, proposer_addr,
                &self.config, &self.metrics,
            )
        }

        pub fn metrics_snapshot(&self) -> super::metrics::ExecutionMetricsSnapshot {
            self.metrics.snapshot()
        }

        pub fn reset_metrics(&self) {
            *self.metrics = ExecutionMetrics::default();
        }

        pub fn is_initialised(&self) -> bool {
            self.initialised
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::ExecutionConfig;
pub use error::{ExecutionError, ExecutionResult};
pub use types::ExecutionReceipt;
pub use metrics::{ExecutionMetrics, ExecutionMetricsSnapshot};
pub use gas::{intrinsic_gas, next_base_fee, effective_prices};
pub use verify::verify_tx_signature;
pub use kv::apply_kv_payload;
pub use evm::execute_evm_payload;
pub use block::{apply_tx, build_block, verify_block};
pub use root::{compute_state_root, compute_tx_root, compute_receipts_root, compute_receipts_root_from_receipts};
pub use manager::ExecutionManager;

// Re-export constants for backward compatibility.
pub use constants::*;

// -----------------------------------------------------------------------------
// Legacy global API (backward compatibility)
// -----------------------------------------------------------------------------

use spin::Once;

static GLOBAL_MANAGER: Once<ExecutionManager> = Once::new();

/// Get the global manager (initialises with defaults if not yet set).
fn global_manager() -> &'static ExecutionManager {
    GLOBAL_MANAGER.get_or_init(|| {
        let mut mgr = ExecutionManager::new(ExecutionConfig::default());
        mgr.init();
        mgr
    })
}

/// Apply a transaction (legacy).
pub fn apply_tx_legacy(
    state: &KvState,
    tx: &Tx,
    base_fee_per_gas: u64,
    proposer_addr: &str,
) -> ExecutionResult<(ExecutionReceipt, KvState)> {
    global_manager().apply_tx(state, tx, base_fee_per_gas, proposer_addr)
}

/// Build a block (legacy).
pub fn build_block_legacy(
    height: Height,
    round: Round,
    parent_id: Hash32,
    proposer_pk: PublicKeyBytes,
    proposer_addr: &str,
    state: &KvState,
    base_fee: u64,
    txs: Vec<Tx>,
) -> ExecutionResult<(Block, KvState, Vec<ExecutionReceipt>)> {
    global_manager().build_block(
        height, round, parent_id, proposer_pk, proposer_addr,
        state, base_fee, txs,
    )
}

/// Verify a block (legacy).
pub fn verify_block_legacy(
    state: &KvState,
    block: &Block,
    expected_proposer_pk: &PublicKeyBytes,
    proposer_addr: &str,
) -> ExecutionResult<(KvState, Vec<ExecutionReceipt>)> {
    global_manager().verify_block(state, block, expected_proposer_pk, proposer_addr)
}

// -----------------------------------------------------------------------------
// Prelude
// -----------------------------------------------------------------------------

/// Convenience prelude for the execution module.
pub mod prelude {
    pub use super::{
        ExecutionConfig, ExecutionError, ExecutionResult, ExecutionReceipt,
        ExecutionManager, ExecutionMetrics,
        apply_tx, build_block, verify_block,
        intrinsic_gas, next_base_fee, effective_prices,
        compute_state_root, compute_tx_root, compute_receipts_root,
        verify_tx_signature,
    };
}

// -----------------------------------------------------------------------------
// Tests (expanded)
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
        let tx = dummy_tx("alice", 0, "set key value");
        let gas = intrinsic_gas(&tx);
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
        let (receipt, new_state) = apply_tx_legacy(&state, &tx, 10, "proposer")?;
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
        let (block, new_state, receipts) = build_block_legacy(
            1, 0, Hash32::zero(), pk, "proposer", &state, 10, vec![tx],
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
        let (block, _, _) = build_block_legacy(
            1, 0, Hash32::zero(), pk.clone(), "proposer", &state, 10, vec![tx],
        )?;
        let (new_state, receipts) = verify_block_legacy(&state, &block, &pk, "proposer")?;
        assert!(!receipts.is_empty());
        assert_eq!(new_state.kv.get(b"key".as_slice()), Some(&b"value".to_vec()));
        Ok(())
    }
}
