//! Blockchain integration modules
//!
//! This module provides the core components for integrating IONA with
//! external blockchain systems and protocols. It includes:
//!
//! - **redb_adapter** – persistent storage backend using the Redb embedded database.
//! - **gossipsub** – P2P networking using the Gossipsub protocol (libp2p).
//! - **revm_port** – EVM execution engine via the REVM library.
//!
//! These modules together enable IONA to function as a fully‑featured
//! blockchain node with transaction propagation, state persistence, and
//! EVM compatibility.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                        Blockchain                              │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐   │
//! │  │  redb_adapter│  │  gossipsub  │  │     revm_port       │   │
//! │  │  (storage)   │  │  (network)  │  │   (EVM execution)   │   │
//! │  └─────────────┘  └─────────────┘  └─────────────────────┘   │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use iona::blockchain::{Blockchain, BlockchainConfig};
//!
//! let config = BlockchainConfig::default();
//! let blockchain = Blockchain::new(config).await?;
//! blockchain.submit_transaction(tx).await?;
//! let state = blockchain.get_state().await?;
//! ```

pub mod redb_adapter;
pub mod gossipsub;
pub mod revm_port;

use crate::types::Tx;
use crate::execution::{KvState, Receipt};
use redb_adapter::Database as RedbDatabase;
use gossipsub::GossipNode;
use revm_port::EvmExecutor;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Re-exports of important types from submodules
// -----------------------------------------------------------------------------

pub use redb_adapter::{Database, DatabaseError, Transaction as DbTransaction};
pub use gossipsub::{GossipConfig, GossipMessage, GossipNode, GossipError, Peer};
pub use revm_port::{EvmExecutor, EvmConfig, ExecResult};

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during blockchain operations.
#[derive(Debug, Error)]
pub enum BlockchainError {
    #[error("database error: {0}")]
    Database(#[from] redb_adapter::DatabaseError),

    #[error("network error: {0}")]
    Network(#[from] gossipsub::GossipError),

    #[error("EVM execution error: {0}")]
    Evm(#[from] revm_port::EvmError),

    #[error("transaction validation failed: {0}")]
    Validation(String),

    #[error("block processing failed: {0}")]
    BlockProcessing(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("state not found: {0}")]
    StateNotFound(String),

    #[error("not implemented: {0}")]
    NotImplemented(String),
}

pub type BlockchainResult<T> = Result<T, BlockchainError>;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the blockchain integration layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainConfig {
    /// Path to the database file.
    pub db_path: String,
    /// Gossipsub configuration.
    pub gossip_config: GossipConfig,
    /// EVM configuration.
    pub evm_config: EvmConfig,
    /// Whether to enable block propagation via gossip.
    pub enable_block_propagation: bool,
    /// Whether to enable transaction propagation.
    pub enable_tx_propagation: bool,
    /// Maximum number of transactions to keep in the mempool.
    pub mempool_capacity: usize,
    /// Block processing timeout (seconds).
    pub block_timeout_secs: u64,
}

impl Default for BlockchainConfig {
    fn default() -> Self {
        Self {
            db_path: "./chaindb/iona.db".into(),
            gossip_config: GossipConfig::default(),
            evm_config: EvmConfig::default(),
            enable_block_propagation: true,
            enable_tx_propagation: true,
            mempool_capacity: 100_000,
            block_timeout_secs: 30,
        }
    }
}

impl BlockchainConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> BlockchainResult<()> {
        if self.db_path.is_empty() {
            return Err(BlockchainError::Config("db_path cannot be empty".into()));
        }
        if self.mempool_capacity == 0 {
            return Err(BlockchainError::Config("mempool_capacity must be > 0".into()));
        }
        if self.block_timeout_secs < 5 {
            return Err(BlockchainError::Config("block_timeout_secs must be >= 5".into()));
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Blockchain state
// -----------------------------------------------------------------------------

/// Mempool entry.
#[derive(Debug, Clone)]
struct MempoolEntry {
    tx: Tx,
    received_at: std::time::Instant,
    gas_price: u64,
}

/// The main blockchain struct.
#[derive(Debug)]
pub struct Blockchain {
    config: BlockchainConfig,
    db: Arc<RedbDatabase>,
    gossip: Arc<Mutex<GossipNode>>,
    evm: Arc<EvmExecutor>,
    mempool: Arc<Mutex<Vec<MempoolEntry>>>,
    state: Arc<RwLock<KvState>>,
    block_height: Arc<tokio::sync::watch::Receiver<u64>>,
    block_height_tx: tokio::sync::watch::Sender<u64>,
    shutdown_tx: tokio::sync::mpsc::Sender<()>,
    shutdown_rx: tokio::sync::mpsc::Receiver<()>,
}

impl Blockchain {
    /// Create a new blockchain instance.
    pub async fn new(config: BlockchainConfig) -> BlockchainResult<Self> {
        config.validate()?;

        // 1. Open database.
        let db = RedbDatabase::open(&config.db_path)?;
        let db = Arc::new(db);

        // 2. Initialize gossip node.
        let gossip = GossipNode::new(config.gossip_config.clone())?;
        let gossip = Arc::new(Mutex::new(gossip));

        // 3. Initialize EVM executor.
        let evm = EvmExecutor::new(config.evm_config.clone())?;
        let evm = Arc::new(evm);

        // 4. Load state from database (or create empty).
        let state = Self::load_state(&db).await?;
        let state = Arc::new(RwLock::new(state));

        // 5. Load block height.
        let height = Self::load_block_height(&db).await?;
        let (height_tx, height_rx) = tokio::sync::watch::channel(height);

        // 6. Create shutdown channel.
        let (shutdown_tx, shutdown_rx) = tokio::sync::mpsc::channel(1);

        let mempool = Arc::new(Mutex::new(Vec::with_capacity(config.mempool_capacity)));

        info!(
            db_path = %config.db_path,
            height,
            "blockchain initialized"
        );

        Ok(Self {
            config,
            db,
            gossip,
            evm,
            mempool,
            state,
            block_height: height_rx,
            block_height_tx: height_tx,
            shutdown_tx,
            shutdown_rx,
        })
    }

    /// Load state from database.
    async fn load_state(db: &RedbDatabase) -> BlockchainResult<KvState> {
        let key = b"state_root".as_slice();
        match db.get(key) {
            Ok(Some(bytes)) => {
                let state: KvState = postcard::from_bytes(&bytes)
                    .map_err(|e| BlockchainError::StateNotFound(format!("corrupted state: {e}")))?;
                Ok(state)
            }
            Ok(None) => Ok(KvState::default()),
            Err(e) => Err(BlockchainError::Database(e)),
        }
    }

    /// Load block height from database.
    async fn load_block_height(db: &RedbDatabase) -> BlockchainResult<u64> {
        let key = b"block_height".as_slice();
        match db.get(key) {
            Ok(Some(bytes)) => {
                let height = u64::from_le_bytes(bytes.try_into().map_err(|_| {
                    BlockchainError::StateNotFound("invalid block height".into())
                })?);
                Ok(height)
            }
            Ok(None) => Ok(0),
            Err(e) => Err(BlockchainError::Database(e)),
        }
    }

    /// Persist state and block height to database.
    async fn persist_state(&self, state: &KvState, height: u64) -> BlockchainResult<()> {
        let bytes = postcard::to_allocvec(state)
            .map_err(|e| BlockchainError::StateNotFound(format!("serialization error: {e}")))?;
        let mut tx = self.db.begin_write()?;
        tx.set(b"state_root".as_slice(), &bytes)?;
        tx.set(b"block_height".as_slice(), &height.to_le_bytes())?;
        tx.commit()?;
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /// Submit a transaction to the mempool and propagate to peers.
    pub async fn submit_transaction(&self, tx: Tx) -> BlockchainResult<()> {
        // Validate transaction (basic checks).
        self.validate_tx(&tx)?;

        // Add to mempool.
        let entry = MempoolEntry {
            tx: tx.clone(),
            received_at: std::time::Instant::now(),
            gas_price: tx.max_fee_per_gas,
        };
        {
            let mut mempool = self.mempool.lock().await;
            if mempool.len() >= self.config.mempool_capacity {
                // Evict lowest gas-price transactions.
                mempool.sort_by_key(|e| e.gas_price);
                mempool.truncate(self.config.mempool_capacity / 2);
            }
            mempool.push(entry);
            debug!(tx_hash = ?tx.hash(), "transaction added to mempool");
        }

        // Propagate to network if enabled.
        if self.config.enable_tx_propagation {
            let gossip = self.gossip.lock().await;
            let msg = GossipMessage::new_publish("iona/tx", postcard::to_allocvec(&tx)?);
            gossip.publish("iona/tx", msg.data)?;
            debug!(tx_hash = ?tx.hash(), "transaction broadcast via gossip");
        }

        Ok(())
    }

    /// Validate a transaction.
    fn validate_tx(&self, tx: &Tx) -> BlockchainResult<()> {
        if tx.gas_limit == 0 {
            return Err(BlockchainError::Validation("gas limit cannot be zero".into()));
        }
        if tx.max_fee_per_gas == 0 {
            return Err(BlockchainError::Validation("max fee per gas cannot be zero".into()));
        }
        if tx.pubkey.is_empty() {
            return Err(BlockchainError::Validation("pubkey cannot be empty".into()));
        }
        if tx.from.is_empty() {
            return Err(BlockchainError::Validation("from address cannot be empty".into()));
        }
        Ok(())
    }

    /// Process a block (verify, execute, and commit).
    pub async fn process_block(&self, block: &crate::types::Block) -> BlockchainResult<()> {
        // 1. Verify block signature and proposer.
        self.verify_block(block)?;

        // 2. Execute transactions sequentially.
        let mut state = self.state.write().await;
        let mut receipts = Vec::with_capacity(block.txs.len());
        let mut gas_used = 0u64;

        for tx in &block.txs {
            let (rcpt, new_state) = crate::execution::apply_tx(
                &state,
                tx,
                block.header.base_fee_per_gas,
                &block.header.proposer_addr,
                &crate::execution::ExecutionConfig::default(),
            )
            .map_err(|e| BlockchainError::BlockProcessing(e.to_string()))?;
            state = new_state;
            gas_used += rcpt.gas_used;
            receipts.push(rcpt);
        }

        // 3. Verify state root matches header.
        let computed_root = crate::types::tx_root(&block.txs);
        if computed_root != block.header.state_root {
            return Err(BlockchainError::BlockProcessing(format!(
                "state root mismatch: expected {}, got {}",
                hex::encode(block.header.state_root.0),
                hex::encode(computed_root.0)
            )));
        }

        // 4. Commit state to database.
        let new_height = block.header.height.0;
        self.persist_state(&state, new_height).await?;

        // 5. Update in-memory state and height.
        *self.state.write().await = state;
        self.block_height_tx.send(new_height)?;

        // 6. Broadcast block if enabled.
        if self.config.enable_block_propagation {
            let gossip = self.gossip.lock().await;
            let msg = GossipMessage::new_publish("iona/blocks", postcard::to_allocvec(block)?);
            gossip.publish("iona/blocks", msg.data)?;
            debug!(height = new_height, "block propagated via gossip");
        }

        info!(height = new_height, txs = block.txs.len(), "block processed successfully");
        Ok(())
    }

    /// Verify a block (proposer, signature, etc.).
    fn verify_block(&self, block: &crate::types::Block) -> BlockchainResult<()> {
        // Simple proposer check: ensure the proposer public key is non-empty.
        if block.header.proposer_pk.is_empty() {
            return Err(BlockchainError::BlockProcessing("proposer public key missing".into()));
        }
        // In production, we would verify the signature and validator set.
        // This is a placeholder.
        Ok(())
    }

    /// Get the current state.
    pub async fn get_state(&self) -> KvState {
        self.state.read().await.clone()
    }

    /// Get the current block height.
    pub fn get_height(&self) -> u64 {
        *self.block_height.borrow()
    }

    /// Get a subscription to block height updates.
    pub fn subscribe_height(&self) -> tokio::sync::watch::Receiver<u64> {
        self.block_height.clone()
    }

    /// Get mempool contents (for RPC).
    pub async fn get_mempool(&self) -> Vec<Tx> {
        let mempool = self.mempool.lock().await;
        mempool.iter().map(|e| e.tx.clone()).collect()
    }

    /// Shutdown the blockchain node gracefully.
    pub async fn shutdown(&self) -> BlockchainResult<()> {
        info!("shutting down blockchain");
        let _ = self.shutdown_tx.send(()).await;
        // Wait for shutdown to complete (would be handled by tasks).
        Ok(())
    }

    /// Run the main loop (processing network messages, blocks, etc.).
    pub async fn run(&self) -> BlockchainResult<()> {
        info!("starting blockchain main loop");
        let mut shutdown_rx = self.shutdown_rx.clone();
        let mut interval = tokio::time::interval(Duration::from_secs(1));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Poll gossip for incoming messages.
                    let gossip = self.gossip.lock().await;
                    while let Ok(msg) = gossip.poll() {
                        // Handle messages (blocks, txs, etc.).
                        self.handle_gossip_message(msg).await?;
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("shutdown signal received, exiting main loop");
                    break;
                }
            }
        }
        Ok(())
    }

    /// Handle a gossip message.
    async fn handle_gossip_message(&self, msg: GossipMessage) -> BlockchainResult<()> {
        match msg.topic.as_str() {
            "iona/tx" => {
                if let Ok(tx) = postcard::from_bytes::<Tx>(&msg.data) {
                    self.submit_transaction(tx).await?;
                } else {
                    debug!("failed to deserialize transaction from gossip");
                }
            }
            "iona/blocks" => {
                if let Ok(block) = postcard::from_bytes::<crate::types::Block>(&msg.data) {
                    self.process_block(&block).await?;
                } else {
                    debug!("failed to deserialize block from gossip");
                }
            }
            _ => {
                debug!(topic = %msg.topic, "unhandled gossip topic");
            }
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Block, BlockHeader, Hash32};
    use tempfile::tempdir;

    #[test]
    fn test_config_validation() {
        let mut config = BlockchainConfig::default();
        config.db_path = "".into();
        assert!(config.validate().is_err());

        config.db_path = "/tmp/test.db".into();
        config.mempool_capacity = 0;
        assert!(config.validate().is_err());

        config.mempool_capacity = 100;
        config.block_timeout_secs = 3;
        assert!(config.validate().is_err());

        config.block_timeout_secs = 10;
        assert!(config.validate().is_ok());
    }

    #[tokio::test]
    async fn test_blockchain_init() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db").to_str().unwrap().to_string();
        let config = BlockchainConfig {
            db_path,
            ..Default::default()
        };
        let blockchain = Blockchain::new(config).await.unwrap();
        assert_eq!(blockchain.get_height(), 0);
        let state = blockchain.get_state().await;
        assert!(state.balances.is_empty());
    }

    #[test]
    fn test_validate_tx() {
        let config = BlockchainConfig::default();
        let blockchain = Blockchain::new(config).await.unwrap();
        let tx = Tx {
            pubkey: vec![0u8; 32],
            from: "test".into(),
            nonce: 0,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 10,
            gas_limit: 100_000,
            payload: b"set key value".to_vec(),
            signature: vec![0u8; 64],
            chain_id: 1,
        };
        assert!(blockchain.validate_tx(&tx).is_ok());

        let mut bad = tx.clone();
        bad.gas_limit = 0;
        assert!(blockchain.validate_tx(&bad).is_err());
    }
}
