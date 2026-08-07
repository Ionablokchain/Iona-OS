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

#![allow(dead_code)]

pub mod redb_adapter;
pub mod gossipsub;
pub mod revm_port;

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for the blockchain integration layer.
    use super::gossipsub::GossipConfig;
    use super::revm_port::EvmConfig;
    use serde::{Deserialize, Serialize};

    /// Configuration for the blockchain integration layer.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct BlockchainConfig {
        pub db_path: String,
        pub gossip_config: GossipConfig,
        pub evm_config: EvmConfig,
        pub enable_block_propagation: bool,
        pub enable_tx_propagation: bool,
        pub mempool_capacity: usize,
        pub block_timeout_secs: u64,
        pub collect_metrics: bool,
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
                collect_metrics: true,
            }
        }
    }

    impl BlockchainConfig {
        pub fn validate(&self) -> Result<(), String> {
            if self.db_path.is_empty() {
                return Err("db_path cannot be empty".into());
            }
            if self.mempool_capacity == 0 {
                return Err("mempool_capacity must be > 0".into());
            }
            if self.block_timeout_secs < 5 {
                return Err("block_timeout_secs must be >= 5".into());
            }
            Ok(())
        }
    }
}

pub mod error {
    //! Error types for blockchain operations.
    use super::redb_adapter::DatabaseError;
    use super::gossipsub::GossipError;
    use super::revm_port::EvmError;
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum BlockchainError {
        #[error("database error: {0}")]
        Database(#[from] DatabaseError),

        #[error("network error: {0}")]
        Network(#[from] GossipError),

        #[error("EVM execution error: {0}")]
        Evm(#[from] EvmError),

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

        #[error("send error: {0}")]
        Send(#[from] tokio::sync::watch::error::SendError<u64>),

        #[error("postcard serialization error: {0}")]
        Serialization(#[from] postcard::Error),
    }

    pub type BlockchainResult<T> = Result<T, BlockchainError>;
}

pub mod state {
    //! State management for the blockchain.
    use super::error::BlockchainResult;
    use super::redb_adapter::Database;
    use crate::execution::KvState;
    use tracing::debug;

    /// Load state from database.
    pub async fn load_state(db: &Database) -> BlockchainResult<KvState> {
        let key = b"state_root".as_slice();
        match db.get(key) {
            Ok(Some(bytes)) => {
                let state: KvState = postcard::from_bytes(&bytes)
                    .map_err(|e| super::error::BlockchainError::StateNotFound(format!("corrupted state: {e}")))?;
                Ok(state)
            }
            Ok(None) => Ok(KvState::default()),
            Err(e) => Err(super::error::BlockchainError::Database(e)),
        }
    }

    /// Load block height from database.
    pub async fn load_block_height(db: &Database) -> BlockchainResult<u64> {
        let key = b"block_height".as_slice();
        match db.get(key) {
            Ok(Some(bytes)) => {
                let height = u64::from_le_bytes(bytes.try_into().map_err(|_| {
                    super::error::BlockchainError::StateNotFound("invalid block height".into())
                })?);
                Ok(height)
            }
            Ok(None) => Ok(0),
            Err(e) => Err(super::error::BlockchainError::Database(e)),
        }
    }

    /// Persist state and block height to database.
    pub async fn persist_state(db: &Database, state: &KvState, height: u64) -> BlockchainResult<()> {
        let bytes = postcard::to_allocvec(state)
            .map_err(|e| super::error::BlockchainError::StateNotFound(format!("serialization error: {e}")))?;
        let mut tx = db.begin_write()?;
        tx.set(b"state_root".as_slice(), &bytes)?;
        tx.set(b"block_height".as_slice(), &height.to_le_bytes())?;
        tx.commit()?;
        debug!(height, "state persisted");
        Ok(())
    }
}

pub mod mempool {
    //! Mempool for pending transactions.
    use super::error::BlockchainResult;
    use crate::types::Tx;
    use std::time::Instant;

    /// Mempool entry.
    #[derive(Debug, Clone)]
    pub struct MempoolEntry {
        pub tx: Tx,
        pub received_at: Instant,
        pub gas_price: u64,
    }

    /// Simple mempool with capacity and eviction.
    #[derive(Debug)]
    pub struct Mempool {
        inner: Vec<MempoolEntry>,
        capacity: usize,
    }

    impl Mempool {
        pub fn new(capacity: usize) -> Self {
            Self {
                inner: Vec::with_capacity(capacity),
                capacity,
            }
        }

        /// Add a transaction, evicting low‑gas entries if full.
        pub fn push(&mut self, entry: MempoolEntry) {
            if self.inner.len() >= self.capacity {
                // Evict lowest gas-price transactions.
                self.inner.sort_by_key(|e| e.gas_price);
                self.inner.truncate(self.capacity / 2);
            }
            self.inner.push(entry);
        }

        /// Get all transactions (for RPC).
        pub fn all(&self) -> Vec<Tx> {
            self.inner.iter().map(|e| e.tx.clone()).collect()
        }

        /// Get the number of pending transactions.
        pub fn len(&self) -> usize {
            self.inner.len()
        }

        /// Check if the mempool is empty.
        pub fn is_empty(&self) -> bool {
            self.inner.is_empty()
        }

        /// Clear the mempool (e.g., after a block is committed).
        pub fn clear(&mut self) {
            self.inner.clear();
        }
    }
}

pub mod metrics {
    //! Metrics for the blockchain.
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Debug, Default)]
    pub struct BlockchainMetrics {
        pub blocks_processed: AtomicU64,
        pub txs_submitted: AtomicU64,
        pub txs_dropped: AtomicU64,
        pub state_commits: AtomicU64,
        pub blocks_broadcast: AtomicU64,
        pub txs_broadcast: AtomicU64,
        pub height: AtomicU64,
        pub mempool_size: AtomicU64,
    }

    impl BlockchainMetrics {
        pub fn inc_blocks_processed(&self) {
            self.blocks_processed.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_txs_submitted(&self) {
            self.txs_submitted.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_txs_dropped(&self) {
            self.txs_dropped.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_state_commits(&self) {
            self.state_commits.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_blocks_broadcast(&self) {
            self.blocks_broadcast.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_txs_broadcast(&self) {
            self.txs_broadcast.fetch_add(1, Ordering::Relaxed);
        }
        pub fn set_height(&self, h: u64) {
            self.height.store(h, Ordering::Relaxed);
        }
        pub fn set_mempool_size(&self, size: usize) {
            self.mempool_size.store(size as u64, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> BlockchainMetricsSnapshot {
            BlockchainMetricsSnapshot {
                blocks_processed: self.blocks_processed.load(Ordering::Relaxed),
                txs_submitted: self.txs_submitted.load(Ordering::Relaxed),
                txs_dropped: self.txs_dropped.load(Ordering::Relaxed),
                state_commits: self.state_commits.load(Ordering::Relaxed),
                blocks_broadcast: self.blocks_broadcast.load(Ordering::Relaxed),
                txs_broadcast: self.txs_broadcast.load(Ordering::Relaxed),
                height: self.height.load(Ordering::Relaxed),
                mempool_size: self.mempool_size.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct BlockchainMetricsSnapshot {
        pub blocks_processed: u64,
        pub txs_submitted: u64,
        pub txs_dropped: u64,
        pub state_commits: u64,
        pub blocks_broadcast: u64,
        pub txs_broadcast: u64,
        pub height: u64,
        pub mempool_size: u64,
    }
}

pub mod blockchain {
    //! The main blockchain struct.
    use super::{
        config::BlockchainConfig,
        error::{BlockchainError, BlockchainResult},
        state::{load_state, load_block_height, persist_state},
        mempool::{Mempool, MempoolEntry},
        metrics::BlockchainMetrics,
        redb_adapter::Database,
        gossipsub::{GossipNode, GossipMessage},
        revm_port::EvmExecutor,
    };
    use crate::types::{Block, Tx, BlockHeader, Hash32};
    use crate::execution::{apply_tx, ExecutionConfig, KvState};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::{Mutex, RwLock, watch, mpsc};
    use tracing::{debug, error, info, warn};

    /// The main blockchain struct.
    pub struct Blockchain {
        config: BlockchainConfig,
        db: Arc<Database>,
        gossip: Arc<Mutex<GossipNode>>,
        evm: Arc<EvmExecutor>,
        mempool: Arc<Mutex<Mempool>>,
        state: Arc<RwLock<KvState>>,
        height_rx: watch::Receiver<u64>,
        height_tx: watch::Sender<u64>,
        shutdown_tx: mpsc::Sender<()>,
        shutdown_rx: mpsc::Receiver<()>,
        metrics: Arc<BlockchainMetrics>,
    }

    impl Blockchain {
        /// Create a new blockchain instance.
        pub async fn new(config: BlockchainConfig) -> BlockchainResult<Self> {
            config.validate().map_err(|e| BlockchainError::Config(e))?;

            // 1. Open database.
            let db = Database::open(&config.db_path)?;
            let db = Arc::new(db);

            // 2. Initialize gossip node.
            let gossip = GossipNode::new(config.gossip_config.clone())?;
            let gossip = Arc::new(Mutex::new(gossip));

            // 3. Initialize EVM executor.
            let evm = EvmExecutor::new(config.evm_config.clone())?;
            let evm = Arc::new(evm);

            // 4. Load state from database.
            let state = load_state(&db).await?;
            let state = Arc::new(RwLock::new(state));

            // 5. Load block height.
            let height = load_block_height(&db).await?;
            let (height_tx, height_rx) = watch::channel(height);

            // 6. Create shutdown channel.
            let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

            let mempool = Arc::new(Mutex::new(Mempool::new(config.mempool_capacity)));
            let metrics = Arc::new(BlockchainMetrics::default());

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
                height_rx,
                height_tx,
                shutdown_tx,
                shutdown_rx,
                metrics,
            })
        }

        // -------------------------------------------------------------------------
        // Public API
        // -------------------------------------------------------------------------

        /// Submit a transaction to the mempool and propagate to peers.
        pub async fn submit_transaction(&self, tx: Tx) -> BlockchainResult<()> {
            self.validate_tx(&tx)?;

            let entry = MempoolEntry {
                tx: tx.clone(),
                received_at: std::time::Instant::now(),
                gas_price: tx.max_fee_per_gas,
            };
            {
                let mut mempool = self.mempool.lock().await;
                mempool.push(entry);
                self.metrics.set_mempool_size(mempool.len());
                self.metrics.inc_txs_submitted();
                debug!(tx_hash = ?tx.hash(), "transaction added to mempool");
            }

            if self.config.enable_tx_propagation {
                let gossip = self.gossip.lock().await;
                let msg = GossipMessage::new_publish("iona/tx", postcard::to_allocvec(&tx)?);
                gossip.publish("iona/tx", msg.data)?;
                self.metrics.inc_txs_broadcast();
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
        pub async fn process_block(&self, block: &Block) -> BlockchainResult<()> {
            self.verify_block(block)?;

            let mut state = self.state.write().await;
            let mut receipts = Vec::with_capacity(block.txs.len());
            let mut gas_used = 0u64;

            for tx in &block.txs {
                let (rcpt, new_state) = apply_tx(
                    &state,
                    tx,
                    block.header.base_fee_per_gas,
                    &block.header.proposer_addr,
                    &ExecutionConfig::default(),
                )
                .map_err(|e| BlockchainError::BlockProcessing(e.to_string()))?;
                state = new_state;
                gas_used += rcpt.gas_used;
                receipts.push(rcpt);
            }

            let computed_root = crate::types::tx_root(&block.txs);
            if computed_root != block.header.state_root {
                return Err(BlockchainError::BlockProcessing(format!(
                    "state root mismatch: expected {}, got {}",
                    hex::encode(block.header.state_root.0),
                    hex::encode(computed_root.0)
                )));
            }

            let new_height = block.header.height.0;
            persist_state(&self.db, &state, new_height).await?;
            self.metrics.inc_state_commits();

            // Update in-memory state and height.
            *self.state.write().await = state;
            self.height_tx.send(new_height)?;
            self.metrics.set_height(new_height);
            self.metrics.inc_blocks_processed();

            // Clear mempool (transactions included in block).
            {
                let mut mempool = self.mempool.lock().await;
                // Remove all txs that are in the block (simple: clear all).
                mempool.clear();
                self.metrics.set_mempool_size(0);
            }

            if self.config.enable_block_propagation {
                let gossip = self.gossip.lock().await;
                let msg = GossipMessage::new_publish("iona/blocks", postcard::to_allocvec(block)?);
                gossip.publish("iona/blocks", msg.data)?;
                self.metrics.inc_blocks_broadcast();
                debug!(height = new_height, "block propagated via gossip");
            }

            info!(height = new_height, txs = block.txs.len(), "block processed successfully");
            Ok(())
        }

        /// Verify a block (proposer, signature, etc.).
        fn verify_block(&self, block: &Block) -> BlockchainResult<()> {
            if block.header.proposer_pk.is_empty() {
                return Err(BlockchainError::BlockProcessing("proposer public key missing".into()));
            }
            // Placeholder: would verify signature and validator set.
            Ok(())
        }

        /// Get the current state.
        pub async fn get_state(&self) -> KvState {
            self.state.read().await.clone()
        }

        /// Get the current block height.
        pub fn get_height(&self) -> u64 {
            *self.height_rx.borrow()
        }

        /// Get a subscription to block height updates.
        pub fn subscribe_height(&self) -> watch::Receiver<u64> {
            self.height_rx.clone()
        }

        /// Get mempool contents (for RPC).
        pub async fn get_mempool(&self) -> Vec<Tx> {
            let mempool = self.mempool.lock().await;
            mempool.all()
        }

        /// Get metrics snapshot.
        pub fn metrics_snapshot(&self) -> super::metrics::BlockchainMetricsSnapshot {
            self.metrics.snapshot()
        }

        /// Shutdown the blockchain node gracefully.
        pub async fn shutdown(&self) -> BlockchainResult<()> {
            info!("shutting down blockchain");
            let _ = self.shutdown_tx.send(()).await;
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
                        let gossip = self.gossip.lock().await;
                        while let Ok(msg) = gossip.poll() {
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
                    if let Ok(block) = postcard::from_bytes::<Block>(&msg.data) {
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
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::BlockchainConfig;
pub use error::{BlockchainError, BlockchainResult};
pub use blockchain::Blockchain;
pub use metrics::{BlockchainMetrics, BlockchainMetricsSnapshot};

// Re-export submodules' important types for convenience.
pub use redb_adapter::{Database, DatabaseError, Transaction as DbTransaction};
pub use gossipsub::{GossipConfig, GossipMessage, GossipNode, GossipError, Peer};
pub use revm_port::{EvmExecutor, EvmConfig, ExecResult};

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
        assert!(blockchain.mempool.lock().await.is_empty());
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

    #[tokio::test]
    async fn test_block_processing() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db").to_str().unwrap().to_string();
        let config = BlockchainConfig {
            db_path,
            enable_block_propagation: false,
            ..Default::default()
        };
        let blockchain = Blockchain::new(config).await.unwrap();

        // Create a dummy block.
        let block = Block {
            header: BlockHeader {
                height: 1,
                round: 0,
                prev: Hash32::zero(),
                proposer_pk: vec![0u8; 32],
                tx_root: Hash32::zero(),
                receipts_root: Hash32::zero(),
                state_root: Hash32::zero(),
                base_fee_per_gas: 1,
                gas_used: 0,
                intrinsic_gas_used: 0,
                exec_gas_used: 0,
                vm_gas_used: 0,
                evm_gas_used: 0,
                chain_id: 1,
                timestamp: 1000,
                protocol_version: 1,
                proposer_addr: "proposer".into(),
            },
            txs: vec![],
            receipts: vec![],
            validator_sig: vec![0u8; 32],
            commit_sig: vec![0u8; 32],
        };
        let result = blockchain.process_block(&block).await;
        assert!(result.is_ok());
        assert_eq!(blockchain.get_height(), 1);
    }
}
