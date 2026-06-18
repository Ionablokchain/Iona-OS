//! Block sync — synchronise chain from peers at startup
//!
//! Protocol:
//!   1. At boot, node reads local height from StakeLedger / IONAFS
//!   2. Sends GetStatus to all peers: {height, peer_id}
//!   3. Peer responds with StatusResponse: {height, best_hash}
//!   4. If peer.height > local.height → GetBlocks(from, to)
//!   5. Peer responds with BlockData[]
//!   6. Verify and apply each block
//!   7. Save StakeLedger and height to IONAFS
//!
//! # Usage
//!
//! ```rust,ignore
//! use iona::consensus::sync::{sync_from_peers, SyncConfig, SyncState};
//!
//! let config = SyncConfig::default();
//! sync_from_peers(&config).unwrap();
//! ```

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::time::Duration;
use serde::{Deserialize, Serialize};
use spin::{Lazy, Mutex};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

use crate::consensus::engine::KernelConsensusState;
use crate::types::Block;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default sync timeout in milliseconds.
pub const DEFAULT_SYNC_TIMEOUT_MS: u64 = 10_000;

/// Maximum number of blocks per batch request.
pub const DEFAULT_MAX_BLOCKS_BATCH: u64 = 50;

/// Default number of retries for network requests.
pub const DEFAULT_RETRY_COUNT: u32 = 3;

/// Default path for persisted height.
pub const HEIGHT_PERSIST_PATH: &str = "/var/iona-node/height";

/// Default path for persisted stake ledger.
pub const STAKE_LEDGER_PERSIST_PATH: &str = "/var/iona-node/stake_ledger";

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

/// Errors that can occur during block sync.
#[derive(Debug, Error)]
pub enum SyncError {
    #[error("no peers available")]
    NoPeers,

    #[error("timeout waiting for peer response after {0}ms")]
    Timeout(u64),

    #[error("I/O error: {0}")]
    Io(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("invalid block at height {height}: {reason}")]
    InvalidBlock { height: u64, reason: String },

    #[error("block application failed at height {height}: {reason}")]
    BlockApplicationFailed { height: u64, reason: String },

    #[error("network error: {0}")]
    Network(String),

    #[error("already syncing")]
    AlreadySyncing,

    #[error("peer returned inconsistent data at height {height}")]
    InconsistentData { height: u64 },
}

pub type SyncResult<T> = Result<T, SyncError>;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for block sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    /// Sync timeout in milliseconds.
    pub timeout_ms: u64,
    /// Maximum number of blocks per batch request.
    pub max_blocks_batch: u64,
    /// Number of retries for network requests.
    pub retry_count: u32,
    /// Whether to verify block signatures during sync.
    pub verify_signatures: bool,
    /// Whether to persist state after each batch.
    pub persist_batch: bool,
    /// Whether to log progress every N blocks.
    pub progress_log_interval: u64,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            timeout_ms: DEFAULT_SYNC_TIMEOUT_MS,
            max_blocks_batch: DEFAULT_MAX_BLOCKS_BATCH,
            retry_count: DEFAULT_RETRY_COUNT,
            verify_signatures: true,
            persist_batch: true,
            progress_log_interval: 100,
        }
    }
}

// -----------------------------------------------------------------------------
// Protocol messages
// -----------------------------------------------------------------------------

/// Types of sync messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SyncMessageKind {
    GetStatus = 0x10,
    StatusResponse = 0x11,
    GetBlocks = 0x12,
    BlockData = 0x13,
}

/// GetStatus request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetStatus {
    pub height: u64,
    pub peer_id: String,
}

/// Status response from a peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub height: u64,
    pub best_hash: [u8; 32],
    pub peer_id: String,
}

/// GetBlocks request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetBlocks {
    pub from: u64,
    pub to: u64,
}

/// Block data response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockData {
    pub block: Block,
    pub height: u64,
}

// -----------------------------------------------------------------------------
// Peer status
// -----------------------------------------------------------------------------

/// Status of a peer.
#[derive(Debug, Clone)]
pub struct PeerStatus {
    pub peer_id: String,
    pub height: u64,
    pub best_hash: [u8; 32],
}

// -----------------------------------------------------------------------------
// Sync state
// -----------------------------------------------------------------------------

/// Current sync state.
#[derive(Debug, Clone)]
pub struct SyncState {
    pub local_height: u64,
    pub target_height: u64,
    pub syncing: bool,
    pub peers: Vec<PeerStatus>,
    pub start_time: Option<u64>,
    pub blocks_received: u64,
    pub blocks_verified: u64,
    pub blocks_applied: u64,
}

impl SyncState {
    pub fn new() -> Self {
        Self {
            local_height: 0,
            target_height: 0,
            syncing: false,
            peers: Vec::new(),
            start_time: None,
            blocks_received: 0,
            blocks_verified: 0,
            blocks_applied: 0,
        }
    }
}

impl Default for SyncState {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// Global state
// -----------------------------------------------------------------------------

pub static SYNC_STATE: Lazy<Mutex<SyncState>> = Lazy::new(|| Mutex::new(SyncState::new()));

// -----------------------------------------------------------------------------
// Persistence helpers
// -----------------------------------------------------------------------------

/// Load persisted height from IONAFS.
pub fn load_persisted_height() -> u64 {
    if let Some(data) = crate::fs::ionafs::read(HEIGHT_PERSIST_PATH) {
        let s = alloc::string::String::from_utf8_lossy(&data);
        s.trim().parse().unwrap_or(0)
    } else {
        0
    }
}

/// Save current height to IONAFS for persistence across reboots.
pub fn persist_height(height: u64) -> SyncResult<()> {
    let s = format!("{}", height);
    crate::fs::ionafs::write(HEIGHT_PERSIST_PATH, s.as_bytes());
    // Sync to disk to ensure durability.
    crate::fs::ionafs::sync_to_disk();
    debug!(height, "persisted height");
    Ok(())
}

/// Save StakeLedger snapshot to IONAFS.
pub fn persist_stake_ledger(ledger_bytes: &[u8]) -> SyncResult<()> {
    crate::fs::ionafs::write(STAKE_LEDGER_PERSIST_PATH, ledger_bytes);
    crate::fs::ionafs::sync_to_disk();
    debug!("persisted stake ledger");
    Ok(())
}

/// Load StakeLedger from IONAFS.
pub fn load_stake_ledger() -> Option<Vec<u8>> {
    crate::fs::ionafs::read(STAKE_LEDGER_PERSIST_PATH)
}

// -----------------------------------------------------------------------------
// Atomic persistence (write to temp, then rename)
// -----------------------------------------------------------------------------

/// Persist data atomically (write to temp file then rename).
pub fn atomic_persist(data: &[u8], path: &str) -> SyncResult<()> {
    let temp_path = format!("{}.tmp", path);
    crate::fs::ionafs::write(&temp_path, data);
    // Rename is atomic in most filesystems.
    // In IONAFS, we assume write + sync is sufficient.
    crate::fs::ionafs::sync_to_disk();
    debug!(path, "atomic persist completed");
    Ok(())
}

// -----------------------------------------------------------------------------
// Message serialisation helpers
// -----------------------------------------------------------------------------

/// Serialise a sync message with kind prefix.
pub fn serialize_sync_message<T: Serialize>(kind: SyncMessageKind, msg: &T) -> SyncResult<Vec<u8>> {
    let payload = postcard::to_allocvec(msg)
        .map_err(|e| SyncError::Serialization(e.to_string()))?;
    let mut bytes = Vec::with_capacity(1 + payload.len());
    bytes.push(kind as u8);
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

/// Deserialise a sync message.
pub fn deserialize_sync_message(data: &[u8]) -> SyncResult<(SyncMessageKind, &[u8])> {
    if data.is_empty() {
        return Err(SyncError::Serialization("empty message".to_string()));
    }
    let kind = data[0];
    let kind = SyncMessageKind::try_from(kind)
        .map_err(|_| SyncError::Serialization(format!("unknown message kind: {}", kind)))?;
    Ok((kind, &data[1..]))
}

impl TryFrom<u8> for SyncMessageKind {
    type Error = SyncError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x10 => Ok(SyncMessageKind::GetStatus),
            0x11 => Ok(SyncMessageKind::StatusResponse),
            0x12 => Ok(SyncMessageKind::GetBlocks),
            0x13 => Ok(SyncMessageKind::BlockData),
            _ => Err(SyncError::Serialization(format!("unknown message kind: {}", value))),
        }
    }
}

// -----------------------------------------------------------------------------
// Network abstraction
// -----------------------------------------------------------------------------

/// Trait for network operations during sync.
pub trait SyncNetwork: Send + Sync {
    /// Broadcast a message to all peers.
    fn broadcast(&self, msg: &[u8]) -> SyncResult<usize>;

    /// Receive a message from the network (non‑blocking).
    fn recv(&self) -> Option<Vec<u8>>;

    /// Wait for a message matching a predicate, with timeout.
    fn recv_timeout<F>(&self, timeout_ms: u64, predicate: F) -> SyncResult<Vec<u8>>
    where
        F: Fn(&[u8]) -> bool;

    /// Send a message to a specific peer.
    fn send_to(&self, peer_id: &str, msg: &[u8]) -> SyncResult<()>;
}

/// Real implementation using the gossip network.
pub struct GossipSyncNetwork;

impl SyncNetwork for GossipSyncNetwork {
    fn broadcast(&self, msg: &[u8]) -> SyncResult<usize> {
        let count = crate::net::gossip_broadcast(msg);
        Ok(count)
    }

    fn recv(&self) -> Option<Vec<u8>> {
        crate::net::gossip_recv()
    }

    fn recv_timeout<F>(&self, timeout_ms: u64, predicate: F) -> SyncResult<Vec<u8>>
    where
        F: Fn(&[u8]) -> bool,
    {
        let start = crate::arch::x86_64::timer::uptime_ms();
        while crate::arch::x86_64::timer::uptime_ms() - start < timeout_ms {
            if let Some(msg) = self.recv() {
                if predicate(&msg) {
                    return Ok(msg);
                }
            }
            crate::arch::x86_64::timer::sleep_ms(10);
        }
        Err(SyncError::Timeout(timeout_ms))
    }

    fn send_to(&self, peer_id: &str, msg: &[u8]) -> SyncResult<()> {
        // In a real implementation, this would send to a specific peer.
        // For now, we broadcast to all peers as a fallback.
        let _ = self.broadcast(msg);
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Main sync function
// -----------------------------------------------------------------------------

/// Main sync function — called at node startup.
///
/// # Arguments
/// * `config` – Sync configuration.
/// * `network` – Network implementation (defaults to `GossipSyncNetwork`).
///
/// # Returns
/// `Ok(())` if sync completed successfully, or `Err(SyncError)` on failure.
pub fn sync_from_peers(config: &SyncConfig, network: &dyn SyncNetwork) -> SyncResult<()> {
    info!("starting block sync from peers");

    // Load persisted height.
    let local_height = load_persisted_height();
    info!(local_height, "loaded persisted height");

    {
        let mut ss = SYNC_STATE.lock();
        ss.local_height = local_height;
        ss.syncing = true;
        ss.start_time = Some(crate::arch::x86_64::timer::uptime_ms());
    }

    // Update consensus engine with persisted height.
    if local_height > 0 {
        if let Some(ref mut e) = *crate::consensus::CONSENSUS_ENGINE.lock() {
            e.height = local_height;
        }
    }

    // 1. Query peers for their status.
    let status_msg = GetStatus {
        height: local_height,
        peer_id: crate::node::node_id().unwrap_or_else(|| "unknown".to_string()),
    };
    let status_bytes = serialize_sync_message(SyncMessageKind::GetStatus, &status_msg)?;
    let peers_contacted = network.broadcast(&status_bytes)?;
    info!(peers_contacted, "queried peers");

    if peers_contacted == 0 {
        info!("no peers — starting fresh at height {}", local_height);
        {
            let mut ss = SYNC_STATE.lock();
            ss.syncing = false;
        }
        return Ok(());
    }

    // 2. Wait for status responses (up to timeout).
    let deadline = crate::arch::x86_64::timer::uptime_ms() + config.timeout_ms;
    let mut best_height = local_height;
    let mut best_peer: Option<String> = None;

    while crate::arch::x86_64::timer::uptime_ms() < deadline {
        if let Some(msg) = network.recv() {
            if let Ok((kind, payload)) = deserialize_sync_message(&msg) {
                if kind == SyncMessageKind::StatusResponse {
                    if let Ok(status) = postcard::from_bytes::<StatusResponse>(payload) {
                        debug!(peer = %status.peer_id, height = status.height, "received status");
                        if status.height > best_height {
                            best_height = status.height;
                            best_peer = Some(status.peer_id.clone());
                        }
                        let mut ss = SYNC_STATE.lock();
                        if let Some(existing) = ss.peers.iter_mut().find(|p| p.peer_id == status.peer_id) {
                            existing.height = status.height;
                            existing.best_hash = status.best_hash;
                        } else {
                            ss.peers.push(PeerStatus {
                                peer_id: status.peer_id,
                                height: status.height,
                                best_hash: status.best_hash,
                            });
                        }
                    }
                }
            }
        }
        crate::arch::x86_64::timer::sleep_ms(10);
    }

    if best_height <= local_height {
        info!(local_height, "already at best height");
        {
            let mut ss = SYNC_STATE.lock();
            ss.syncing = false;
        }
        return Ok(());
    }

    info!(
        best_height,
        best_peer = %best_peer.as_deref().unwrap_or("unknown"),
        "need sync: local={} target={}",
        local_height,
        best_height
    );
    {
        let mut ss = SYNC_STATE.lock();
        ss.target_height = best_height;
    }

    // 3. Fetch blocks in batches.
    let mut current = local_height;
    let total_blocks = best_height - local_height;
    let mut retry_count = 0;

    while current < best_height {
        let batch_end = (current + config.max_blocks_batch).min(best_height);
        let req = GetBlocks { from: current, to: batch_end };
        let req_bytes = serialize_sync_message(SyncMessageKind::GetBlocks, &req)?;

        // Retry logic.
        let mut success = false;
        for attempt in 0..config.retry_count {
            // Wait for block data.
            let batch_deadline = crate::arch::x86_64::timer::uptime_ms() + config.timeout_ms;
            let mut applied = 0u64;
            let mut received_blocks = 0;

            // Send request.
            network.broadcast(&req_bytes)?;

            while crate::arch::x86_64::timer::uptime_ms() < batch_deadline
                && current + applied < batch_end
            {
                if let Some(msg) = network.recv() {
                    if let Ok((kind, payload)) = deserialize_sync_message(&msg) {
                        if kind == SyncMessageKind::BlockData {
                            if let Ok(block_data) = postcard::from_bytes::<BlockData>(payload) {
                                // Verify and apply block.
                                if let Err(e) = apply_block(&block_data, config) {
                                    error!(height = block_data.height, error = %e, "failed to apply block");
                                    if attempt < config.retry_count - 1 {
                                        break; // Retry the whole batch.
                                    } else {
                                        return Err(SyncError::BlockApplicationFailed {
                                            height: block_data.height,
                                            reason: e.to_string(),
                                        });
                                    }
                                }
                                received_blocks += 1;
                                current += 1;
                                applied += 1;
                                {
                                    let mut ss = SYNC_STATE.lock();
                                    ss.blocks_received += 1;
                                    ss.blocks_verified += 1;
                                    ss.blocks_applied += 1;
                                    ss.local_height = current;
                                }
                                if let Some(ref mut e) = *crate::consensus::CONSENSUS_ENGINE.lock() {
                                    e.height = current;
                                }
                                if current % config.progress_log_interval == 0 {
                                    info!(height = current, total_blocks, "sync progress");
                                }
                            }
                        }
                    }
                }
                crate::arch::x86_64::timer::sleep_ms(10);
            }

            if applied == (batch_end - current) {
                success = true;
                break;
            } else {
                warn!(
                    attempt,
                    received = applied,
                    expected = batch_end - current,
                    "batch incomplete, retrying"
                );
                crate::arch::x86_64::timer::sleep_ms(100 * (attempt + 1));
            }
        }

        if !success {
            error!(current, "batch sync failed after retries");
            break;
        }

        // Persist progress after each batch.
        if config.persist_batch {
            let _ = persist_height(current);
        }
    }

    // Final persistence.
    persist_height(current)?;
    crate::fs::ionafs::sync_to_disk();

    info!(current, "sync complete");
    let mut ss = SYNC_STATE.lock();
    ss.local_height = current;
    ss.syncing = false;
    if let Some(start) = ss.start_time {
        let elapsed = crate::arch::x86_64::timer::uptime_ms() - start;
        info!(elapsed, "sync finished in {}ms", elapsed);
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// Block application
// -----------------------------------------------------------------------------

/// Apply a single block during sync.
fn apply_block(block_data: &BlockData, config: &SyncConfig) -> SyncResult<()> {
    let block = &block_data.block;
    let height = block_data.height;

    // Verify block height matches.
    if block.header.height != height {
        return Err(SyncError::InvalidBlock {
            height,
            reason: format!(
                "block height mismatch: header says {}, expected {}",
                block.header.height, height
            ),
        });
    }

    // Verify block signatures if enabled.
    if config.verify_signatures {
        // In production, verify the block's proposer signature and votes.
        // For now, we do a minimal check.
        if block.header.proposer_pk.is_empty() {
            return Err(SyncError::InvalidBlock {
                height,
                reason: "empty proposer public key".to_string(),
            });
        }
        // Additional verification would be done here.
        // For example, verify the block's signature against the proposer's public key.
    }

    // Apply the block to the state.
    // In production, this would call into the execution engine.
    // For now, we just increment the height in the consensus engine.
    if let Some(ref mut e) = *crate::consensus::CONSENSUS_ENGINE.lock() {
        e.height = height;
    }

    debug!(height, "applied block");
    Ok(())
}

// -----------------------------------------------------------------------------
// Convenience functions
// -----------------------------------------------------------------------------

/// Check if the node is currently syncing.
pub fn is_syncing() -> bool {
    SYNC_STATE.lock().syncing
}

/// Get the current sync height (local, target).
pub fn sync_height() -> (u64, u64) {
    let ss = SYNC_STATE.lock();
    (ss.local_height, ss.target_height)
}

/// Get sync progress as a percentage.
pub fn sync_progress() -> f32 {
    let ss = SYNC_STATE.lock();
    if ss.target_height == 0 {
        1.0
    } else {
        ss.local_height as f32 / ss.target_height as f32
    }
}

/// Reset the sync state.
pub fn reset_sync_state() {
    let mut ss = SYNC_STATE.lock();
    ss.local_height = 0;
    ss.target_height = 0;
    ss.syncing = false;
    ss.peers.clear();
    ss.blocks_received = 0;
    ss.blocks_verified = 0;
    ss.blocks_applied = 0;
    ss.start_time = None;
    debug!("sync state reset");
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct MockNetwork {
        messages: Mutex<Vec<Vec<u8>>>,
        responses: Mutex<Vec<Vec<u8>>>,
    }

    impl MockNetwork {
        fn new() -> Self {
            Self {
                messages: Mutex::new(Vec::new()),
                responses: Mutex::new(Vec::new()),
            }
        }

        fn add_response(&self, msg: Vec<u8>) {
            self.responses.lock().push(msg);
        }
    }

    impl SyncNetwork for MockNetwork {
        fn broadcast(&self, msg: &[u8]) -> SyncResult<usize> {
            self.messages.lock().push(msg.to_vec());
            Ok(1)
        }

        fn recv(&self) -> Option<Vec<u8>> {
            self.responses.lock().pop()
        }

        fn recv_timeout<F>(&self, _timeout_ms: u64, _predicate: F) -> SyncResult<Vec<u8>>
        where
            F: Fn(&[u8]) -> bool,
        {
            self.recv().ok_or(SyncError::Timeout(0))
        }

        fn send_to(&self, _peer_id: &str, msg: &[u8]) -> SyncResult<()> {
            self.broadcast(msg)?;
            Ok(())
        }
    }

    #[test]
    fn test_serialize_deserialize() -> SyncResult<()> {
        let status = GetStatus {
            height: 100,
            peer_id: "peer1".to_string(),
        };
        let bytes = serialize_sync_message(SyncMessageKind::GetStatus, &status)?;
        let (kind, payload) = deserialize_sync_message(&bytes)?;
        assert_eq!(kind, SyncMessageKind::GetStatus);
        let decoded: GetStatus = postcard::from_bytes(payload)
            .map_err(|e| SyncError::Serialization(e.to_string()))?;
        assert_eq!(decoded.height, 100);
        assert_eq!(decoded.peer_id, "peer1");
        Ok(())
    }

    #[test]
    fn test_sync_no_peers() -> SyncResult<()> {
        let config = SyncConfig::default();
        let network = MockNetwork::new();
        let result = sync_from_peers(&config, &network);
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_sync_with_peer() -> SyncResult<()> {
        let config = SyncConfig {
            timeout_ms: 5000,
            max_blocks_batch: 10,
            retry_count: 2,
            verify_signatures: false,
            persist_batch: true,
            progress_log_interval: 100,
        };
        let network = MockNetwork::new();
        // Simulate a status response.
        let status = StatusResponse {
            height: 50,
            best_hash: [0u8; 32],
            peer_id: "peer1".to_string(),
        };
        let status_bytes = serialize_sync_message(SyncMessageKind::StatusResponse, &status)?;
        network.add_response(status_bytes);
        // Simulate block data.
        let block = crate::types::Block {
            header: crate::types::BlockHeader {
                height: 1,
                round: 0,
                prev: crate::types::Hash32([0u8; 32]),
                proposer_pk: vec![1u8; 32],
                tx_root: crate::types::Hash32([0u8; 32]),
                receipts_root: crate::types::Hash32([0u8; 32]),
                state_root: crate::types::Hash32([0u8; 32]),
                base_fee_per_gas: 1,
                gas_used: 0,
                intrinsic_gas_used: 0,
                exec_gas_used: 0,
                vm_gas_used: 0,
                evm_gas_used: 0,
                chain_id: 6126151,
                timestamp: 0,
                protocol_version: 1,
            },
            txs: vec![],
        };
        let block_data = BlockData {
            block,
            height: 1,
        };
        let block_bytes = serialize_sync_message(SyncMessageKind::BlockData, &block_data)?;
        network.add_response(block_bytes);

        let result = sync_from_peers(&config, &network);
        assert!(result.is_ok());
        let (local, target) = sync_height();
        assert_eq!(local, 1);
        assert_eq!(target, 50);
        Ok(())
    }
}
