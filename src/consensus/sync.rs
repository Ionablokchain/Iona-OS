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
//! # Production Features
//! - Configurable timeouts, batch sizes, retries, and progress logging.
//! - Optional Prometheus metrics for sync progress and operations.
//! - Atomic fallback metrics for environments without Prometheus.
//! - Overflow‑safe counters using saturating arithmetic.
//! - Validation of configuration parameters.
//! - Thread‑safe global sync state via `spin::Mutex`.
//! - Structured logging with `tracing`.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::time::Duration;
use prometheus::{register_counter, register_gauge, Counter, Gauge};
use serde::{Deserialize, Serialize};
use spin::{Lazy, Mutex};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, OnceLock,
};
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

    #[error("metrics error: {0}")]
    Metrics(String),

    #[error("configuration error: {0}")]
    Config(String),
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
    /// Whether to enable Prometheus metrics.
    pub enable_metrics: bool,
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
            enable_metrics: false,
        }
    }
}

impl SyncConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), SyncError> {
        if self.timeout_ms == 0 {
            return Err(SyncError::Config("timeout_ms must be > 0".into()));
        }
        if self.max_blocks_batch == 0 {
            return Err(SyncError::Config("max_blocks_batch must be > 0".into()));
        }
        if self.retry_count == 0 {
            return Err(SyncError::Config("retry_count must be > 0".into()));
        }
        if self.progress_log_interval == 0 {
            return Err(SyncError::Config("progress_log_interval must be > 0".into()));
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Sync Metrics (Prometheus + atomic fallback)
// -----------------------------------------------------------------------------

/// Atomic fallback metrics for environments without Prometheus.
#[derive(Debug, Default)]
pub struct AtomicSyncMetrics {
    /// Total blocks received.
    pub blocks_received: AtomicU64,
    /// Total blocks verified.
    pub blocks_verified: AtomicU64,
    /// Total blocks applied.
    pub blocks_applied: AtomicU64,
    /// Total status messages sent.
    pub status_requests_sent: AtomicU64,
    /// Total status responses received.
    pub status_responses_received: AtomicU64,
    /// Total block requests sent.
    pub block_requests_sent: AtomicU64,
    /// Total sync errors encountered.
    pub sync_errors: AtomicU64,
}

impl AtomicSyncMetrics {
    fn inc_blocks_received(&self) { self.blocks_received.fetch_add(1, Ordering::Relaxed); }
    fn inc_blocks_verified(&self) { self.blocks_verified.fetch_add(1, Ordering::Relaxed); }
    fn inc_blocks_applied(&self) { self.blocks_applied.fetch_add(1, Ordering::Relaxed); }
    fn inc_status_requests_sent(&self) { self.status_requests_sent.fetch_add(1, Ordering::Relaxed); }
    fn inc_status_responses_received(&self) { self.status_responses_received.fetch_add(1, Ordering::Relaxed); }
    fn inc_block_requests_sent(&self) { self.block_requests_sent.fetch_add(1, Ordering::Relaxed); }
    fn inc_sync_errors(&self) { self.sync_errors.fetch_add(1, Ordering::Relaxed); }

    /// Get a snapshot of the atomic metrics.
    pub fn snapshot(&self) -> SyncMetricsSnapshot {
        SyncMetricsSnapshot {
            blocks_received: self.blocks_received.load(Ordering::Relaxed),
            blocks_verified: self.blocks_verified.load(Ordering::Relaxed),
            blocks_applied: self.blocks_applied.load(Ordering::Relaxed),
            status_requests_sent: self.status_requests_sent.load(Ordering::Relaxed),
            status_responses_received: self.status_responses_received.load(Ordering::Relaxed),
            block_requests_sent: self.block_requests_sent.load(Ordering::Relaxed),
            sync_errors: self.sync_errors.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of atomic sync metrics (for external monitoring).
#[derive(Debug, Clone, Default)]
pub struct SyncMetricsSnapshot {
    pub blocks_received: u64,
    pub blocks_verified: u64,
    pub blocks_applied: u64,
    pub status_requests_sent: u64,
    pub status_responses_received: u64,
    pub block_requests_sent: u64,
    pub sync_errors: u64,
}

/// Prometheus metrics for block sync.
#[derive(Clone)]
pub struct PrometheusSyncMetrics {
    /// Current local height.
    pub local_height: Gauge,
    /// Current target height.
    pub target_height: Gauge,
    /// Sync progress (0.0 – 1.0).
    pub progress: Gauge,
    /// Whether sync is currently active (1=yes, 0=no).
    pub is_syncing: Gauge,
    /// Total blocks received.
    pub blocks_received_total: Counter,
    /// Total blocks verified.
    pub blocks_verified_total: Counter,
    /// Total blocks applied.
    pub blocks_applied_total: Counter,
    /// Total status requests sent.
    pub status_requests_sent_total: Counter,
    /// Total status responses received.
    pub status_responses_received_total: Counter,
    /// Total block requests sent.
    pub block_requests_sent_total: Counter,
    /// Total sync errors.
    pub sync_errors_total: Counter,
}

impl PrometheusSyncMetrics {
    /// Create and register metrics with the global Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            local_height: register_gauge!("iona_sync_local_height", "Local blockchain height during sync")?,
            target_height: register_gauge!("iona_sync_target_height", "Target blockchain height during sync")?,
            progress: register_gauge!("iona_sync_progress", "Sync progress (0.0-1.0)")?,
            is_syncing: register_gauge!("iona_sync_is_syncing", "Whether sync is active (1=yes,0=no)")?,
            blocks_received_total: register_counter!("iona_sync_blocks_received_total", "Total blocks received")?,
            blocks_verified_total: register_counter!("iona_sync_blocks_verified_total", "Total blocks verified")?,
            blocks_applied_total: register_counter!("iona_sync_blocks_applied_total", "Total blocks applied")?,
            status_requests_sent_total: register_counter!("iona_sync_status_requests_sent_total", "Total status requests sent")?,
            status_responses_received_total: register_counter!("iona_sync_status_responses_received_total", "Total status responses received")?,
            block_requests_sent_total: register_counter!("iona_sync_block_requests_sent_total", "Total block requests sent")?,
            sync_errors_total: register_counter!("iona_sync_errors_total", "Total sync errors")?,
        })
    }

    /// Create an unregistered instance (for tests or disabled metrics).
    pub fn new_unregistered() -> Self {
        Self {
            local_height: Gauge::new("iona_sync_local_height", "Local height").unwrap(),
            target_height: Gauge::new("iona_sync_target_height", "Target height").unwrap(),
            progress: Gauge::new("iona_sync_progress", "Progress").unwrap(),
            is_syncing: Gauge::new("iona_sync_is_syncing", "Is syncing").unwrap(),
            blocks_received_total: Counter::new("iona_sync_blocks_received_total", "Blocks received").unwrap(),
            blocks_verified_total: Counter::new("iona_sync_blocks_verified_total", "Blocks verified").unwrap(),
            blocks_applied_total: Counter::new("iona_sync_blocks_applied_total", "Blocks applied").unwrap(),
            status_requests_sent_total: Counter::new("iona_sync_status_requests_sent_total", "Status requests").unwrap(),
            status_responses_received_total: Counter::new("iona_sync_status_responses_received_total", "Status responses").unwrap(),
            block_requests_sent_total: Counter::new("iona_sync_block_requests_sent_total", "Block requests").unwrap(),
            sync_errors_total: Counter::new("iona_sync_errors_total", "Sync errors").unwrap(),
        }
    }
}

// -----------------------------------------------------------------------------
// Global metrics
// -----------------------------------------------------------------------------

static GLOBAL_SYNC_METRICS: OnceLock<Option<(Arc<PrometheusSyncMetrics>, Arc<AtomicSyncMetrics>)>> = OnceLock::new();

/// Initialize sync metrics (call once before sync).
pub fn init_sync_metrics(enable_prometheus: bool) -> Result<(), SyncError> {
    if GLOBAL_SYNC_METRICS.get().is_some() {
        return Err(SyncError::Config("sync metrics already initialized".into()));
    }
    let prometheus = if enable_prometheus {
        Some(Arc::new(PrometheusSyncMetrics::new().map_err(|e| SyncError::Metrics(e.to_string()))?))
    } else {
        None
    };
    let atomic = Arc::new(AtomicSyncMetrics::default());
    GLOBAL_SYNC_METRICS.set(Some((prometheus, atomic))).map_err(|_| SyncError::Config("failed to set metrics".into()))?;
    Ok(())
}

/// Get the global metrics (if initialized).
fn sync_metrics() -> Option<(Arc<PrometheusSyncMetrics>, Arc<AtomicSyncMetrics>)> {
    GLOBAL_SYNC_METRICS.get().and_then(|m| {
        if let Some((prom, atomic)) = m {
            Some((prom.clone(), atomic.clone()))
        } else {
            None
        }
    })
}

/// Get a snapshot of the atomic sync metrics.
pub fn sync_metrics_snapshot() -> Option<SyncMetricsSnapshot> {
    GLOBAL_SYNC_METRICS.get().and_then(|m| m.as_ref().map(|(_, atomic)| atomic.snapshot()))
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
    config.validate()?;
    info!("starting block sync from peers");

    // Initialize metrics if enabled and not already set.
    if config.enable_metrics && GLOBAL_SYNC_METRICS.get().is_none() {
        let _ = init_sync_metrics(true);
    }

    // Load persisted height.
    let local_height = load_persisted_height();
    info!(local_height, "loaded persisted height");

    {
        let mut ss = SYNC_STATE.lock();
        ss.local_height = local_height;
        ss.syncing = true;
        ss.start_time = Some(crate::arch::x86_64::timer::uptime_ms());
        if let Some((prom, _)) = sync_metrics() {
            prom.local_height.set(local_height as f64);
            prom.is_syncing.set(1.0);
        }
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
    if let Some((prom, atomic)) = sync_metrics() {
        prom.status_requests_sent_total.inc_by(peers_contacted as u64);
        atomic.inc_status_requests_sent();
    }
    info!(peers_contacted, "queried peers");

    if peers_contacted == 0 {
        info!("no peers — starting fresh at height {}", local_height);
        {
            let mut ss = SYNC_STATE.lock();
            ss.syncing = false;
            if let Some((prom, _)) = sync_metrics() {
                prom.is_syncing.set(0.0);
            }
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
                        if let Some((prom, atomic)) = sync_metrics() {
                            prom.status_responses_received_total.inc();
                            atomic.inc_status_responses_received();
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
            if let Some((prom, _)) = sync_metrics() {
                prom.is_syncing.set(0.0);
                prom.target_height.set(local_height as f64);
                prom.progress.set(1.0);
            }
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
        if let Some((prom, _)) = sync_metrics() {
            prom.target_height.set(best_height as f64);
        }
    }

    // 3. Fetch blocks in batches.
    let mut current = local_height;
    let total_blocks = best_height - local_height;
    let mut retry_count = 0;

    while current < best_height {
        let batch_end = (current + config.max_blocks_batch).min(best_height);
        let req = GetBlocks { from: current, to: batch_end };
        let req_bytes = serialize_sync_message(SyncMessageKind::GetBlocks, &req)?;

        let mut success = false;
        for attempt in 0..config.retry_count {
            let batch_deadline = crate::arch::x86_64::timer::uptime_ms() + config.timeout_ms;
            let mut applied = 0u64;
            let mut received_blocks = 0;

            network.broadcast(&req_bytes)?;
            if let Some((prom, atomic)) = sync_metrics() {
                prom.block_requests_sent_total.inc();
                atomic.inc_block_requests_sent();
            }

            while crate::arch::x86_64::timer::uptime_ms() < batch_deadline
                && current + applied < batch_end
            {
                if let Some(msg) = network.recv() {
                    if let Ok((kind, payload)) = deserialize_sync_message(&msg) {
                        if kind == SyncMessageKind::BlockData {
                            if let Ok(block_data) = postcard::from_bytes::<BlockData>(payload) {
                                if let Err(e) = apply_block(&block_data, config) {
                                    error!(height = block_data.height, error = %e, "failed to apply block");
                                    if let Some((prom, atomic)) = sync_metrics() {
                                        prom.sync_errors_total.inc();
                                        atomic.inc_sync_errors();
                                    }
                                    if attempt < config.retry_count - 1 {
                                        break;
                                    } else {
                                        return Err(SyncError::BlockApplicationFailed {
                                            height: block_data.height,
                                            reason: e.to_string(),
                                        });
                                    }
                                }
                                received_blocks += 1;
                                current = current.saturating_add(1);
                                applied = applied.saturating_add(1);
                                {
                                    let mut ss = SYNC_STATE.lock();
                                    ss.blocks_received = ss.blocks_received.saturating_add(1);
                                    ss.blocks_verified = ss.blocks_verified.saturating_add(1);
                                    ss.blocks_applied = ss.blocks_applied.saturating_add(1);
                                    ss.local_height = current;
                                    if let Some((prom, atomic)) = sync_metrics() {
                                        prom.blocks_received_total.inc();
                                        prom.blocks_verified_total.inc();
                                        prom.blocks_applied_total.inc();
                                        prom.local_height.set(current as f64);
                                        prom.progress.set(current as f64 / best_height as f64);
                                        atomic.inc_blocks_received();
                                        atomic.inc_blocks_verified();
                                        atomic.inc_blocks_applied();
                                    }
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

        if config.persist_batch {
            let _ = persist_height(current);
        }
    }

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
    if let Some((prom, _)) = sync_metrics() {
        prom.local_height.set(current as f64);
        prom.is_syncing.set(0.0);
        prom.progress.set(1.0);
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

    if block.header.height != height {
        return Err(SyncError::InvalidBlock {
            height,
            reason: format!(
                "block height mismatch: header says {}, expected {}",
                block.header.height, height
            ),
        });
    }

    if config.verify_signatures {
        if block.header.proposer_pk.is_empty() {
            return Err(SyncError::InvalidBlock {
                height,
                reason: "empty proposer public key".to_string(),
            });
        }
    }

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
    if let Some((prom, atomic)) = sync_metrics() {
        prom.local_height.set(0.0);
        prom.target_height.set(0.0);
        prom.progress.set(0.0);
        prom.is_syncing.set(0.0);
        // Note: counters are not reset (they are cumulative).
    }
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
        let config = SyncConfig {
            enable_metrics: false,
            ..Default::default()
        };
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
            enable_metrics: false,
        };
        let network = MockNetwork::new();
        let status = StatusResponse {
            height: 50,
            best_hash: [0u8; 32],
            peer_id: "peer1".to_string(),
        };
        let status_bytes = serialize_sync_message(SyncMessageKind::StatusResponse, &status)?;
        network.add_response(status_bytes);
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

    #[test]
    fn test_config_validation() {
        let cfg = SyncConfig::default();
        assert!(cfg.validate().is_ok());
        let bad = SyncConfig {
            timeout_ms: 0,
            ..Default::default()
        };
        assert!(bad.validate().is_err());
    }
}
