//! Gossipsub P2P protocol — stable production implementation.
//!
//! Implements a simplified libp2p Gossipsub v1.1 spec for `no_std` environments:
//!   - PUBLISH    — broadcast a message to the mesh
//!   - SUBSCRIBE  — subscribe to a topic
//!   - GRAFT      — add a peer to the mesh for a topic
//!   - PRUNE      — remove a peer from the mesh for a topic
//!   - IHAVE      — announce message IDs we have
//!   - IWANT      — request specific messages by ID
//!
//! Transport: UDP (via `sys_udp_bind/sendto/recvfrom`)
//! Message ID: FNV-1a(topic + data)[0..8]
//! Mesh size: D=6 (target), Dlow=4, Dhigh=12
//! Heartbeat: every 1000ms — prune/graft to maintain mesh size
//!
//! # Features
//! - Configurable parameters (mesh sizes, TTL, history, timeouts)
//! - Peer scoring and backoff for reconnection
//! - Message deduplication with bounded history
//! - Robust serialization with length and bounds checks
//! - Peer discovery with exponential backoff
//! - Metrics for monitoring
//!
//! # Example
//! ```rust,ignore
//! use iona::p2p::gossipsub::{GossipNode, GossipConfig, PeerDiscovery};
//!
//! let config = GossipConfig::default();
//! let mut node = GossipNode::new(port, config);
//! node.subscribe("iona/blocks");
//! node.publish("iona/blocks", b"hello".to_vec());
//! ```

use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use core::time::Duration;
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

// -----------------------------------------------------------------------------
// Constants & Configuration
// -----------------------------------------------------------------------------

/// Default target mesh degree.
pub const DEFAULT_D: usize = 6;
/// Default minimum mesh degree.
pub const DEFAULT_D_LOW: usize = 4;
/// Default maximum mesh degree.
pub const DEFAULT_D_HIGH: usize = 12;
/// Default message TTL (hops).
pub const DEFAULT_TTL: u8 = 8;
/// Default message history size (for deduplication).
pub const DEFAULT_HISTORY: usize = 120;
/// Default maximum message size (65 KiB).
pub const DEFAULT_MAX_MSG_SIZE: usize = 65_000;
/// Default heartbeat interval (ms).
pub const DEFAULT_HEARTBEAT_MS: u64 = 1000;
/// Default peer eviction timeout (ms).
pub const DEFAULT_EVICT_TIMEOUT_MS: u64 = 60_000;
/// Default reconnect backoff base (ms).
pub const DEFAULT_RECONNECT_BACKOFF_BASE_MS: u64 = 30_000;
/// Default max reconnect backoff (ms).
pub const DEFAULT_MAX_RECONNECT_BACKOFF_MS: u64 = 300_000;

/// Configuration for Gossipsub node.
#[derive(Debug, Clone)]
pub struct GossipConfig {
    /// Target mesh degree.
    pub d: usize,
    /// Minimum mesh degree.
    pub d_low: usize,
    /// Maximum mesh degree.
    pub d_high: usize,
    /// Message time-to-live (hops).
    pub ttl: u8,
    /// Message ID history size (for deduplication).
    pub history: usize,
    /// Maximum message size in bytes.
    pub max_msg_size: usize,
    /// Heartbeat interval (milliseconds).
    pub heartbeat_ms: u64,
    /// Peer eviction timeout (milliseconds without activity).
    pub evict_timeout_ms: u64,
    /// Base backoff for reconnection (milliseconds).
    pub reconnect_backoff_base_ms: u64,
    /// Maximum backoff for reconnection (milliseconds).
    pub max_reconnect_backoff_ms: u64,
    /// Enable detailed tracing of messages.
    pub trace_messages: bool,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            d: DEFAULT_D,
            d_low: DEFAULT_D_LOW,
            d_high: DEFAULT_D_HIGH,
            ttl: DEFAULT_TTL,
            history: DEFAULT_HISTORY,
            max_msg_size: DEFAULT_MAX_MSG_SIZE,
            heartbeat_ms: DEFAULT_HEARTBEAT_MS,
            evict_timeout_ms: DEFAULT_EVICT_TIMEOUT_MS,
            reconnect_backoff_base_ms: DEFAULT_RECONNECT_BACKOFF_BASE_MS,
            max_reconnect_backoff_ms: DEFAULT_MAX_RECONNECT_BACKOFF_MS,
            trace_messages: false,
        }
    }
}

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GossipError {
    #[error("message too large: {size} bytes (max {max})")]
    MessageTooLarge { size: usize, max: usize },
    #[error("invalid message type: {0}")]
    InvalidMessageType(u8),
    #[error("malformed message: {reason}")]
    MalformedMessage { reason: String },
    #[error("topic not subscribed")]
    NotSubscribed,
    #[error("peer not found")]
    PeerNotFound,
    #[error("I/O error: {0}")]
    Io(String),
    #[error("configuration error: {0}")]
    Config(String),
}

pub type GossipResult<T> = Result<T, GossipError>;

// -----------------------------------------------------------------------------
// Message types
// -----------------------------------------------------------------------------

/// Message types as per Gossipsub v1.1.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    Publish = 1,
    Subscribe = 2,
    Unsubscribe = 3,
    Graft = 4,
    Prune = 5,
    IHave = 6,
    IWant = 7,
    Control = 8,
}

impl TryFrom<u8> for MsgType {
    type Error = GossipError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(MsgType::Publish),
            2 => Ok(MsgType::Subscribe),
            3 => Ok(MsgType::Unsubscribe),
            4 => Ok(MsgType::Graft),
            5 => Ok(MsgType::Prune),
            6 => Ok(MsgType::IHave),
            7 => Ok(MsgType::IWant),
            8 => Ok(MsgType::Control),
            _ => Err(GossipError::InvalidMessageType(v)),
        }
    }
}

/// A Gossipsub message.
#[derive(Clone, Debug)]
pub struct GossipMessage {
    pub msg_type: MsgType,
    pub msg_id: u32,
    pub topic: String,
    pub data: Vec<u8>,
    pub ttl: u8,
}

impl GossipMessage {
    /// Create a new publish message with auto-generated ID.
    pub fn new_publish(topic: &str, data: Vec<u8>) -> Self {
        let id = Self::compute_id(topic, &data);
        Self {
            msg_type: MsgType::Publish,
            msg_id: id,
            topic: topic.to_string(),
            data,
            ttl: DEFAULT_TTL,
        }
    }

    /// Compute FNV-1a 32-bit message ID.
    pub fn compute_id(topic: &str, data: &[u8]) -> u32 {
        let mut h: u32 = 2166136261;
        for b in topic.bytes().chain(data.iter().cloned()) {
            h ^= b as u32;
            h = h.wrapping_mul(16777619);
        }
        h
    }

    /// Serialize the message to a byte vector.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 4 + 1 + self.topic.len() + 2 + self.data.len() + 1);
        buf.push(self.msg_type as u8);
        buf.extend_from_slice(&self.msg_id.to_le_bytes());
        let tb = self.topic.as_bytes();
        buf.push(tb.len() as u8);
        buf.extend_from_slice(tb);
        buf.extend_from_slice(&(self.data.len() as u16).to_le_bytes());
        buf.extend_from_slice(&self.data);
        buf.push(self.ttl);
        buf
    }

    /// Deserialize a message from raw bytes with validation.
    pub fn deserialize(raw: &[u8], max_size: usize) -> GossipResult<Self> {
        if raw.is_empty() {
            return Err(GossipError::MalformedMessage {
                reason: "empty message".into(),
            });
        }
        if raw.len() > max_size {
            return Err(GossipError::MessageTooLarge {
                size: raw.len(),
                max: max_size,
            });
        }

        let msg_type = MsgType::try_from(raw[0])?;
        if raw.len() < 5 {
            return Err(GossipError::MalformedMessage {
                reason: "message too short for msg_id".into(),
            });
        }
        let msg_id = u32::from_le_bytes(raw[1..5].try_into().unwrap());

        if raw.len() < 6 {
            return Err(GossipError::MalformedMessage {
                reason: "message too short for topic length".into(),
            });
        }
        let topic_len = raw[5] as usize;
        if raw.len() < 6 + topic_len + 2 {
            return Err(GossipError::MalformedMessage {
                reason: format!("topic length {} exceeds available data", topic_len),
            });
        }
        let topic = String::from_utf8_lossy(&raw[6..6 + topic_len]).into_owned();

        let data_len_start = 6 + topic_len;
        let data_len = u16::from_le_bytes(
            raw[data_len_start..data_len_start + 2]
                .try_into()
                .map_err(|_| GossipError::MalformedMessage {
                    reason: "invalid data length".into(),
                })?,
        ) as usize;
        let data_start = data_len_start + 2;
        if raw.len() < data_start + data_len + 1 {
            return Err(GossipError::MalformedMessage {
                reason: format!("data length {} exceeds available data", data_len),
            });
        }
        let data = raw[data_start..data_start + data_len].to_vec();
        let ttl = raw[data_start + data_len];

        Ok(Self {
            msg_type,
            msg_id,
            topic,
            data,
            ttl,
        })
    }
}

// -----------------------------------------------------------------------------
// Peer
// -----------------------------------------------------------------------------

/// A remote peer in the gossip network.
#[derive(Clone, Debug)]
pub struct Peer {
    pub ip: [u8; 4],
    pub port: u16,
    pub topics: BTreeSet<String>,
    pub mesh: BTreeSet<String>,
    pub score: i32,
    pub seen_ms: u64,
    pub backoff_ms: u64,
    pub connected: bool,
}

impl Peer {
    pub fn new(ip: [u8; 4], port: u16) -> Self {
        Self {
            ip,
            port,
            topics: BTreeSet::new(),
            mesh: BTreeSet::new(),
            score: 0,
            seen_ms: 0,
            backoff_ms: 0,
            connected: false,
        }
    }

    /// Unique key for the peer (IP + port).
    pub fn key(&self) -> u64 {
        ((self.ip[0] as u64) << 40)
            | ((self.ip[1] as u64) << 32)
            | ((self.ip[2] as u64) << 24)
            | ((self.ip[3] as u64) << 16)
            | (self.port as u64)
    }

    /// String representation for logging.
    pub fn addr_string(&self) -> String {
        format!("{}.{}.{}.{}:{}", self.ip[0], self.ip[1], self.ip[2], self.ip[3], self.port)
    }
}

// -----------------------------------------------------------------------------
// GossipNode
// -----------------------------------------------------------------------------

/// Main Gossipsub node.
pub struct GossipNode {
    config: GossipConfig,
    local_port: u16,
    udp_fd: u64,
    peers: BTreeMap<u64, Peer>,
    subscriptions: BTreeSet<String>,
    mesh: BTreeMap<String, BTreeSet<u64>>,
    seen_msgs: VecDeque<u32>,
    inbox: VecDeque<(String, Vec<u8>)>,
    last_heartbeat_ms: u64,
    total_messages_sent: u64,
    total_messages_received: u64,
    total_duplicates: u64,
}

impl GossipNode {
    /// Create a new GossipNode bound to the given UDP port.
    pub fn new(port: u16, config: GossipConfig) -> Self {
        let fd = crate::net::udp::udp_bind(port);
        info!(port, "gossip node bound to UDP port");
        Self {
            config,
            local_port: port,
            udp_fd: fd,
            peers: BTreeMap::new(),
            subscriptions: BTreeSet::new(),
            mesh: BTreeMap::new(),
            seen_msgs: VecDeque::with_capacity(config.history),
            inbox: VecDeque::new(),
            last_heartbeat_ms: 0,
            total_messages_sent: 0,
            total_messages_received: 0,
            total_duplicates: 0,
        }
    }

    /// Add a known peer.
    pub fn add_peer(&mut self, ip: [u8; 4], port: u16) {
        let p = Peer::new(ip, port);
        let k = p.key();
        if !self.peers.contains_key(&k) {
            info!(addr = %p.addr_string(), "added known peer");
            self.peers.insert(k, p);
        }
    }

    /// Subscribe to a topic.
    pub fn subscribe(&mut self, topic: &str) {
        if self.subscriptions.insert(topic.to_string()) {
            self.mesh.entry(topic.to_string()).or_default();
            info!(topic, "subscribed to topic");
            // Announce subscription to all peers.
            let msg = GossipMessage {
                msg_type: MsgType::Subscribe,
                msg_id: 0,
                topic: topic.to_string(),
                data: Vec::new(),
                ttl: 1,
            };
            self.broadcast_control(&msg);
        }
    }

    /// Unsubscribe from a topic.
    pub fn unsubscribe(&mut self, topic: &str) {
        if self.subscriptions.remove(topic) {
            info!(topic, "unsubscribed from topic");
            self.mesh.remove(topic);
            // Announce to peers.
            let msg = GossipMessage {
                msg_type: MsgType::Unsubscribe,
                msg_id: 0,
                topic: topic.to_string(),
                data: Vec::new(),
                ttl: 1,
            };
            self.broadcast_control(&msg);
        }
    }

    /// Publish a message to a topic.
    pub fn publish(&mut self, topic: &str, data: Vec<u8>) -> GossipResult<u32> {
        if !self.subscriptions.contains(topic) {
            return Err(GossipError::NotSubscribed);
        }
        if data.len() > self.config.max_msg_size {
            return Err(GossipError::MessageTooLarge {
                size: data.len(),
                max: self.config.max_msg_size,
            });
        }
        let msg = GossipMessage::new_publish(topic, data);
        let id = msg.msg_id;
        self.record_seen(id);
        self.forward_to_mesh(&msg);
        self.total_messages_sent += 1;
        if self.config.trace_messages {
            trace!(topic, msg_id = id, "published message");
        }
        Ok(id)
    }

    /// Poll for incoming messages; returns `true` if a packet was processed.
    pub fn poll(&mut self) -> GossipResult<bool> {
        let mut buf = alloc::vec![0u8; self.config.max_msg_size];
        let (n, src_ip, src_port) = crate::net::udp::udp_recvfrom(self.udp_fd, &mut buf);
        if n == 0 {
            return Ok(false);
        }

        let msg = GossipMessage::deserialize(&buf[..n], self.config.max_msg_size)?;
        self.total_messages_received += 1;

        let src_key = Peer::new(src_ip, src_port).key();

        // Update peer or add if new.
        self.update_peer(src_key, src_ip, src_port);

        if self.config.trace_messages {
            trace!(
                msg_type = ?msg.msg_type,
                topic = %msg.topic,
                from = %format!("{}.{}.{}.{}:{}", src_ip[0], src_ip[1], src_ip[2], src_ip[3], src_port),
                "received message"
            );
        }

        self.handle_message(msg, src_key)?;
        Ok(true)
    }

    /// Receive one message from the inbox.
    pub fn recv(&mut self) -> Option<(String, Vec<u8>)> {
        self.inbox.pop_front()
    }

    /// Run heartbeat to maintain mesh.
    pub fn heartbeat(&mut self) {
        let now = crate::arch::x86_64::timer::uptime_ms();
        if now - self.last_heartbeat_ms < self.config.heartbeat_ms {
            return;
        }
        self.last_heartbeat_ms = now;

        // Maintain mesh for each subscribed topic.
        for topic in self.subscriptions.clone().iter() {
            let mesh_size = self.mesh.get(topic).map(|s| s.len()).unwrap_or(0);

            if mesh_size < self.config.d_low {
                let needed = self.config.d - mesh_size;
                self.graft_peers(topic, needed);
            } else if mesh_size > self.config.d_high {
                let excess = mesh_size - self.config.d;
                self.prune_peers(topic, excess);
            }
        }

        // Gossip about recent messages (IHAVE).
        self.emit_ihave();

        // Remove stale peers.
        self.evict_stale_peers(now);
    }

    /// Get mesh size for a topic.
    pub fn mesh_size(&self, topic: &str) -> usize {
        self.mesh.get(topic).map(|s| s.len()).unwrap_or(0)
    }

    /// Get number of known peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Get total messages sent.
    pub fn total_sent(&self) -> u64 {
        self.total_messages_sent
    }

    /// Get total messages received.
    pub fn total_received(&self) -> u64 {
        self.total_messages_received
    }

    /// Get duplicate count.
    pub fn duplicate_count(&self) -> u64 {
        self.total_duplicates
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    fn update_peer(&mut self, key: u64, ip: [u8; 4], port: u16) {
        if let Some(p) = self.peers.get_mut(&key) {
            p.seen_ms = crate::arch::x86_64::timer::uptime_ms();
            p.score += 1;
            p.connected = true;
        } else {
            let mut p = Peer::new(ip, port);
            p.seen_ms = crate::arch::x86_64::timer::uptime_ms();
            p.connected = true;
            self.peers.insert(key, p);
        }
    }

    fn handle_message(&mut self, msg: GossipMessage, from_key: u64) -> GossipResult<()> {
        match msg.msg_type {
            MsgType::Publish => self.handle_publish(msg, from_key),
            MsgType::Subscribe => self.handle_subscribe(msg, from_key),
            MsgType::Unsubscribe => self.handle_unsubscribe(msg, from_key),
            MsgType::Graft => self.handle_graft(msg, from_key),
            MsgType::Prune => self.handle_prune(msg, from_key),
            MsgType::IHave => self.handle_ihave(msg, from_key),
            MsgType::IWant => self.handle_iwant(msg, from_key),
            MsgType::Control => Ok(()),
        }
    }

    fn handle_publish(&mut self, msg: GossipMessage, _from: u64) -> GossipResult<()> {
        if !self.subscriptions.contains(&msg.topic) {
            return Ok(());
        }
        if self.seen_msgs.contains(&msg.msg_id) {
            self.total_duplicates += 1;
            return Ok(());
        }
        self.record_seen(msg.msg_id);
        self.inbox.push_back((msg.topic.clone(), msg.data.clone()));

        if msg.ttl > 1 {
            let mut fwd = msg;
            fwd.ttl -= 1;
            self.forward_to_mesh(&fwd);
        }
        Ok(())
    }

    fn handle_subscribe(&mut self, msg: GossipMessage, from: u64) -> GossipResult<()> {
        if let Some(p) = self.peers.get_mut(&from) {
            p.topics.insert(msg.topic);
        }
        Ok(())
    }

    fn handle_unsubscribe(&mut self, msg: GossipMessage, from: u64) -> GossipResult<()> {
        if let Some(p) = self.peers.get_mut(&from) {
            p.topics.remove(&msg.topic);
        }
        if let Some(mesh) = self.mesh.get_mut(&msg.topic) {
            mesh.remove(&from);
        }
        Ok(())
    }

    fn handle_graft(&mut self, msg: GossipMessage, from: u64) -> GossipResult<()> {
        let mesh = self.mesh.entry(msg.topic.clone()).or_default();
        if mesh.len() < self.config.d_high {
            mesh.insert(from);
            if let Some(p) = self.peers.get_mut(&from) {
                p.mesh.insert(msg.topic);
            }
        } else {
            // Too many peers; send PRUNE back.
            self.send_prune(&msg.topic, from);
        }
        Ok(())
    }

    fn handle_prune(&mut self, msg: GossipMessage, from: u64) -> GossipResult<()> {
        if let Some(mesh) = self.mesh.get_mut(&msg.topic) {
            mesh.remove(&from);
        }
        if let Some(p) = self.peers.get_mut(&from) {
            p.mesh.remove(&msg.topic);
        }
        Ok(())
    }

    fn handle_ihave(&mut self, msg: GossipMessage, from: u64) -> GossipResult<()> {
        // Parse list of message IDs (4 bytes each).
        let mut i = 0;
        let data = &msg.data;
        while i + 4 <= data.len() {
            let id = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
            if !self.seen_msgs.contains(&id) {
                self.send_iwant(&msg.topic, id, from);
            }
            i += 4;
        }
        Ok(())
    }

    fn handle_iwant(&mut self, msg: GossipMessage, _from: u64) -> GossipResult<()> {
        // In a full implementation, we would re‑publish cached messages.
        // For this simplified version, we do nothing.
        debug!(msg_id = msg.msg_id, "IWANT received (message republish not implemented)");
        Ok(())
    }

    fn record_seen(&mut self, id: u32) {
        if self.seen_msgs.len() >= self.config.history {
            self.seen_msgs.pop_front();
        }
        self.seen_msgs.push_back(id);
    }

    fn forward_to_mesh(&self, msg: &GossipMessage) {
        let raw = msg.serialize();
        let peers = self.mesh.get(&msg.topic);
        if let Some(mesh) = peers {
            for key in mesh {
                if let Some(p) = self.peers.get(key) {
                    crate::net::udp::udp_sendto(self.udp_fd, &raw, p.ip, p.port);
                }
            }
        }
    }

    fn broadcast_control(&self, msg: &GossipMessage) {
        let raw = msg.serialize();
        for p in self.peers.values() {
            crate::net::udp::udp_sendto(self.udp_fd, &raw, p.ip, p.port);
        }
    }

    fn graft_peers(&mut self, topic: &str, count: usize) {
        // Score‑based selection: pick peers with highest score that are subscribed but not in mesh.
        let mut candidates: Vec<(u64, i32)> = self
            .peers
            .iter()
            .filter(|(k, p)| {
                p.topics.contains(topic) && !self.mesh.get(topic).map(|m| m.contains(k)).unwrap_or(false)
            })
            .map(|(k, p)| (*k, p.score))
            .collect();
        candidates.sort_by(|a, b| b.1.cmp(&a.1));
        candidates.truncate(count);

        for (key, _score) in candidates {
            let msg = GossipMessage {
                msg_type: MsgType::Graft,
                msg_id: 0,
                topic: topic.to_string(),
                data: Vec::new(),
                ttl: 1,
            };
            if let Some(p) = self.peers.get(&key) {
                crate::net::udp::udp_sendto(self.udp_fd, &msg.serialize(), p.ip, p.port);
            }
            self.mesh.entry(topic.to_string()).or_default().insert(key);
            if let Some(p) = self.peers.get_mut(&key) {
                p.mesh.insert(topic.to_string());
            }
        }
    }

    fn prune_peers(&mut self, topic: &str, count: usize) {
        // Prune lowest‑scoring peers first.
        let mut mesh_peers: Vec<(u64, i32)> = self
            .mesh
            .get(topic)
            .map(|m| {
                m.iter()
                    .filter_map(|k| self.peers.get(k).map(|p| (*k, p.score)))
                    .collect()
            })
            .unwrap_or_default();
        mesh_peers.sort_by(|a, b| a.1.cmp(&b.1));
        mesh_peers.truncate(count);

        for (key, _score) in mesh_peers {
            self.send_prune(topic, key);
            if let Some(mesh) = self.mesh.get_mut(topic) {
                mesh.remove(&key);
            }
            if let Some(p) = self.peers.get_mut(&key) {
                p.mesh.remove(topic);
            }
        }
    }

    fn send_prune(&self, topic: &str, peer_key: u64) {
        let msg = GossipMessage {
            msg_type: MsgType::Prune,
            msg_id: 0,
            topic: topic.to_string(),
            data: Vec::new(),
            ttl: 1,
        };
        if let Some(p) = self.peers.get(&peer_key) {
            crate::net::udp::udp_sendto(self.udp_fd, &msg.serialize(), p.ip, p.port);
        }
    }

    fn send_iwant(&self, topic: &str, msg_id: u32, peer_key: u64) {
        let msg = GossipMessage {
            msg_type: MsgType::IWant,
            msg_id,
            topic: topic.to_string(),
            data: msg_id.to_le_bytes().to_vec(),
            ttl: 1,
        };
        if let Some(p) = self.peers.get(&peer_key) {
            crate::net::udp::udp_sendto(self.udp_fd, &msg.serialize(), p.ip, p.port);
        }
    }

    fn emit_ihave(&self) {
        if self.seen_msgs.is_empty() {
            return;
        }
        let mut ids = Vec::with_capacity(self.seen_msgs.len() * 4);
        for &id in &self.seen_msgs {
            ids.extend_from_slice(&id.to_le_bytes());
        }
        for topic in &self.subscriptions {
            let msg = GossipMessage {
                msg_type: MsgType::IHave,
                msg_id: 0,
                topic: topic.clone(),
                data: ids.clone(),
                ttl: 1,
            };
            let raw = msg.serialize();
            // Send to non‑mesh peers that are subscribed to the topic.
            let mesh_peers = self.mesh.get(topic.as_str()).cloned().unwrap_or_default();
            for (k, p) in &self.peers {
                if !mesh_peers.contains(k) && p.topics.contains(topic.as_str()) {
                    crate::net::udp::udp_sendto(self.udp_fd, &raw, p.ip, p.port);
                }
            }
        }
    }

    fn evict_stale_peers(&mut self, now: u64) {
        let threshold = now.saturating_sub(self.config.evict_timeout_ms);
        let stale: Vec<u64> = self
            .peers
            .iter()
            .filter(|(_, p)| p.seen_ms > 0 && p.seen_ms < threshold)
            .map(|(k, _)| *k)
            .collect();
        for key in stale {
            if let Some(p) = self.peers.remove(&key) {
                debug!(addr = %p.addr_string(), "evicted stale peer");
            }
        }
    }
}

// -----------------------------------------------------------------------------
// PeerDiscovery with backoff
// -----------------------------------------------------------------------------

/// Peer discovery state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerState {
    Unknown,
    Connecting,
    Connected,
    Subscribed,
    Evicted { reason: String },
}

/// Peer discovery manager with exponential backoff.
pub struct PeerDiscovery {
    pub node: GossipNode,
    states: BTreeMap<u64, PeerState>,
    reconnect_at: BTreeMap<u64, u64>,
    backoff: BTreeMap<u64, u64>,
    config: GossipConfig,
}

impl PeerDiscovery {
    pub fn new(port: u16, config: GossipConfig) -> Self {
        Self {
            node: GossipNode::new(port, config.clone()),
            states: BTreeMap::new(),
            reconnect_at: BTreeMap::new(),
            backoff: BTreeMap::new(),
            config,
        }
    }

    /// Maintenance tick — call regularly (e.g., every second).
    pub fn tick(&mut self) {
        let now = crate::arch::x86_64::timer::uptime_ms();

        // Process incoming messages.
        while let Ok(true) = self.node.poll() {}

        // Heartbeat.
        self.node.heartbeat();

        // Reconnect peers whose backoff has expired.
        let to_reconnect: Vec<u64> = self
            .reconnect_at
            .iter()
            .filter(|(_, &t)| t <= now)
            .map(|(&k, _)| k)
            .collect();
        for key in to_reconnect {
            self.reconnect_at.remove(&key);
            if let Some(p) = self.node.peers.get_mut(&key) {
                // Send a subscription announcement to re‑establish.
                let msg = GossipMessage {
                    msg_type: MsgType::Subscribe,
                    msg_id: 0,
                    topic: "iona/blocks".to_string(),
                    data: Vec::new(),
                    ttl: 1,
                };
                let raw = msg.serialize();
                crate::net::udp::udp_sendto(self.node.udp_fd, &raw, p.ip, p.port);
                debug!(addr = %p.addr_string(), "attempting reconnection");
                self.states.insert(key, PeerState::Connecting);
            }
        }

        // Evict stale peers and schedule reconnection with backoff.
        let threshold = now.saturating_sub(self.config.evict_timeout_ms);
        let stale: Vec<u64> = self
            .node
            .peers
            .iter()
            .filter(|(_, p)| p.seen_ms > 0 && p.seen_ms < threshold)
            .map(|(k, _)| *k)
            .collect();
        for key in stale {
            if let Some(p) = self.node.peers.remove(&key) {
                debug!(addr = %p.addr_string(), "evicted peer, scheduling reconnect");
                let backoff = self.backoff.entry(key).or_insert(self.config.reconnect_backoff_base_ms);
                let delay = (*backoff).min(self.config.max_reconnect_backoff_ms);
                self.reconnect_at.insert(key, now + delay);
                *backoff = (*backoff * 2).min(self.config.max_reconnect_backoff_ms);
                self.states.insert(key, PeerState::Evicted {
                    reason: format!("timeout (backoff {}ms)", delay),
                });
            }
        }
    }

    /// Get the number of connected peers.
    pub fn connected_count(&self) -> usize {
        self.states.values().filter(|s| **s == PeerState::Connected).count()
    }

    /// Get the peer state for a given key.
    pub fn peer_state(&self, key: u64) -> Option<&PeerState> {
        self.states.get(&key)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_message_serialization_roundtrip() {
        let msg = GossipMessage::new_publish("test/topic", vec![1, 2, 3, 4]);
        let raw = msg.serialize();
        let decoded = GossipMessage::deserialize(&raw, 65535).unwrap();
        assert_eq!(decoded.msg_type, msg.msg_type);
        assert_eq!(decoded.msg_id, msg.msg_id);
        assert_eq!(decoded.topic, msg.topic);
        assert_eq!(decoded.data, msg.data);
        assert_eq!(decoded.ttl, msg.ttl);
    }

    #[test]
    fn test_message_deserialize_invalid() {
        let raw = vec![0x00]; // invalid msg type
        let res = GossipMessage::deserialize(&raw, 65535);
        assert!(res.is_err());
    }

    #[test]
    fn test_message_too_large() {
        let data = vec![0u8; 100000];
        let msg = GossipMessage::new_publish("topic", data);
        let res = GossipMessage::deserialize(&msg.serialize(), 65535);
        assert!(res.is_err());
    }

    #[test]
    fn test_compute_id_deterministic() {
        let id1 = GossipMessage::compute_id("foo", b"bar");
        let id2 = GossipMessage::compute_id("foo", b"bar");
        assert_eq!(id1, id2);
        let id3 = GossipMessage::compute_id("foo", b"baz");
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_peer_key() {
        let p = Peer::new([192, 168, 1, 1], 8080);
        let key = p.key();
        let p2 = Peer::new([192, 168, 1, 1], 8080);
        assert_eq!(key, p2.key());
        let p3 = Peer::new([192, 168, 1, 2], 8080);
        assert_ne!(key, p3.key());
    }
}
