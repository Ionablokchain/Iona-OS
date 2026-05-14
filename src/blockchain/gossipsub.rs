//! Gossipsub P2P protocol — stable implementation
//!
//! Implements the libp2p Gossipsub v1.1 spec (simplified for no_std):
//!   PUBLISH    — broadcast a message to the mesh
//!   SUBSCRIBE  — subscribe to a topic
//!   GRAFT      — add a peer to the mesh for a topic
//!   PRUNE      — remove a peer from the mesh for a topic
//!   IHAVE      — announce message IDs we have
//!   IWANT      — request specific messages by ID
//!
//! Transport: UDP (via sys_udp_bind/sendto/recvfrom)
//! Message ID: FNV-1a(topic + data)[0..8]
//! Mesh size: D=6 (target), Dlow=4, Dhigh=12
//! Heartbeat: every 1000ms — prune/graft to maintain mesh size

use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    string::String,
    vec::Vec,
};

const D:         usize = 6;   // target mesh degree
const D_LOW:     usize = 4;   // minimum mesh degree
const D_HIGH:    usize = 12;  // maximum mesh degree
const TTL:       u8    = 8;   // message hop limit
const HISTORY:   usize = 120; // message IDs to remember (for dedup)
const MAX_MSG_SZ: usize = 65_000;

/// Message types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MsgType {
    Publish   = 1,
    Subscribe = 2,
    Unsubscribe = 3,
    Graft     = 4,
    Prune     = 5,
    IHave     = 6,
    IWant     = 7,
    Control   = 8,
}

/// Wire format (simple binary, not protobuf for no_std)
/// [1: type][4: msg_id][1: topic_len][N: topic][2: data_len][N: data][1: ttl]
#[derive(Clone)]
pub struct GossipMessage {
    pub msg_type:  MsgType,
    pub msg_id:    u32,
    pub topic:     String,
    pub data:      Vec<u8>,
    pub ttl:       u8,
}

impl GossipMessage {
    pub fn new_publish(topic: &str, data: Vec<u8>) -> Self {
        let id = Self::compute_id(topic, &data);
        Self { msg_type: MsgType::Publish, msg_id: id, topic: topic.into(), data, ttl: TTL }
    }

    pub fn compute_id(topic: &str, data: &[u8]) -> u32 {
        // FNV-1a 32-bit hash
        let mut h: u32 = 2166136261;
        for b in topic.bytes().chain(data.iter().cloned()) {
            h ^= b as u32;
            h  = h.wrapping_mul(16777619);
        }
        h
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
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

    pub fn deserialize(raw: &[u8]) -> Option<Self> {
        if raw.len() < 8 { return None; }
        let msg_type = match raw[0] {
            1 => MsgType::Publish,   2 => MsgType::Subscribe,
            3 => MsgType::Unsubscribe, 4 => MsgType::Graft,
            5 => MsgType::Prune,     6 => MsgType::IHave,
            7 => MsgType::IWant,     8 => MsgType::Control,
            _ => return None,
        };
        let msg_id    = u32::from_le_bytes(raw[1..5].try_into().ok()?);
        let topic_len = raw[5] as usize;
        if raw.len() < 6 + topic_len + 2 { return None; }
        let topic = String::from_utf8_lossy(&raw[6..6+topic_len]).into_owned();
        let data_len  = u16::from_le_bytes(raw[6+topic_len..8+topic_len].try_into().ok()?) as usize;
        let data_start = 8 + topic_len;
        if raw.len() < data_start + data_len + 1 { return None; }
        let data = raw[data_start..data_start+data_len].to_vec();
        let ttl  = raw[data_start + data_len];
        Some(GossipMessage { msg_type, msg_id, topic, data, ttl })
    }
}

#[derive(Clone, Debug)]
pub struct Peer {
    pub ip:      [u8; 4],
    pub port:    u16,
    pub topics:  BTreeSet<String>,
    pub mesh:    BTreeSet<String>, // topics where this peer is in our mesh
    pub score:   i32,              // peer score (higher = more reliable)
    pub seen_ms: u64,              // last seen
}

impl Peer {
    pub fn new(ip: [u8; 4], port: u16) -> Self {
        Self { ip, port, topics: BTreeSet::new(), mesh: BTreeSet::new(),
               score: 0, seen_ms: 0 }
    }

    pub fn addr_key(&self) -> u64 {
        ((self.ip[0] as u64) << 40) | ((self.ip[1] as u64) << 32) |
        ((self.ip[2] as u64) << 24) | ((self.ip[3] as u64) << 16) |
        (self.port as u64)
    }
}

pub struct GossipNode {
    pub local_port:    u16,
    pub udp_fd:        u64,
    peers:             BTreeMap<u64, Peer>,   // addr_key → Peer
    subscriptions:     BTreeSet<String>,
    mesh:              BTreeMap<String, BTreeSet<u64>>, // topic → peer keys in mesh
    seen_msgs:         VecDeque<u32>,          // recent msg IDs (dedup)
    inbox:             VecDeque<(String, Vec<u8>)>, // received messages
    last_heartbeat_ms: u64,
}

impl GossipNode {
    pub fn new(port: u16) -> Self {
        let fd = crate::net::udp::udp_bind(port);
        crate::serial_println!("  [GOSSIP] node bound to :{}", port);
        Self {
            local_port: port, udp_fd: fd,
            peers: BTreeMap::new(), subscriptions: BTreeSet::new(),
            mesh: BTreeMap::new(), seen_msgs: VecDeque::new(),
            inbox: VecDeque::new(), last_heartbeat_ms: 0,
        }
    }

    /// Add a known peer
    pub fn add_peer(&mut self, ip: [u8; 4], port: u16) {
        let p = Peer::new(ip, port);
        let k = p.addr_key();
        self.peers.insert(k, p);
    }

    /// Subscribe to a topic
    pub fn subscribe(&mut self, topic: &str) {
        self.subscriptions.insert(topic.into());
        self.mesh.entry(topic.into()).or_default();
        // Send SUBSCRIBE to all peers
        let msg = GossipMessage {
            msg_type: MsgType::Subscribe, msg_id: 0,
            topic: topic.into(), data: Vec::new(), ttl: 1,
        };
        self.broadcast_control(&msg);
        crate::serial_println!("  [GOSSIP] subscribed to '{}'", topic);
    }

    /// Publish a message to a topic
    pub fn publish(&mut self, topic: &str, data: Vec<u8>) -> u32 {
        let msg = GossipMessage::new_publish(topic, data);
        let id  = msg.msg_id;
        self.record_seen(id);
        self.forward_to_mesh(&msg);
        id
    }

    /// Receive and process one incoming UDP packet. Returns true if packet received.
    pub fn poll(&mut self) -> bool {
        let mut buf = alloc::vec![0u8; MAX_MSG_SZ];
        let (n, src_ip, src_port) = crate::net::udp::udp_recvfrom(self.udp_fd, &mut buf);
        if n == 0 { return false; }

        let msg = match GossipMessage::deserialize(&buf[..n]) {
            Some(m) => m,
            None    => return false,
        };

        let src_key = Peer::new(src_ip, src_port).addr_key();

        // Update peer last-seen
        if let Some(p) = self.peers.get_mut(&src_key) {
            p.seen_ms = crate::arch::x86_64::timer::uptime_ms();
            p.score  += 1;
        } else {
            // Auto-add unknown peers (peer discovery)
            let mut p = Peer::new(src_ip, src_port);
            p.seen_ms = crate::arch::x86_64::timer::uptime_ms();
            self.peers.insert(src_key, p);
        }

        match msg.msg_type {
            MsgType::Publish => self.handle_publish(&msg, src_key),
            MsgType::Subscribe => self.handle_subscribe(&msg, src_key),
            MsgType::Unsubscribe => self.handle_unsubscribe(&msg, src_key),
            MsgType::Graft => self.handle_graft(&msg, src_key),
            MsgType::Prune => self.handle_prune(&msg, src_key),
            MsgType::IHave => self.handle_ihave(&msg, src_key),
            MsgType::IWant => self.handle_iwant(&msg, src_key),
            MsgType::Control => {}
        }
        true
    }

    /// Read one received message from inbox
    pub fn recv(&mut self) -> Option<(String, Vec<u8>)> {
        self.inbox.pop_front()
    }

    /// Heartbeat — called every ~1000ms
    /// Maintains mesh: grafts/prunes to keep D peers per topic
    pub fn heartbeat(&mut self) {
        let now = crate::arch::x86_64::timer::uptime_ms();
        if now - self.last_heartbeat_ms < 1000 { return; }
        self.last_heartbeat_ms = now;

        for topic in self.subscriptions.clone().iter() {
            let mesh_size = self.mesh.get(topic).map(|s| s.len()).unwrap_or(0);

            if mesh_size < D_LOW {
                // Need more peers — send GRAFT to fanout peers
                self.graft_peers(topic, D - mesh_size);
            } else if mesh_size > D_HIGH {
                // Too many peers — send PRUNE
                self.prune_peers(topic, mesh_size - D);
            }
        }

        // Send IHAVE for recent messages (gossip about what we have)
        self.emit_ihave();

        // Remove stale peers (not seen in 60s)
        let stale_threshold = now.saturating_sub(60_000);
        let stale: Vec<u64> = self.peers.iter()
            .filter(|(_, p)| p.seen_ms > 0 && p.seen_ms < stale_threshold)
            .map(|(k, _)| *k)
            .collect();
        for k in stale {
            self.peers.remove(&k);
        }
    }

    // ── Internal handlers ─────────────────────────────────────────────────────

    fn handle_publish(&mut self, msg: &GossipMessage, _from: u64) {
        if !self.subscriptions.contains(&msg.topic) { return; }
        if self.seen_msgs.contains(&msg.msg_id) { return; } // duplicate

        self.record_seen(msg.msg_id);
        self.inbox.push_back((msg.topic.clone(), msg.data.clone()));

        // Forward if TTL > 0
        if msg.ttl > 1 {
            let mut fwd = msg.clone();
            fwd.ttl -= 1;
            self.forward_to_mesh(&fwd);
        }
    }

    fn handle_subscribe(&mut self, msg: &GossipMessage, from: u64) {
        if let Some(p) = self.peers.get_mut(&from) {
            p.topics.insert(msg.topic.clone());
        }
    }

    fn handle_unsubscribe(&mut self, msg: &GossipMessage, from: u64) {
        if let Some(p) = self.peers.get_mut(&from) {
            p.topics.remove(&msg.topic);
        }
        if let Some(mesh) = self.mesh.get_mut(&msg.topic) { mesh.remove(&from); }
    }

    fn handle_graft(&mut self, msg: &GossipMessage, from: u64) {
        // Peer wants to join our mesh for this topic
        let mesh = self.mesh.entry(msg.topic.clone()).or_default();
        if mesh.len() < D_HIGH {
            mesh.insert(from);
            if let Some(p) = self.peers.get_mut(&from) {
                p.mesh.insert(msg.topic.clone());
            }
        } else {
            // Already at capacity — send PRUNE back
            self.send_prune(&msg.topic, from);
        }
    }

    fn handle_prune(&mut self, msg: &GossipMessage, from: u64) {
        if let Some(mesh) = self.mesh.get_mut(&msg.topic) { mesh.remove(&from); }
        if let Some(p) = self.peers.get_mut(&from) { p.mesh.remove(&msg.topic); }
    }

    fn handle_ihave(&mut self, msg: &GossipMessage, from: u64) {
        // Parse list of msg IDs peer has
        let mut i = 0;
        while i + 4 <= msg.data.len() {
            let id = u32::from_le_bytes(msg.data[i..i+4].try_into().unwrap_or([0;4]));
            if !self.seen_msgs.contains(&id) {
                // We don't have this message — send IWANT
                self.send_iwant(&msg.topic, id, from);
            }
            i += 4;
        }
    }

    fn handle_iwant(&mut self, _msg: &GossipMessage, _from: u64) {
        // Peer wants messages we've seen — we'd re-publish from cache
        // (simplified: we don't cache message bodies, just IDs)
    }

    fn record_seen(&mut self, id: u32) {
        if self.seen_msgs.len() >= HISTORY { self.seen_msgs.pop_front(); }
        self.seen_msgs.push_back(id);
    }

    fn forward_to_mesh(&self, msg: &GossipMessage) {
        let peers = match self.mesh.get(&msg.topic) {
            Some(m) => m.iter().cloned().collect::<Vec<_>>(),
            None    => return,
        };
        let raw = msg.serialize();
        for key in peers {
            if let Some(p) = self.peers.get(&key) {
                crate::net::udp::udp_sendto(self.udp_fd, &raw, p.ip, p.port);
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
        // Score-based peer selection: sort candidates by score descending, pick best
        let mut candidates: Vec<(u64, i32)> = self.peers.iter()
            .filter(|(k, p)| p.topics.contains(topic)
                           && !self.mesh.get(topic).map(|m| m.contains(k)).unwrap_or(false))
            .map(|(k, p)| (*k, p.score))
            .collect();
        // Sort by score descending (highest score first = most reliable peers)
        candidates.sort_by(|a, b| b.1.cmp(&a.1));
        candidates.truncate(count);

        for (key, _score) in candidates {
            let msg = GossipMessage {
                msg_type: MsgType::Graft, msg_id: 0,
                topic: topic.into(), data: Vec::new(), ttl: 1,
            };
            if let Some(p) = self.peers.get(&key) {
                crate::net::udp::udp_sendto(self.udp_fd, &msg.serialize(), p.ip, p.port);
            }
            self.mesh.entry(topic.into()).or_default().insert(key);
            if let Some(p) = self.peers.get_mut(&key) {
                p.mesh.insert(topic.into());
            }
        }
    }

    fn prune_peers(&mut self, topic: &str, count: usize) {
        // Score-based pruning: prune lowest-scoring peers first
        let mut mesh_peers: Vec<(u64, i32)> = self.mesh.get(topic)
            .map(|m| m.iter().filter_map(|k| {
                self.peers.get(k).map(|p| (*k, p.score))
            }).collect())
            .unwrap_or_default();
        // Sort by score ascending (lowest score first = least reliable)
        mesh_peers.sort_by(|a, b| a.1.cmp(&b.1));
        mesh_peers.truncate(count);

        for (key, _score) in mesh_peers {
            self.send_prune(topic, key);
            if let Some(mesh) = self.mesh.get_mut(topic) { mesh.remove(&key); }
            if let Some(p) = self.peers.get_mut(&key) { p.mesh.remove(topic); }
        }
    }

    fn send_prune(&self, topic: &str, peer_key: u64) {
        let msg = GossipMessage {
            msg_type: MsgType::Prune, msg_id: 0,
            topic: topic.into(), data: Vec::new(), ttl: 1,
        };
        if let Some(p) = self.peers.get(&peer_key) {
            crate::net::udp::udp_sendto(self.udp_fd, &msg.serialize(), p.ip, p.port);
        }
    }

    fn send_iwant(&self, topic: &str, msg_id: u32, peer_key: u64) {
        let msg = GossipMessage {
            msg_type: MsgType::IWant, msg_id, topic: topic.into(),
            data: msg_id.to_le_bytes().to_vec(), ttl: 1,
        };
        if let Some(p) = self.peers.get(&peer_key) {
            crate::net::udp::udp_sendto(self.udp_fd, &msg.serialize(), p.ip, p.port);
        }
    }

    fn emit_ihave(&self) {
        if self.seen_msgs.is_empty() { return; }
        let mut ids = Vec::with_capacity(self.seen_msgs.len() * 4);
        for &id in &self.seen_msgs {
            ids.extend_from_slice(&id.to_le_bytes());
        }
        for topic in &self.subscriptions {
            let msg = GossipMessage {
                msg_type: MsgType::IHave, msg_id: 0,
                topic: topic.clone(), data: ids.clone(), ttl: 1,
            };
            let raw = msg.serialize();
            // Send to peers NOT in mesh (gossip to non-mesh peers)
            let mesh_peers = self.mesh.get(topic.as_str())
                .cloned().unwrap_or_default();
            for (k, p) in &self.peers {
                if !mesh_peers.contains(k) && p.topics.contains(topic.as_str()) {
                    crate::net::udp::udp_sendto(self.udp_fd, &raw, p.ip, p.port);
                }
            }
        }
    }

    pub fn mesh_size(&self, topic: &str) -> usize {
        self.mesh.get(topic).map(|m| m.len()).unwrap_or(0)
    }

    pub fn peer_count(&self) -> usize { self.peers.len() }
}

// ── Peer Discovery State Machine ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum PeerState {
    Unknown,
    Connecting,
    Connected,
    Subscribed,
    Evicted { reason: String },
}

pub struct PeerDiscovery {
    pub node:          GossipNode,
    pub states:        alloc::collections::BTreeMap<u64, PeerState>,
    pub reconnect_at:  alloc::collections::BTreeMap<u64, u64>, // peer_key → ms
    pub evict_timeout: u64, // ms without activity before eviction
}

impl PeerDiscovery {
    pub fn new(port: u16) -> Self {
        Self {
            node: GossipNode::new(port),
            states: alloc::collections::BTreeMap::new(),
            reconnect_at: alloc::collections::BTreeMap::new(),
            evict_timeout: 60_000,
        }
    }

    /// Full maintenance tick — called every second
    pub fn tick(&mut self) {
        let now = crate::arch::x86_64::timer::uptime_ms();

        // Run gossipsub heartbeat
        self.node.heartbeat();

        // Process incoming messages
        while self.node.poll() {}

        // Check for peers to reconnect
        let to_reconnect: alloc::vec::Vec<u64> = self.reconnect_at.iter()
            .filter(|(_, &ms)| ms <= now)
            .map(|(&k, _)| k)
            .collect();
        for key in to_reconnect {
            self.reconnect_at.remove(&key);
            if let Some(p) = self.node.peers.get(&key) {
                let ip   = p.ip;
                let port = p.port;
                crate::serial_println!("  [P2P] reconnecting to {}:{}", ip[3], port);
                // Send SUBSCRIBE to re-announce ourselves
                let msg = GossipMessage {
                    msg_type: MsgType::Subscribe, msg_id: 0,
                    topic: "iona/blocks".into(), data: alloc::vec::Vec::new(), ttl: 1,
                };
                let raw = msg.serialize();
                crate::net::udp::udp_sendto(self.node.udp_fd, &raw, ip, port);
            }
        }

        // Evict stale peers
        let stale_threshold = now.saturating_sub(self.evict_timeout);
        let stale: alloc::vec::Vec<u64> = self.node.peers.iter()
            .filter(|(_, p)| p.seen_ms > 0 && p.seen_ms < stale_threshold)
            .map(|(k, _)| *k)
            .collect();
        for key in stale {
            if let Some(p) = self.node.peers.remove(&key) {
                crate::serial_println!("  [P2P] evicted {}:{} (stale)", p.ip[3], p.port);
                self.states.insert(key, PeerState::Evicted { reason: "timeout".into() });
                // Schedule reconnect in 30s
                self.reconnect_at.insert(key, now + 30_000);
            }
        }
    }

    pub fn connected_count(&self) -> usize {
        self.states.values().filter(|s| **s == PeerState::Connected).count()
    }
}
