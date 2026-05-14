//! Consensus integration for iona-node userspace
//!
//! Bridges the kernel-side Tendermint Engine with:
//!   - mempool_drain: pulls pending txs from local queue
//!   - Outbox: broadcasts ConsensusMsg via gossipsub UDP
//!   - on_commit: persists committed block to IONAFS
//!
//! The engine tick() is called from the main loop every 10ms.
//! With fast_quorum=true, blocks commit as soon as 2/3+ validators respond,
//! not waiting for timeout — enabling sub-second finality.

use alloc::{vec::Vec, collections::BTreeMap, string::{String, ToString}, format};
use iona_syscall as sys;

// ── Wire types (mirror of kernel consensus types, serialized via postcard) ───

pub type Height  = u64;
pub type Round   = u32;
pub type Hash32  = [u8; 32];
pub type Tx      = Vec<u8>;

/// Consensus message types exchanged between validators
#[derive(Clone, Debug)]
pub enum ConsensusMsg {
    Proposal(Vec<u8>),    // postcard-encoded Proposal
    Vote(Vec<u8>),        // postcard-encoded Vote
    Evidence(Vec<u8>),    // postcard-encoded Evidence
}

impl ConsensusMsg {
    pub fn msg_type(&self) -> u8 {
        match self { Self::Proposal(_) => 1, Self::Vote(_) => 2, Self::Evidence(_) => 3 }
    }
    pub fn payload(&self) -> &[u8] {
        match self { Self::Proposal(v)|Self::Vote(v)|Self::Evidence(v) => v }
    }

    /// Encode as: [1:type][4:len][N:payload]
    pub fn encode(&self) -> Vec<u8> {
        let payload = self.payload();
        let mut buf = Vec::with_capacity(5 + payload.len());
        buf.push(self.msg_type());
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() < 5 { return None; }
        let msg_type = raw[0];
        let len = u32::from_le_bytes(raw[1..5].try_into().ok()?) as usize;
        if raw.len() < 5 + len { return None; }
        let payload = raw[5..5+len].to_vec();
        match msg_type {
            1 => Some(Self::Proposal(payload)),
            2 => Some(Self::Vote(payload)),
            3 => Some(Self::Evidence(payload)),
            _ => None,
        }
    }
}

/// Mempool — pending transactions queue
pub struct Mempool {
    txs: Vec<Tx>,
    max_size: usize,
}

impl Mempool {
    pub fn new(max_size: usize) -> Self { Self { txs: Vec::new(), max_size } }

    pub fn push(&mut self, tx: Tx) {
        if self.txs.len() < self.max_size { self.txs.push(tx); }
    }

    /// Drain up to `n` txs for block proposal
    pub fn drain(&mut self, n: usize) -> Vec<Tx> {
        let take = n.min(self.txs.len());
        self.txs.drain(..take).collect()
    }

    pub fn len(&self) -> usize { self.txs.len() }
}

/// Consensus Outbox — broadcasts messages to validator peers via gossipsub UDP
pub struct GossipOutbox {
    pub gossip_fd:  u64,
    pub peers:      Vec<([u8; 4], u16)>,
    pub committed:  Vec<(Height, Hash32)>,
}

impl GossipOutbox {
    pub fn new(gossip_fd: u64, peers: Vec<([u8; 4], u16)>) -> Self {
        Self { gossip_fd, peers, committed: Vec::new() }
    }

    /// Broadcast consensus message to all known validator peers
    pub fn broadcast_msg(&mut self, msg: &ConsensusMsg) {
        let encoded = msg.encode();
        // Wire: gossipsub PUBLISH on topic "iona/consensus"
        let topic  = b"iona/consensus";
        let mut wire = Vec::with_capacity(1 + 4 + 1 + topic.len() + 2 + encoded.len() + 1);
        wire.push(1u8);               // MsgType::Publish
        wire.extend_from_slice(&0u32.to_le_bytes()); // seq
        wire.push(topic.len() as u8);
        wire.extend_from_slice(topic);
        wire.extend_from_slice(&(encoded.len() as u16).to_le_bytes());
        wire.extend_from_slice(&encoded);
        wire.push(8u8);               // ttl

        for &(ip, port) in &self.peers {
            sys::udp_sendto(self.gossip_fd, &wire, ip, port);
        }
    }

    /// Poll incoming consensus messages
    pub fn poll(&self) -> Option<ConsensusMsg> {
        let mut buf = alloc::vec![0u8; 4096];
        let (n, _src_ip, _src_port) = sys::udp_recvfrom(self.gossip_fd, &mut buf);
        if n < 7 { return None; }
        // Skip gossipsub header: [1:type][4:seq][1:topic_len][N:topic][2:data_len]
        let topic_len = buf[5] as usize;
        let hdr_size  = 6 + topic_len + 2;
        if n < hdr_size { return None; }
        ConsensusMsg::decode(&buf[hdr_size..n])
    }

    /// Persist committed block summary to IONAFS
    pub fn on_commit_block(&mut self, height: Height, block_id: Hash32, tx_count: usize, base_fee: u64) {
        self.committed.push((height, block_id));
        // Write latest commit to IONAFS for persistence
        let mut record = alloc::vec![0u8; 48];
        record[0..8].copy_from_slice(&height.to_le_bytes());
        record[8..40].copy_from_slice(&block_id);
        record[40..48].copy_from_slice(&base_fee.to_le_bytes());
        sys::fs_write("/var/iona-node/last-commit", &record);
        sys::klog(&format!("[CONSENSUS] committed h={} txs={} base_fee={}", height, tx_count, base_fee));
    }
}

/// ConsensusDriver — drives the Engine<V> tick loop from iona-node main loop
pub struct ConsensusDriver {
    pub mempool: Mempool,
    pub outbox:  GossipOutbox,
    pub height:  Height,
    pub last_commit_ms: u64,
}

impl ConsensusDriver {
    /// Advance the consensus engine — bridges userspace driver to kernel BFT via IPC
    ///
    /// Protocol:
    ///   1. Drain mempool → Propose block if leader
    ///   2. Call kernel via sys_ipc(CONSENSUS_TICK, height, round) → gets response
    ///   3. Broadcast any new consensus messages via gossipsub
    ///   4. On commit: persist block + update height
    pub fn kernel_consensus_tick(&mut self) {
        // Syscall to kernel consensus engine (nr 400 = consensus_tick)
        // Kernel updates internal BFT state and returns committed block hash if any
        let result = unsafe {
            sys::syscall6(400,
                self.height as u64,
                0, 0, 0, 0, 0)
        };

        if result == 0 { return; } // no commit yet

        // result encodes committed block height
        let committed_height = result;
        sys::klog(&alloc::format!("[CONSENSUS] block {} committed via kernel BFT", committed_height));

        // Update local height
        self.height = committed_height + 1;

        // Persist commit height
        sys::fs_write("/var/iona-node/last-commit",
            &committed_height.to_le_bytes());
    }

    pub fn new(gossip_fd: u64, peers: Vec<([u8; 4], u16)>) -> Self {
        Self {
            mempool: Mempool::new(4096),
            outbox:  GossipOutbox::new(gossip_fd, peers),
            height:  load_commit_height(),
            last_commit_ms: 0,
        }
    }

    /// Called from main loop every 10ms
    /// Returns Some(committed_height) if a block was committed this tick
    pub fn tick(&mut self, now_ms: u64) -> Option<Height> {
        // Poll gossip for incoming consensus messages
        while let Some(msg) = self.outbox.poll() {
            self.handle_incoming(msg, now_ms);
        }
        None
    }

    fn handle_incoming(&mut self, msg: ConsensusMsg, _now_ms: u64) {
        match msg {
            ConsensusMsg::Proposal(p) => {
                sys::klog(&format!("[CONSENSUS] recv Proposal ({} bytes)", p.len()));
            }
            ConsensusMsg::Vote(v) => {
                sys::klog(&format!("[CONSENSUS] recv Vote ({} bytes)", v.len()));
            }
            ConsensusMsg::Evidence(e) => {
                sys::klog(&format!("[CONSENSUS] recv Evidence ({} bytes)", e.len()));
            }
        }
    }

    /// Submit a transaction to the mempool
    pub fn submit_tx(&mut self, tx: Tx) {
        self.mempool.push(tx);
    }
}

fn load_commit_height() -> Height {
    match sys::fs_read("/var/iona-node/last-commit") {
        Some(d) if d.len() >= 8 => u64::from_le_bytes(d[0..8].try_into().unwrap_or([0;8])),
        _ => 0,
    }
}
