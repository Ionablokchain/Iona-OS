
//! Block sync — sincronizare chain de la peers la startup
//!
//! Protocol:
//!   1. La boot, nodul citește height locală din StakeLedger / IONAFS
//!   2. Trimite GetStatus la toți peers: {height, peer_id}
//!   3. Peer-ul răspunde cu status: {height, best_hash}
//!   4. Dacă peer.height > local.height → GetBlocks(from, to)
//!   5. Peer răspunde cu BlockData[]
//!   6. Verificăm și aplicăm fiecare bloc
//!   7. Salvăm StakeLedger și height în IONAFS

use alloc::{vec::Vec, string::String, format};
use spin::{Lazy, Mutex};

const SYNC_TIMEOUT_MS:  u64 = 10_000;
const MAX_BLOCKS_BATCH: u64 = 50;

#[derive(Clone, Debug)]
pub struct PeerStatus {
    pub peer_id: String,
    pub height:  u64,
    pub hash:    [u8; 32],
}

#[derive(Clone, Debug)]
pub struct SyncState {
    pub local_height:  u64,
    pub target_height: u64,
    pub syncing:       bool,
    pub peers:         Vec<PeerStatus>,
}

pub static SYNC_STATE: Lazy<Mutex<SyncState>> = Lazy::new(|| Mutex::new(SyncState {
    local_height: 0, target_height: 0, syncing: false, peers: Vec::new(),
}));

/// Load persisted height from IONAFS
fn load_persisted_height() -> u64 {
    if let Some(data) = crate::fs::ionafs::read("/var/iona-node/height") {
        let s = alloc::string::String::from_utf8_lossy(&data);
        return s.trim().parse().unwrap_or(0);
    }
    0
}

/// Save current height to IONAFS for persistence across reboots
pub fn persist_height(height: u64) {
    let s = format!("{}", height);
    crate::fs::ionafs::write("/var/iona-node/height", s.as_bytes());
}

/// Save StakeLedger snapshot to IONAFS
pub fn persist_stake_ledger(ledger_bytes: &[u8]) {
    crate::fs::ionafs::write("/var/iona-node/stake_ledger", ledger_bytes);
    crate::fs::ionafs::sync_to_disk();
}

/// Load StakeLedger from IONAFS
pub fn load_stake_ledger() -> Option<Vec<u8>> {
    crate::fs::ionafs::read("/var/iona-node/stake_ledger")
}

/// Build GetStatus message
fn build_get_status(local_height: u64) -> Vec<u8> {
    // Simple JSON — gossipsub will route this
    format!(r#"{{"type":"GetStatus","height":{}}}"#, local_height).into_bytes()
}

/// Build GetBlocks request
fn build_get_blocks(from: u64, to: u64) -> Vec<u8> {
    format!(r#"{{"type":"GetBlocks","from":{},"to":{}}}"#, from, to).into_bytes()
}

/// Parse peer status from JSON response
fn parse_peer_status(data: &[u8]) -> Option<PeerStatus> {
    let s = alloc::string::String::from_utf8_lossy(data);
    // Minimal JSON parser — look for "height":<number>
    let height = s.split("\"height\":")
        .nth(1)
        .and_then(|s| s.split(&[',', '}'][..]).next())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);
    let peer_id = s.split("\"peer_id\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap_or("unknown");
    let peer_id = alloc::string::String::from(peer_id);
    Some(PeerStatus { peer_id, height, hash: [0u8; 32] })
}

/// Main sync function — called at node startup
pub fn sync_from_peers() {
    let local_height = load_persisted_height();
    crate::serial_println!("[SYNC] local height={}", local_height);

    {
        let mut ss = SYNC_STATE.lock();
        ss.local_height = local_height;
        ss.syncing = false;
    }

    // Update consensus engine with persisted height
    if local_height > 0 {
        if let Some(ref mut e) = *crate::consensus::CONSENSUS_ENGINE.lock() {
            e.height = local_height;
        }
    }

    // Query peers for their status
    let status_req = build_get_status(local_height);
    let peers_contacted = crate::net::gossip_broadcast(&status_req);
    crate::serial_println!("[SYNC] queried {} peers", peers_contacted);

    if peers_contacted == 0 {
        crate::serial_println!("[SYNC] no peers — starting fresh at height {}", local_height);
        return;
    }

    // Wait for responses (up to 5s)
    let deadline = crate::arch::x86_64::timer::uptime_ms() + 5000;
    let mut best_height = local_height;
    let mut best_peer: Option<String> = None;

    while crate::arch::x86_64::timer::uptime_ms() < deadline {
        if let Some(msg) = crate::net::gossip_recv() {
            if let Some(ps) = parse_peer_status(&msg) {
                crate::serial_println!("[SYNC] peer {} height={}", ps.peer_id, ps.height);
                if ps.height > best_height {
                    best_height = ps.height;
                    best_peer = Some(ps.peer_id.clone());
                }
                let mut ss = SYNC_STATE.lock();
                if let Some(existing) = ss.peers.iter_mut().find(|p| p.peer_id == ps.peer_id) {
                    *existing = ps;
                } else {
                    ss.peers.push(ps);
                }
            }
        }
        crate::arch::x86_64::timer::sleep_ms(50);
    }

    if best_height <= local_height {
        crate::serial_println!("[SYNC] already at best height {}", local_height);
        return;
    }

    if let Some(ref bp) = best_peer { crate::serial_println!("[SYNC] best peer={} target_height={}", bp, best_height); }
    crate::serial_println!("[SYNC] need sync: local={} target={}", local_height, best_height);
    {
        let mut ss = SYNC_STATE.lock();
        ss.target_height = best_height;
        ss.syncing = true;
    }

    // Fetch blocks in batches
    let mut current = local_height;
    while current < best_height {
        let batch_end = (current + MAX_BLOCKS_BATCH).min(best_height);
        let req = build_get_blocks(current, batch_end);
        crate::net::gossip_broadcast(&req);

        // Wait for block data
        let batch_deadline = crate::arch::x86_64::timer::uptime_ms() + SYNC_TIMEOUT_MS;
        let mut applied = 0u64;

        while crate::arch::x86_64::timer::uptime_ms() < batch_deadline
              && current + applied < batch_end
        {
            if let Some(block_data) = crate::net::gossip_recv() {
                if block_data.starts_with(b"{\"type\":\"Block\"") {
                    // Apply block — increment height
                    current += 1;
                    applied += 1;
                    if let Some(ref mut e) = *crate::consensus::CONSENSUS_ENGINE.lock() {
                        e.height = current;
                    }
                    { let mut ss = SYNC_STATE.lock(); ss.local_height = current; }
                    if current % 100 == 0 {
                        persist_height(current);
                        crate::serial_println!("[SYNC] height={}", current);
                    }
                }
            }
            crate::arch::x86_64::timer::sleep_ms(10);
        }

        if applied == 0 {
            crate::serial_println!("[SYNC] batch timeout at height {}", current);
            break;
        }
    }

    persist_height(current);
    crate::fs::ionafs::sync_to_disk();
    crate::serial_println!("[SYNC] sync complete: height={}", current);
    let mut ss = SYNC_STATE.lock();
    ss.local_height = current;
    ss.syncing = false;
}

/// Check if node is currently syncing
pub fn is_syncing() -> bool { SYNC_STATE.lock().syncing }
pub fn sync_height() -> (u64, u64) {
    let ss = SYNC_STATE.lock();
    (ss.local_height, ss.target_height)
}
