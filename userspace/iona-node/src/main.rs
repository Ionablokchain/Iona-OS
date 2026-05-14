//! IONA Node v0.6.0 — process userspace pe IONA OS Kernel
//!
//! Aceasta este calea principală: ELF compilat, boot în ring 3 via IRETQ.
//! Nu există fallback kernel-mode în acest fișier.
//!
//! Syscall ABI (iona_syscall crate):
//!   read/write via fd 0/1/2
//!   fs_read / fs_write → IONAFS
//!   tcp_connect / tcp_send / tcp_recv → smoltcp
//!   udp_bind / udp_sendto / udp_recvfrom → gossipsub transport
//!   uptime_ms → kernel timer
//!   klog → dmesg ring buffer
//!   ipc_recv → kernel IPC queue
//!
//! Boot sequence (ring 3):
//!   1. _start → run_main → iona_main
//!   2. Load /etc/iona-node.json from IONAFS
//!   3. Bind UDP port 9000 for gossipsub
//!   4. TCP listen port 7777 for admin HTTP
//!   5. Connect to chain RPC (10.0.2.2:9001)
//!   6. Main loop: reconcile (30s) → attest (60s) → gossip (1s) → sleep (10ms)

#![no_std]
#![no_main]

extern crate alloc;

#[global_allocator]
static ALLOC: iona_syscall::IonaBumpAlloc = iona_syscall::IonaBumpAlloc;

mod supervisor;
mod reconcile;
mod attestation;
mod p2p;
mod fs;
mod consensus;

use alloc::{format, string::{String, ToString}, vec::Vec};
use iona_syscall as sys;
use supervisor::Supervisor;
use reconcile::{ReconcileEngine, DeployManifest};
use attestation::AttestationBuilder;

// ── Config ────────────────────────────────────────────────────────────────────
struct Config {
    chain_rpc:             String,
    reconcile_interval_ms: u64,
    attest_interval_ms:    u64,
    gossip_interval_ms:    u64,
    admin_port:            u16,
    gossip_port:           u16,
    validator_peers:       Vec<([u8; 4], u16)>,
    node_id:               [u8; 8],
}

impl Config {
    fn load() -> Self {
        // Read chain RPC from kernel config (syscall 322)
        let mut rpc_buf = alloc::vec![0u8; 256];
        let n = sys::get_chain_rpc_url(&mut rpc_buf);
        let chain_rpc = if n > 0 {
            String::from_utf8_lossy(&rpc_buf[..n]).into_owned()
        } else {
            "http://10.0.2.2:9001".into()
        };

        // Read local config
        let json = fs::read_json("/etc/iona-node.json");
        let reconcile_ms = json_u64(&json, "reconcile_interval_ms", 30_000);
        let attest_ms    = json_u64(&json, "attest_interval_ms",    60_000);
        let gossip_ms    = json_u64(&json, "gossip_interval_ms",     1_000);
        let admin_port   = json_u64(&json, "admin_port",   7777) as u16;
        let gossip_port  = json_u64(&json, "gossip_port",  9000) as u16;

        // Node ID from uptime + first 4 bytes of chain RPC hash
        let uptime = sys::uptime_ms();
        let node_id = [
            (uptime >> 0)  as u8, (uptime >> 8)  as u8,
            (uptime >> 16) as u8, (uptime >> 24) as u8,
            (chain_rpc.len() & 0xFF) as u8, 0x10, 0x4E, 0x41, // "NA"
        ];

        // Testnet validator peers from config
        let mut peers = Vec::new();
        // Parse "peers": ["10.0.2.2:9000", "..."]  (simplified)
        if let Some(ref js) = json {
            let mut rest = js.as_str();
            while let Some(pos) = rest.find("\"peers\"") {
                rest = &rest[pos+7..];
                // Extract peer IPs from the array
                if let Some(start) = rest.find('[') {
                    rest = &rest[start+1..];
                    if let Some(end) = rest.find(']') {
                        let arr = &rest[..end];
                        for entry in arr.split(',') {
                            let entry = entry.trim().trim_matches('"');
                            if let Some((ip_str, port_str)) = entry.rsplit_once(':') {
                                let port: u16 = port_str.parse().unwrap_or(9000);
                                let octets: Vec<u8> = ip_str.split('.').filter_map(|o| o.parse().ok()).collect();
                                if octets.len() == 4 {
                                    peers.push(([octets[0],octets[1],octets[2],octets[3]], port));
                                }
                            }
                        }
                        rest = &rest[end+1..];
                    }
                }
                break;
            }
        }
        if peers.is_empty() {
            // Default: try the chain RPC host on gossip port
            peers.push(([10,0,2,2], gossip_port));
        }

        Config { chain_rpc, reconcile_interval_ms: reconcile_ms, attest_interval_ms: attest_ms,
            gossip_interval_ms: gossip_ms, admin_port, gossip_port,
            validator_peers: peers, node_id: node_id[..8].try_into().unwrap_or([0;8]) }
    }
}

fn json_u64(json: &Option<String>, field: &str, default: u64) -> u64 {
    json.as_ref().and_then(|s| {
        let key = format!("\"{}\":", field);
        s.find(&key).and_then(|pos| {
            s[pos + key.len()..].trim_start()
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .and_then(|n| n.parse().ok())
        })
    }).unwrap_or(default)
}

// ── Entry point ───────────────────────────────────────────────────────────────
#[no_mangle]
pub extern "C" fn _start() -> ! {
    sys::run_main(iona_main)
}

fn iona_main() -> i32 {
    sys::klog("=== IONA Node v0.6.0 starting (ring 3) ===");

    let config = Config::load();
    sys::klog(&format!("[NODE] chain_rpc={}", config.chain_rpc));
    sys::klog(&format!("[NODE] gossip_port={} admin_port={}", config.gossip_port, config.admin_port));
    sys::klog(&format!("[NODE] validator_peers={}", config.validator_peers.len()));

    let mut supervisor  = Supervisor::new();
    let mut reconcile   = ReconcileEngine::new();
    let attester        = AttestationBuilder::new(config.chain_rpc.clone(), "v0.6.0-ring3".into());

    // ── Bind gossipsub UDP ────────────────────────────────────────────────────
    let gossip_fd = sys::udp_bind(config.gossip_port);
    if gossip_fd == u64::MAX {
        sys::klog("[NODE] WARNING: udp_bind failed, gossip disabled");
    } else {
        sys::klog(&format!("[NODE] gossipsub UDP bound :{}", config.gossip_port));
        // Subscribe to iona/blocks and iona/status topics
        announce_subscribe(gossip_fd, &config, "iona/blocks");
        announce_subscribe(gossip_fd, &config, "iona/status");
    }

    // ── Admin HTTP ────────────────────────────────────────────────────────────
    let admin_fd = sys::tcp_listen(config.admin_port);
    if admin_fd != u64::MAX {
        sys::klog(&format!("[NODE] admin HTTP listening :{}", config.admin_port));
    }

    // ── Main loop variables ───────────────────────────────────────────────────
    let mut height           = load_height_from_storage();
    let mut last_reconcile   = 0u64;
    let mut last_attest      = 0u64;
    let mut last_gossip      = 0u64;
    let mut last_health      = 0u64;
    let mut gossip_seq       = 0u64;
    // Consensus driver
    let peer_list: alloc::vec::Vec<([u8;4],u16)> = config.validator_peers
        .iter().map(|&(ip,p)| (ip,p)).collect();
    let mut cons = consensus::ConsensusDriver::new(gossip_fd, peer_list);

    sys::klog("[NODE] entering main loop");

    loop {
        let now = sys::uptime_ms();

        // ── Reconcile ──────────────────────────────────────────────────────────
        if now - last_reconcile >= config.reconcile_interval_ms {
            last_reconcile = now;
            height += 1;
            persist_height(height);

            match fetch_desired_state(&config.chain_rpc) {
                Ok(manifests) => {
                    let count = manifests.len();
                    reconcile.set_desired(manifests);
                    reconcile.reconcile_once(&mut supervisor);
                    sys::klog(&format!("[NODE] reconcile h={} manifests={} procs={}",
                        height, count, supervisor.running_count()));
                }
                Err(e) => sys::klog(&format!("[NODE] fetch_desired failed: {}", e)),
            }
            supervisor.tick();
        }

        // ── Attestation ────────────────────────────────────────────────────────
        if now - last_attest >= config.attest_interval_ms {
            last_attest = now;
            let ok = attester.submit(&supervisor, height);
            sys::klog(&format!("[NODE] attest h={} ok={}", height, ok));
        }

        // ── Gossip ─────────────────────────────────────────────────────────────
        if now - last_gossip >= config.gossip_interval_ms && gossip_fd != u64::MAX {
            last_gossip = now;
            gossip_seq += 1;
            gossip_heartbeat(gossip_fd, &config, height, gossip_seq);
            // Poll incoming gossip messages
            recv_gossip(gossip_fd);
        }

        // ── Admin HTTP (non-blocking accept) ───────────────────────────────────
        if admin_fd != u64::MAX {
            let conn = sys::tcp_accept(admin_fd);
            if conn != u64::MAX {
                handle_admin(conn, &supervisor, height, now);
            }
        }

        // ── IPC commands ───────────────────────────────────────────────────────
        while let Some(msg) = sys::ipc_recv() {
            handle_ipc(&msg, &mut supervisor, &mut reconcile);
        }

        // ── Health log every 60s ───────────────────────────────────────────────
        if now - last_health >= 60_000 {
            last_health = now;
            let (tf, uf) = sys::mem_stats();
            sys::klog(&format!("[NODE] health h={} mem={}MB/{}MB uptime={:.0}s",
                height, uf*4/1024, tf*4/1024, now as f64/1000.0));
        }

        // Consensus tick — drives Tendermint BFT engine
        let _ = cons.tick(now);

        sys::sleep_ms(10);
    }
}

// ── Storage persistence ────────────────────────────────────────────────────────
fn load_height_from_storage() -> u64 {
    match sys::fs_read("/var/iona-node/height") {
        Some(data) if data.len() >= 8 => u64::from_le_bytes(data[..8].try_into().unwrap_or([0;8])),
        _ => 0,
    }
}

fn persist_height(h: u64) {
    sys::fs_write("/var/iona-node/height", &h.to_le_bytes());
}

// ── Gossip ────────────────────────────────────────────────────────────────────
fn announce_subscribe(fd: u64, config: &Config, topic: &str) {
    // Wire format: [1:type=SUBSCRIBE][4:msg_id=0][1:topic_len][N:topic][2:data_len=0][1:ttl=1]
    let tb = topic.as_bytes();
    let mut msg = alloc::vec![
        2u8,                           // MsgType::Subscribe
        0,0,0,0,                       // msg_id = 0
        tb.len() as u8,                // topic_len
    ];
    msg.extend_from_slice(tb);
    msg.extend_from_slice(&[0u8, 0]);  // data_len = 0
    msg.push(1);                       // ttl

    for &(ip, port) in &config.validator_peers {
        sys::udp_sendto(fd, &msg, ip, port);
    }
    sys::klog(&format!("[GOSSIP] subscribed to '{}'", topic));
}

fn gossip_heartbeat(fd: u64, config: &Config, height: u64, seq: u64) {
    // PUBLISH iona/status with height payload
    let topic = b"iona/status";
    let data  = height.to_le_bytes();

    let mut msg = alloc::vec![
        1u8,                                        // MsgType::Publish
        (seq & 0xFF) as u8, ((seq>>8)&0xFF) as u8,
        ((seq>>16)&0xFF) as u8, ((seq>>24)&0xFF) as u8,
        topic.len() as u8,
    ];
    msg.extend_from_slice(topic);
    msg.extend_from_slice(&(data.len() as u16).to_le_bytes());
    msg.extend_from_slice(&data);
    msg.push(8); // ttl

    for &(ip, port) in &config.validator_peers {
        sys::udp_sendto(fd, &msg, ip, port);
    }
}

fn recv_gossip(fd: u64) {
    let mut buf = alloc::vec![0u8; 4096];
    let (n, src_ip, src_port) = sys::udp_recvfrom(fd, &mut buf);
    if n > 0 {
        sys::klog(&format!("[GOSSIP] recv {}B from {}.{}.{}.{}:{}",
            n, src_ip[0], src_ip[1], src_ip[2], src_ip[3], src_port));
    }
}

// ── Desired state fetch ───────────────────────────────────────────────────────
fn fetch_desired_state(chain_url: &str) -> Result<Vec<DeployManifest>, &'static str> {
    let url  = format!("{}/chain/desired_state", chain_url);
    // Parse host IP from URL (default to 10.0.2.2:8080)
    let fd   = sys::tcp_connect([10, 0, 2, 2], 8080);
    let req  = format!("GET /chain/desired_state HTTP/1.0
Host: iona

");
    sys::tcp_send(fd, req.as_bytes());

    let mut buf = alloc::vec![0u8; 8192];
    let n = sys::tcp_recv(fd, &mut buf);
    sys::tcp_close(fd);

    let body = core::str::from_utf8(&buf[..n.min(buf.len())]).map_err(|_| "non-UTF8")?;
    // Skip HTTP headers
    let json = body.find("

").map(|p| &body[p+4..]).unwrap_or(body);
    Ok(parse_manifests(json))
}

fn parse_manifests(json: &str) -> Vec<DeployManifest> {
    let mut result = Vec::new();
    let mut rest   = json;
    while let Some(start) = rest.find("{\"name\":") {
        rest     = &rest[start..];
        let end  = rest.find('}').unwrap_or(rest.len());
        let obj  = &rest[..end+1];
        let name     = extract_str(obj, "name").unwrap_or("unknown");
        let fs_path  = extract_str(obj, "fs_path").unwrap_or("");
        let max_gas  = extract_u64(obj, "max_gas").unwrap_or(10_000_000);
        if !fs_path.is_empty() {
            result.push(DeployManifest {
                name: name.into(), wasm_path: fs_path.into(),
                max_gas, max_restarts: 3,
            });
        }
        rest = &rest[end+1..];
    }
    result
}

fn extract_str<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{}\":\"", key);
    let start  = json.find(&needle)? + needle.len();
    let end    = json[start..].find('"')? + start;
    Some(&json[start..end])
}

fn extract_u64(json: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{}\":", key);
    let start  = json.find(&needle)? + needle.len();
    json[start..].trim_start().split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
}

// ── Admin HTTP ────────────────────────────────────────────────────────────────
fn handle_admin(fd: u64, sup: &Supervisor, height: u64, now: u64) {
    let mut buf = alloc::vec![0u8; 4096];
    let n = sys::tcp_recv(fd, &mut buf);
    if n == 0 { sys::tcp_close(fd); return; }

    let req   = core::str::from_utf8(&buf[..n]).unwrap_or("");
    let first = req.lines().next().unwrap_or("");

    let (status, body) = if first.contains("/health") {
        ("200 OK", format!(r#"{{"ok":true,"uptime_ms":{},"height":{},"procs":{}}}"#,
            now, height, sup.running_count()))
    } else if first.contains("/admin/status") {
        ("200 OK", format!(r#"{{"version":"v0.6.0-ring3","height":{},"procs":{}}}"#,
            height, sup.running_count()))
    } else if first.contains("/metrics") {
        ("200 OK", format!("iona_node_height {}
iona_procs {}
iona_uptime_ms {}
",
            height, sup.running_count(), now))
    } else {
        ("404 Not Found", r#"{"error":"not found"}"#.into())
    };

    let resp = format!(
        "HTTP/1.0 {}
Content-Type: application/json
Content-Length: {}

{}",
        status, body.len(), body);
    sys::tcp_send(fd, resp.as_bytes());
    sys::tcp_close(fd);
}

// ── IPC ───────────────────────────────────────────────────────────────────────
fn handle_ipc(msg: &[u8], sup: &mut Supervisor, rec: &mut ReconcileEngine) {
    let s = core::str::from_utf8(msg).unwrap_or("");
    if let Some(path) = s.strip_prefix("DEPLOY:") {
        let name = path.split('/').last().unwrap_or("module");
        let _ = sup.deploy(name, path, 10_000_000, 3);
        sys::klog(&format!("[NODE] IPC: deploy '{}'", path));
    } else if let Some(pid_str) = s.strip_prefix("KILL:") {
        let pid: u64 = pid_str.parse().unwrap_or(0);
        sup.kill(pid);
        sys::klog(&format!("[NODE] IPC: kill pid={}", pid));
    } else if s.starts_with("STATUS") {
        sys::klog("[NODE] IPC: STATUS request");
    }
}

#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo) -> ! {
    let msg = format!("{}", info.message());
    sys::klog(&format!("[NODE PANIC] {}", msg));
    sys::exit(1)
}


// ── Peer health tracking ──────────────────────────────────────────────────────

pub struct PeerHealth {
    pub ip:            [u8; 4],
    pub port:          u16,
    pub last_seen_ms:  u64,
    pub latency_ms:    u64,
    pub failure_count: u32,
    pub is_healthy:    bool,
}

impl PeerHealth {
    pub fn new(ip: [u8; 4], port: u16) -> Self {
        Self { ip, port, last_seen_ms: 0, latency_ms: 0, failure_count: 0, is_healthy: false }
    }
    pub fn mark_ok(&mut self, latency: u64) {
        self.last_seen_ms = sys::uptime_ms();
        self.latency_ms   = latency;
        self.is_healthy   = true;
        self.failure_count = 0;
    }
    pub fn mark_fail(&mut self) {
        self.failure_count += 1;
        self.is_healthy = self.failure_count < 3;
    }
}

// ── Admin status endpoint ─────────────────────────────────────────────────────

pub fn admin_handler(fd: u64, height: u64, peer_count: usize) {
    let status_json = alloc::format!(
        "{{"status":"ok","height":{},"peers":{},"uptime_ms":{}}}",
        height, peer_count, sys::uptime_ms()
    );
    let response = alloc::format!(
        "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n         Content-Length: {}\r\n\r\n{}",
        status_json.len(), status_json
    );
    sys::tcp_send(fd, response.as_bytes());
    sys::tcp_close(fd);
}
