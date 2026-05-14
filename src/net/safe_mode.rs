//! Safe network mode — minimal networking pentru recovery
//!
//! Când nodul e în safe mode, blocăm:
//!   - Gossip outbound
//!   - P2P connections
//!   - Admin API write endpoints
//!
//! Permitem:
//!   - Serial debug
//!   - Local admin read-only
//!   - DHCP renew

use core::sync::atomic::{AtomicBool, Ordering};

pub static SAFE_MODE: AtomicBool = AtomicBool::new(false);

pub fn enter_safe_mode(reason: &str) {
    SAFE_MODE.store(true, Ordering::SeqCst);
    crate::serial_println!("[NET-SAFE] Entering safe mode: {}", reason);
    crate::fs::ionafs::write("/var/log/safe-mode.log", reason.as_bytes());
}

pub fn exit_safe_mode() {
    SAFE_MODE.store(false, Ordering::SeqCst);
    crate::serial_println!("[NET-SAFE] Exiting safe mode");
}

pub fn is_safe_mode() -> bool { SAFE_MODE.load(Ordering::SeqCst) }

/// Check if an outbound connection is allowed in current mode
pub fn allow_outbound(dest_ip: &[u8; 4], port: u16) -> bool {
    if !is_safe_mode() { return true; }
    // In safe mode: only allow local/loopback
    let is_local = dest_ip[0] == 127 || dest_ip[0] == 10
        || (dest_ip[0] == 192 && dest_ip[1] == 168);
    if !is_local {
        crate::serial_println!("[NET-SAFE] Blocked outbound to {}.{}.{}.{}:{}",
            dest_ip[0], dest_ip[1], dest_ip[2], dest_ip[3], port);
    }
    is_local
}
