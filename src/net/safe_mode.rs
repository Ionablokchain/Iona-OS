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

/// Indicator global pentru modul safe.
/// `Release` la intrare, `Acquire` la verificare pentru vizibilitate corectă între fire.
pub static SAFE_MODE: AtomicBool = AtomicBool::new(false);

/// Intră în safe mode. Motivul este serializat și salvat în jurnal (best-effort).
/// Nu face panică dacă scrierea în fișier eșuează.
pub fn enter_safe_mode(reason: &str) {
    // Scriem mai întâi jurnalul, ca să avem o încercare de persistență
    // înainte de a modifica starea globală.
    if let Err(_e) = crate::fs::ionafs::write("/var/log/safe-mode.log", reason.as_bytes()) {
        crate::serial_println!("[NET-SAFE] Eroare la scrierea logului safe mode");
    }

    // Setăm flagul cu Release pentru a ne asigura că orice scriere anterioară
    // (ex. logul) este vizibilă înainte ca alte fire să vadă noul mod.
    SAFE_MODE.store(true, Ordering::Release);
    crate::serial_println!("[NET-SAFE] Entering safe mode: {}", reason);
}

/// Iese din safe mode.
pub fn exit_safe_mode() {
    // Ștergem flagul cu Release; eventuale operații ulterioare vor vedea această schimbare.
    SAFE_MODE.store(false, Ordering::Release);
    crate::serial_println!("[NET-SAFE] Exiting safe mode");
    // Opțional: logare și în fișier, dar este mai puțin critică.
    let _ = crate::fs::ionafs::write("/var/log/safe-mode.log", b"Exited safe mode");
}

/// Verifică dacă ne aflăm în safe mode.
/// Folosește `Acquire` pentru a vedea toate scrierile efectuate înainte de ultimul store.
#[inline]
pub fn is_safe_mode() -> bool {
    SAFE_MODE.load(Ordering::Acquire)
}

/// Decide dacă o conexiune outbound este permisă în modul curent.
/// În safe mode, sunt acceptate doar destinații din spațiul de adrese privat (RFC 1918)
/// și loopback.
#[inline]
pub fn allow_outbound(dest_ip: &[u8; 4], port: u16) -> bool {
    if !is_safe_mode() {
        return true;
    }

    // Verificăm toate blocurile private:
    // - 127.0.0.0/8 (loopback)
    // - 10.0.0.0/8
    // - 172.16.0.0/12
    // - 192.168.0.0/16
    // - 169.254.0.0/16 (link-local)
    let is_local = dest_ip[0] == 127
        || dest_ip[0] == 10
        || (dest_ip[0] == 172 && dest_ip[1] >= 16 && dest_ip[1] <= 31)
        || (dest_ip[0] == 192 && dest_ip[1] == 168)
        || (dest_ip[0] == 169 && dest_ip[1] == 254);

    if !is_local {
        crate::serial_println!(
            "[NET-SAFE] Blocked outbound to {}.{}.{}.{}:{}",
            dest_ip[0], dest_ip[1], dest_ip[2], dest_ip[3], port
        );
    }
    is_local
}
