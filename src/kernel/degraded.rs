//! Degraded mode — kernel continues with reduced functionality
//!
//! Triggered when a non-critical component fails at boot or runtime.
//! Instead of panicking, we enter degraded mode and log what's missing.

use alloc::vec::Vec;
use alloc::string::String;
use spin::{Lazy, Mutex};

#[derive(Clone, Debug)]
pub struct DegradedComponent {
    pub name:   String,
    pub reason: String,
    pub affects: Vec<String>,
}

static DEGRADED: Lazy<Mutex<Vec<DegradedComponent>>> =
    Lazy::new(|| Mutex::new(Vec::new()));

pub fn is_degraded() -> bool { !DEGRADED.lock().is_empty() }

pub fn mark_degraded(name: &str, reason: &str, affects: &[&str]) {
    let comp = DegradedComponent {
        name:    name.into(),
        reason:  reason.into(),
        affects: affects.iter().map(|s| (*s).into()).collect(),
    };
    crate::serial_println!("[DEGRADED] {} — {}", name, reason);
    if !affects.is_empty() {
        crate::serial_println!("[DEGRADED]  affects: {:?}", affects);
    }
    DEGRADED.lock().push(comp);
}

pub fn components() -> Vec<DegradedComponent> { DEGRADED.lock().clone() }

pub fn status_string() -> String {
    let comps = DEGRADED.lock();
    if comps.is_empty() { return "OK".into(); }
    let names: Vec<&str> = comps.iter().map(|c| c.name.as_str()).collect();
    alloc::format!("DEGRADED ({}): {}", comps.len(), names.join(", "))
}

/// Log degraded status to /var/log/degraded.log
pub fn persist_status() {
    let comps = DEGRADED.lock();
    if comps.is_empty() { return; }
    let mut log = alloc::format!("Boot degraded at {}ms:\n",
        crate::arch::x86_64::timer::uptime_ms());
    for c in comps.iter() {
        log.push_str(&alloc::format!("  - {}: {}\n", c.name, c.reason));
    }
    crate::fs::ionafs::write("/var/log/degraded.log", log.as_bytes());
}
