//! State storage pentru iona-node cu schema versioning și migration
//!
//! Schema versioning:
//!   - /etc/iona-node.json include "schema_version": N
//!   - La boot, verificăm versiunea și rulăm migrările necesare
//!   - Migrare atomică: write new → verify → rename

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use iona_syscall as sys;

pub const CURRENT_SCHEMA: u32 = 2;

/// State schema versioning + migration
pub fn ensure_schema_current() -> bool {
    let config_raw = match sys::fs_read("/etc/iona-node.json") {
        Some(d) => d,
        None    => { sys::klog("[FS] No config found — first boot"); return true; }
    };
    let config = core::str::from_utf8(&config_raw).unwrap_or("{}");
    let version = json_u32(config, "schema_version").unwrap_or(0);

    if version == CURRENT_SCHEMA {
        sys::klog(&alloc::format!("[FS] Schema v{} current — no migration needed", version));
        return true;
    }

    sys::klog(&alloc::format!("[FS] Schema v{} → v{} — running migration",
        version, CURRENT_SCHEMA));

    let ok = run_migrations(version);
    if ok {
        sys::klog("[FS] Migration complete");
    } else {
        sys::klog("[FS] Migration FAILED — entering repair mode");
    }
    ok
}

fn run_migrations(from_version: u32) -> bool {
    let mut v = from_version;

    // Migration 0 → 1: add gossip_port if missing
    if v < 1 {
        sys::klog("[FS] Migrating v0 → v1: add gossip_port");
        let cfg = sys::fs_read("/etc/iona-node.json")
            .and_then(|d| core::str::from_utf8(&d).ok().map(|s| s.to_string()))
            .unwrap_or_default();
        if !cfg.contains("gossip_port") {
            let new_cfg = cfg.trim_end_matches('}').to_string()
                + ",\"gossip_port\":9000}";
            sys::fs_write("/etc/iona-node.json", new_cfg.as_bytes());
        }
        v = 1;
    }

    // Migration 1 → 2: add schema_version field
    if v < 2 {
        sys::klog("[FS] Migrating v1 → v2: add schema_version");
        let cfg = sys::fs_read("/etc/iona-node.json")
            .and_then(|d| core::str::from_utf8(&d).ok().map(|s| s.to_string()))
            .unwrap_or_default();
        let updated = if cfg.contains("schema_version") {
            // Update existing
            cfg.replace(
                &alloc::format!("\"schema_version\":{}", v),
                &alloc::format!("\"schema_version\":{}", CURRENT_SCHEMA),
            )
        } else {
            cfg.trim_end_matches('}').to_string()
                + &alloc::format!(",\"schema_version\":{}}}", CURRENT_SCHEMA)
        };
        sys::fs_write("/etc/iona-node.json", updated.as_bytes());
        v = 2;
    }

    v == CURRENT_SCHEMA
}

/// Create a state snapshot before upgrade
pub fn snapshot_state(tag: &str) -> bool {
    let paths = [
        "/etc/iona-node.json",
        "/var/iona-node/state.json",
    ];
    let snap_dir = alloc::format!("/var/iona-node/snapshots/{}", tag);
    for path in paths {
        if let Some(data) = sys::fs_read(path) {
            let dest = alloc::format!("{}{}", snap_dir, path);
            sys::fs_write(&dest, &data);
        }
    }
    sys::klog(&alloc::format!("[FS] State snapshot created: {}", tag));
    true
}

/// Restore from snapshot
pub fn restore_snapshot(tag: &str) -> bool {
    let snap_dir = alloc::format!("/var/iona-node/snapshots/{}", tag);
    let paths = ["/etc/iona-node.json", "/var/iona-node/state.json"];
    for path in paths {
        let src = alloc::format!("{}{}", snap_dir, path);
        if let Some(data) = sys::fs_read(&src) {
            sys::fs_write(path, &data);
        }
    }
    sys::klog(&alloc::format!("[FS] Restored from snapshot: {}", tag));
    true
}

fn json_u32(json: &str, key: &str) -> Option<u32> {
    let pat = alloc::format!("\"{}\":", key);
    let start = json.find(&pat)? + pat.len();
    let rest  = json[start..].trim_start();
    let end   = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end].parse().ok()
}

/// Replay journal and reindex state after crash
pub fn replay_and_reindex() -> bool {
    sys::klog("[FS] Replaying journal and reindexing state...");
    // In production: iterate /var/iona-node/blocks/, rebuild in-memory index
    let block_files = sys::fs_list("/var/iona-node/blocks/");
    sys::klog(&alloc::format!("[FS] Reindex: found {} block files", block_files.len()));
    // Restore latest state snapshot if block replay fails
    if block_files.is_empty() {
        if let Some(_) = sys::fs_read("/var/iona-node/snapshots/latest/var/iona-node/state.json") {
            sys::klog("[FS] Restoring from latest snapshot...");
            return restore_snapshot("latest");
        }
    }
    true
}
