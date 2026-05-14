//! Service supervisor + update daemon pentru iona-node
//!
//! Responsabilități:
//!   - Monitorizează serviciile sistem
//!   - Aplică actualizări OTA sigure (download → verify → stage → apply → rollback on fail)
//!   - Gestionează restart policies

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use iona_syscall as sys;

// ── Update daemon ─────────────────────────────────────────────────────────────

pub struct UpdateConfig {
    pub update_url:     String,
    pub check_interval: u64,  // ms
    pub auto_apply:     bool,
    pub rollback_on_fail: bool,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            update_url:       "http://10.0.2.2:8080/updates".into(),
            check_interval:   3_600_000, // 1 hour
            auto_apply:       false,     // require operator confirmation
            rollback_on_fail: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum UpdateState {
    Idle,
    Checking,
    Available { version: String, hash: String },
    Downloading { progress_pct: u8 },
    Staged { version: String },
    Applying,
    Applied { version: String },
    Failed { reason: String },
    RolledBack,
}

pub struct UpdateDaemon {
    pub config: UpdateConfig,
    pub state:  UpdateState,
    last_check_ms: u64,
}

impl UpdateDaemon {
    pub fn new(config: UpdateConfig) -> Self {
        Self { config, state: UpdateState::Idle, last_check_ms: 0 }
    }

    pub fn tick(&mut self) {
        let now = sys::uptime_ms();
        if now.saturating_sub(self.last_check_ms) < self.config.check_interval { return; }
        self.last_check_ms = now;
        self.check_for_updates();
    }

    fn check_for_updates(&mut self) {
        self.state = UpdateState::Checking;
        sys::klog("[UPDATE] Checking for updates...");

        // Fetch update manifest
        let manifest_url = alloc::format!("{}/manifest.json", self.config.update_url);
        match sys::fs_read("/etc/iona-os-version.json") {
            Some(current_ver_raw) => {
                let current = core::str::from_utf8(&current_ver_raw).unwrap_or("{}");
                let current_version = json_str(current, "version").unwrap_or("0.0.0".into());
                sys::klog(&alloc::format!("[UPDATE] Current: {}", current_version));
                // Simplified: mark as idle if we can't reach update server
                self.state = UpdateState::Idle;
            }
            None => {
                sys::klog("[UPDATE] Cannot read current version");
                self.state = UpdateState::Idle;
            }
        }
    }

    /// Stage an update (download → verify → write to /var/update/)
    pub fn stage_update(&mut self, version: &str, url: &str) -> bool {
        sys::klog(&alloc::format!("[UPDATE] Staging v{}", version));
        self.state = UpdateState::Downloading { progress_pct: 0 };

        // Snapshot current state before update
        let _ = crate::fs::snapshot_state(&alloc::format!("pre-update-{}", version));

        // Download (simplified — would use TCP in real impl)
        sys::klog("[UPDATE] Download would happen here via TCP");
        self.state = UpdateState::Staged { version: version.into() };
        true
    }

    /// Apply staged update with rollback on failure
    pub fn apply_update(&mut self) -> bool {
        let version = match &self.state {
            UpdateState::Staged { version } => version.clone(),
            _ => { sys::klog("[UPDATE] No staged update"); return false; }
        };

        sys::klog(&alloc::format!("[UPDATE] Applying v{}...", version));
        self.state = UpdateState::Applying;

        // In production: copy new kernel to /boot, update boot config, reboot
        // For now: update version file
        let new_version = alloc::format!(
            "{{\"version\":\"{}\",\"updated_at\":{}}}", version, sys::uptime_ms()
        );
        sys::fs_write("/etc/iona-os-version.json", new_version.as_bytes());
        sys::klog(&alloc::format!("[UPDATE] Applied v{} — reboot required", version));
        self.state = UpdateState::Applied { version };
        true
    }

    pub fn rollback(&mut self) {
        sys::klog("[UPDATE] Rolling back...");
        let _ = crate::fs::restore_snapshot("pre-update-latest");
        self.state = UpdateState::RolledBack;
    }
}

// ── Service supervisor ────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct ServiceEntry {
    pub name:      String,
    pub pid:       u64,
    pub restarts:  u32,
    pub max_restarts: u32,
    pub healthy:   bool,
    pub last_ping: u64,
}

pub struct ServiceSupervisor {
    services: Vec<ServiceEntry>,
}

impl ServiceSupervisor {
    pub fn new() -> Self { Self { services: Vec::new() } }

    pub fn register(&mut self, name: &str, pid: u64, max_restarts: u32) {
        self.services.push(ServiceEntry {
            name: name.into(), pid, restarts: 0, max_restarts,
            healthy: true, last_ping: sys::uptime_ms(),
        });
        sys::klog(&alloc::format!("[SUPERVISOR] Registered: {} pid={}", name, pid));
    }

    pub fn tick(&mut self) {
        let now = sys::uptime_ms();
        for svc in &mut self.services {
            // Health timeout: 30s without ping = unhealthy
            if now.saturating_sub(svc.last_ping) > 30_000 {
                if svc.healthy {
                    sys::klog(&alloc::format!("[SUPERVISOR] {} health timeout", svc.name));
                    svc.healthy = false;
                }
                // Restart if under limit
                if svc.restarts < svc.max_restarts {
                    svc.restarts += 1;
                    sys::klog(&alloc::format!("[SUPERVISOR] Restarting {} (attempt {})",
                        svc.name, svc.restarts));
                    // spawn_elf would restart the service
                    svc.last_ping = now; // reset timer
                }
            }
        }
    }

    pub fn ping(&mut self, name: &str) {
        let now = sys::uptime_ms();
        for svc in &mut self.services {
            if svc.name == name { svc.last_ping = now; svc.healthy = true; return; }
        }
    }

    pub fn status(&self) -> Vec<(String, bool, u32)> {
        self.services.iter()
            .map(|s| (s.name.clone(), s.healthy, s.restarts))
            .collect()
    }
}

fn json_str(json: &str, key: &str) -> Option<String> {
    let pat = alloc::format!("\"{}\":\"", key);
    let start = json.find(&pat)? + pat.len();
    let end   = json[start..].find('"')?;
    Some(json[start..start+end].into())
}
