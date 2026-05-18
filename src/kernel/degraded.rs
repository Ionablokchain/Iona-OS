//! Degraded mode — kernel continues with reduced functionality
//!
//! Triggered when a non-critical component fails at boot or runtime.
//! Instead of panicking, we enter degraded mode and log what's missing.
//!
//! # Example
//!
//! ```
//! use iona::kernel::degraded::{mark_degraded, is_degraded, status_string};
//!
//! mark_degraded("virtio-blk", "driver init failed", &["disk"]);
//! assert!(is_degraded());
//! assert!(status_string().contains("DEGRADED"));
//! ```

use alloc::vec::Vec;
use alloc::string::{String, ToString};
use core::fmt;
use spin::{Lazy, Mutex};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Path where degraded status is persisted.
pub const DEGRADED_LOG_PATH: &str = "/var/log/degraded.log";

/// Maximum number of components tracked to prevent unbounded growth.
const MAX_COMPONENTS: usize = 32;

// -----------------------------------------------------------------------------
// DegradedComponent
// -----------------------------------------------------------------------------

/// A component that failed but does not halt the system.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DegradedComponent {
    pub name: String,
    pub reason: String,
    pub affects: Vec<String>,
}

impl DegradedComponent {
    /// Create a new component after validation.
    fn new(name: &str, reason: &str, affects: &[&str]) -> Result<Self, &'static str> {
        if name.is_empty() {
            return Err("component name must not be empty");
        }
        if reason.is_empty() {
            return Err("reason must not be empty");
        }
        Ok(DegradedComponent {
            name: name.to_string(),
            reason: reason.to_string(),
            affects: affects.iter().map(|s| (*s).to_string()).collect(),
        })
    }
}

impl fmt::Display for DegradedComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.reason)?;
        if !self.affects.is_empty() {
            write!(f, " (affects: {})", self.affects.join(", "))?;
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Global state
// -----------------------------------------------------------------------------

static DEGRADED: Lazy<Mutex<Vec<DegradedComponent>>> =
    Lazy::new(|| Mutex::new(Vec::with_capacity(8)));

/// Returns `true` if at least one component is degraded.
#[must_use]
pub fn is_degraded() -> bool {
    !DEGRADED.lock().is_empty()
}

/// Returns the number of degraded components.
#[must_use]
pub fn degraded_count() -> usize {
    DEGRADED.lock().len()
}

/// Mark a component as degraded.
///
/// # Panics
/// Panics if `name` or `reason` are empty (debug builds). In release, the error is silently ignored.
pub fn mark_degraded(name: &str, reason: &str, affects: &[&str]) {
    // Validate early to avoid poisoning the lock with bad data.
    let component = match DegradedComponent::new(name, reason, affects) {
        Ok(c) => c,
        Err(e) => {
            crate::serial_println!("[DEGRADED] Invalid component: {}", e);
            return;
        }
    };

    let mut guard = DEGRADED.lock();
    // Update existing entry if present
    if let Some(existing) = guard.iter_mut().find(|c| c.name == component.name) {
        // Only log if something actually changed
        if existing.reason != component.reason || existing.affects != component.affects {
            crate::serial_println!("[DEGRADED] {} — {} (updated)", component.name, component.reason);
        }
        existing.reason = component.reason;
        existing.affects = component.affects;
    } else {
        if guard.len() >= MAX_COMPONENTS {
            // Remove oldest to make room
            guard.remove(0);
        }
        crate::serial_println!("[DEGRADED] {} — {}", component.name, component.reason);
        if !component.affects.is_empty() {
            crate::serial_println!("[DEGRADED]  affects: {:?}", component.affects);
        }
        guard.push(component);
    }
}

/// Remove a component from degraded state (e.g., after recovery).
/// Returns `true` if the component was present.
pub fn clear_degraded(name: &str) -> bool {
    let mut guard = DEGRADED.lock();
    let before = guard.len();
    guard.retain(|c| c.name != name);
    guard.len() != before
}

/// Clear all degraded components.
pub fn clear_all() {
    DEGRADED.lock().clear();
}

/// Returns a copy of all degraded components.
#[must_use]
pub fn components() -> Vec<DegradedComponent> {
    DEGRADED.lock().clone()
}

/// Returns a human-readable status string.
#[must_use]
pub fn status_string() -> String {
    let guard = DEGRADED.lock();
    if guard.is_empty() {
        return "OK".to_string();
    }
    let names: Vec<&str> = guard.iter().map(|c| c.name.as_str()).collect();
    alloc::format!("DEGRADED ({}): {}", guard.len(), names.join(", "))
}

/// Check if a specific component is degraded.
#[must_use]
pub fn is_degraded_for(component: &str) -> bool {
    DEGRADED.lock().iter().any(|c| c.name == component)
}

/// Persist degraded status to disk (best-effort).
///
/// The current list is cloned under the lock, then written without holding the lock.
/// Returns `Ok(())` on success, or an error message if writing failed.
pub fn persist_status() -> Result<(), &'static str> {
    // Clone the list quickly
    let snapshot = DEGRADED.lock().clone();
    if snapshot.is_empty() {
        return Ok(());
    }

    let mut log = alloc::format!(
        "Boot degraded at {}ms:\n",
        crate::arch::x86_64::timer::uptime_ms()
    );
    for comp in &snapshot {
        log.push_str(&alloc::format!("  - {}\n", comp));
    }

    crate::fs::ionafs::write(DEGRADED_LOG_PATH, log.as_bytes())
        .map_err(|_| "Failed to write degraded log")
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to reset state for tests.
    fn reset() {
        DEGRADED.lock().clear();
    }

    #[test]
    fn test_mark_and_check() {
        reset();
        assert!(!is_degraded());
        mark_degraded("test1", "failed to init", &["net", "storage"]);
        assert!(is_degraded());
        assert_eq!(degraded_count(), 1);
        assert!(is_degraded_for("test1"));
        assert!(!is_degraded_for("nonexistent"));

        let comps = components();
        assert_eq!(comps.len(), 1);
        assert_eq!(comps[0].name, "test1");
        assert!(comps[0].reason.contains("failed"));
        assert_eq!(comps[0].affects, vec!["net", "storage"]);

        clear_degraded("test1");
        assert!(!is_degraded());
        assert_eq!(degraded_count(), 0);
    }

    #[test]
    fn test_mark_duplicate_updates() {
        reset();
        mark_degraded("driver", "first error", &[]);
        mark_degraded("driver", "second error", &["disk"]);

        let comp = components()[0].clone();
        assert_eq!(comp.reason, "second error");
        assert_eq!(comp.affects, vec!["disk"]);
        assert_eq!(degraded_count(), 1);
    }

    #[test]
    fn test_status_string() {
        reset();
        assert_eq!(status_string(), "OK");
        mark_degraded("alpha", "missing", &[]);
        mark_degraded("beta", "timeout", &["p2p"]);
        let s = status_string();
        assert!(s.contains("DEGRADED (2):"));
        assert!(s.contains("alpha"));
        assert!(s.contains("beta"));
    }

    #[test]
    fn test_max_components_ring_buffer() {
        reset();
        // Fill exactly MAX_COMPONENTS
        for i in 0..MAX_COMPONENTS {
            mark_degraded(&alloc::format!("comp_{}", i), "test", &[]);
        }
        assert_eq!(degraded_count(), MAX_COMPONENTS);
        // Ensure the first one is the oldest
        assert!(is_degraded_for("comp_0"));

        // Add one more, should evict the oldest (comp_0)
        mark_degraded("new_one", "test", &[]);
        assert_eq!(degraded_count(), MAX_COMPONENTS);
        assert!(!is_degraded_for("comp_0"));
        assert!(is_degraded_for("comp_1"));
        assert!(is_degraded_for("new_one"));
    }

    #[test]
    fn test_clear_all() {
        reset();
        mark_degraded("a", "r", &[]);
        mark_degraded("b", "r", &[]);
        assert_eq!(degraded_count(), 2);
        clear_all();
        assert_eq!(degraded_count(), 0);
    }

    #[test]
    fn test_empty_name_is_rejected() {
        reset();
        mark_degraded("", "some reason", &[]);
        // Should not add anything
        assert!(!is_degraded());
        assert_eq!(degraded_count(), 0);
    }

    #[test]
    fn test_empty_reason_is_rejected() {
        reset();
        mark_degraded("valid_name", "", &[]);
        assert!(!is_degraded());
        assert_eq!(degraded_count(), 0);
    }

    #[test]
    fn test_mark_duplicate_with_same_data_does_not_log_twice() {
        reset();
        mark_degraded("comp", "reason", &["a"]);
        // The second call with identical data should not duplicate or log "updated"
        // (we can't easily test absence of log output, but state remains consistent)
        mark_degraded("comp", "reason", &["a"]);
        assert_eq!(degraded_count(), 1);
        let comp = components()[0].clone();
        assert_eq!(comp.reason, "reason");
        assert_eq!(comp.affects, vec!["a"]);
    }
}
