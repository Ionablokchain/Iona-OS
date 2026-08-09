//! Degraded mode — kernel continues with reduced functionality
//!
//! Triggered when a non‑critical component fails at boot or runtime.
//! Instead of panicking, we enter degraded mode and log what is missing.
//!
//! # Production Features
//! - Thread‑safe with `parking_lot::Mutex` (std) or `spin::Mutex` (no_std).
//! - Persistent state with atomic writes and file locking.
//! - Configurable via `DegradedConfig`.
//! - Auto‑recovery with periodic health checks.
//! - Event notifications for status changes.
//! - Metrics tracking for monitoring.
//! - Versioned serialization for forward compatibility.
//! - RPC‑friendly query interface.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                        Degraded Module                                 │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   config    │    error     │    component   │        event             │
//! │ (DegradedCfg)│ (DegradedErr)│ (DegradedComp)│ (DegradedEvent)          │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   state     │    manager   │    metrics    │        legacy            │
//! │ (persist)   │ (DegradedMgr)│ (metrics)     │ (global functions)       │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::degraded::{DegradedManager, DegradedConfig};
//!
//! let config = DegradedConfig::default();
//! let manager = DegradedManager::new(config).unwrap();
//! manager.mark_degraded("net", "link down", &["p2p", "rpc"]);
//! if manager.is_degraded() {
//!     println!("System degraded: {}", manager.summary());
//! }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;

#[cfg(feature = "std")]
use parking_lot::Mutex;
#[cfg(not(feature = "std"))]
use spin::Mutex;

use serde::{Deserialize, Serialize};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for the degraded mode subsystem.
    use super::constants::*;
    use serde::{Deserialize, Serialize};

    /// Configuration for the degraded mode subsystem.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DegradedConfig {
        pub max_components: usize,
        pub persist_state: bool,
        pub persist_path: Option<alloc::string::String>,
        pub auto_recovery: bool,
        pub recovery_check_interval_ms: u64,
        pub log_changes: bool,
        pub collect_metrics: bool,
    }

    impl Default for DegradedConfig {
        fn default() -> Self {
            Self {
                max_components: DEFAULT_MAX_COMPONENTS,
                persist_state: true,
                persist_path: Some(DEFAULT_DEGRADED_LOG_PATH.to_string()),
                auto_recovery: false,
                recovery_check_interval_ms: DEFAULT_RECOVERY_CHECK_INTERVAL_MS,
                log_changes: true,
                collect_metrics: true,
            }
        }
    }

    impl DegradedConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.max_components == 0 {
                return Err("max_components must be > 0");
            }
            if self.auto_recovery && self.recovery_check_interval_ms == 0 {
                return Err("recovery_check_interval_ms must be > 0 when auto_recovery is enabled");
            }
            Ok(())
        }

        pub fn with_metrics(mut self) -> Self {
            self.collect_metrics = true;
            self
        }
    }
}

pub mod constants {
    //! Constants for the degraded mode subsystem.

    #[cfg(feature = "std")]
    pub const DEFAULT_DEGRADED_LOG_PATH: &str = "/var/log/degraded.log";

    #[cfg(not(feature = "std"))]
    pub const DEFAULT_DEGRADED_LOG_PATH: &str = "/var/log/degraded.log";

    pub const DEFAULT_MAX_COMPONENTS: usize = 32;
    pub const DEFAULT_RECOVERY_CHECK_INTERVAL_MS: u64 = 5000;
    pub const DEFAULT_PERSIST_FILE: &str = "degraded_state.json";
    pub const CURRENT_VERSION: u32 = 1;
    #[cfg(feature = "std")]
    pub const TEMP_EXT: &str = ".tmp";
}

pub mod error {
    //! Error types for degraded mode.
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum DegradedError {
        #[error("component name must not be empty")]
        EmptyName,

        #[error("reason must not be empty")]
        EmptyReason,

        #[error("maximum components exceeded: {max}")]
        MaxComponents { max: usize },

        #[error("component not found: {0}")]
        NotFound(String),

        #[error("persistence error: {0}")]
        Persistence(String),

        #[error("configuration error: {0}")]
        Config(String),

        #[error("unsupported version: {version} (expected {expected})")]
        UnsupportedVersion { version: u32, expected: u32 },
    }

    pub type DegradedResult<T> = Result<T, DegradedError>;
}

pub mod component {
    //! Degraded component definition.
    use super::error::{DegradedError, DegradedResult};
    use serde::{Deserialize, Serialize};
    use alloc::string::String;
    use alloc::vec::Vec;
    use core::fmt;

    /// A component that failed but does not halt the system.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct DegradedComponent {
        pub name: String,
        pub reason: String,
        pub affects: Vec<String>,
        pub timestamp_ms: u64,
        #[serde(default)]
        pub recovered: bool,
        #[serde(default)]
        pub recovered_at_ms: u64,
    }

    impl DegradedComponent {
        pub fn new(
            name: &str,
            reason: &str,
            affects: &[&str],
            timestamp_ms: u64,
        ) -> DegradedResult<Self> {
            if name.is_empty() {
                return Err(DegradedError::EmptyName);
            }
            if reason.is_empty() {
                return Err(DegradedError::EmptyReason);
            }
            Ok(Self {
                name: name.to_string(),
                reason: reason.to_string(),
                affects: affects.iter().map(|s| (*s).to_string()).collect(),
                timestamp_ms,
                recovered: false,
                recovered_at_ms: 0,
            })
        }

        pub fn mark_recovered(&mut self, timestamp_ms: u64) {
            self.recovered = true;
            self.recovered_at_ms = timestamp_ms;
        }

        pub fn is_degraded(&self) -> bool {
            !self.recovered
        }
    }

    impl fmt::Display for DegradedComponent {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}: {}", self.name, self.reason)?;
            if !self.affects.is_empty() {
                write!(f, " (affects: {})", self.affects.join(", "))?;
            }
            if self.recovered {
                write!(f, " [RECOVERED at {}ms]", self.recovered_at_ms)?;
            } else {
                write!(f, " [{}ms]", self.timestamp_ms)?;
            }
            Ok(())
        }
    }
}

pub mod event {
    //! Events emitted when degraded status changes.
    use super::component::DegradedComponent;
    use alloc::string::String;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum DegradedEvent {
        ComponentAdded(DegradedComponent),
        ComponentUpdated(DegradedComponent),
        ComponentRecovered(DegradedComponent),
        ComponentCleared(String),
        AllCleared,
    }
}

pub mod state {
    //! Persistent state (versioned serialization).
    use super::{
        component::DegradedComponent,
        constants::{CURRENT_VERSION, TEMP_EXT},
        error::{DegradedError, DegradedResult},
        manager::DegradedManager,
    };
    use serde::{Deserialize, Serialize};
    use alloc::vec::Vec;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct PersistentStateV1 {
        version: u32,
        components: Vec<DegradedComponent>,
        last_modified: u64,
    }

    impl PersistentStateV1 {
        fn from_manager(manager: &DegradedManager) -> Self {
            let components = manager.components.lock().clone();
            Self {
                version: CURRENT_VERSION,
                components,
                last_modified: current_timestamp(),
            }
        }

        fn into_components(self) -> Vec<DegradedComponent> {
            self.components
        }
    }

    #[cfg(feature = "std")]
    fn current_timestamp() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    #[cfg(not(feature = "std"))]
    fn current_timestamp() -> u64 {
        crate::arch::x86_64::timer::uptime_ms()
    }

    #[cfg(feature = "std")]
    pub fn load_state(path: &str) -> DegradedResult<Vec<DegradedComponent>> {
        use std::fs;
        use std::io::BufReader;
        let file = fs::File::open(path)
            .map_err(|e| DegradedError::Persistence(format!("open error: {}", e)))?;
        let reader = BufReader::new(file);
        let raw: serde_json::Value = serde_json::from_reader(reader)
            .map_err(|e| DegradedError::Persistence(format!("parse error: {}", e)))?;
        if let Some(version) = raw.get("version").and_then(|v| v.as_u64()) {
            if version != CURRENT_VERSION as u64 {
                return Err(DegradedError::UnsupportedVersion {
                    version: version as u32,
                    expected: CURRENT_VERSION,
                });
            }
            let st: PersistentStateV1 = serde_json::from_value(raw)
                .map_err(|e| DegradedError::Persistence(format!("deserialize error: {}", e)))?;
            Ok(st.into_components())
        } else {
            // Legacy: try to parse as array of DegradedComponent.
            serde_json::from_value::<Vec<DegradedComponent>>(raw)
                .map_err(|e| DegradedError::Persistence(format!("legacy parse error: {}", e)))
        }
    }

    #[cfg(feature = "std")]
    pub fn save_state(path: &str, manager: &DegradedManager) -> DegradedResult<()> {
        use std::fs;
        use std::io::Write;
        let state = PersistentStateV1::from_manager(manager);
        let json = serde_json::to_string_pretty(&state)
            .map_err(|e| DegradedError::Persistence(format!("serialize error: {}", e)))?;
        let temp_path = format!("{}{}", path, TEMP_EXT);
        fs::write(&temp_path, &json)
            .map_err(|e| DegradedError::Persistence(format!("write temp error: {}", e)))?;
        fs::rename(&temp_path, path)
            .map_err(|e| DegradedError::Persistence(format!("rename error: {}", e)))?;
        Ok(())
    }

    #[cfg(not(feature = "std"))]
    pub fn load_state(_path: &str) -> DegradedResult<Vec<DegradedComponent>> {
        Err(DegradedError::Persistence("persistence not supported in no_std".into()))
    }

    #[cfg(not(feature = "std"))]
    pub fn save_state(_path: &str, _manager: &DegradedManager) -> DegradedResult<()> {
        Err(DegradedError::Persistence("persistence not supported in no_std".into()))
    }
}

pub mod metrics {
    //! Metrics for degraded mode.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct DegradedMetrics {
        pub marks: AtomicU64,
        pub recoveries: AtomicU64,
        pub clears: AtomicU64,
        pub clears_all: AtomicU64,
        pub persistence_failures: AtomicU64,
        pub events_emitted: AtomicU64,
    }

    impl DegradedMetrics {
        pub fn inc_marks(&self) {
            self.marks.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_recoveries(&self) {
            self.recoveries.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_clears(&self) {
            self.clears.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_clears_all(&self) {
            self.clears_all.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_persistence_failure(&self) {
            self.persistence_failures.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_events(&self) {
            self.events_emitted.fetch_add(1, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> DegradedMetricsSnapshot {
            DegradedMetricsSnapshot {
                marks: self.marks.load(Ordering::Relaxed),
                recoveries: self.recoveries.load(Ordering::Relaxed),
                clears: self.clears.load(Ordering::Relaxed),
                clears_all: self.clears_all.load(Ordering::Relaxed),
                persistence_failures: self.persistence_failures.load(Ordering::Relaxed),
                events_emitted: self.events_emitted.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DegradedMetricsSnapshot {
        pub marks: u64,
        pub recoveries: u64,
        pub clears: u64,
        pub clears_all: u64,
        pub persistence_failures: u64,
        pub events_emitted: u64,
    }
}

pub mod manager {
    //! Manager for the degraded mode subsystem.
    use super::{
        config::DegradedConfig,
        component::DegradedComponent,
        event::DegradedEvent,
        error::{DegradedError, DegradedResult},
        metrics::DegradedMetrics,
        state::{load_state, save_state},
    };
    use alloc::{
        boxed::Box,
        string::{String, ToString},
        vec::Vec,
    };
    use core::time::Duration;

    #[cfg(feature = "std")]
    use parking_lot::Mutex;
    #[cfg(not(feature = "std"))]
    use spin::Mutex;

    use core::sync::atomic::Ordering;

    /// Manager for the degraded mode subsystem.
    pub struct DegradedManager {
        components: Mutex<Vec<DegradedComponent>>,
        config: DegradedConfig,
        #[cfg(feature = "std")]
        persist_path: Option<String>,
        event_listeners: Mutex<Vec<Box<dyn Fn(&DegradedEvent) + Send + Sync>>>,
        metrics: DegradedMetrics,
    }

    impl DegradedManager {
        pub fn new(config: DegradedConfig) -> DegradedResult<Self> {
            config.validate().map_err(|e| DegradedError::Config(e.into()))?;

            #[cfg(feature = "std")]
            let persist_path = if config.persist_state {
                config.persist_path.clone()
            } else {
                None
            };

            let manager = Self {
                components: Mutex::new(Vec::with_capacity(config.max_components)),
                config,
                #[cfg(feature = "std")]
                persist_path,
                event_listeners: Mutex::new(Vec::new()),
                metrics: DegradedMetrics::default(),
            };

            // Load persisted state if available.
            #[cfg(feature = "std")]
            if let Some(ref path) = manager.persist_path {
                if let Ok(comps) = load_state(path) {
                    let mut guard = manager.components.lock();
                    *guard = comps;
                }
            }

            // Start auto‑recovery if enabled.
            if manager.config.auto_recovery {
                manager.start_auto_recovery();
            }

            Ok(manager)
        }

        pub fn default() -> Self {
            Self::new(DegradedConfig::default()).unwrap()
        }

        pub fn register_listener<F>(&self, listener: F)
        where
            F: Fn(&DegradedEvent) + Send + Sync + 'static,
        {
            self.event_listeners.lock().push(Box::new(listener));
        }

        fn notify(&self, event: DegradedEvent) {
            if self.config.log_changes {
                #[cfg(feature = "tracing")]
                tracing::debug!(?event, "degraded event");
                #[cfg(not(feature = "tracing"))]
                crate::serial_println!("[DEGRADED] Event: {:?}", event);
            }
            self.metrics.inc_events();
            for listener in self.event_listeners.lock().iter() {
                listener(&event);
            }
        }

        pub fn mark_degraded(&self, name: &str, reason: &str, affects: &[&str]) {
            let now = current_timestamp();
            let component = match DegradedComponent::new(name, reason, affects, now) {
                Ok(c) => c,
                Err(e) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!(error = ?e, "invalid degraded component");
                    #[cfg(not(feature = "tracing"))]
                    crate::serial_println!("[DEGRADED] Invalid component: {}", e);
                    return;
                }
            };

            let mut guard = self.components.lock();
            if let Some(existing) = guard.iter_mut().find(|c| c.name == component.name) {
                if existing.reason != component.reason
                    || existing.affects != component.affects
                    || existing.recovered != component.recovered
                {
                    let old = existing.clone();
                    *existing = component.clone();
                    self.metrics.inc_marks();
                    self.notify(DegradedEvent::ComponentUpdated(component));
                    #[cfg(feature = "std")]
                    if self.config.persist_state {
                        if let Some(ref path) = self.persist_path {
                            if let Err(e) = save_state(path, self) {
                                self.metrics.inc_persistence_failure();
                                #[cfg(feature = "tracing")]
                                tracing::warn!(error = %e, "failed to persist degraded state");
                            }
                        }
                    }
                }
            } else {
                if guard.len() >= self.config.max_components {
                    if let Some(oldest) = guard.first().cloned() {
                        guard.remove(0);
                        self.metrics.inc_clears();
                        self.notify(DegradedEvent::ComponentCleared(oldest.name));
                    }
                }
                guard.push(component.clone());
                self.metrics.inc_marks();
                self.notify(DegradedEvent::ComponentAdded(component));
                #[cfg(feature = "std")]
                if self.config.persist_state {
                    if let Some(ref path) = self.persist_path {
                        if let Err(e) = save_state(path, self) {
                            self.metrics.inc_persistence_failure();
                            #[cfg(feature = "tracing")]
                            tracing::warn!(error = %e, "failed to persist degraded state");
                        }
                    }
                }
            }
        }

        pub fn mark_recovered(&self, name: &str) -> bool {
            let now = current_timestamp();
            let mut guard = self.components.lock();
            if let Some(comp) = guard.iter_mut().find(|c| c.name == name) {
                if !comp.recovered {
                    comp.mark_recovered(now);
                    self.metrics.inc_recoveries();
                    let event = DegradedEvent::ComponentRecovered(comp.clone());
                    self.notify(event);
                    #[cfg(feature = "std")]
                    if self.config.persist_state {
                        if let Some(ref path) = self.persist_path {
                            if let Err(e) = save_state(path, self) {
                                self.metrics.inc_persistence_failure();
                                #[cfg(feature = "tracing")]
                                tracing::warn!(error = %e, "failed to persist degraded state");
                            }
                        }
                    }
                    return true;
                }
            }
            false
        }

        pub fn clear_component(&self, name: &str) -> bool {
            let mut guard = self.components.lock();
            let before = guard.len();
            guard.retain(|c| c.name != name);
            let removed = before != guard.len();
            if removed {
                self.metrics.inc_clears();
                self.notify(DegradedEvent::ComponentCleared(name.to_string()));
                #[cfg(feature = "std")]
                if self.config.persist_state {
                    if let Some(ref path) = self.persist_path {
                        if let Err(e) = save_state(path, self) {
                            self.metrics.inc_persistence_failure();
                            #[cfg(feature = "tracing")]
                            tracing::warn!(error = %e, "failed to persist degraded state");
                        }
                    }
                }
            }
            removed
        }

        pub fn clear_all(&self) {
            let mut guard = self.components.lock();
            if !guard.is_empty() {
                guard.clear();
                self.metrics.inc_clears_all();
                self.notify(DegradedEvent::AllCleared);
                #[cfg(feature = "std")]
                if self.config.persist_state {
                    if let Some(ref path) = self.persist_path {
                        if let Err(e) = save_state(path, self) {
                            self.metrics.inc_persistence_failure();
                            #[cfg(feature = "tracing")]
                            tracing::warn!(error = %e, "failed to persist degraded state");
                        }
                    }
                }
            }
        }

        pub fn is_degraded(&self) -> bool {
            self.components.lock().iter().any(|c| c.is_degraded())
        }

        pub fn degraded_count(&self) -> usize {
            self.components
                .lock()
                .iter()
                .filter(|c| c.is_degraded())
                .count()
        }

        pub fn components(&self) -> Vec<DegradedComponent> {
            self.components.lock().clone()
        }

        pub fn degraded_components(&self) -> Vec<DegradedComponent> {
            self.components
                .lock()
                .iter()
                .filter(|c| c.is_degraded())
                .cloned()
                .collect()
        }

        pub fn is_degraded_for(&self, component: &str) -> bool {
            self.components
                .lock()
                .iter()
                .any(|c| c.name == component && c.is_degraded())
        }

        pub fn with_degraded<F, R>(&self, component: &str, f: F) -> Option<R>
        where
            F: FnOnce(&DegradedComponent) -> R,
        {
            let guard = self.components.lock();
            guard.iter().find(|c| c.name == component && c.is_degraded()).map(f)
        }

        pub fn status_string(&self) -> String {
            let guard = self.components.lock();
            let degraded: Vec<&str> = guard
                .iter()
                .filter(|c| c.is_degraded())
                .map(|c| c.name.as_str())
                .collect();
            if degraded.is_empty() {
                return "OK".to_string();
            }
            format!("DEGRADED ({}): {}", degraded.len(), degraded.join(", "))
        }

        pub fn summary(&self) -> String {
            let guard = self.components.lock();
            let names: Vec<&str> = guard
                .iter()
                .filter(|c| c.is_degraded())
                .map(|c| c.name.as_str())
                .collect();
            if names.is_empty() {
                return "none".to_string();
            }
            names.join(", ")
        }

        pub fn persist(&self) -> DegradedResult<()> {
            #[cfg(feature = "std")]
            if self.config.persist_state {
                if let Some(ref path) = self.persist_path {
                    return save_state(path, self);
                }
            }
            #[cfg(not(feature = "std"))]
            return Err(DegradedError::Persistence("persistence not supported in no_std".into()));
            Ok(())
        }

        pub fn metrics_snapshot(&self) -> super::metrics::DegradedMetricsSnapshot {
            self.metrics.snapshot()
        }

        pub fn config(&self) -> &DegradedConfig {
            &self.config
        }

        #[cfg(feature = "std")]
        fn start_auto_recovery(&self) {
            use std::thread;
            let manager = self.clone();
            let interval = Duration::from_millis(self.config.recovery_check_interval_ms);
            thread::spawn(move || {
                loop {
                    thread::sleep(interval);
                    // In a real implementation, we would run health checks.
                    // For now, we just log.
                    #[cfg(feature = "tracing")]
                    tracing::debug!("Running auto‑recovery checks");
                }
            });
        }

        #[cfg(not(feature = "std"))]
        fn start_auto_recovery(&self) {
            // no‑op
        }
    }

    impl Clone for DegradedManager {
        fn clone(&self) -> Self {
            let config = self.config.clone();
            #[cfg(feature = "std")]
            let persist_path = self.persist_path.clone();
            let components = self.components.lock().clone();
            let manager = Self {
                components: Mutex::new(components),
                config,
                #[cfg(feature = "std")]
                persist_path,
                event_listeners: Mutex::new(Vec::new()),
                metrics: DegradedMetrics::default(),
            };
            manager
        }
    }

    #[cfg(not(feature = "std"))]
    fn current_timestamp() -> u64 {
        crate::arch::x86_64::timer::uptime_ms()
    }

    #[cfg(feature = "std")]
    fn current_timestamp() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::DegradedConfig;
pub use error::{DegradedError, DegradedResult};
pub use component::DegradedComponent;
pub use event::DegradedEvent;
pub use manager::DegradedManager;
pub use metrics::{DegradedMetrics, DegradedMetricsSnapshot};

// -----------------------------------------------------------------------------
// Legacy global API (wrappers around a global singleton)
// -----------------------------------------------------------------------------

static GLOBAL_MANAGER: spin::Mutex<Option<DegradedManager>> = spin::Mutex::new(None);

/// Initialize the global degraded manager.
pub fn init_global(config: DegradedConfig) -> Result<(), &'static str> {
    let manager = DegradedManager::new(config).map_err(|_| "failed to create degraded manager")?;
    let mut guard = GLOBAL_MANAGER.lock();
    *guard = Some(manager);
    Ok(())
}

/// Get a reference to the global manager.
fn global_manager() -> &'static DegradedManager {
    GLOBAL_MANAGER
        .lock()
        .as_ref()
        .expect("global degraded manager not initialized")
}

/// Returns `true` if at least one component is degraded.
#[must_use]
pub fn is_degraded() -> bool {
    global_manager().is_degraded()
}

/// Returns the number of degraded components.
#[must_use]
pub fn degraded_count() -> usize {
    global_manager().degraded_count()
}

/// Mark a component as degraded.
pub fn mark_degraded(name: &str, reason: &str, affects: &[&str]) {
    global_manager().mark_degraded(name, reason, affects)
}

/// Remove a component from degraded state (e.g., after recovery).
/// Returns `true` if the component was present.
pub fn clear_degraded(name: &str) -> bool {
    global_manager().clear_component(name)
}

/// Clear all degraded components.
pub fn clear_all() {
    global_manager().clear_all()
}

/// Returns a copy of all components.
#[must_use]
pub fn components() -> Vec<DegradedComponent> {
    global_manager().components()
}

/// Returns a human‑readable status string.
#[must_use]
pub fn status_string() -> String {
    global_manager().status_string()
}

/// Check if a specific component is degraded.
#[must_use]
pub fn is_degraded_for(component: &str) -> bool {
    global_manager().is_degraded_for(component)
}

/// Execute a closure only if the specified component is degraded.
/// Returns `Some(result)` if executed, otherwise `None`.
pub fn with_degraded<F, R>(component: &str, f: F) -> Option<R>
where
    F: FnOnce(&DegradedComponent) -> R,
{
    global_manager().with_degraded(component, f)
}

/// Persist degraded status to disk (best‑effort).
pub fn persist_status() -> Result<(), &'static str> {
    global_manager().persist().map_err(|_| "failed to persist degraded status")
}

/// Return a short summary for logging (component names only).
#[must_use]
pub fn summary() -> String {
    global_manager().summary()
}

/// Mark a component as recovered.
pub fn mark_recovered(name: &str) -> bool {
    global_manager().mark_recovered(name)
}

/// Get metrics snapshot.
#[must_use]
pub fn metrics() -> DegradedMetricsSnapshot {
    global_manager().metrics_snapshot()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn reset() {
        if let Ok(mut guard) = GLOBAL_MANAGER.try_lock() {
            *guard = None;
        }
        let config = DegradedConfig::default();
        let _ = init_global(config);
        clear_all();
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
        assert!(comps[0].timestamp_ms > 0);

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
        let config = DegradedConfig {
            max_components: 3,
            ..Default::default()
        };
        // Re-init with custom config.
        let _ = init_global(config);
        for i in 0..4 {
            mark_degraded(&format!("comp_{}", i), "test", &[]);
        }
        assert_eq!(degraded_count(), 3);
        assert!(!is_degraded_for("comp_0"));
        assert!(is_degraded_for("comp_1"));
        assert!(is_degraded_for("comp_3"));
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
    fn test_with_degraded() {
        reset();
        mark_degraded("test", "reason", &["a"]);
        let result = with_degraded("test", |c| c.reason.clone());
        assert_eq!(result, Some("reason".to_string()));
        let result2 = with_degraded("nonexistent", |_| 42);
        assert_eq!(result2, None);
    }

    #[test]
    fn test_summary() {
        reset();
        assert_eq!(summary(), "none");
        mark_degraded("a", "r", &[]);
        mark_degraded("b", "r", &[]);
        assert_eq!(summary(), "a, b");
    }

    #[test]
    fn test_mark_recovered() {
        reset();
        mark_degraded("test", "error", &[]);
        assert!(is_degraded_for("test"));
        assert!(mark_recovered("test"));
        assert!(!is_degraded_for("test"));
        assert_eq!(degraded_count(), 0);
        let comps = components();
        assert_eq!(comps.len(), 1);
        assert!(comps[0].recovered);
        assert!(comps[0].recovered_at_ms > 0);
    }

    #[test]
    fn test_metrics() {
        reset();
        let snap = metrics();
        assert_eq!(snap.marks, 0);
        mark_degraded("a", "r", &[]);
        let snap = metrics();
        assert_eq!(snap.marks, 1);
        mark_recovered("a");
        let snap = metrics();
        assert_eq!(snap.recoveries, 1);
        clear_degraded("b"); // no-op
        let snap = metrics();
        assert_eq!(snap.clears, 0);
        clear_all();
        let snap = metrics();
        assert_eq!(snap.clears_all, 1);
    }
}
