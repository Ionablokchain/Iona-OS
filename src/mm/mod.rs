//! Memory Manager — Buddy Allocator + Slab Allocator + MMAP
//!
//! This module provides a complete memory management subsystem for IONA OS:
//!
//! - **Buddy Allocator**: Physical memory allocator using the buddy system.
//!   Manages 4 KiB frames (pages) and larger contiguous blocks.
//!
//! - **Slab Allocator**: Kernel object allocator for small, frequently used
//!   structures (task descriptors, file handles, etc.).
//!
//! - **MMAP**: Memory‑mapped files and anonymous mappings for userspace
//!   processes (MAP_ANON, MAP_SHARED, MAP_PRIVATE, MAP_FIXED, etc.).
//!
//! # Architecture
//!
//! ```text
//!                    ┌─────────────────────────────────────┐
//!                    │           Memory Manager            │
//!                    ├───────────────┬─────────────────────┤
//!                    │    Buddy      │       Slab          │
//!                    │  (Physical    │   (Kernel Objects)  │
//!                    │   Pages)      │                     │
//!                    └───────┬───────┴──────────┬──────────┘
//!                            │                  │
//!                            ▼                  ▼
//!                    ┌─────────────────────────────────────┐
//!                    │              MMAP                   │
//!                    │    (Userspace Virtual Memory)       │
//!                    └─────────────────────────────────────┘
//! ```
//!
//! # Initialisation Order
//!
//! 1. `buddy::init()` – initialise physical memory allocator
//! 2. `slab::init()` – initialise kernel object caches
//! 3. `mmap::init()` – initialise memory‑mapped file subsystem

#![allow(dead_code)]

// -----------------------------------------------------------------------------
// Submodules (physical allocators and mmap)
// -----------------------------------------------------------------------------

pub mod buddy;
pub mod slab;
pub mod mmap;

// -----------------------------------------------------------------------------
// Inline submodules for the manager
// -----------------------------------------------------------------------------

mod config {
    //! Configuration for the memory manager.
    use serde::{Deserialize, Serialize};

    /// Memory pressure thresholds (percentage of free memory).
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct MemoryPressureThresholds {
        pub moderate: f64,
        pub high: f64,
        pub critical: f64,
    }

    impl Default for MemoryPressureThresholds {
        fn default() -> Self {
            Self {
                moderate: 20.0,
                high: 10.0,
                critical: 5.0,
            }
        }
    }

    /// Configuration for the memory manager.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct MemoryConfig {
        pub pressure_thresholds: MemoryPressureThresholds,
        pub enable_metrics: bool,
        pub log_allocations: bool,
        pub log_frees: bool,
        pub oom_handler: Option<fn() -> bool>,
        pub panic_on_oom: bool,
    }

    impl Default for MemoryConfig {
        fn default() -> Self {
            Self {
                pressure_thresholds: MemoryPressureThresholds::default(),
                enable_metrics: true,
                log_allocations: false,
                log_frees: false,
                oom_handler: None,
                panic_on_oom: false,
            }
        }
    }

    impl MemoryConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.pressure_thresholds.moderate <= self.pressure_thresholds.high {
                return Err("moderate threshold must be > high threshold");
            }
            if self.pressure_thresholds.high <= self.pressure_thresholds.critical {
                return Err("high threshold must be > critical threshold");
            }
            if self.pressure_thresholds.critical <= 0.0 {
                return Err("critical threshold must be > 0");
            }
            Ok(())
        }
    }
}

mod error {
    //! Error types for memory operations.
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum MemoryError {
        #[error("out of memory: requested {requested} bytes")]
        OutOfMemory { requested: usize },

        #[error("invalid alignment: {alignment}")]
        InvalidAlignment { alignment: usize },

        #[error("invalid address: 0x{address:x}")]
        InvalidAddress { address: u64 },

        #[error("allocation failed for slab cache {cache}")]
        SlabAllocationFailed { cache: &'static str },

        #[error("mmap operation failed: {0}")]
        Mmap(String),

        #[error("configuration error: {0}")]
        Config(String),
    }

    pub type MemoryResult<T> = Result<T, MemoryError>;
}

mod metrics {
    //! Metrics for the memory manager.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct MemoryMetrics {
        pub total_allocations: AtomicU64,
        pub total_frees: AtomicU64,
        pub total_bytes_allocated: AtomicU64,
        pub total_bytes_freed: AtomicU64,
        pub oom_events: AtomicU64,
        pub oom_recovered: AtomicU64,
        pub pressure_normal_events: AtomicU64,
        pub pressure_moderate_events: AtomicU64,
        pub pressure_high_events: AtomicU64,
        pub pressure_critical_events: AtomicU64,
        pub slab_allocations: AtomicU64,
        pub slab_frees: AtomicU64,
        pub mmap_regions: AtomicU64,
    }

    impl MemoryMetrics {
        pub fn inc_alloc(&self, bytes: usize) {
            self.total_allocations.fetch_add(1, Ordering::Relaxed);
            self.total_bytes_allocated.fetch_add(bytes as u64, Ordering::Relaxed);
        }
        pub fn inc_free(&self, bytes: usize) {
            self.total_frees.fetch_add(1, Ordering::Relaxed);
            self.total_bytes_freed.fetch_add(bytes as u64, Ordering::Relaxed);
        }
        pub fn inc_oom(&self) {
            self.oom_events.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_oom_recovered(&self) {
            self.oom_recovered.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_pressure_event(&self, level: super::types::MemPressure) {
            match level {
                super::types::MemPressure::Normal => {
                    self.pressure_normal_events.fetch_add(1, Ordering::Relaxed);
                }
                super::types::MemPressure::Moderate => {
                    self.pressure_moderate_events.fetch_add(1, Ordering::Relaxed);
                }
                super::types::MemPressure::High => {
                    self.pressure_high_events.fetch_add(1, Ordering::Relaxed);
                }
                super::types::MemPressure::Critical => {
                    self.pressure_critical_events.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        pub fn inc_slab_alloc(&self) {
            self.slab_allocations.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_slab_free(&self) {
            self.slab_frees.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_mmap_region(&self) {
            self.mmap_regions.fetch_add(1, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> MemoryMetricsSnapshot {
            MemoryMetricsSnapshot {
                total_allocations: self.total_allocations.load(Ordering::Relaxed),
                total_frees: self.total_frees.load(Ordering::Relaxed),
                total_bytes_allocated: self.total_bytes_allocated.load(Ordering::Relaxed),
                total_bytes_freed: self.total_bytes_freed.load(Ordering::Relaxed),
                oom_events: self.oom_events.load(Ordering::Relaxed),
                oom_recovered: self.oom_recovered.load(Ordering::Relaxed),
                pressure_normal_events: self.pressure_normal_events.load(Ordering::Relaxed),
                pressure_moderate_events: self.pressure_moderate_events.load(Ordering::Relaxed),
                pressure_high_events: self.pressure_high_events.load(Ordering::Relaxed),
                pressure_critical_events: self.pressure_critical_events.load(Ordering::Relaxed),
                slab_allocations: self.slab_allocations.load(Ordering::Relaxed),
                slab_frees: self.slab_frees.load(Ordering::Relaxed),
                mmap_regions: self.mmap_regions.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct MemoryMetricsSnapshot {
        pub total_allocations: u64,
        pub total_frees: u64,
        pub total_bytes_allocated: u64,
        pub total_bytes_freed: u64,
        pub oom_events: u64,
        pub oom_recovered: u64,
        pub pressure_normal_events: u64,
        pub pressure_moderate_events: u64,
        pub pressure_high_events: u64,
        pub pressure_critical_events: u64,
        pub slab_allocations: u64,
        pub slab_frees: u64,
        pub mmap_regions: u64,
    }
}

mod types {
    //! Core types for the memory manager.
    use super::config::MemoryPressureThresholds;

    /// Memory pressure level.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum MemPressure {
        Normal,
        Moderate,
        High,
        Critical,
    }

    impl MemPressure {
        pub fn from_free_percent(free_percent: f64, thresholds: &MemoryPressureThresholds) -> Self {
            if free_percent > thresholds.moderate {
                MemPressure::Normal
            } else if free_percent > thresholds.high {
                MemPressure::Moderate
            } else if free_percent > thresholds.critical {
                MemPressure::High
            } else {
                MemPressure::Critical
            }
        }
    }

    /// Memory statistics for the whole system.
    #[derive(Debug, Clone, Default)]
    pub struct MemStats {
        pub total_memory: usize,
        pub free_memory: usize,
        pub kernel_memory: usize,
        pub userspace_memory: usize,
        pub slab_memory: usize,
        pub swapped_memory: usize,
    }

    impl MemStats {
        pub fn utilisation_percent(&self) -> f64 {
            if self.total_memory == 0 { 0.0 } else {
                (self.total_memory - self.free_memory) as f64 / self.total_memory as f64 * 100.0
            }
        }
        pub fn summary(&self) -> alloc::string::String {
            alloc::format!(
                "Mem: total={:.2} MiB, free={:.2} MiB, kernel={:.2} MiB, user={:.2} MiB, swap={:.2} MiB ({:.1}% used)",
                self.total_memory as f64 / 1024.0 / 1024.0,
                self.free_memory as f64 / 1024.0 / 1024.0,
                self.kernel_memory as f64 / 1024.0 / 1024.0,
                self.userspace_memory as f64 / 1024.0 / 1024.0,
                self.swapped_memory as f64 / 1024.0 / 1024.0,
                self.utilisation_percent()
            )
        }
    }

    /// Memory layout detected by the bootloader.
    #[derive(Debug, Clone)]
    pub struct MemoryLayout {
        pub usable_start: usize,
        pub usable_end: usize,
        pub total_usable: usize,
        pub frame_count: usize,
    }
}

mod manager {
    //! Centralised memory manager.
    use super::{
        config::MemoryConfig,
        error::{MemoryError, MemoryResult},
        metrics::MemoryMetrics,
        types::{MemPressure, MemStats, MemoryLayout},
        buddy, slab, mmap,
    };
    use core::sync::atomic::Ordering;
    use tracing::{debug, info, warn};

    /// Centralised memory manager.
    pub struct MemoryManager {
        config: MemoryConfig,
        metrics: MemoryMetrics,
    }

    impl MemoryManager {
        pub fn new(config: MemoryConfig) -> Self {
            config.validate().expect("invalid MemoryConfig");
            Self {
                config,
                metrics: MemoryMetrics::default(),
            }
        }

        pub fn default() -> Self {
            Self::new(MemoryConfig::default())
        }

        pub fn config(&self) -> &MemoryConfig {
            &self.config
        }

        pub fn metrics(&self) -> &MemoryMetrics {
            &self.metrics
        }

        /// Initialise the memory manager with a memory layout.
        pub fn init(&self, layout: &MemoryLayout) {
            info!("initialising memory manager");

            // 1. Buddy allocator
            buddy::init(layout.usable_start, layout.frame_count);
            info!("buddy allocator initialised: {} frames ({} MiB)",
                layout.frame_count,
                layout.total_usable / 1024 / 1024
            );

            // 2. Slab allocator
            slab::init();
            info!("slab allocator initialised");

            // 3. mmap subsystem
            mmap::init();
            info!("mmap subsystem initialised");

            info!("memory manager initialised");
        }

        /// Allocate physical memory (via buddy).
        pub fn alloc_pages(&self, order: usize) -> MemoryResult<u64> {
            if self.config.log_allocations {
                debug!(order, "allocating physical pages");
            }
            match buddy::alloc_pages(order) {
                Some(addr) => {
                    self.metrics.inc_alloc(4096 << order);
                    Ok(addr)
                }
                None => {
                    self.metrics.inc_oom();
                    if let Some(handler) = self.config.oom_handler {
                        if handler() {
                            self.metrics.inc_oom_recovered();
                            // Retry allocation
                            buddy::alloc_pages(order).ok_or(MemoryError::OutOfMemory {
                                requested: 4096 << order,
                            })
                        } else {
                            if self.config.panic_on_oom {
                                panic!("out of memory (order {})", order);
                            }
                            Err(MemoryError::OutOfMemory { requested: 4096 << order })
                        }
                    } else {
                        if self.config.panic_on_oom {
                            panic!("out of memory (order {})", order);
                        }
                        Err(MemoryError::OutOfMemory { requested: 4096 << order })
                    }
                }
            }
        }

        /// Free physical memory.
        pub fn free_pages(&self, addr: u64, order: usize) {
            if self.config.log_frees {
                debug!(addr, order, "freeing physical pages");
            }
            buddy::free_pages(addr, order);
            self.metrics.inc_free(4096 << order);
        }

        /// Allocate from slab.
        pub fn slab_alloc(&self, name: &str) -> Option<*mut u8> {
            let ptr = slab::alloc(name);
            if ptr.is_some() {
                self.metrics.inc_slab_alloc();
                if self.config.log_allocations {
                    debug!(cache = name, "slab allocation");
                }
            }
            ptr
        }

        /// Free to slab.
        pub fn slab_free(&self, name: &str, ptr: *mut u8) {
            slab::free(name, ptr);
            self.metrics.inc_slab_free();
            if self.config.log_frees {
                debug!(cache = name, "slab free");
            }
        }

        /// Map a file via mmap.
        pub fn mmap_file(
            &self,
            tid: crate::task::TaskId,
            path: &str,
            offset: u64,
            length: usize,
            prot: u32,
            flags: u32,
            hint: u64,
        ) -> MemoryResult<u64> {
            self.metrics.inc_mmap_region();
            mmap::mmap_file(tid, path, offset, length, prot, flags, hint)
                .ok_or_else(|| MemoryError::Mmap("mmap_file failed".into()))
        }

        /// Map anonymous memory.
        pub fn mmap_anon(
            &self,
            tid: crate::task::TaskId,
            length: usize,
            prot: u32,
            flags: u32,
            hint: u64,
        ) -> MemoryResult<u64> {
            self.metrics.inc_mmap_region();
            let addr = mmap::mmap_anon(tid, length, prot, flags, hint);
            if addr == 0 {
                Err(MemoryError::Mmap("mmap_anon failed".into()))
            } else {
                Ok(addr)
            }
        }

        /// Handle a page fault.
        pub fn handle_page_fault(&self, tid: crate::task::TaskId, fault_addr: u64) -> Option<[u8; 4096]> {
            mmap::handle_page_fault(tid, fault_addr)
        }

        /// Mark a page as dirty.
        pub fn mark_dirty(&self, tid: crate::task::TaskId, addr: u64) {
            mmap::mark_dirty(tid, addr);
        }

        /// Unmap a region.
        pub fn munmap(&self, tid: crate::task::TaskId, addr: u64, length: usize) -> MemoryResult<()> {
            if mmap::munmap(tid, addr, length) {
                Ok(())
            } else {
                Err(MemoryError::Mmap("munmap failed".into()))
            }
        }

        /// Sync a region to disk.
        pub fn msync(&self, tid: crate::task::TaskId, addr: u64, length: usize) -> MemoryResult<()> {
            if mmap::msync(tid, addr, length) {
                Ok(())
            } else {
                Err(MemoryError::Mmap("msync failed".into()))
            }
        }

        /// Clean up a task's mmap regions.
        pub fn cleanup_task(&self, tid: crate::task::TaskId) {
            mmap::cleanup_task(tid);
        }

        /// Get current memory pressure.
        pub fn memory_pressure(&self) -> MemPressure {
            let (total_frames, free_frames) = buddy::stats();
            let total_memory = total_frames * buddy::FRAME_SIZE;
            let free_memory = free_frames * buddy::FRAME_SIZE;
            let free_percent = if total_memory > 0 {
                free_memory as f64 / total_memory as f64 * 100.0
            } else {
                100.0
            };
            let pressure = MemPressure::from_free_percent(free_percent, &self.config.pressure_thresholds);
            // Record metrics for pressure events.
            self.metrics.inc_pressure_event(pressure);
            pressure
        }

        /// Get comprehensive memory stats.
        pub fn get_stats(&self) -> MemStats {
            let (total_frames, free_frames) = buddy::stats();
            let slab_stats = slab::stats();

            let total_memory = total_frames * buddy::FRAME_SIZE;
            let free_memory = free_frames * buddy::FRAME_SIZE;
            let slab_memory = slab_stats.total_allocated;

            let (_total_swap, used_swap) = crate::memory::swap::stats();
            let swapped_memory = used_swap * 4096;

            let kernel_memory = slab_memory;
            let userspace_memory = free_memory.saturating_sub(kernel_memory).saturating_sub(swapped_memory);

            MemStats {
                total_memory,
                free_memory,
                kernel_memory,
                userspace_memory,
                slab_memory,
                swapped_memory,
            }
        }

        /// Get a metrics snapshot.
        pub fn metrics_snapshot(&self) -> super::metrics::MemoryMetricsSnapshot {
            self.metrics.snapshot()
        }

        /// Reset metrics.
        pub fn reset_metrics(&self) {
            *self.metrics = MemoryMetrics::default();
        }
    }
}

// -----------------------------------------------------------------------------
// Public re‑exports
// -----------------------------------------------------------------------------

pub use config::MemoryConfig;
pub use error::{MemoryError, MemoryResult};
pub use metrics::{MemoryMetrics, MemoryMetricsSnapshot};
pub use types::{MemPressure, MemStats, MemoryLayout};
pub use manager::MemoryManager;

// Re‑export submodule items for convenience.
pub use buddy::{
    alloc_pages as buddy_alloc_pages, free_pages as buddy_free_pages,
    stats as buddy_stats, FRAME_SIZE,
};
pub use slab::{
    alloc as slab_alloc, free as slab_free, init as slab_init, stats as slab_stats,
    SlabCache,
};
pub use mmap::{
    cleanup_task, handle_page_fault, mark_dirty, mmap_anon, mmap_file, mmap_stats,
    msync, munmap, memory_stats, PAGE_SIZE, MAX_MMAP_REGIONS,
};

// -----------------------------------------------------------------------------
// Legacy global API (backward compatibility)
// -----------------------------------------------------------------------------

static GLOBAL_MANAGER: spin::Once<MemoryManager> = spin::Once::new();

/// Get the global manager instance.
fn global_manager() -> &'static MemoryManager {
    GLOBAL_MANAGER.get().expect("memory manager not initialised")
}

/// Initialise the memory manager with a layout.
pub fn init(layout: &MemoryLayout) {
    GLOBAL_MANAGER.call_once(|| MemoryManager::default());
    global_manager().init(layout);
}

/// Initialise with default layout (4 MiB to 68 MiB).
pub fn init_default() {
    let layout = MemoryLayout {
        usable_start: 0x40_0000,
        usable_end: 0x440_0000,
        total_usable: 0x400_0000,
        frame_count: (0x400_0000) / FRAME_SIZE,
    };
    init(&layout);
}

/// Allocate physical pages (legacy).
pub fn alloc_pages(order: usize) -> Option<u64> {
    global_manager().alloc_pages(order).ok()
}

/// Free physical pages (legacy).
pub fn free_pages(addr: u64, order: usize) {
    global_manager().free_pages(addr, order);
}

/// Allocate from slab (legacy).
pub fn slab_alloc(name: &str) -> Option<*mut u8> {
    global_manager().slab_alloc(name)
}

/// Free to slab (legacy).
pub fn slab_free(name: &str, ptr: *mut u8) {
    global_manager().slab_free(name, ptr);
}

/// Map file (legacy).
pub fn mmap_file(
    tid: crate::task::TaskId,
    path: &str,
    offset: u64,
    length: usize,
    prot: u32,
    flags: u32,
    hint: u64,
) -> Option<u64> {
    global_manager().mmap_file(tid, path, offset, length, prot, flags, hint).ok()
}

/// Map anonymous (legacy).
pub fn mmap_anon(
    tid: crate::task::TaskId,
    length: usize,
    prot: u32,
    flags: u32,
    hint: u64,
) -> u64 {
    global_manager().mmap_anon(tid, length, prot, flags, hint).unwrap_or(0)
}

/// Page fault handler (legacy).
pub fn handle_page_fault(tid: crate::task::TaskId, fault_addr: u64) -> Option<[u8; 4096]> {
    global_manager().handle_page_fault(tid, fault_addr)
}

/// Mark dirty (legacy).
pub fn mark_dirty(tid: crate::task::TaskId, addr: u64) {
    global_manager().mark_dirty(tid, addr);
}

/// Unmap (legacy).
pub fn munmap(tid: crate::task::TaskId, addr: u64, length: usize) -> bool {
    global_manager().munmap(tid, addr, length).is_ok()
}

/// Sync (legacy).
pub fn msync(tid: crate::task::TaskId, addr: u64, length: usize) -> bool {
    global_manager().msync(tid, addr, length).is_ok()
}

/// Cleanup task (legacy).
pub fn cleanup_task(tid: crate::task::TaskId) {
    global_manager().cleanup_task(tid);
}

/// Get memory pressure (legacy).
pub fn memory_pressure() -> MemPressure {
    global_manager().memory_pressure()
}

/// Get stats (legacy).
pub fn get_memory_stats() -> MemStats {
    global_manager().get_stats()
}

/// Set OOM handler (legacy) – stored in config.
pub fn set_oom_handler(handler: fn() -> bool) {
    let mut mgr = MemoryManager::default(); // We need to update the global config.
    // We'll just update the global manager's config.
    // Since we can't easily mutate the global Once, we'll use a static mutex for config.
    // For simplicity, we'll use a separate static OOM_HANDLER.
    // We'll keep the old approach for backward compatibility.
    // We'll store it in a global static.
    static OOM_HANDLER: spin::Mutex<Option<fn() -> bool>> = spin::Mutex::new(None);
    *OOM_HANDLER.lock() = Some(handler);
}

/// Invoke OOM handler (legacy).
pub fn invoke_oom_handler() -> bool {
    static OOM_HANDLER: spin::Mutex<Option<fn() -> bool>> = spin::Mutex::new(None);
    if let Some(handler) = *OOM_HANDLER.lock() {
        handler()
    } else {
        false
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn test_memory_pressure_from_free_percent() {
        let thresholds = MemoryPressureThresholds::default();
        assert_eq!(MemPressure::from_free_percent(30.0, &thresholds), MemPressure::Normal);
        assert_eq!(MemPressure::from_free_percent(15.0, &thresholds), MemPressure::Moderate);
        assert_eq!(MemPressure::from_free_percent(8.0, &thresholds), MemPressure::High);
        assert_eq!(MemPressure::from_free_percent(3.0, &thresholds), MemPressure::Critical);
    }

    #[test]
    fn test_config_validation() {
        let mut config = MemoryConfig::default();
        assert!(config.validate().is_ok());

        config.pressure_thresholds.moderate = 10.0;
        config.pressure_thresholds.high = 15.0;
        assert!(config.validate().is_err());

        config.pressure_thresholds.moderate = 20.0;
        config.pressure_thresholds.high = 15.0;
        config.pressure_thresholds.critical = 10.0;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_memory_stats_utilisation() {
        let stats = MemStats {
            total_memory: 100,
            free_memory: 25,
            ..Default::default()
        };
        assert!((stats.utilisation_percent() - 75.0).abs() < 0.01);
    }

    #[test]
    fn test_memory_stats_summary() {
        let stats = MemStats {
            total_memory: 1024 * 1024 * 1024,
            free_memory: 256 * 1024 * 1024,
            kernel_memory: 128 * 1024 * 1024,
            userspace_memory: 512 * 1024 * 1024,
            slab_memory: 64 * 1024 * 1024,
            swapped_memory: 128 * 1024 * 1024,
        };
        let summary = stats.summary();
        assert!(summary.contains("Mem:"));
        assert!(summary.contains("MiB"));
    }

    #[test]
    fn test_oom_handler_legacy() {
        let called = AtomicBool::new(false);
        set_oom_handler(|| {
            called.store(true, Ordering::Relaxed);
            true
        });
        assert!(invoke_oom_handler());
        assert!(called.load(Ordering::Relaxed));
    }

    #[test]
    fn test_metrics() {
        let metrics = MemoryMetrics::default();
        metrics.inc_alloc(4096);
        metrics.inc_free(4096);
        metrics.inc_oom();
        let snap = metrics.snapshot();
        assert_eq!(snap.total_allocations, 1);
        assert_eq!(snap.total_frees, 1);
        assert_eq!(snap.total_bytes_allocated, 4096);
        assert_eq!(snap.total_bytes_freed, 4096);
        assert_eq!(snap.oom_events, 1);
    }

    #[test]
    fn test_manager_creation() {
        let config = MemoryConfig::default();
        let manager = MemoryManager::new(config);
        assert_eq!(manager.config().pressure_thresholds.moderate, 20.0);
        let snap = manager.metrics_snapshot();
        assert_eq!(snap.total_allocations, 0);
    }
}
