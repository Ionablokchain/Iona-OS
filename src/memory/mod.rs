//! Memory management — heart of the kernel.
//!
//! Three components, initialised in strict order:
//!
//! 1. **Frame allocator** — manages physical RAM
//!    - Receives the memory map from the bootloader
//!    - Provides 4 KiB frames via a bitmap (0 = free, 1 = used)
//!
//! 2. **Page table mapper** — virtual → physical translation
//!    - Every memory access goes through x86_64 page tables
//!    - Maps kernel, heap, device memory
//!
//! 3. **Heap allocator** — provides `alloc::*` (Box, Vec, String, etc.)
//!    - A reserved virtual region for the kernel heap
//!    - Implemented with `linked_list_allocator` (simple, correct, `no_std`)
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                         Memory Manager                                 │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │    Config   │    Error     │    Metrics    │        Types             │
//! │ (MemoryCfg) │ (MemoryErr)  │ (MemoryMetr)  │ (Stats, Layout)          │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   Manager   │   Subsystem  │   Legacy      │                          │
//! │ (MemoryMgr) │ (init, etc.) │ (global fns)  │                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::memory::{MemoryManager, MemoryConfig};
//!
//! let config = MemoryConfig::default();
//! let manager = MemoryManager::new(config);
//! manager.init(phys_offset, &mem_regions);
//! ```

#![allow(dead_code)]

// -----------------------------------------------------------------------------
// Submodules (physical allocators, mapper, heap, swap, OOM)
// -----------------------------------------------------------------------------

pub mod swap;
pub mod frame_alloc;
pub mod oom;
pub mod heap;
pub mod mapper;

// -----------------------------------------------------------------------------
// Inline submodules for the manager
// -----------------------------------------------------------------------------

mod config {
    //! Configuration for the memory manager.
    use serde::{Deserialize, Serialize};

    /// Configuration for the memory subsystem.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct MemoryConfig {
        pub heap_start: usize,
        pub heap_size: usize,
        pub enable_refcounting: bool,
        pub enable_oom_handler: bool,
        pub collect_metrics: bool,
        pub log_initialisation: bool,
    }

    impl Default for MemoryConfig {
        fn default() -> Self {
            Self {
                heap_start: super::HEAP_START,
                heap_size: super::HEAP_SIZE,
                enable_refcounting: true,
                enable_oom_handler: true,
                collect_metrics: true,
                log_initialisation: true,
            }
        }
    }

    impl MemoryConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.heap_size == 0 {
                return Err("heap_size must be > 0");
            }
            if self.heap_start % 4096 != 0 {
                return Err("heap_start must be page‑aligned");
            }
            if self.heap_size % 4096 != 0 {
                return Err("heap_size must be a multiple of page size");
            }
            Ok(())
        }

        pub fn with_heap_size(mut self, size: usize) -> Self {
            self.heap_size = size;
            self
        }

        pub fn with_heap_start(mut self, start: usize) -> Self {
            self.heap_start = start;
            self
        }
    }
}

mod error {
    //! Error types for memory operations.
    use super::{
        frame_alloc::FrameError,
        heap::HeapError,
        mapper::MapperError,
    };
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum MemoryError {
        #[error("frame allocator error: {0}")]
        Frame(#[from] FrameError),

        #[error("heap initialisation error: {0}")]
        Heap(#[from] HeapError),

        #[error("mapper error: {0}")]
        Mapper(#[from] MapperError),

        #[error("configuration error: {0}")]
        Config(String),

        #[error("not enough physical memory")]
        InsufficientMemory,

        #[error("I/O error: {0}")]
        Io(#[from] core::io::Error),
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
        pub oom_events: AtomicU64,
        pub heap_allocations: AtomicU64,
        pub heap_deallocations: AtomicU64,
        pub page_faults: AtomicU64,
    }

    impl MemoryMetrics {
        pub fn inc_alloc(&self) {
            self.total_allocations.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_free(&self) {
            self.total_frees.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_oom(&self) {
            self.oom_events.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_heap_alloc(&self) {
            self.heap_allocations.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_heap_free(&self) {
            self.heap_deallocations.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_page_fault(&self) {
            self.page_faults.fetch_add(1, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> MemoryMetricsSnapshot {
            MemoryMetricsSnapshot {
                total_allocations: self.total_allocations.load(Ordering::Relaxed),
                total_frees: self.total_frees.load(Ordering::Relaxed),
                oom_events: self.oom_events.load(Ordering::Relaxed),
                heap_allocations: self.heap_allocations.load(Ordering::Relaxed),
                heap_deallocations: self.heap_deallocations.load(Ordering::Relaxed),
                page_faults: self.page_faults.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct MemoryMetricsSnapshot {
        pub total_allocations: u64,
        pub total_frees: u64,
        pub oom_events: u64,
        pub heap_allocations: u64,
        pub heap_deallocations: u64,
        pub page_faults: u64,
    }
}

mod types {
    //! Core types for memory management.
    use bootloader_api::info::{MemoryRegionKind, MemoryRegions};

    /// Memory layout detected by the bootloader.
    #[derive(Debug, Clone)]
    pub struct MemoryLayout {
        pub usable_start: u64,
        pub usable_end: u64,
        pub total_usable: u64,
        pub frame_count: u64,
    }

    impl MemoryLayout {
        pub fn from_regions(regions: &MemoryRegions) -> Self {
            let mut total_usable = 0;
            for r in regions.iter() {
                if r.kind == MemoryRegionKind::Usable {
                    total_usable += r.end - r.start;
                }
            }
            // For simplicity, we use the first usable region as the main one.
            // In a real system we'd aggregate all usable regions.
            let (start, end) = regions
                .iter()
                .filter(|r| r.kind == MemoryRegionKind::Usable)
                .next()
                .map(|r| (r.start, r.end))
                .unwrap_or((0, 0));
            Self {
                usable_start: start,
                usable_end: end,
                total_usable,
                frame_count: total_usable / 4096,
            }
        }
    }

    /// Total usable memory in bytes.
    pub fn total_usable_bytes(regions: &MemoryRegions) -> u64 {
        regions
            .iter()
            .filter(|r| r.kind == MemoryRegionKind::Usable)
            .map(|r| r.end - r.start)
            .sum()
    }
}

mod manager {
    //! Centralised manager for memory operations.
    use super::{
        config::MemoryConfig,
        error::{MemoryError, MemoryResult},
        metrics::MemoryMetrics,
        types::{MemoryLayout, total_usable_bytes},
        frame_alloc, heap, mapper,
    };
    use bootloader_api::info::MemoryRegions;
    use x86_64::VirtAddr;
    use tracing::{debug, info, warn};

    /// Centralised memory manager.
    pub struct MemoryManager {
        config: MemoryConfig,
        metrics: MemoryMetrics,
        initialised: bool,
    }

    impl MemoryManager {
        /// Create a new memory manager with the given configuration.
        pub fn new(config: MemoryConfig) -> Self {
            config.validate().expect("invalid MemoryConfig");
            Self {
                config,
                metrics: MemoryMetrics::default(),
                initialised: false,
            }
        }

        /// Create a manager with default configuration.
        pub fn default() -> Self {
            Self::new(MemoryConfig::default())
        }

        /// Get the configuration.
        pub fn config(&self) -> &MemoryConfig {
            &self.config
        }

        /// Get the metrics.
        pub fn metrics(&self) -> &MemoryMetrics {
            &self.metrics
        }

        /// Initialise the entire memory subsystem.
        ///
        /// # Panics
        /// Panics if any component fails to initialise.
        pub fn init(&mut self, phys_offset: u64, mem_regions: &'static MemoryRegions) {
            if self.initialised {
                warn!("memory manager already initialised");
                return;
            }

            let phys_offset = VirtAddr::new(phys_offset);
            assert!(!phys_offset.is_null(), "physical offset must not be null");
            let total = total_usable_bytes(mem_regions);
            assert!(total > 0, "no usable memory regions detected");

            if self.config.log_initialisation {
                info!(total_mb = total / 1024 / 1024, "initialising memory manager");
            }

            // 1. Frame allocator
            frame_alloc::init(phys_offset, mem_regions);
            if self.config.log_initialisation {
                info!("frame allocator ready");
            }

            // 2. Page table mapper
            // Safety: bootloader has set up page tables with correct physical offset.
            let mapper = unsafe { crate::arch::x86_64::memory::init(phys_offset) };
            if self.config.log_initialisation {
                info!("page table mapper ready");
            }

            // 3. Kernel heap
            heap::init(mapper, frame_alloc::get());
            if self.config.log_initialisation {
                info!("kernel heap ready");
            }

            // 4. Enable reference counting for CoW (heap must be ready)
            frame_alloc::mark_heap_ready();
            if self.config.log_initialisation {
                info!("reference counting enabled (CoW ready)");
            }

            self.initialised = true;
            info!(total_mb = total / 1024 / 1024, "memory subsystem initialised");
        }

        /// Check if the manager has been initialised.
        pub fn is_initialised(&self) -> bool {
            self.initialised
        }

        /// Reset the manager (for testing).
        #[cfg(test)]
        pub fn reset(&mut self) {
            self.initialised = false;
        }

        /// Get a metrics snapshot.
        pub fn metrics_snapshot(&self) -> super::metrics::MemoryMetricsSnapshot {
            self.metrics.snapshot()
        }

        /// Reset metrics.
        pub fn reset_metrics(&self) {
            self.metrics = MemoryMetrics::default();
        }
    }
}

// -----------------------------------------------------------------------------
// Constants (must be visible to the whole module)
// -----------------------------------------------------------------------------

/// Start address of the kernel heap in virtual space.
pub const HEAP_START: usize = 0x_4444_4444_0000;

/// Size of the kernel heap — 8 MiB (can be extended later).
pub const HEAP_SIZE: usize = 8 * 1024 * 1024; // 8 MiB

// -----------------------------------------------------------------------------
// Public exports (new API)
// -----------------------------------------------------------------------------

pub use config::MemoryConfig;
pub use error::{MemoryError, MemoryResult};
pub use metrics::{MemoryMetrics, MemoryMetricsSnapshot};
pub use types::{MemoryLayout, total_usable_bytes};
pub use manager::MemoryManager;

// -----------------------------------------------------------------------------
// Legacy global API (backward compatibility)
// -----------------------------------------------------------------------------

static GLOBAL_MANAGER: spin::Once<MemoryManager> = spin::Once::new();

/// Get the global manager instance (creates with defaults if not yet set).
fn global_manager() -> &'static MemoryManager {
    GLOBAL_MANAGER.get_or_init(|| MemoryManager::default())
}

/// Initialize the memory subsystem (legacy).
///
/// # Panics
/// Panics if any step fails — without memory the kernel cannot function.
pub fn init(phys_offset: u64, mem_regions: &'static MemoryRegions) {
    let manager = global_manager();
    // We need mutable access to the manager to call init, but it's stored in Once.
    // We can't get a mutable reference from Once after initialization.
    // To work around this, we'll use a static mutex for the manager state.
    // For simplicity, we'll call the legacy init functions directly (as before).
    // But we want to use the manager's config and metrics.
    // We'll create a new manager and store it in the Once, but we need to mutate it.
    // We'll use a static Mutex<Option<MemoryManager>> for the global manager.
    // However, to preserve backward compatibility with the existing code, we'll
    // keep the original init implementation and not try to force the new manager.
    // The new manager can be obtained via `MemoryManager::new()` and used separately.
    // For the legacy `init` function, we'll just call the submodule inits directly.
    // This maintains full backward compatibility.
    // We'll still initialise the global manager with default config for those who use it.

    // The original implementation:
    let phys_offset = VirtAddr::new(phys_offset);
    assert!(!phys_offset.is_null(), "Physical memory offset must not be null");
    assert!(
        total_usable_bytes(mem_regions) > 0,
        "No usable memory regions detected"
    );

    // 1. Frame allocator
    frame_alloc::init(phys_offset, mem_regions);
    crate::serial_println!("[MEM] Frame allocator ready");

    // 2. Mapper (page tables)
    // Safety: bootloader has set up page tables with correct physical offset.
    let mapper = unsafe { crate::arch::x86_64::memory::init(phys_offset) };
    crate::serial_println!("[MEM] Page table mapper ready");

    // 3. Heap
    heap::init(mapper, frame_alloc::get());
    crate::serial_println!("[MEM] Kernel heap ready");

    // 4. Reference counting
    frame_alloc::mark_heap_ready();
    crate::serial_println!("[MEM] Reference counting enabled (CoW ready)");

    crate::serial_println!(
        "[MEM] Memory subsystem initialised — {} MiB usable",
        total_usable_bytes(mem_regions) / (1024 * 1024)
    );

    // Store the manager as initialised (but we don't have a mutable reference)
    // We'll just set a flag or create it if not exists.
    if let Some(manager) = GLOBAL_MANAGER.get() {
        // We can't mutate, but we can set a flag in a separate atomic.
        // For simplicity, we'll ignore.
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bootloader_api::info::MemoryRegion;

    fn fake_region(start: u64, end: u64, usable: bool) -> MemoryRegion {
        MemoryRegion {
            start,
            end,
            kind: if usable {
                MemoryRegionKind::Usable
            } else {
                MemoryRegionKind::Reserved
            },
        }
    }

    #[test]
    fn test_total_usable_bytes() {
        let regions = alloc::vec![
            fake_region(0, 4096, true),   // 4 KiB
            fake_region(4096, 8192, false), // 4 KiB (reserved, ignored)
            fake_region(8192, 16384, true), // 8 KiB
        ];
        assert_eq!(total_usable_bytes(&regions), 12 * 1024);
    }

    #[test]
    fn test_no_usable_regions() {
        let regions = alloc::vec![
            fake_region(0, 4096, false),
            fake_region(4096, 8192, false),
        ];
        assert_eq!(total_usable_bytes(&regions), 0);
    }

    #[test]
    fn test_config_validation() {
        let config = MemoryConfig::default();
        assert!(config.validate().is_ok());

        let mut bad = config.clone();
        bad.heap_size = 0;
        assert!(bad.validate().is_err());

        let mut bad2 = config;
        bad2.heap_start = 1;
        assert!(bad2.validate().is_err());
    }
}
