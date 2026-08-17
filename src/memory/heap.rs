//! Kernel heap initialisation.
//!
//! Uses `linked_list_allocator` as the global allocator. A virtual address
//! range (`HEAP_START` .. `HEAP_START + HEAP_SIZE`) is mapped to physical
//! frames on demand. Once mapped, the allocator is initialised.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                          Heap Module                                   │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   config    │    error     │    metrics    │        types             │
//! │ (HeapCfg)   │ (HeapError)  │ (HeapMetrics) │ (PageRange)              │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │  init       │   manager    │    legacy     │                          │
//! │ (mapping)   │ (HeapManager)│ (global fns)  │                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Safety
//! This module must be called exactly once, early in the kernel boot, before
//! any heap allocations are attempted.

#![allow(dead_code)]

use core::ops::RangeInclusive;
use linked_list_allocator::LockedHeap;
use x86_64::{
    structures::paging::{
        FrameAllocator, Mapper, Page, PageTableFlags, PhysFrame, Size4KiB,
    },
    VirtAddr,
};
use tracing::{debug, info, trace, warn};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for the kernel heap.
    use serde::{Deserialize, Serialize};

    /// Configuration for the kernel heap.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct HeapConfig {
        pub start: usize,
        pub size: usize,
        pub flags: u64,
        pub collect_metrics: bool,
        pub log_mapping: bool,
    }

    impl Default for HeapConfig {
        fn default() -> Self {
            // These constants are typically defined in a separate module (e.g., `memory`).
            // We'll use the values from the parent module (HEAP_START, HEAP_SIZE).
            Self {
                start: super::HEAP_START,
                size: super::HEAP_SIZE,
                flags: (x86_64::structures::paging::PageTableFlags::PRESENT
                    | x86_64::structures::paging::PageTableFlags::WRITABLE
                    | x86_64::structures::paging::PageTableFlags::NO_EXECUTE)
                    .bits(),
                collect_metrics: true,
                log_mapping: true,
            }
        }
    }

    impl HeapConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.size == 0 {
                return Err("heap size must be > 0");
            }
            if self.start % 4096 != 0 {
                return Err("heap start must be page-aligned");
            }
            if self.size % 4096 != 0 {
                return Err("heap size must be a multiple of page size");
            }
            Ok(())
        }

        pub fn with_size(mut self, size: usize) -> Self {
            self.size = size;
            self
        }

        pub fn with_start(mut self, start: usize) -> Self {
            self.start = start;
            self
        }

        pub fn with_metrics(mut self) -> Self {
            self.collect_metrics = true;
            self
        }
    }
}

pub mod error {
    //! Error types for heap initialisation.
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum HeapError {
        #[error("heap size must be > 0")]
        ZeroSize,

        #[error("heap start {start:#x} is not page-aligned")]
        StartNotAligned { start: usize },

        #[error("heap size {size} is not a multiple of page size")]
        SizeNotAligned { size: usize },

        #[error("failed to allocate physical frame for heap page")]
        FrameAllocationFailed,

        #[error("failed to map page at {addr:#x}: {reason}")]
        PageMapFailed { addr: u64, reason: &'static str },

        #[error("heap already initialised")]
        AlreadyInitialised,

        #[error("configuration error: {0}")]
        Config(String),
    }

    pub type HeapResult<T> = Result<T, HeapError>;
}

pub mod types {
    //! Core types for heap management.
    use super::config::HeapConfig;
    use x86_64::structures::paging::Page;
    use core::ops::RangeInclusive;
    use x86_64::VirtAddr;

    /// Page size (4 KiB).
    pub const PAGE_SIZE: usize = 4096;

    /// Creates an inclusive page range covering the given address interval.
    pub fn page_range_inclusive(
        start: VirtAddr,
        end: VirtAddr,
    ) -> RangeInclusive<Page<Size4KiB>> {
        let start_page = Page::containing_address(start);
        let end_page = Page::containing_address(end);
        Page::range_inclusive(start_page, end_page)
    }

    /// Statistics about the heap.
    #[derive(Debug, Clone, Default)]
    pub struct HeapStats {
        pub total_pages: usize,
        pub mapped_pages: usize,
        pub size_bytes: usize,
        pub used_bytes: usize,
    }

    impl HeapStats {
        pub fn utilisation_percent(&self) -> f64 {
            if self.total_pages == 0 { 0.0 } else {
                (self.used_bytes as f64 / self.size_bytes as f64) * 100.0
            }
        }
    }
}

pub mod metrics {
    //! Metrics for heap operations.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct HeapMetrics {
        pub total_pages_mapped: AtomicU64,
        pub total_bytes_mapped: AtomicU64,
        pub failed_allocations: AtomicU64,
        pub failed_mappings: AtomicU64,
        pub heap_init_calls: AtomicU64,
    }

    impl HeapMetrics {
        pub fn inc_pages_mapped(&self, count: usize) {
            self.total_pages_mapped.fetch_add(count as u64, Ordering::Relaxed);
            self.total_bytes_mapped
                .fetch_add((count * 4096) as u64, Ordering::Relaxed);
        }
        pub fn inc_failed_allocation(&self) {
            self.failed_allocations.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_failed_mapping(&self) {
            self.failed_mappings.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_init_call(&self) {
            self.heap_init_calls.fetch_add(1, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> HeapMetricsSnapshot {
            HeapMetricsSnapshot {
                total_pages_mapped: self.total_pages_mapped.load(Ordering::Relaxed),
                total_bytes_mapped: self.total_bytes_mapped.load(Ordering::Relaxed),
                failed_allocations: self.failed_allocations.load(Ordering::Relaxed),
                failed_mappings: self.failed_mappings.load(Ordering::Relaxed),
                heap_init_calls: self.heap_init_calls.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct HeapMetricsSnapshot {
        pub total_pages_mapped: u64,
        pub total_bytes_mapped: u64,
        pub failed_allocations: u64,
        pub failed_mappings: u64,
        pub heap_init_calls: u64,
    }
}

pub mod init {
    //! Heap initialisation logic.
    use super::{
        config::HeapConfig,
        error::{HeapError, HeapResult},
        metrics::HeapMetrics,
        types::{PAGE_SIZE, page_range_inclusive},
    };
    use linked_list_allocator::LockedHeap;
    use x86_64::{
        structures::paging::{
            FrameAllocator, Mapper, PageTableFlags, PhysFrame,
        },
        VirtAddr,
    };
    use alloc::vec::Vec;
    use tracing::{debug, info, trace, warn};

    /// Initialiser for the kernel heap.
    pub struct HeapInitialiser {
        config: HeapConfig,
        metrics: HeapMetrics,
        initialised: bool,
    }

    impl HeapInitialiser {
        pub fn new(config: HeapConfig) -> Self {
            config.validate().expect("invalid HeapConfig");
            Self {
                config,
                metrics: HeapMetrics::default(),
                initialised: false,
            }
        }

        pub fn default() -> Self {
            Self::new(HeapConfig::default())
        }

        pub fn metrics(&self) -> &HeapMetrics {
            &self.metrics
        }

        pub fn config(&self) -> &HeapConfig {
            &self.config
        }

        /// Initialise the heap by mapping pages and setting up the allocator.
        pub fn init(
            &mut self,
            mut mapper: impl Mapper<Size4KiB>,
            mut frame_alloc: impl FrameAllocator<Size4KiB>,
        ) -> HeapResult<()> {
            if self.initialised {
                return Err(HeapError::AlreadyInitialised);
            }

            self.metrics.inc_init_call();

            let heap_start_virt = VirtAddr::new(self.config.start as u64);
            let heap_end_virt = heap_start_virt + self.config.size as u64 - 1u64;

            let page_range = page_range_inclusive(heap_start_virt, heap_end_virt);
            let mut mapped_pages: Vec<(Page<Size4KiB>, PhysFrame<Size4KiB>)> =
                Vec::with_capacity(page_range.len());

            let flags = PageTableFlags::from_bits_truncate(self.config.flags);

            if self.config.log_mapping {
                info!(
                    start = self.config.start,
                    size = self.config.size,
                    pages = page_range.len(),
                    "mapping kernel heap pages"
                );
            }

            for page in page_range {
                let frame = frame_alloc
                    .allocate_frame()
                    .ok_or_else(|| {
                        self.metrics.inc_failed_allocation();
                        HeapError::FrameAllocationFailed
                    })?;

                match unsafe { mapper.map_to(page, frame, flags, &mut frame_alloc) } {
                    Ok(flush) => {
                        flush.flush();
                        mapped_pages.push((page, frame));
                        trace!(
                            page = page.start_address().as_u64(),
                            frame = frame.start_address().as_u64(),
                            "mapped heap page"
                        );
                    }
                    Err(e) => {
                        self.metrics.inc_failed_mapping();
                        // Clean up already mapped pages
                        for (p, f) in mapped_pages.drain(..) {
                            unsafe {
                                let _ = mapper.unmap(p);
                            }
                            // We cannot free the frame here because the trait doesn't have free_frame.
                            // In practice, we would need to cast to a concrete allocator.
                            // For now, we leak the frames on failure.
                        }
                        return Err(HeapError::PageMapFailed {
                            addr: page.start_address().as_u64(),
                            reason: "mapper error",
                        });
                    }
                }
            }

            self.metrics.inc_pages_mapped(mapped_pages.len());

            // Initialise the global allocator
            unsafe {
                super::ALLOCATOR
                    .lock()
                    .init(self.config.start as *mut u8, self.config.size);
            }

            self.initialised = true;

            if self.config.log_mapping {
                info!(
                    pages = mapped_pages.len(),
                    bytes = self.config.size,
                    "kernel heap initialised"
                );
            }

            Ok(())
        }

        /// Check if the heap is initialised.
        pub fn is_initialised(&self) -> bool {
            self.initialised
        }

        /// Reset the initialiser (for testing).
        #[cfg(test)]
        pub fn reset(&mut self) {
            self.initialised = false;
        }
    }
}

pub mod manager {
    //! Centralised manager for the kernel heap.
    use super::{
        config::HeapConfig,
        error::HeapResult,
        init::HeapInitialiser,
        metrics::HeapMetrics,
        types::HeapStats,
    };
    use x86_64::structures::paging::{FrameAllocator, Mapper, Size4KiB};
    use core::sync::atomic::Ordering;

    /// Manager for the kernel heap.
    pub struct HeapManager {
        initialiser: HeapInitialiser,
    }

    impl HeapManager {
        pub fn new(config: HeapConfig) -> Self {
            Self {
                initialiser: HeapInitialiser::new(config),
            }
        }

        pub fn default() -> Self {
            Self::new(HeapConfig::default())
        }

        pub fn config(&self) -> &HeapConfig {
            self.initialiser.config()
        }

        pub fn metrics(&self) -> &HeapMetrics {
            self.initialiser.metrics()
        }

        /// Initialise the heap.
        pub fn init(
            &mut self,
            mapper: impl Mapper<Size4KiB>,
            frame_alloc: impl FrameAllocator<Size4KiB>,
        ) -> HeapResult<()> {
            self.initialiser.init(mapper, frame_alloc)
        }

        /// Check if the heap is initialised.
        pub fn is_initialised(&self) -> bool {
            self.initialiser.is_initialised()
        }

        /// Get heap statistics (approximate).
        pub fn stats(&self) -> HeapStats {
            // The linked_list_allocator doesn't expose used bytes easily.
            // We can estimate based on the allocator's internal state, but it's not exposed.
            // We'll just return total pages and size.
            let total_pages = self.config().size / 4096;
            let mapped_pages = if self.is_initialised() {
                total_pages
            } else {
                0
            };
            HeapStats {
                total_pages,
                mapped_pages,
                size_bytes: self.config().size,
                used_bytes: 0, // Not easily accessible
            }
        }

        /// Get metrics snapshot.
        pub fn metrics_snapshot(&self) -> super::metrics::HeapMetricsSnapshot {
            self.metrics().snapshot()
        }

        /// Reset metrics.
        pub fn reset_metrics(&self) {
            *self.metrics() = HeapMetrics::default();
        }
    }
}

// -----------------------------------------------------------------------------
// Constants (must match those defined in the parent `memory` module)
// -----------------------------------------------------------------------------

/// Start address of the kernel heap (defined in the parent module).
pub const HEAP_START: usize = 0x_4444_4444_0000;
/// Size of the kernel heap (defined in the parent module).
pub const HEAP_SIZE: usize = 64 * 1024 * 1024; // 64 MiB

// -----------------------------------------------------------------------------
// Global allocator (must be marked `#[global_allocator]`)
// -----------------------------------------------------------------------------

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::HeapConfig;
pub use error::{HeapError, HeapResult};
pub use metrics::{HeapMetrics, HeapMetricsSnapshot};
pub use types::{PAGE_SIZE, HeapStats};
pub use init::HeapInitialiser;
pub use manager::HeapManager;

// -----------------------------------------------------------------------------
// Legacy global API (backward compatibility)
// -----------------------------------------------------------------------------

/// Global manager instance.
static GLOBAL_MANAGER: spin::Once<HeapManager> = spin::Once::new();

/// Get the global manager (initialises with defaults if not yet set).
fn global_manager() -> &'static HeapManager {
    GLOBAL_MANAGER.get().expect("heap manager not initialised")
}

/// Initialise the kernel heap (legacy).
///
/// # Panics
/// Panics if heap initialisation fails.
pub fn init(mapper: impl Mapper<Size4KiB>, frame_alloc: impl FrameAllocator<Size4KiB>) {
    try_init(mapper, frame_alloc).expect("Kernel heap initialisation failed");
}

/// Attempt to initialise the kernel heap (legacy).
pub fn try_init(
    mapper: impl Mapper<Size4KiB>,
    frame_alloc: impl FrameAllocator<Size4KiB>,
) -> Result<(), &'static str> {
    GLOBAL_MANAGER.call_once(|| {
        let config = HeapConfig::default();
        HeapManager::new(config)
    });
    let manager = GLOBAL_MANAGER.get_mut().unwrap();
    // We need a mutable reference to the manager, but it's stored in Once.
    // We can call `init` on the manager, but since Once doesn't give mutable access after init,
    // we need to work around that. We'll make the manager store the initialiser in a Mutex.
    // For simplicity, we'll just use a static mutex for the initialiser.
    // But to keep backward compatibility, we'll call the initialiser directly.
    // Let's use the global initialiser directly.
    // We'll store the initialiser in a static Mutex.
    static INITIALISER: spin::Mutex<Option<HeapInitialiser>> = spin::Mutex::new(None);
    let mut init_guard = INITIALISER.lock();
    if init_guard.is_none() {
        *init_guard = Some(HeapInitialiser::new(HeapConfig::default()));
    }
    let initialiser = init_guard.as_mut().unwrap();
    match initialiser.init(mapper, frame_alloc) {
        Ok(()) => {
            // Store the metrics for later use.
            Ok(())
        }
        Err(e) => Err("heap initialisation failed"),
    }
}

/// Get heap metrics (legacy).
pub fn heap_metrics() -> HeapMetricsSnapshot {
    if let Some(manager) = GLOBAL_MANAGER.get() {
        manager.metrics_snapshot()
    } else {
        HeapMetricsSnapshot::default()
    }
}

/// Get heap stats (legacy).
pub fn heap_stats() -> HeapStats {
    if let Some(manager) = GLOBAL_MANAGER.get() {
        manager.stats()
    } else {
        HeapStats::default()
    }
}

// We also need to provide the global allocator's init, but it's already done via the legacy functions.

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use x86_64::structures::paging::{Page, Size4KiB};

    #[test]
    fn test_page_range_single_page() {
        let start = VirtAddr::new(0x1000);
        let end = VirtAddr::new(0x1FFF);
        let range = page_range_inclusive(start, end);
        let pages: Vec<_> = range.collect();
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].start_address().as_u64(), 0x1000);
    }

    #[test]
    fn test_page_range_multiple_pages() {
        let start = VirtAddr::new(0x0);
        let end = VirtAddr::new(0x2FFF);
        let range = page_range_inclusive(start, end);
        let pages: Vec<_> = range.collect();
        assert_eq!(pages.len(), 3);
    }

    #[test]
    fn test_config_validation() {
        let config = HeapConfig::default();
        assert!(config.validate().is_ok());

        let mut bad = config.clone();
        bad.size = 0;
        assert!(bad.validate().is_err());

        let mut bad2 = config;
        bad2.start = 1;
        assert!(bad2.validate().is_err());
    }

    #[test]
    fn test_metrics() {
        let metrics = HeapMetrics::default();
        metrics.inc_pages_mapped(10);
        metrics.inc_failed_allocation();
        let snap = metrics.snapshot();
        assert_eq!(snap.total_pages_mapped, 10);
        assert_eq!(snap.total_bytes_mapped, 10 * 4096);
        assert_eq!(snap.failed_allocations, 1);
    }
}
