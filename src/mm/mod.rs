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

pub mod buddy;
pub mod slab;
pub mod mmap;

use core::sync::atomic::{AtomicUsize, Ordering};
use spin::{Lazy, Mutex};
use tracing::{debug, info, warn};

// -----------------------------------------------------------------------------
// Re‑exports
// -----------------------------------------------------------------------------

pub use buddy::{
    alloc_frame, alloc_pages, alloc_pages_aligned, dealloc_frame, dealloc_pages,
    get_free_frame_count, get_total_frame_count, stats as buddy_stats,
};
pub use slab::{
    alloc as slab_alloc, free as slab_free, init as slab_init, SlabCache,
};
pub use mmap::{
    cleanup_task, handle_page_fault, init as mmap_init, mark_dirty, memory_stats,
    mmap_anon, mmap_file, mmap_stats, msync, munmap, MmapRegion, MmapStats,
    MAX_MMAP_REGIONS, PAGE_SIZE,
};

// -----------------------------------------------------------------------------
// Global memory statistics
// -----------------------------------------------------------------------------

/// Global memory statistics.
#[derive(Debug, Default)]
pub struct MemStats {
    /// Total physical memory (bytes).
    pub total_memory: usize,
    /// Free physical memory (bytes).
    pub free_memory: usize,
    /// Memory used by the kernel (bytes).
    pub kernel_memory: usize,
    /// Memory used by userspace processes (bytes).
    pub userspace_memory: usize,
    /// Memory used by slab allocator (bytes).
    pub slab_memory: usize,
    /// Memory swapped out (bytes).
    pub swapped_memory: usize,
}

impl MemStats {
    /// Calculate memory utilisation percentage.
    pub fn utilisation_percent(&self) -> f64 {
        if self.total_memory == 0 {
            0.0
        } else {
            (self.total_memory - self.free_memory) as f64 / self.total_memory as f64 * 100.0
        }
    }

    /// Get a human‑readable summary.
    pub fn summary(&self) -> String {
        format!(
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

// -----------------------------------------------------------------------------
// OOM handler
// -----------------------------------------------------------------------------

/// Out‑of‑memory handler type.
pub type OomHandler = fn() -> bool;

/// Global OOM handler (can be set by the kernel).
static OOM_HANDLER: Lazy<Mutex<Option<OomHandler>>> = Lazy::new(|| Mutex::new(None));

/// Set the out‑of‑memory handler.
///
/// The handler should attempt to free memory (e.g., by killing low‑priority tasks)
/// and return `true` if memory was successfully freed, `false` otherwise.
pub fn set_oom_handler(handler: OomHandler) {
    *OOM_HANDLER.lock() = Some(handler);
    info!("OOM handler registered");
}

/// Call the OOM handler (if registered). Returns `true` if the handler
/// successfully freed memory, `false` otherwise.
pub fn invoke_oom_handler() -> bool {
    if let Some(handler) = *OOM_HANDLER.lock() {
        info!("invoking OOM handler");
        handler()
    } else {
        warn!("no OOM handler registered");
        false
    }
}

// -----------------------------------------------------------------------------
// Kernel memory pressure
// -----------------------------------------------------------------------------

/// Kernel memory pressure level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemPressure {
    /// Normal operation (free memory > 20%).
    Normal,
    /// Moderate pressure (free memory between 10% and 20%).
    Moderate,
    /// High pressure (free memory between 5% and 10%).
    High,
    /// Critical (free memory < 5%).
    Critical,
}

impl MemPressure {
    /// Get pressure level from free memory percentage.
    pub fn from_free_percent(free_percent: f64) -> Self {
        if free_percent > 20.0 {
            MemPressure::Normal
        } else if free_percent > 10.0 {
            MemPressure::Moderate
        } else if free_percent > 5.0 {
            MemPressure::High
        } else {
            MemPressure::Critical
        }
    }
}

/// Get current memory pressure level.
pub fn memory_pressure() -> MemPressure {
    let (total_frames, free_frames) = buddy::stats();
    let total_memory = total_frames * buddy::FRAME_SIZE;
    let free_memory = free_frames * buddy::FRAME_SIZE;
    let free_percent = if total_memory > 0 {
        free_memory as f64 / total_memory as f64 * 100.0
    } else {
        100.0
    };
    MemPressure::from_free_percent(free_percent)
}

// -----------------------------------------------------------------------------
// Memory initialisation
// -----------------------------------------------------------------------------

/// Memory layout detected by the bootloader.
#[derive(Debug, Clone)]
pub struct MemoryLayout {
    /// Start of usable physical memory.
    pub usable_start: usize,
    /// End of usable physical memory.
    pub usable_end: usize,
    /// Total usable memory (bytes).
    pub total_usable: usize,
    /// Number of 4 KiB frames available.
    pub frame_count: usize,
}

/// Detect memory layout from bootloader info.
/// This should be called very early in the boot process.
pub fn detect_memory_layout() -> MemoryLayout {
    // Default layout: 4 MB to 68 MB (64 MB usable)
    let usable_start = 0x40_0000;   // 4 MB
    let usable_end = 0x440_0000;    // 68 MB
    let total_usable = usable_end - usable_start;
    let frame_count = total_usable / buddy::FRAME_SIZE;

    debug!(
        usable_start,
        usable_end,
        total_usable_mb = total_usable / 1024 / 1024,
        frame_count,
        "detected memory layout"
    );

    MemoryLayout {
        usable_start,
        usable_end,
        total_usable,
        frame_count,
    }
}

/// Initialise the entire memory management subsystem.
///
/// # Arguments
/// * `memory_layout` – Memory layout detected by the bootloader.
pub fn init(memory_layout: &MemoryLayout) {
    info!("initialising memory manager");

    // 1. Initialise buddy allocator with detected physical memory
    buddy::init(memory_layout.usable_start, memory_layout.frame_count);
    info!("buddy allocator initialised: {} frames ({} MiB)",
        memory_layout.frame_count,
        memory_layout.total_usable / 1024 / 1024
    );

    // 2. Initialise slab allocator for kernel objects
    slab::init();
    info!("slab allocator initialised");

    // 3. Initialise mmap subsystem
    mmap::init();
    info!("mmap subsystem initialised");

    info!("memory manager initialised");
}

/// Initialise with default memory layout (4 MB to 68 MB).
pub fn init_default() {
    let layout = detect_memory_layout();
    init(&layout);
}

// -----------------------------------------------------------------------------
// Comprehensive memory statistics
// -----------------------------------------------------------------------------

/// Get comprehensive memory statistics.
pub fn get_memory_stats() -> MemStats {
    let (total_frames, free_frames) = buddy::stats();
    let slab_stats = slab::stats();

    let total_memory = total_frames * buddy::FRAME_SIZE;
    let free_memory = free_frames * buddy::FRAME_SIZE;
    let slab_memory = slab_stats.total_allocated;

    // Get swap stats
    let (_total_swap, used_swap) = crate::memory::swap::stats();
    let swapped_memory = used_swap * 4096; // Assuming 4 KiB pages

    // Estimate kernel and userspace memory (simplified)
    let kernel_memory = slab_memory; // Kernel memory ≈ slab allocated memory
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

// -----------------------------------------------------------------------------
// Memory debugging
// -----------------------------------------------------------------------------

/// Check for memory leaks (only in debug builds).
pub fn check_leaks() {
    #[cfg(debug_assertions)]
    {
        let buddy_stats = buddy::stats();
        let slab_stats = slab::stats();

        if buddy_stats.1 != buddy_stats.0 {
            warn!(
                "possible memory leak: {} frames allocated, {} free",
                buddy_stats.0 - buddy_stats.1,
                buddy_stats.1
            );
        }

        if slab_stats.active_objects > 0 {
            warn!(
                "slab leak: {} active objects still allocated",
                slab_stats.active_objects
            );
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mem_pressure() {
        assert_eq!(MemPressure::from_free_percent(30.0), MemPressure::Normal);
        assert_eq!(MemPressure::from_free_percent(15.0), MemPressure::Moderate);
        assert_eq!(MemPressure::from_free_percent(8.0), MemPressure::High);
        assert_eq!(MemPressure::from_free_percent(3.0), MemPressure::Critical);
    }

    #[test]
    fn test_memory_layout_detection() {
        let layout = detect_memory_layout();
        assert_eq!(layout.usable_start, 0x40_0000);
        assert!(layout.frame_count > 0);
        assert_eq!(layout.total_usable, layout.frame_count * buddy::FRAME_SIZE);
    }

    #[test]
    fn test_mem_stats_utilisation() {
        let stats = MemStats {
            total_memory: 100,
            free_memory: 25,
            ..Default::default()
        };
        assert!((stats.utilisation_percent() - 75.0).abs() < 0.01);
    }

    #[test]
    fn test_mem_stats_summary() {
        let stats = MemStats {
            total_memory: 1024 * 1024 * 1024, // 1 GiB
            free_memory: 256 * 1024 * 1024,   // 256 MiB
            kernel_memory: 128 * 1024 * 1024, // 128 MiB
            userspace_memory: 512 * 1024 * 1024, // 512 MiB
            slab_memory: 64 * 1024 * 1024,    // 64 MiB
            swapped_memory: 128 * 1024 * 1024, // 128 MiB
        };
        let summary = stats.summary();
        assert!(summary.contains("Mem:"));
        assert!(summary.contains("MiB"));
    }

    #[test]
    fn test_oom_handler() {
        let called = core::sync::atomic::AtomicBool::new(false);
        set_oom_handler(|| {
            called.store(true, Ordering::Relaxed);
            true
        });
        assert!(invoke_oom_handler());
        assert!(called.load(Ordering::Relaxed));
    }
}
