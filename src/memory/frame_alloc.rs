//! Physical Frame Allocator — bitmap + reference counting for CoW.
//!
//! # Overview
//! - A bitmap tracks which physical frames are free/used.
//! - Reference counts allow Copy-on-Write sharing of frames.
//! - The allocator is split into two layers: a low-level bitmap allocator
//!   (`RawBitmapAllocator`) and a higher-level one that manages refcounts
//!   (`FrameAllocator`).
//! - Refcounts are only enabled after the kernel heap is initialised
//!   (`mark_heap_ready`). Before that, frames are allocated without refcounting.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                    Physical Frame Allocator Module                     │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   config    │    error     │    metrics    │         types            │
//! │ (FrameCfg)  │ (FrameError) │ (FrameMetrics)│ (FrameIndex, etc.)       │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │    raw      │   refcount   │   allocator   │        manager           │
//! │ (bitmap)    │ (refcounts)  │ (main impl)   │ (FrameManager)           │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::memory::frame_alloc::{FrameManager, FrameConfig};
//!
//! let config = FrameConfig::default();
//! let manager = FrameManager::new(config);
//! manager.init(phys_offset, &mem_regions);
//! manager.mark_heap_ready();
//! let frame = manager.allocate_one().unwrap();
//! manager.free_frame(frame);
//! ```

#![allow(dead_code)]

use bootloader_api::info::{MemoryRegionKind, MemoryRegions};
use core::sync::atomic::{AtomicBool, Ordering};
use spin::{Mutex, RwLock};
use x86_64::{
    structures::paging::{FrameAllocator, PhysFrame, Size4KiB},
    PhysAddr, VirtAddr,
};
use tracing::{debug, info, trace, warn};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod constants {
    //! Constants for the frame allocator.
    pub const PAGE_SIZE: usize = 4096;
    /// Maximum physical memory supported: 2 GiB → 524 288 frames.
    pub const MAX_FRAMES: usize = (2 * 1024 * 1024 * 1024) / PAGE_SIZE;
    /// Bitmap size in `u64` words.
    pub const BITMAP_SIZE: usize = MAX_FRAMES / 64;
    /// Default maximum frames.
    pub const DEFAULT_MAX_FRAMES: usize = MAX_FRAMES;
}

pub mod config {
    //! Configuration for the frame allocator.
    use serde::{Deserialize, Serialize};
    use super::constants::DEFAULT_MAX_FRAMES;

    /// Configuration for the frame allocator.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct FrameConfig {
        pub max_frames: usize,
        pub enable_refcounting: bool,
        pub collect_metrics: bool,
        pub log_allocations: bool,
        pub log_frees: bool,
        pub reserve_first_mib: bool,
    }

    impl Default for FrameConfig {
        fn default() -> Self {
            Self {
                max_frames: DEFAULT_MAX_FRAMES,
                enable_refcounting: true,
                collect_metrics: true,
                log_allocations: false,
                log_frees: false,
                reserve_first_mib: true,
            }
        }
    }

    impl FrameConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.max_frames == 0 {
                return Err("max_frames must be > 0");
            }
            Ok(())
        }

        pub fn with_metrics(mut self) -> Self {
            self.collect_metrics = true;
            self
        }

        pub fn with_logging(mut self) -> Self {
            self.log_allocations = true;
            self.log_frees = true;
            self
        }
    }
}

pub mod error {
    //! Error types for the frame allocator.
    use x86_64::structures::paging::PhysFrame;
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum FrameError {
        #[error("no free frames available")]
        OutOfFrames,

        #[error("invalid frame index {index} (max {max})")]
        InvalidFrameIndex { index: usize, max: usize },

        #[error("frame is already free")]
        AlreadyFree,

        #[error("reference count underflow for frame {frame:?}")]
        RefcountUnderflow { frame: PhysFrame },

        #[error("frame allocation not initialised")]
        NotInitialised,

        #[error("configuration error: {0}")]
        Config(String),
    }

    pub type FrameResult<T> = Result<T, FrameError>;
}

pub mod types {
    //! Core types for the frame allocator.
    use super::constants::PAGE_SIZE;
    use x86_64::{
        structures::paging::{PhysFrame, Size4KiB},
        PhysAddr,
    };
    use core::fmt;

    /// Frame index (0..MAX_FRAMES-1).
    pub type FrameIndex = usize;

    /// Convert a frame index to a `PhysFrame`.
    #[inline]
    pub fn phys_frame_from_index(idx: FrameIndex) -> PhysFrame<Size4KiB> {
        PhysFrame::containing_address(PhysAddr::new((idx * PAGE_SIZE) as u64))
    }

    /// Convert a `PhysFrame` to its frame index.
    #[inline]
    pub fn phys_frame_to_index(frame: PhysFrame<Size4KiB>) -> FrameIndex {
        frame.start_address().as_u64() as usize / PAGE_SIZE
    }

    /// Decomposes a frame number into word/bit for the bitmap.
    #[inline]
    pub const fn frame_to_word_bit(frame: FrameIndex) -> (usize, usize) {
        (frame / 64, frame % 64)
    }

    /// Statistics about the frame allocator.
    #[derive(Debug, Clone, Default)]
    pub struct FrameStats {
        pub total_frames: usize,
        pub free_frames: usize,
        pub used_frames: usize,
        pub refcounted_frames: usize,
        pub total_allocations: u64,
        pub total_frees: u64,
    }

    impl fmt::Display for FrameStats {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            writeln!(f, "Frame Allocator Statistics:")?;
            writeln!(f, "  Total frames: {}", self.total_frames)?;
            writeln!(f, "  Free frames: {}", self.free_frames)?;
            writeln!(f, "  Used frames: {}", self.used_frames)?;
            writeln!(f, "  Refcounted frames: {}", self.refcounted_frames)?;
            writeln!(f, "  Total allocations: {}", self.total_allocations)?;
            writeln!(f, "  Total frees: {}", self.total_frees)
        }
    }
}

pub mod raw {
    //! Raw bitmap allocator (no refcounting).
    use super::{
        config::FrameConfig,
        constants::{BITMAP_SIZE, MAX_FRAMES, PAGE_SIZE},
        types::{FrameIndex, phys_frame_from_index, frame_to_word_bit},
    };
    use bootloader_api::info::{MemoryRegionKind, MemoryRegions};
    use x86_64::VirtAddr;
    use core::fmt;

    /// A simple bitmap-based physical frame allocator.
    #[derive(Debug)]
    pub struct RawBitmapAllocator {
        bitmap: [u64; BITMAP_SIZE],
        next_hint: usize,
        total_frames: usize,
        used_frames: usize,
        max_frames: usize,
        _phys_offset: u64,
    }

    impl RawBitmapAllocator {
        /// Creates a new, empty allocator (all frames initially marked as used).
        pub const fn new() -> Self {
            Self {
                bitmap: [0u64; BITMAP_SIZE],
                next_hint: 0,
                total_frames: 0,
                used_frames: 0,
                max_frames: MAX_FRAMES,
                _phys_offset: 0,
            }
        }

        /// Creates a new allocator with a custom maximum frame count.
        pub fn with_max_frames(max_frames: usize) -> Self {
            let mut this = Self::new();
            this.max_frames = max_frames.min(MAX_FRAMES);
            this
        }

        /// Initialises the allocator from the memory map provided by the bootloader.
        pub fn init(&mut self, phys_offset: VirtAddr, mem_regions: &MemoryRegions, config: &FrameConfig) {
            self._phys_offset = phys_offset.as_u64();
            // Mark all frames as used initially.
            self.bitmap.fill(!0u64);

            let mut total = 0;
            for region in mem_regions.iter() {
                if region.kind != MemoryRegionKind::Usable {
                    continue;
                }
                let frame_start = region.start as usize / PAGE_SIZE;
                let frame_end = region.end as usize / PAGE_SIZE;
                for i in frame_start..frame_end {
                    if i < self.max_frames {
                        self.mark_free(i);
                        total += 1;
                    }
                }
            }

            // Reserve the first 1 MiB (e.g., bootloader, kernel early code).
            if config.reserve_first_mib {
                let reserved_end = 0x100000 / PAGE_SIZE; // 256 frames
                for i in 0..reserved_end {
                    if i < self.max_frames {
                        self.mark_used(i);
                    }
                }
            }

            self.total_frames = total;
            self.next_hint = if config.reserve_first_mib { 256 } else { 0 };
        }

        /// Marks a frame as free.
        pub fn mark_free(&mut self, frame: FrameIndex) {
            if frame >= self.max_frames {
                return;
            }
            let (word, bit) = frame_to_word_bit(frame);
            if word < BITMAP_SIZE {
                self.bitmap[word] &= !(1u64 << bit);
            }
        }

        /// Marks a frame as used.
        pub fn mark_used(&mut self, frame: FrameIndex) {
            if frame >= self.max_frames {
                return;
            }
            let (word, bit) = frame_to_word_bit(frame);
            if word < BITMAP_SIZE {
                self.bitmap[word] |= 1u64 << bit;
            }
        }

        /// Checks if a frame is free.
        pub fn is_free(&self, frame: FrameIndex) -> bool {
            if frame >= self.max_frames {
                return false;
            }
            let (word, bit) = frame_to_word_bit(frame);
            word < BITMAP_SIZE && (self.bitmap[word] >> bit) & 1 == 0
        }

        /// Allocates a single physical frame.
        pub fn alloc_frame(&mut self) -> Option<x86_64::structures::paging::PhysFrame<Size4KiB>> {
            // Search from hint to end
            for i in self.next_hint..self.total_frames {
                if self.is_free(i) {
                    self.mark_used(i);
                    self.used_frames += 1;
                    self.next_hint = i + 1;
                    return Some(phys_frame_from_index(i));
                }
            }
            // Wrap around
            for i in 0..self.next_hint {
                if self.is_free(i) {
                    self.mark_used(i);
                    self.used_frames += 1;
                    self.next_hint = i + 1;
                    return Some(phys_frame_from_index(i));
                }
            }
            None
        }

        /// Frees a previously allocated frame.
        pub fn free_frame(&mut self, frame: x86_64::structures::paging::PhysFrame<Size4KiB>) {
            let idx = super::types::phys_frame_to_index(frame);
            if idx < self.max_frames {
                self.mark_free(idx);
                self.used_frames = self.used_frames.saturating_sub(1);
                // Move hint backward to allow immediate reuse.
                if idx < self.next_hint {
                    self.next_hint = idx;
                }
            }
        }

        /// Returns total and used frame counts.
        pub fn stats(&self) -> (usize, usize) {
            (self.total_frames, self.used_frames)
        }

        /// Get total frames.
        pub fn total_frames(&self) -> usize {
            self.total_frames
        }

        /// Get used frames.
        pub fn used_frames(&self) -> usize {
            self.used_frames
        }

        /// Get free frames.
        pub fn free_frames(&self) -> usize {
            self.total_frames.saturating_sub(self.used_frames)
        }

        /// Get the maximum frames.
        pub fn max_frames(&self) -> usize {
            self.max_frames
        }

        /// Reset the allocator.
        pub fn reset(&mut self) {
            self.bitmap.fill(!0u64);
            self.total_frames = 0;
            self.used_frames = 0;
            self.next_hint = 0;
        }
    }

    impl Default for RawBitmapAllocator {
        fn default() -> Self {
            Self::new()
        }
    }

    impl fmt::Display for RawBitmapAllocator {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "RawBitmapAllocator: {} total, {} used, {} free",
                self.total_frames,
                self.used_frames,
                self.free_frames()
            )
        }
    }
}

pub mod refcount {
    //! Reference counting for copy-on-write.
    use super::{
        config::FrameConfig,
        constants::MAX_FRAMES,
        types::{FrameIndex, phys_frame_to_index},
        error::{FrameError, FrameResult},
        raw::RawBitmapAllocator,
    };
    use x86_64::structures::paging::PhysFrame;
    use spin::Mutex;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicBool, Ordering};
    use tracing::{debug, trace};

    /// Reference counts per frame. Index = frame number.
    /// 0 = free, 1 = exclusively owned, 2+ = shared (CoW).
    static REFCOUNTS: Mutex<Vec<u32>> = Mutex::new(Vec::new());

    /// Heap readiness flag.
    static HEAP_READY: AtomicBool = AtomicBool::new(false);

    /// Mark the heap as ready, enabling reference counting.
    pub fn mark_heap_ready(max_frames: usize) {
        let mut rc = REFCOUNTS.lock();
        *rc = vec![0u32; max_frames.min(MAX_FRAMES)];
        HEAP_READY.store(true, Ordering::Release);
        trace!("reference counting enabled for {} frames", rc.len());
    }

    /// Check if reference counting is enabled.
    pub fn is_refcounting_enabled() -> bool {
        HEAP_READY.load(Ordering::Acquire)
    }

    /// Increment the reference count of `frame` (used for CoW sharing).
    pub fn inc_ref(frame: PhysFrame) -> FrameResult<()> {
        if !HEAP_READY.load(Ordering::Acquire) {
            // If heap is not ready, refcounting is disabled.
            return Ok(());
        }
        let idx = phys_frame_to_index(frame);
        let mut rc = REFCOUNTS.lock();
        if idx >= rc.len() {
            return Err(FrameError::InvalidFrameIndex {
                index: idx,
                max: rc.len(),
            });
        }
        rc[idx] += 1;
        trace!(frame_index = idx, new_count = rc[idx], "incremented refcount");
        Ok(())
    }

    /// Decrement the reference count of `frame`. If it reaches 0, the frame is freed.
    pub fn dec_ref(frame: PhysFrame, bitmap: &mut RawBitmapAllocator) -> FrameResult<()> {
        if !HEAP_READY.load(Ordering::Acquire) {
            // If heap is not ready, just free the frame directly.
            bitmap.free_frame(frame);
            return Ok(());
        }
        let idx = phys_frame_to_index(frame);
        let mut rc = REFCOUNTS.lock();
        if idx >= rc.len() {
            return Err(FrameError::InvalidFrameIndex {
                index: idx,
                max: rc.len(),
            });
        }
        if rc[idx] == 0 {
            return Err(FrameError::RefcountUnderflow { frame });
        }
        rc[idx] -= 1;
        let new_count = rc[idx];
        if new_count == 0 {
            drop(rc); // release lock before freeing
            bitmap.free_frame(frame);
            trace!(frame_index = idx, "freed frame (refcount reached 0)");
        } else {
            trace!(frame_index = idx, new_count, "decremented refcount");
        }
        Ok(())
    }

    /// Get the reference count of a frame.
    pub fn get_ref(frame: PhysFrame) -> u32 {
        if !HEAP_READY.load(Ordering::Acquire) {
            return 0;
        }
        let idx = phys_frame_to_index(frame);
        let rc = REFCOUNTS.lock();
        rc.get(idx).copied().unwrap_or(0)
    }

    /// Reset reference counts (for testing).
    #[cfg(test)]
    pub fn reset_refcounts() {
        *REFCOUNTS.lock() = Vec::new();
        HEAP_READY.store(false, Ordering::Release);
    }
}

pub mod metrics {
    //! Metrics for the frame allocator.
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct FrameMetrics {
        pub allocations: AtomicU64,
        pub frees: AtomicU64,
        pub allocation_failures: AtomicU64,
        pub refcount_incs: AtomicU64,
        pub refcount_decs: AtomicU64,
        pub oom_events: AtomicU64,
        pub total_frames: AtomicUsize,
        pub free_frames: AtomicUsize,
    }

    impl FrameMetrics {
        pub fn inc_alloc(&self) {
            self.allocations.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_free(&self) {
            self.frees.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_alloc_failure(&self) {
            self.allocation_failures.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_refcount_inc(&self) {
            self.refcount_incs.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_refcount_dec(&self) {
            self.refcount_decs.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_oom(&self) {
            self.oom_events.fetch_add(1, Ordering::Relaxed);
        }
        pub fn set_total_frames(&self, n: usize) {
            self.total_frames.store(n, Ordering::Relaxed);
        }
        pub fn set_free_frames(&self, n: usize) {
            self.free_frames.store(n, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> FrameMetricsSnapshot {
            FrameMetricsSnapshot {
                allocations: self.allocations.load(Ordering::Relaxed),
                frees: self.frees.load(Ordering::Relaxed),
                allocation_failures: self.allocation_failures.load(Ordering::Relaxed),
                refcount_incs: self.refcount_incs.load(Ordering::Relaxed),
                refcount_decs: self.refcount_decs.load(Ordering::Relaxed),
                oom_events: self.oom_events.load(Ordering::Relaxed),
                total_frames: self.total_frames.load(Ordering::Relaxed),
                free_frames: self.free_frames.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct FrameMetricsSnapshot {
        pub allocations: u64,
        pub frees: u64,
        pub allocation_failures: u64,
        pub refcount_incs: u64,
        pub refcount_decs: u64,
        pub oom_events: u64,
        pub total_frames: usize,
        pub free_frames: usize,
    }
}

pub mod allocator {
    //! Main frame allocator combining bitmap and refcounting.
    use super::{
        config::FrameConfig,
        error::{FrameError, FrameResult},
        metrics::FrameMetrics,
        raw::RawBitmapAllocator,
        refcount,
        types::{phys_frame_to_index, FrameStats},
    };
    use bootloader_api::info::MemoryRegions;
    use x86_64::{
        structures::paging::{PhysFrame, Size4KiB},
        VirtAddr,
    };
    use spin::Mutex;
    use tracing::{debug, info, trace, warn};

    /// Main frame allocator.
    pub struct FrameAllocator {
        bitmap: Mutex<RawBitmapAllocator>,
        config: FrameConfig,
        metrics: FrameMetrics,
        initialised: Mutex<bool>,
    }

    impl FrameAllocator {
        /// Create a new frame allocator with the given configuration.
        pub fn new(config: FrameConfig) -> Self {
            config.validate().expect("invalid FrameConfig");
            Self {
                bitmap: Mutex::new(RawBitmapAllocator::with_max_frames(config.max_frames)),
                config,
                metrics: FrameMetrics::default(),
                initialised: Mutex::new(false),
            }
        }

        /// Create a default frame allocator.
        pub fn default() -> Self {
            Self::new(FrameConfig::default())
        }

        /// Get a reference to the metrics.
        pub fn metrics(&self) -> &FrameMetrics {
            &self.metrics
        }

        /// Get the configuration.
        pub fn config(&self) -> &FrameConfig {
            &self.config
        }

        /// Initialise the allocator with the memory map.
        pub fn init(&self, phys_offset: VirtAddr, mem_regions: &MemoryRegions) {
            let mut bitmap = self.bitmap.lock();
            bitmap.init(phys_offset, mem_regions, &self.config);
            *self.initialised.lock() = true;
            let stats = bitmap.stats();
            self.metrics.set_total_frames(stats.0);
            self.metrics.set_free_frames(stats.0 - stats.1);
            info!(
                total_frames = stats.0,
                used_frames = stats.1,
                free_frames = stats.0 - stats.1,
                "frame allocator initialised"
            );
        }

        /// Mark the heap as ready, enabling reference counting.
        pub fn mark_heap_ready(&self) {
            let max_frames = self.bitmap.lock().max_frames();
            refcount::mark_heap_ready(max_frames);
            info!("heap ready, reference counting enabled");
        }

        /// Allocate a single frame with refcount = 1 if refcounting is enabled.
        pub fn allocate_one(&self) -> FrameResult<PhysFrame<Size4KiB>> {
            if !*self.initialised.lock() {
                return Err(FrameError::NotInitialised);
            }
            let mut bitmap = self.bitmap.lock();
            let frame = bitmap.alloc_frame().ok_or_else(|| {
                self.metrics.inc_alloc_failure();
                self.metrics.inc_oom();
                FrameError::OutOfFrames
            })?;
            self.metrics.inc_alloc();
            if self.config.log_allocations {
                trace!(
                    frame = phys_frame_to_index(frame),
                    "allocated frame"
                );
            }
            if refcount::is_refcounting_enabled() {
                let idx = phys_frame_to_index(frame);
                let mut rc = super::refcount::REFCOUNTS.lock();
                if idx < rc.len() {
                    rc[idx] = 1;
                    self.metrics.inc_refcount_inc();
                }
            }
            Ok(frame)
        }

        /// Free a frame, decrementing refcount and freeing if zero.
        pub fn free_frame(&self, frame: PhysFrame<Size4KiB>) -> FrameResult<()> {
            if !*self.initialised.lock() {
                return Err(FrameError::NotInitialised);
            }
            let mut bitmap = self.bitmap.lock();
            self.metrics.inc_free();
            if self.config.log_frees {
                trace!(
                    frame = phys_frame_to_index(frame),
                    "freeing frame"
                );
            }
            refcount::dec_ref(frame, &mut bitmap)?;
            Ok(())
        }

        /// Increment the reference count of a frame (for CoW).
        pub fn inc_ref(&self, frame: PhysFrame<Size4KiB>) -> FrameResult<()> {
            refcount::inc_ref(frame)?;
            self.metrics.inc_refcount_inc();
            Ok(())
        }

        /// Get the reference count of a frame.
        pub fn get_ref(&self, frame: PhysFrame<Size4KiB>) -> u32 {
            refcount::get_ref(frame)
        }

        /// Get statistics.
        pub fn stats(&self) -> FrameStats {
            let bitmap = self.bitmap.lock();
            let (total, used) = bitmap.stats();
            FrameStats {
                total_frames: total,
                free_frames: total - used,
                used_frames: used,
                refcounted_frames: if refcount::is_refcounting_enabled() {
                    let rc = super::refcount::REFCOUNTS.lock();
                    rc.iter().filter(|&&c| c > 0).count()
                } else {
                    0
                },
                total_allocations: self.metrics.allocations.load(Ordering::Relaxed),
                total_frees: self.metrics.frees.load(Ordering::Relaxed),
            }
        }

        /// Get total frames.
        pub fn total_frames(&self) -> usize {
            self.bitmap.lock().total_frames()
        }

        /// Get free frames.
        pub fn free_frames(&self) -> usize {
            let bitmap = self.bitmap.lock();
            bitmap.free_frames()
        }

        /// Check if the allocator is initialised.
        pub fn is_initialised(&self) -> bool {
            *self.initialised.lock()
        }

        /// Reset the allocator (for testing).
        #[cfg(test)]
        pub fn reset(&self) {
            let mut bitmap = self.bitmap.lock();
            bitmap.reset();
            *self.initialised.lock() = false;
            super::refcount::reset_refcounts();
        }
    }

    impl Default for FrameAllocator {
        fn default() -> Self {
            Self::new(FrameConfig::default())
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::FrameConfig;
pub use error::{FrameError, FrameResult};
pub use metrics::{FrameMetrics, FrameMetricsSnapshot};
pub use types::{FrameIndex, FrameStats, phys_frame_from_index, phys_frame_to_index};
pub use allocator::FrameAllocator;

// Re‑export for backward compatibility.
pub use constants::{PAGE_SIZE, MAX_FRAMES, BITMAP_SIZE};

// -----------------------------------------------------------------------------
// Legacy global API (backward compatibility)
// -----------------------------------------------------------------------------

use core::sync::atomic::Ordering;

static GLOBAL_ALLOCATOR: spin::Once<FrameAllocator> = spin::Once::new();

/// Get the global allocator instance.
fn global_allocator() -> &'static FrameAllocator {
    GLOBAL_ALLOCATOR.get().expect("frame allocator not initialised")
}

/// Initialise the frame allocator (legacy).
pub fn init(phys_offset: VirtAddr, mem_regions: &'static MemoryRegions) {
    GLOBAL_ALLOCATOR.call_once(|| FrameAllocator::default());
    global_allocator().init(phys_offset, mem_regions);
    let (t, u) = stats();
    crate::serial_println!(
        "    Frames: {} total, {} used, {} free",
        t, u, t - u
    );
    crate::serial_println!(
        "    RAM: {} MiB usable",
        t * PAGE_SIZE / 1_048_576
    );
}

/// Mark heap ready (legacy).
pub fn mark_heap_ready() {
    global_allocator().mark_heap_ready();
}

/// Allocate a frame with refcount (legacy).
pub fn allocate_one() -> Option<PhysFrame<Size4KiB>> {
    global_allocator().allocate_one().ok()
}

/// Allocate a frame (alias for allocate_one) (legacy).
pub fn alloc_frame_and_ref() -> Option<PhysFrame<Size4KiB>> {
    allocate_one()
}

/// Increment refcount (legacy).
pub fn inc_ref(frame: PhysFrame<Size4KiB>) {
    let _ = global_allocator().inc_ref(frame);
}

/// Decrement refcount and free if zero (legacy).
pub fn dec_ref(frame: PhysFrame<Size4KiB>) {
    let _ = global_allocator().free_frame(frame);
}

/// Free a frame (legacy).
pub fn free_frame(frame: PhysFrame<Size4KiB>) {
    dec_ref(frame);
}

/// Get refcount (legacy).
pub fn get_ref(frame: PhysFrame<Size4KiB>) -> u32 {
    global_allocator().get_ref(frame)
}

/// Get stats (legacy).
pub fn stats() -> (usize, usize) {
    let stats = global_allocator().stats();
    (stats.total_frames, stats.used_frames)
}

/// Get stats as u64 (legacy).
pub fn frame_stats() -> (u64, u64) {
    let stats = global_allocator().stats();
    (stats.total_frames as u64, stats.used_frames as u64)
}

/// Kernel frame allocator wrapper (implements `FrameAllocator` trait).
pub struct KernelFrameAllocator;

unsafe impl FrameAllocator<Size4KiB> for KernelFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        allocate_one()
    }
}

/// Compatibility function for older code.
pub fn get() -> impl FrameAllocator<Size4KiB> {
    KernelFrameAllocator
}

/// Reset global allocator (for testing).
#[cfg(test)]
pub fn reset_global() {
    if let Some(alloc) = GLOBAL_ALLOCATOR.get() {
        alloc.reset();
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use x86_64::structures::paging::PhysFrame;

    fn test_allocator() -> FrameAllocator {
        let config = FrameConfig {
            max_frames: 512,
            reserve_first_mib: false,
            ..Default::default()
        };
        let alloc = FrameAllocator::new(config);
        // Manually simulate memory regions for testing.
        // We'll use a mock memory map (just mark frames 0..511 as usable).
        let mut bitmap = alloc.bitmap.lock();
        bitmap.total_frames = 512;
        for i in 0..512 {
            bitmap.mark_free(i);
        }
        // Mark first 256 as reserved (used) to simulate kernel/bootloader.
        for i in 0..256 {
            bitmap.mark_used(i);
        }
        *alloc.initialised.lock() = true;
        alloc
    }

    #[test]
    fn test_alloc_and_free() {
        let alloc = test_allocator();
        let frame = alloc.allocate_one().expect("should allocate");
        let idx = phys_frame_to_index(frame);
        assert!(idx >= 256 && idx < 512);
        assert!(alloc.get_ref(frame) == 0 || alloc.get_ref(frame) == 1);
        alloc.free_frame(frame).unwrap();
        assert_eq!(alloc.get_ref(frame), 0);
    }

    #[test]
    fn test_exhaustion() {
        let alloc = test_allocator();
        // Allocate all free frames (256 of them)
        for _ in 0..256 {
            alloc.allocate_one().expect("should allocate");
        }
        assert!(alloc.allocate_one().is_err());
    }

    #[test]
    fn test_free_reuse() {
        let alloc = test_allocator();
        let f1 = alloc.allocate_one().unwrap();
        let f2 = alloc.allocate_one().unwrap();
        alloc.free_frame(f1).unwrap();
        let f3 = alloc.allocate_one().unwrap();
        assert_eq!(phys_frame_to_index(f1), phys_frame_to_index(f3));
    }

    #[test]
    fn test_refcount_basic() {
        let alloc = test_allocator();
        alloc.mark_heap_ready();

        let frame = alloc.allocate_one().unwrap();
        assert_eq!(alloc.get_ref(frame), 1);
        alloc.inc_ref(frame).unwrap();
        assert_eq!(alloc.get_ref(frame), 2);
        alloc.free_frame(frame).unwrap();
        assert_eq!(alloc.get_ref(frame), 1);
        alloc.free_frame(frame).unwrap();
        assert_eq!(alloc.get_ref(frame), 0);
        // The frame should now be freed, and trying to free again should fail
        // (the refcount underflow error would be returned).
        // We'll just check that the refcount is 0.
    }

    #[test]
    fn test_stats() {
        let alloc = test_allocator();
        let stats = alloc.stats();
        assert_eq!(stats.total_frames, 512);
        assert_eq!(stats.free_frames, 256);
        assert_eq!(stats.used_frames, 256);
        alloc.allocate_one().unwrap();
        let stats2 = alloc.stats();
        assert_eq!(stats2.free_frames, 255);
        assert_eq!(stats2.used_frames, 257);
    }

    #[test]
    fn test_config_validation() {
        let config = FrameConfig::default();
        assert!(config.validate().is_ok());

        let mut bad = config.clone();
        bad.max_frames = 0;
        assert!(bad.validate().is_err());
    }
}
