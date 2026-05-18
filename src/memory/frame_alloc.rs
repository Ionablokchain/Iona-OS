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

use bootloader_api::info::{MemoryRegionKind, MemoryRegions};
use core::sync::atomic::{AtomicBool, Ordering};
use spin::{Lazy, Mutex};
use x86_64::{
    structures::paging::{FrameAllocator, PhysFrame, Size4KiB},
    PhysAddr, VirtAddr,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

pub const PAGE_SIZE: usize = 4096;
/// Maximum physical memory supported: 2 GiB → 524 288 frames.
const MAX_FRAMES: usize = (2 * 1024 * 1024 * 1024) / PAGE_SIZE;
/// Bitmap size in `u64` words.
const BITMAP_SIZE: usize = MAX_FRAMES / 64;

// -----------------------------------------------------------------------------
// Heap readiness flag
// -----------------------------------------------------------------------------

/// Set to `true` once the kernel heap is ready. Before that, refcounting
/// is disabled because its `Vec<u32>` would try to allocate from the not-yet-
/// existent heap.
static HEAP_READY: AtomicBool = AtomicBool::new(false);

/// Reference counts per frame. Index = frame number.
/// 0 = free, 1 = exclusively owned, 2+ = shared (CoW).
static REFCOUNTS: Lazy<Mutex<Vec<u32>>> = Lazy::new(|| {
    Mutex::new(vec![0u32; MAX_FRAMES])
});

// -----------------------------------------------------------------------------
// Raw bitmap allocator (no refcounting)
// -----------------------------------------------------------------------------

/// A simple bitmap-based physical frame allocator.
///
/// The bitmap is a fixed-size array of `u64` words. Each bit represents one
/// physical frame (0 = free, 1 = used). The allocator supports up to 2 GiB
/// of physical memory.
///
/// This type is intentionally `pub(crate)` so it can be unit-tested.
#[derive(Debug)]
struct RawBitmapAllocator {
    bitmap:      [u64; BITMAP_SIZE],
    next_hint:   usize,
    total_frames: usize,
    used_frames: usize,
    /// Physical address offset used to translate physical addresses when needed
    /// (not used internally, but kept for potential future use).
    _phys_offset: u64,
}

impl RawBitmapAllocator {
    /// Creates a new, empty allocator (all frames initially marked as used).
    const fn new() -> Self {
        Self {
            bitmap:      [0u64; BITMAP_SIZE],
            next_hint:   0,
            total_frames: 0,
            used_frames: 0,
            _phys_offset: 0,
        }
    }

    /// Initialises the allocator from the memory map provided by the bootloader.
    fn init(&mut self, phys_offset: VirtAddr, mem_regions: &MemoryRegions) {
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
                if i < MAX_FRAMES {
                    self.mark_free(i);
                    total += 1;
                }
            }
        }

        // Reserve the first 1 MiB (e.g., bootloader, kernel early code).
        let reserved_end = 0x100000 / PAGE_SIZE; // 256 frames
        for i in 0..reserved_end {
            if i < MAX_FRAMES {
                self.mark_used(i);
            }
        }

        self.total_frames = total;
        self.next_hint = reserved_end;
    }

    /// Marks a frame as free.
    fn mark_free(&mut self, frame: usize) {
        let (word, bit) = frame_to_word_bit(frame);
        if word < BITMAP_SIZE {
            self.bitmap[word] &= !(1u64 << bit);
        }
    }

    /// Marks a frame as used.
    fn mark_used(&mut self, frame: usize) {
        let (word, bit) = frame_to_word_bit(frame);
        if word < BITMAP_SIZE {
            self.bitmap[word] |= 1u64 << bit;
        }
    }

    /// Checks if a frame is free.
    fn is_free(&self, frame: usize) -> bool {
        let (word, bit) = frame_to_word_bit(frame);
        word < BITMAP_SIZE && (self.bitmap[word] >> bit) & 1 == 0
    }

    /// Allocates a single physical frame.
    fn alloc_frame(&mut self) -> Option<PhysFrame> {
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
    fn free_frame(&mut self, frame: PhysFrame) {
        let idx = phys_frame_to_index(frame);
        if idx < MAX_FRAMES {
            self.mark_free(idx);
            self.used_frames = self.used_frames.saturating_sub(1);
            // Move hint backward to allow immediate reuse.
            if idx < self.next_hint {
                self.next_hint = idx;
            }
        }
    }

    /// Returns total and used frame counts.
    fn stats(&self) -> (usize, usize) {
        (self.total_frames, self.used_frames)
    }
}

// -----------------------------------------------------------------------------
// Global allocator instance
// -----------------------------------------------------------------------------

static RAW_ALLOCATOR: Mutex<RawBitmapAllocator> = Mutex::new(RawBitmapAllocator::new());

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Initialises the frame allocator from the bootloader memory map.
pub fn init(phys_offset: VirtAddr, mem_regions: &'static MemoryRegions) {
    let mut alloc = RAW_ALLOCATOR.lock();
    alloc.init(phys_offset, mem_regions);
    let (t, u) = alloc.stats();
    crate::serial_println!(
        "    Frames: {} total, {} used, {} free",
        t, u, t - u
    );
    crate::serial_println!(
        "    RAM: {} MiB usable",
        t * PAGE_SIZE / 1_048_576
    );
}

/// Signals that the kernel heap is ready, enabling reference counting.
pub fn mark_heap_ready() {
    HEAP_READY.store(true, Ordering::Release);
}

/// Allocates a frame, setting its reference count to 1 if refcounting is active.
pub fn alloc_frame_and_ref() -> Option<PhysFrame> {
    let frame = RAW_ALLOCATOR.lock().alloc_frame()?;
    if HEAP_READY.load(Ordering::Acquire) {
        let idx = phys_frame_to_index(frame);
        if idx < MAX_FRAMES {
            REFCOUNTS.lock()[idx] = 1;
        }
    }
    Some(frame)
}

/// Increments the reference count of `frame` (used for CoW sharing).
///
/// # Panics
/// Panics if called before the heap is ready (refcounting not available).
pub fn inc_ref(frame: PhysFrame) {
    assert!(
        HEAP_READY.load(Ordering::Acquire),
        "inc_ref called before heap is ready"
    );
    let idx = phys_frame_to_index(frame);
    if idx < MAX_FRAMES {
        REFCOUNTS.lock()[idx] += 1;
    }
}

/// Decrements the reference count of `frame`. If it reaches 0, the frame is freed.
///
/// # Panics
/// Panics if called before the heap is ready.
pub fn dec_ref(frame: PhysFrame) {
    assert!(
        HEAP_READY.load(Ordering::Acquire),
        "dec_ref called before heap is ready"
    );
    let idx = phys_frame_to_index(frame);
    if idx >= MAX_FRAMES {
        return;
    }
    let mut rc = REFCOUNTS.lock();
    if rc[idx] > 0 {
        rc[idx] -= 1;
    }
    if rc[idx] == 0 {
        drop(rc); // release lock before freeing
        RAW_ALLOCATOR.lock().free_frame(frame);
    }
}

/// Returns the reference count of `frame` (0 if not in use or heap not ready).
pub fn get_ref(frame: PhysFrame) -> u32 {
    if !HEAP_READY.load(Ordering::Acquire) {
        return 0;
    }
    let idx = phys_frame_to_index(frame);
    if idx < MAX_FRAMES {
        REFCOUNTS.lock()[idx]
    } else {
        0
    }
}

/// Convenience alias for `dec_ref`.
pub fn free_frame(frame: PhysFrame) {
    dec_ref(frame);
}

/// Allocates a single frame (with refcount = 1 if heap is ready).
pub fn allocate_one() -> Option<PhysFrame> {
    alloc_frame_and_ref()
}

/// Returns `(total_frames, used_frames)`.
pub fn stats() -> (usize, usize) {
    RAW_ALLOCATOR.lock().stats()
}

/// Returns `(total_pages, used_pages)` as `u64` for syscalls.
pub fn frame_stats() -> (u64, u64) {
    let (t, u) = stats();
    (t as u64, u as u64)
}

// -----------------------------------------------------------------------------
// Public frame allocator wrapper (implements `FrameAllocator` trait)
// -----------------------------------------------------------------------------

/// A wrapper that implements `FrameAllocator<Size4KiB>` using the global allocator.
pub struct KernelFrameAllocator;

unsafe impl FrameAllocator<Size4KiB> for KernelFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        alloc_frame_and_ref()
    }
}

/// Compatibility function for older code that expects a `get()` function.
pub fn get() -> impl FrameAllocator<Size4KiB> {
    KernelFrameAllocator
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Converts a frame index to a `PhysFrame<Size4KiB>`.
fn phys_frame_from_index(idx: usize) -> PhysFrame<Size4KiB> {
    PhysFrame::containing_address(PhysAddr::new((idx * PAGE_SIZE) as u64))
}

/// Converts a `PhysFrame` to its frame index.
fn phys_frame_to_index(frame: PhysFrame<Size4KiB>) -> usize {
    frame.start_address().as_u64() as usize / PAGE_SIZE
}

/// Decomposes a frame number into word/bit for the bitmap.
const fn frame_to_word_bit(frame: usize) -> (usize, usize) {
    (frame / 64, frame % 64)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Creates a minimal bitmap allocator for testing.
    fn test_allocator() -> RawBitmapAllocator {
        let mut alloc = RawBitmapAllocator::new();
        // Simulate 512 frames total, first 256 reserved.
        // Manually mark frames 0..255 as used, 256..511 as free.
        for i in 0..256 {
            alloc.mark_used(i);
        }
        for i in 256..512 {
            alloc.mark_free(i);
        }
        alloc.total_frames = 512;
        alloc.next_hint = 256;
        alloc
    }

    #[test]
    fn test_alloc_and_free() {
        let mut alloc = test_allocator();
        let frame = alloc.alloc_frame().expect("should allocate");
        let idx = phys_frame_to_index(frame);
        assert!(idx >= 256 && idx < 512);
        assert!(!alloc.is_free(idx));

        alloc.free_frame(frame);
        assert!(alloc.is_free(idx));
    }

    #[test]
    fn test_exhaustion() {
        let mut alloc = test_allocator();
        // Allocate all free frames (256 of them)
        for _ in 0..256 {
            alloc.alloc_frame().expect("should allocate");
        }
        assert!(alloc.alloc_frame().is_none());
    }

    #[test]
    fn test_free_reuse() {
        let mut alloc = test_allocator();
        let f1 = alloc.alloc_frame().unwrap();
        let f2 = alloc.alloc_frame().unwrap();
        alloc.free_frame(f1);
        let f3 = alloc.alloc_frame().unwrap();
        // The freed frame should be reused (exact frame may vary, but total free count should be consistent)
        assert_eq!(phys_frame_to_index(f1), phys_frame_to_index(f3));
    }

    #[test]
    fn test_refcount_basic() {
        // Simulate heap ready
        HEAP_READY.store(true, Ordering::Release);
        // We need a frame; use a fake frame index? No, we need a real PhysFrame
        // that we can allocate. But in unit tests we don't have real memory.
        // We'll test the logic on a mocked frame index by bypassing the bitmap
        // using a direct index (the refcount functions are index-based).
        // Since `inc_ref` and `dec_ref` take a PhysFrame, we can create a
        // PhysFrame from a known index and test the refcount layer.
        let frame = phys_frame_from_index(500);
        // Initially refcount should be 0
        assert_eq!(get_ref(frame), 0);
        inc_ref(frame); // 1
        assert_eq!(get_ref(frame), 1);
        inc_ref(frame); // 2
        assert_eq!(get_ref(frame), 2);
        dec_ref(frame); // 1
        assert_eq!(get_ref(frame), 1);
        dec_ref(frame); // 0
        assert_eq!(get_ref(frame), 0);
        // Frame should not be freed because it wasn't allocated via bitmap.
        // In real usage, dec_ref to 0 triggers free, but in test environment
        // the bitmap doesn't have it as used, so free is a no-op.
        // We'll just check refcount is 0.
    }
}
