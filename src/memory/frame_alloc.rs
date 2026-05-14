//! Physical Frame Allocator — bitmap + reference counting pentru CoW
use bootloader_api::info::{MemoryRegionKind, MemoryRegions};
use core::sync::atomic::{AtomicBool, Ordering};
use spin::{Lazy, Mutex};
use x86_64::{
    structures::paging::{FrameAllocator, PhysFrame, Size4KiB},
    PhysAddr, VirtAddr,
};

pub const PAGE_SIZE: usize = 4096;
/// Support up to 2 GB of physical RAM (524 288 frames)
const MAX_FRAMES:    usize = (2 * 1024 * 1024 * 1024) / PAGE_SIZE;
const BITMAP_SIZE:   usize = MAX_FRAMES / 64;

/// Set to true once the kernel heap is ready; before that we must not
/// touch REFCOUNTS because its Lazy<Vec> would try to allocate from
/// the heap that is still being set up.
static HEAP_READY: AtomicBool = AtomicBool::new(false);

/// Reference counts per frame — pentru Copy-on-Write
/// refcount[i] = number of address spaces sharing frame i
/// 0 = frame liber, 1 = owned by one, 2+ = shared (CoW)
static REFCOUNTS: Lazy<Mutex<alloc::vec::Vec<u32>>> = Lazy::new(|| {
    Mutex::new(alloc::vec![0u32; MAX_FRAMES])
});

struct BitmapAllocator {
    bitmap:      [u64; BITMAP_SIZE],
    next_hint:   usize,
    total:       usize,
    used:        usize,
    phys_offset: u64,
}

impl BitmapAllocator {
    const fn new() -> Self {
        Self { bitmap: [0u64; BITMAP_SIZE], next_hint: 0, total: 0, used: 0, phys_offset: 0 }
    }

    fn init(&mut self, phys_offset: VirtAddr, mem_regions: &MemoryRegions) {
        self.phys_offset = phys_offset.as_u64();
        self.bitmap.fill(!0u64);
        let mut total = 0usize;
        for region in mem_regions.iter() {
            if region.kind != MemoryRegionKind::Usable { continue; }
            let frame_start = ((region.start as usize) + PAGE_SIZE - 1) / PAGE_SIZE;
            let frame_end   = region.end as usize / PAGE_SIZE;
            for i in frame_start..frame_end { self.set_free(i); total += 1; }
        }
        for i in 0..(0x100000 / PAGE_SIZE) { self.set_used(i); }
        self.total    = total;
        self.next_hint = 0x100000 / PAGE_SIZE;
    }

    fn set_free(&mut self, f: usize) { let (w,b)=(f/64,f%64); if w<BITMAP_SIZE { self.bitmap[w] &= !(1u64<<b); } }
    fn set_used(&mut self, f: usize) { let (w,b)=(f/64,f%64); if w<BITMAP_SIZE { self.bitmap[w] |=  1u64<<b; } }
    fn is_free(&self,  f: usize) -> bool { let (w,b)=(f/64,f%64); w<BITMAP_SIZE && (self.bitmap[w]>>b)&1==0 }

    fn alloc_frame(&mut self) -> Option<PhysFrame> {
        for i in self.next_hint..self.total {
            if self.is_free(i) {
                self.set_used(i); self.used += 1; self.next_hint = i + 1;
                return Some(PhysFrame::containing_address(PhysAddr::new((i * PAGE_SIZE) as u64)));
            }
        }
        for i in 0..self.next_hint {
            if self.is_free(i) {
                self.set_used(i); self.used += 1; self.next_hint = i + 1;
                return Some(PhysFrame::containing_address(PhysAddr::new((i * PAGE_SIZE) as u64)));
            }
        }
        None
    }

    fn free_frame_inner(&mut self, frame: PhysFrame) {
        let idx = frame.start_address().as_u64() as usize / PAGE_SIZE;
        self.set_free(idx);
        self.used = self.used.saturating_sub(1);
        if idx < self.next_hint { self.next_hint = idx; }
    }

    pub fn stats(&self) -> (usize, usize) { (self.total, self.used) }
}

unsafe impl Send for BitmapAllocator {}

static ALLOCATOR: Mutex<BitmapAllocator> = Mutex::new(BitmapAllocator::new());

pub fn init(phys_offset: VirtAddr, mem_regions: &'static MemoryRegions) {
    ALLOCATOR.lock().init(phys_offset, mem_regions);
    let (t, u) = ALLOCATOR.lock().stats();
    crate::serial_println!("    Frames: {} total, {} used, {} free", t, u, t-u);
    crate::serial_println!("    RAM: {} MB usable", t * PAGE_SIZE / 1_048_576);
}

pub fn get() -> impl FrameAllocator<Size4KiB> { LockedAllocator }

struct LockedAllocator;
unsafe impl FrameAllocator<Size4KiB> for LockedAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> { alloc_frame_and_ref() }
}

/// Notify the frame allocator that the kernel heap is ready.
/// After this call, REFCOUNTS will be lazily initialised on first use.
pub fn mark_heap_ready() {
    HEAP_READY.store(true, Ordering::Release);
}

/// Alloc + set refcount=1 (skips refcount before heap is ready)
pub fn alloc_frame_and_ref() -> Option<PhysFrame> {
    let frame = ALLOCATOR.lock().alloc_frame()?;
    if HEAP_READY.load(Ordering::Relaxed) {
        let idx = frame.start_address().as_u64() as usize / PAGE_SIZE;
        if idx < MAX_FRAMES {
            let mut rc = REFCOUNTS.lock();
            rc[idx] = 1;
        }
    }
    Some(frame)
}

/// Increment refcount (share frame for CoW)
pub fn inc_ref(frame: PhysFrame) {
    let idx = frame.start_address().as_u64() as usize / PAGE_SIZE;
    if idx < MAX_FRAMES { REFCOUNTS.lock()[idx] += 1; }
}

/// Decrement refcount; free frame if reaches 0
pub fn dec_ref(frame: PhysFrame) {
    let idx = frame.start_address().as_u64() as usize / PAGE_SIZE;
    if idx >= MAX_FRAMES { return; }
    let mut rc = REFCOUNTS.lock();
    if rc[idx] > 0 { rc[idx] -= 1; }
    if rc[idx] == 0 {
        drop(rc);
        ALLOCATOR.lock().free_frame_inner(frame);
    }
}

/// Get refcount for a frame
pub fn get_ref(frame: PhysFrame) -> u32 {
    let idx = frame.start_address().as_u64() as usize / PAGE_SIZE;
    if idx < MAX_FRAMES { REFCOUNTS.lock()[idx] } else { 0 }
}

pub fn free_frame(frame: PhysFrame) { dec_ref(frame); }

pub fn allocate_one() -> Option<PhysFrame> { alloc_frame_and_ref() }

pub struct KernelFrameAllocator;
unsafe impl FrameAllocator<Size4KiB> for KernelFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> { alloc_frame_and_ref() }
}

pub fn stats() -> (usize, usize) { ALLOCATOR.lock().stats() }

/// Returns (total_pages, used_pages) for mem_stats syscall
pub fn frame_stats() -> (u64, u64) {
    let (total, used) = stats();
    (total as u64, used as u64)
}
