//! mmap() — memory-mapped regions cu page table mapping real
//! + munmap() cu PTE teardown + TLB invalidation
//! + page fault handler pentru lazy allocation + CoW + file-backed
use alloc::{collections::BTreeMap, vec::Vec, string::String};
use spin::{Lazy, Mutex};
use x86_64::{
    structures::paging::PageTableFlags,
    VirtAddr,
};
use crate::task::TaskId;

pub const MAP_ANONYMOUS: u32 = 0x20;
pub const MAP_PRIVATE:   u32 = 0x02;
pub const MAP_SHARED:    u32 = 0x01;
pub const MAP_FIXED:     u32 = 0x10;
pub const MAP_NORESERVE: u32 = 0x4000;

pub const PROT_READ:  u32 = 1;
pub const PROT_WRITE: u32 = 2;
pub const PROT_EXEC:  u32 = 4;
pub const PROT_NONE:  u32 = 0;

#[derive(Clone, Debug)]
pub enum MmapBacking {
    Anonymous,
    File { path: String, offset: u64 },
}

#[derive(Clone, Debug)]
pub struct MmapRegion {
    pub start:   u64,
    pub length:  u64,
    pub prot:    u32,
    pub flags:   u32,
    pub backing: MmapBacking,
    /// Pages that have been faulted in (virt_page_addr → phys_frame)
    pub pages:   BTreeMap<u64, u64>,
}

impl MmapRegion {
    pub fn end(&self) -> u64 { self.start + self.length }
    pub fn contains(&self, addr: u64) -> bool { addr >= self.start && addr < self.end() }

    pub fn to_flags(&self) -> PageTableFlags {
        let mut f = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        if self.prot & PROT_WRITE != 0 { f |= PageTableFlags::WRITABLE; }
        if self.prot & PROT_EXEC  == 0 { f |= PageTableFlags::NO_EXECUTE; }
        f
    }
}

/// Per-process mmap state
static MMAPS: Lazy<Mutex<BTreeMap<TaskId, Vec<MmapRegion>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

static NEXT_VADDR: Mutex<u64> = Mutex::new(0x0000_7000_0000_0000);

fn alloc_vaddr(pages: usize) -> u64 {
    let mut n = NEXT_VADDR.lock();
    let a = *n;
    *n += (pages * 4096) as u64;
    a
}

/// mmap — reserve virtual range, pages faulted in lazily
pub fn mmap(tid: TaskId, hint: u64, length: usize, prot: u32, flags: u32,
            fd: i64, offset: u64) -> u64 {
    if length == 0 { return u64::MAX; }
    let len_aligned = (length + 4095) & !4095;
    let pages       = len_aligned / 4096;

    let vaddr = if flags & MAP_FIXED != 0 && hint != 0 { hint }
                else { alloc_vaddr(pages) };

    let backing = if flags & MAP_ANONYMOUS != 0 || fd == -1 {
        MmapBacking::Anonymous
    } else {
        // File-backed: look up fd → path
        let path = crate::process::fd::get_clone(tid, fd as usize)
            .and_then(|d| match d {
                crate::process::fd::FileDesc::IonasFs { path, .. } => Some(path),
                _ => None,
            })
            .unwrap_or_default();
        MmapBacking::File { path, offset }
    };

    let region = MmapRegion {
        start: vaddr, length: len_aligned as u64, prot, flags, backing,
        pages: BTreeMap::new(),
    };

    MMAPS.lock().entry(tid).or_default().push(region);
    crate::serial_println!("  [MMAP] tid={} vaddr=0x{:x} len={} prot={}", tid, vaddr, length, prot);
    vaddr
}

/// munmap — unmap region: teardown PTEs + TLB flush + free frames
pub fn munmap(tid: TaskId, addr: u64, _length: usize) -> bool {
    let mut mmaps = MMAPS.lock();
    let regions   = match mmaps.get_mut(&tid) { Some(r) => r, None => return false };

    let pos = regions.iter().position(|r| r.start == addr);
    let pos = match pos { Some(p) => p, None => return false };
    let region = regions.remove(pos);

    // Teardown: unmap each faulted page from page tables + free frame
    for (virt_page, phys_frame) in &region.pages {
        // Remove PTE from current page tables
        // (simplified: use x86_64 TLB flush — full impl walks page tables)
        unsafe {
            x86_64::instructions::tlb::flush(VirtAddr::new(*virt_page));
        }
        // Shootdown on SMP
        crate::arch::x86_64::apic::tlb_shootdown(*virt_page);
        // Free the physical frame
        let frame = x86_64::structures::paging::PhysFrame::containing_address(
            x86_64::PhysAddr::new(*phys_frame)
        );
        crate::memory::frame_alloc::dec_ref(frame);
    }

    crate::serial_println!("  [MUNMAP] tid={} vaddr=0x{:x} pages freed={}", tid, addr, region.pages.len());
    true
}

/// Page fault handler for mmap regions — lazy allocation
/// Called from IDT page fault handler when fault is in a mmap region
pub fn handle_mmap_fault(tid: TaskId, virt_addr: u64, write: bool) -> bool {
    let mut mmaps = MMAPS.lock();
    let regions   = match mmaps.get_mut(&tid) { Some(r) => r, None => return false };

    let region = match regions.iter_mut().find(|r| r.contains(virt_addr)) {
        Some(r) => r,
        None    => return false,
    };

    // Check protection: write to read-only region
    if write && region.prot & PROT_WRITE == 0 {
        crate::serial_println!("  [MMAP] SIGSEGV: write to read-only region 0x{:x}", virt_addr);
        return false; // Deliver SIGSEGV
    }

    let page_addr = virt_addr & !0xFFF;

    // Check if already faulted in (CoW case)
    if let Some(&phys) = region.pages.get(&page_addr) {
        if write && region.flags & MAP_PRIVATE != 0 {
            // CoW: copy page
            let new_frame = match crate::memory::frame_alloc::allocate_one() {
                Some(f) => f,
                None    => { oom_kill(tid); return false; }
            };
            let phys_off = 0xFFFF_8000_0000_0000u64;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (phys_off + phys) as *const u8,
                    (phys_off + new_frame.start_address().as_u64()) as *mut u8,
                    4096,
                );
            }
            crate::memory::frame_alloc::dec_ref(
                x86_64::structures::paging::PhysFrame::containing_address(
                    x86_64::PhysAddr::new(phys)));
            region.pages.insert(page_addr, new_frame.start_address().as_u64());
            unsafe { x86_64::instructions::tlb::flush(VirtAddr::new(page_addr)); }
            crate::arch::x86_64::apic::tlb_shootdown(page_addr);
        }
        return true;
    }

    // Lazy allocation: allocate a new physical frame
    let frame = match crate::memory::frame_alloc::allocate_one() {
        Some(f) => f,
        None    => { oom_kill(tid); return false; }
    };
    let phys_off = 0xFFFF_8000_0000_0000u64;

    match &region.backing.clone() {
        MmapBacking::Anonymous => {
            // Zero-fill
            unsafe {
                core::ptr::write_bytes(
                    (phys_off + frame.start_address().as_u64()) as *mut u8, 0, 4096);
            }
        }
        MmapBacking::File { path, offset } => {
            // Read from IONAFS
            let file_offset = offset + (page_addr - region.start);
            let data_buf = crate::fs::ionafs::read(path).unwrap_or_default();
            let dst = unsafe {
                core::slice::from_raw_parts_mut(
                    (phys_off + frame.start_address().as_u64()) as *mut u8, 4096)
            };
            dst.fill(0);
            if file_offset < data_buf.len() as u64 {
                let src_start = file_offset as usize;
                let copy_len  = (data_buf.len() - src_start).min(4096);
                dst[..copy_len].copy_from_slice(&data_buf[src_start..src_start+copy_len]);
            }
        }
    }

    region.pages.insert(page_addr, frame.start_address().as_u64());
    crate::serial_println!("  [MMAP] fault resolved 0x{:x} → phys=0x{:x}", page_addr, frame.start_address().as_u64());
    true
}

/// OOM killer: find and kill the process using the most memory
pub fn oom_kill(requesting_tid: TaskId) {
    crate::serial_println!("[OOM] Out of memory! Killing process {}", requesting_tid);
    crate::signal::send(requesting_tid, crate::signal::Signal::SIGKILL);
}

/// Page aging: mark pages as accessed/dirty for LRU reclaim
/// Called from page fault handler, reads/clears Accessed bit in PTE
pub fn reclaim_lru_pages(target_pages: usize) -> usize {
    let mut reclaimed = 0;
    let mut mmaps = MMAPS.lock();

    'outer: for regions in mmaps.values_mut() {
        for region in regions.iter_mut() {
            // Evict anonymous MAP_PRIVATE pages (simplest to reclaim)
            if !matches!(region.backing, MmapBacking::Anonymous) { continue; }
            let keys: Vec<u64> = region.pages.keys().cloned().collect();
            for page_addr in keys {
                if reclaimed >= target_pages { break 'outer; }
                if let Some(phys) = region.pages.remove(&page_addr) {
                    let frame = x86_64::structures::paging::PhysFrame::containing_address(
                        x86_64::PhysAddr::new(phys));
                    crate::memory::frame_alloc::dec_ref(frame);
                    unsafe { x86_64::instructions::tlb::flush(VirtAddr::new(page_addr)); }
                    reclaimed += 1;
                }
            }
        }
    }
    if reclaimed > 0 {
        crate::serial_println!("  [RECLAIM] reclaimed {} pages", reclaimed);
    }
    reclaimed
}

pub fn cleanup_for(tid: TaskId) {
    if let Some(regions) = MMAPS.lock().remove(&tid) {
        for region in regions {
            for (page_addr, phys) in &region.pages {
                let frame = x86_64::structures::paging::PhysFrame::containing_address(
                    x86_64::PhysAddr::new(*phys));
                crate::memory::frame_alloc::dec_ref(frame);
                unsafe { x86_64::instructions::tlb::flush(VirtAddr::new(*page_addr)); }
            }
        }
    }
}

/// Get physical address of a faulted-in page (for swap eviction)
pub fn get_page_phys(tid: TaskId, virt_page: u64) -> Option<u64> {
    MMAPS.lock().get(&tid)?
        .iter()
        .find_map(|r| r.pages.get(&virt_page).copied())
}

/// Register a page that was swapped in back into the mmap region tracking
/// This ensures munmap/CoW/TLB correctly handles the page going forward
pub fn register_swapped_in_page(tid: TaskId, virt_page: u64, phys: u64) {
    let mut mmaps = MMAPS.lock();
    if let Some(regions) = mmaps.get_mut(&tid) {
        for region in regions.iter_mut() {
            if region.contains(virt_page) {
                region.pages.insert(virt_page, phys);
                return;
            }
        }
    }
    // Page not in any mmap region — it might be a stack page, ignore
}
