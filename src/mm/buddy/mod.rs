//! Buddy allocator — allocates 2^order pages, O(log n), no external fragmentation
use alloc::vec::Vec;
use spin::{Lazy, Mutex};

pub const MAX_ORDER: usize = 11;  // 0..10: 1..1024 pages (4MB max block)
pub const PAGE_SIZE: usize = 4096;

pub struct BuddyAllocator {
    free:        [Vec<u64>; MAX_ORDER],
    total_pages: usize,
    free_pages:  usize,
}

impl BuddyAllocator {
    pub fn new() -> Self {
        const E: Vec<u64> = Vec::new();
        Self { free: [E; MAX_ORDER], total_pages: 0, free_pages: 0 }
    }

    pub fn add_region(&mut self, base: u64, pages: usize) {
        let mut addr = base;
        let mut rem  = pages;
        self.total_pages += pages;
        self.free_pages  += pages;
        while rem > 0 {
            let mut ord = MAX_ORDER - 1;
            loop {
                let sz  = 1usize << ord;
                let aln = addr % ((sz * PAGE_SIZE) as u64) == 0;
                if sz <= rem && aln { break; }
                if ord == 0 { break; }
                ord -= 1;
            }
            self.free[ord].push(addr);
            let sz = 1usize << ord;
            addr += (sz * PAGE_SIZE) as u64;
            rem  -= sz;
        }
    }

    pub fn alloc(&mut self, order: usize) -> Option<u64> {
        let mut fo = order;
        while fo < MAX_ORDER && self.free[fo].is_empty() { fo += 1; }
        if fo >= MAX_ORDER { return None; }
        let addr = self.free[fo].pop().unwrap_or(0);
        let mut co = fo;
        while co > order {
            co -= 1;
            self.free[co].push(addr + (1u64 << co) * PAGE_SIZE as u64);
        }
        self.free_pages -= 1 << order;
        Some(addr)
    }

    pub fn free(&mut self, mut addr: u64, mut order: usize) {
        self.free_pages += 1 << order;
        while order < MAX_ORDER - 1 {
            let bs  = (1u64 << order) * PAGE_SIZE as u64;
            let bud = if addr % (bs * 2) == 0 { addr + bs } else { addr - bs };
            if let Some(p) = self.free[order].iter().position(|&a| a == bud) {
                self.free[order].swap_remove(p);
                addr = addr.min(bud);
                order += 1;
            } else { break; }
        }
        self.free[order].push(addr);
    }

    pub fn free_pages(&self)  -> usize { self.free_pages }
    pub fn total_pages(&self) -> usize { self.total_pages }
}

static BUDDY: Lazy<Mutex<BuddyAllocator>> = Lazy::new(|| Mutex::new(BuddyAllocator::new()));

pub fn init(base: u64, pages: usize) {
    crate::serial_println!("  [BUDDY] adding region base=0x{:x} pages={}", base, pages);
    let (tp, fp) = {
        let mut b = BUDDY.lock();
        b.add_region(base, pages);
        (b.total_pages(), b.free_pages())
    };
    crate::serial_println!("  [BUDDY] {} pages ({} MB) available", fp, fp * 4096 / 1_048_576);
    crate::serial_println!("  [BUDDY] init done tp={} fp={}", tp, fp);
}

pub fn alloc_pages(order: usize) -> Option<u64> { BUDDY.lock().alloc(order) }
pub fn free_pages(addr: u64, order: usize)       { BUDDY.lock().free(addr, order); }
pub fn alloc_page()  -> Option<u64>              { alloc_pages(0) }
pub fn free_page(a: u64)                         { free_pages(a, 0); }
pub fn stats() -> (usize, usize) { let b = BUDDY.lock(); (b.total_pages(), b.free_pages()) }
