//! Memory Manager — Buddy + Slab
pub mod buddy;
pub mod slab;

pub fn init() {
    // Buddy starts at 4MB phys, covers 64MB
    buddy::init(0x40_0000, 16_384);
    slab::init();
}

pub mod mmap;
