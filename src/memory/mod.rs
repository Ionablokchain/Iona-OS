//! Memory management — inima kernelului
//!
//! Trei componente, inițializate în ordine:
//!
//! 1. FRAME ALLOCATOR — gestionează RAM fizic
//!    - Primește memory map de la bootloader
//!    - Returnează frame-uri de 4KB libere când cineva cere memorie
//!    - Implementare: bitmap (1 bit per frame, 0=liber, 1=ocupat)
//!
//! 2. PAGE TABLE MAPPER — mapare virtuală → fizică
//!    - Orice acces la memorie trece prin page tables (hardware x86_64)
//!    - Mapăm kernel, heap, device memory
//!
//! 3. HEAP ALLOCATOR — furnizează alloc::* (Box, Vec, String etc.)
//!    - O regiune virtuală rezervată pentru heap kernel
//!    - Allocator: linked_list_allocator (simplu, correct, no_std)

pub mod swap;

pub mod frame_alloc;
pub mod oom;
pub mod heap;
pub mod mapper;

use bootloader_api::info::{MemoryRegionKind, MemoryRegions};
use x86_64::VirtAddr;

/// Adresa de start a heap-ului kernel în spațiul virtual
pub const HEAP_START: usize = 0x_4444_4444_0000;
/// Dimensiunea heap-ului kernel — 8MB pentru început
pub const HEAP_SIZE:  usize = 8 * 1024 * 1024;

/// Inițializează complet subsistemul de memorie.
/// Ordinea este strictă și nu poate fi schimbată.
pub fn init(phys_offset: u64, mem_regions: &'static MemoryRegions) {
    let phys_offset = VirtAddr::new(phys_offset);

    // ── 1. Frame allocator ────────────────────────────────────────────────────
    frame_alloc::init(phys_offset, mem_regions);

    // ── 2. Mapper (page tables) ───────────────────────────────────────────────
    let mapper = unsafe { crate::arch::x86_64::memory::init(phys_offset) };

    // ── 3. Heap ───────────────────────────────────────────────────────────────
    heap::init(mapper, frame_alloc::get());

    // Now that the heap is live, enable refcount tracking in the frame allocator
    frame_alloc::mark_heap_ready();
}

/// Returnează cantitatea de RAM utilizabilă detectată la boot
pub fn total_usable_bytes(mem_regions: &MemoryRegions) -> u64 {
    mem_regions
        .iter()
        .filter(|r| r.kind == MemoryRegionKind::Usable)
        .map(|r| r.end - r.start)
        .sum()
}
