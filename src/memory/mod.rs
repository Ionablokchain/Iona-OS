//! Memory management — inima kernelului
//!
//! Trei componente, inițializate în ordine:
//!
//! 1. **Frame allocator** — gestionează RAM-ul fizic
//!    - Primește memory map de la bootloader
//!    - Oferă frame-uri de 4 KiB libere (bitmap: 0 = liber, 1 = ocupat)
//!
//! 2. **Page table mapper** — mapare virtuală → fizică
//!    - Orice acces la memorie trece prin tabelele de pagini (hardware x86_64)
//!    - Mapăm kernel, heap, memorie pentru dispozitive
//!
//! 3. **Heap allocator** — oferă `alloc::*` (Box, Vec, String etc.)
//!    - O regiune virtuală rezervată pentru heap-ul kernelului
//!    - Implementat cu linked_list_allocator (simplu, corect, no_std)

pub mod swap;
pub mod frame_alloc;
pub mod oom;
pub mod heap;
pub mod mapper;

use bootloader_api::info::{MemoryRegionKind, MemoryRegions};
use x86_64::VirtAddr;

/// Adresa de start a heap-ului kernel în spațiul virtual.
pub const HEAP_START: usize = 0x_4444_4444_0000;
/// Dimensiunea heap-ului kernel — 8 MiB (poate fi extinsă ulterior).
pub const HEAP_SIZE:  usize = 8 * 1024 * 1024; // 8 MiB

/// Inițializează complet subsistemul de memorie.
///
/// # Ordinea este strictă și nu poate fi schimbată:
/// 1. Frame allocator (bitmap)
/// 2. Page table mapper (OffsetPageTable)
/// 3. Kernel heap (linked_list_allocator)
///
/// # Panics
/// Panică dacă orice etapă eșuează — fără memorie kernelul nu poate funcționa.
pub fn init(phys_offset: u64, mem_regions: &'static MemoryRegions) {
    let phys_offset = VirtAddr::new(phys_offset);

    // Validare rapidă
    assert!(
        !phys_offset.is_null(),
        "Physical memory offset must not be null"
    );
    assert!(
        total_usable_bytes(mem_regions) > 0,
        "No usable memory regions detected"
    );

    // ── 1. Frame allocator ────────────────────────────────────────────────────
    frame_alloc::init(phys_offset, mem_regions);
    crate::serial_println!("[MEM] Frame allocator ready");

    // ── 2. Mapper (page tables) ───────────────────────────────────────────────
    // Safety: bootloader has set up page tables with correct physical offset.
    let mapper = unsafe { crate::arch::x86_64::memory::init(phys_offset) };
    crate::serial_println!("[MEM] Page table mapper ready");

    // ── 3. Heap ───────────────────────────────────────────────────────────────
    heap::init(mapper, frame_alloc::get());
    crate::serial_println!("[MEM] Kernel heap ready");

    // Acum heap-ul este live → activăm contorizarea referințelor pentru CoW
    frame_alloc::mark_heap_ready();
    crate::serial_println!("[MEM] Reference counting enabled (CoW ready)");

    crate::serial_println!(
        "[MEM] Memory subsystem initialised — {} MiB usable",
        total_usable_bytes(mem_regions) / (1024 * 1024)
    );
}

/// Returnează cantitatea totală de RAM utilizabilă (în octeți) raportată de bootloader.
pub fn total_usable_bytes(mem_regions: &MemoryRegions) -> u64 {
    mem_regions
        .iter()
        .filter(|r| r.kind == MemoryRegionKind::Usable)
        .map(|r| r.end.saturating_sub(r.start))  // previne underflow teoretic
        .sum()
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
            fake_region(0, 4096, true),             // 4 KiB
            fake_region(4096, 8192, false),         // 4 KiB (rezervat, ignorat)
            fake_region(8192, 16384, true),         // 8 KiB
        ];
        // 4 + 8 = 12 KiB
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
}
