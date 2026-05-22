//! x86‑64 specific memory utilities.
//!
//! This module provides low‑level helpers for working with the x86_64
//! paging structures and the `OffsetPageTable` used by the bootloader.
//! It allows safe access to the active page table and initialisation
//! of the recursive mapping used by the `x86_64` crate.
//!
//! # Safety
//!
//! All functions in this module are `unsafe` because they directly
//! manipulate page tables – a single mistake can cause page faults
//! or corrupt the virtual memory mapping. The caller must ensure
//! that all given addresses are valid and that the page tables are
//! correctly set up by the bootloader.

use x86_64::{
    structures::paging::{OffsetPageTable, PageTable, PhysFrame},
    registers::control::Cr3,
    VirtAddr,
};

/// Obtain a mutable reference to the active level‑4 page table (PML4).
///
/// The function reads the current page table root from the `CR3` register,
/// adds the given physical offset (usually the virtual base where physical
/// memory is mapped, e.g., `0xFFFF_8000_0000_0000`), and returns a
/// `&'static mut PageTable`.
///
/// # Safety
///
/// - `phys_offset` must be the virtual base address where the bootloader
///   maps all physical memory (e.g., the `physical_memory_offset` passed
///   by the bootloader to the kernel).
/// - The physical address read from `CR3` must be valid (i.e., point to
///   a correctly initialised page table).
/// - The computed virtual address must be mapped to the physical page
///   table frame (which it typically is when `phys_offset` is correct).
/// - The caller must ensure that no other code is simultaneously modifying
///   the page tables in an incompatible way (interrupts should be disabled).
///
/// # Example
/// ```
/// unsafe {
///     let offset = VirtAddr::new(0xFFFF_8000_0000_0000);
///     let l4 = active_level_4_table(offset);
///     // Now you can inspect or modify the PML4 entries.
/// }
/// ```
#[inline(always)]
pub unsafe fn active_level_4_table(phys_offset: VirtAddr) -> &'static mut PageTable {
    let (l4_frame, _) = Cr3::read();
    let phys = l4_frame.start_address();
    let virt = phys_offset + phys.as_u64();
    let table_ptr = virt.as_mut_ptr();
    &mut *table_ptr
}

/// Initialise an `OffsetPageTable` for the active mapping.
///
/// This is the standard way to obtain a `OffsetPageTable` that can be
/// used with the `x86_64` crate's paging abstractions. It uses the
/// recursive mapping created by the bootloader.
///
/// # Safety
///
/// Same as `active_level_4_table`, plus:
/// - The page table must be set up with a recursive entry (or the
///   `OffsetPageTable` constructor expects that the physical memory
///   offset is correct). The `OffsetPageTable::new` function will
///   panic if the offset does not map the page table frames properly.
/// - This function should be called exactly once, early in the kernel
///   initialisation, before any other paging operations.
///
/// # Returns
///
/// An `OffsetPageTable<'static>` that can be used for mapping and
/// unmapping pages.
///
/// # Example
/// ```
/// unsafe {
///     let offset = VirtAddr::new(0xFFFF_8000_0000_0000);
///     let mut page_table = init(offset);
///     // Now use page_table to map new pages, etc.
/// }
/// ```
pub unsafe fn init(phys_offset: VirtAddr) -> OffsetPageTable<'static> {
    let l4 = active_level_4_table(phys_offset);
    OffsetPageTable::new(l4, phys_offset)
}

/// Get the physical address of the current page table root (CR3).
///
/// Returns the physical frame containing the PML4 page table.
/// This is useful for debugging or when preparing a new page table
/// for another CPU.
#[inline(always)]
pub fn current_page_table_root() -> PhysFrame {
    let (frame, _) = Cr3::read();
    frame
}

/// Helper to create a virtual address from a physical address using
/// the given offset. This is useful when you have a physical address
/// (e.g., from a frame) and you need its virtual mapping.
///
/// # Safety
/// The computed virtual address must be valid (i.e., the physical address
/// is actually mapped at that offset).
#[inline(always)]
pub unsafe fn phys_to_virt(phys: u64, phys_offset: VirtAddr) -> VirtAddr {
    phys_offset + phys
}

/// Helper to convert a virtual address back to its physical address,
/// assuming the given offset is the base where physical memory is mapped.
/// This is **not** a general translation – it only works when the virtual
/// address lies within the direct physical mapping window.
///
/// # Safety
/// The virtual address must be inside the direct mapping area.
#[inline(always)]
pub unsafe fn virt_to_phys(virt: VirtAddr, phys_offset: VirtAddr) -> u64 {
    virt.as_u64() - phys_offset.as_u64()
}

// -----------------------------------------------------------------------------
// Tests (compile‑time / do not run on real hardware)
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consts_work() {
        // Just check that the functions compile and constants are okay.
        let _ = current_page_table_root();
    }
}
