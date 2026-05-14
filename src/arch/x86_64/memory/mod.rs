//! Memory utilities specifice x86_64

use x86_64::{
    structures::paging::{
        OffsetPageTable, PageTable,
    }, VirtAddr,
};

/// Creează un OffsetPageTable la adresa dată a page table-ului L4
///
/// SAFETY: adresa fizică completă trebuie să fie mapată la phys_offset + adresa
pub unsafe fn active_level_4_table(phys_offset: VirtAddr) -> &'static mut PageTable {
    use x86_64::registers::control::Cr3;
    let (l4_frame, _) = Cr3::read();
    let phys = l4_frame.start_address();
    let virt = phys_offset + phys.as_u64();
    let table: *mut PageTable = virt.as_mut_ptr();
    &mut *table
}

pub unsafe fn init(phys_offset: VirtAddr) -> OffsetPageTable<'static> {
    let l4 = active_level_4_table(phys_offset);
    OffsetPageTable::new(l4, phys_offset)
}
