//! Per-process virtual address space
//!
//! Fiecare proces userspace are propriile page tables (L4).
//! La context switch schimbăm CR3 → CPU folosește page tables noi.

use x86_64::{
    structures::paging::{
        OffsetPageTable, PageTable, PhysFrame, Page, PageTableFlags, Size4KiB, Mapper,
    }, VirtAddr,
};

/// Spațiu de adrese al unui proces
pub struct AddressSpace {
    /// Frame-ul fizic care conține L4 page table
    pub l4_frame: PhysFrame,
    /// Adresa virtuală a regiunii de stack userspace
    pub stack_top: u64,
    /// Adresa entry point (din ELF)
    pub entry_point: u64,
    /// argc (number of arguments)
    pub argc: u64,
}

impl AddressSpace {
    /// Creează un nou spațiu de adrese pentru un proces userspace.
    /// Copiază kernelul din spațiul curent (kernel e mapat în toate procesele,
    /// în jumătatea superioară a spațiului virtual: 0xFFFF_8000_0000_0000+)
    pub fn new() -> Result<Self, &'static str> {
        // Alocăm un frame pentru L4
        let l4_frame = crate::memory::frame_alloc::allocate_one()
            .ok_or("OOM: cannot allocate L4 frame")?;

        let phys_offset = VirtAddr::new(0xFFFF_8000_0000_0000);
        let l4_virt = phys_offset + l4_frame.start_address().as_u64();
        let l4: &mut PageTable = unsafe { &mut *l4_virt.as_mut_ptr() };

        // Zeros all entries
        l4.zero();

        // Copiăm intrările kernel (jumătatea superioară: indices 256-511)
        let current_l4 = unsafe {
            let (frame, _) = x86_64::registers::control::Cr3::read();
            let virt = phys_offset + frame.start_address().as_u64();
            &*(virt.as_ptr::<PageTable>())
        };
        for i in 256..512 {
            l4[i] = current_l4[i].clone();
        }

        Ok(AddressSpace {
            l4_frame,
            stack_top:   0,
            entry_point: 0,
            argc:        0,
        })
    }

    /// Activează acest spațiu de adrese — încarcă CR3
    pub fn activate(&self) {
        unsafe {
            x86_64::registers::control::Cr3::write(
                self.l4_frame,
                x86_64::registers::control::Cr3Flags::empty(),
            );
        }
    }

    /// Mapează o pagină în spațiul de adrese al procesului
    pub fn map_page(
        &mut self,
        page:  Page<Size4KiB>,
        frame: PhysFrame,
        flags: PageTableFlags,
    ) -> Result<(), &'static str> {
        let phys_offset = VirtAddr::new(0xFFFF_8000_0000_0000);
        let l4_virt = phys_offset + self.l4_frame.start_address().as_u64();
        let l4: &mut PageTable = unsafe { &mut *l4_virt.as_mut_ptr() };
        let mut mapper = unsafe { OffsetPageTable::new(l4, phys_offset) };

        let mut fa = crate::memory::frame_alloc::KernelFrameAllocator;
        unsafe {
            mapper.map_to(page, frame, flags, &mut fa)
                .map_err(|_| "map_to failed")?
                .flush();
        }
        Ok(())
    }
}
