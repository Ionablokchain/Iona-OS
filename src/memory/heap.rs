//! Kernel heap — furnizează alloc::* după init
//!
//! linked_list_allocator: simplu, correct, no_std.
//! Alocăm o regiune virtuală (HEAP_START..HEAP_START+HEAP_SIZE),
//! o mapăm în page tables cu frame-uri fizice, și inițializăm allocatorul.

use linked_list_allocator::LockedHeap;
use x86_64::{
    structures::paging::{
        FrameAllocator, Mapper, Page, PageTableFlags, Size4KiB,
    },
    VirtAddr,
};
use super::{HEAP_START, HEAP_SIZE};

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

pub fn init(
    mut mapper: impl Mapper<Size4KiB>,
    mut alloc:  impl FrameAllocator<Size4KiB>,
) {
    let heap_start = VirtAddr::new(HEAP_START as u64);
    let heap_end   = heap_start + HEAP_SIZE as u64 - 1u64;
    let page_range = {
        let start_page = Page::containing_address(heap_start);
        let end_page   = Page::containing_address(heap_end);
        Page::range_inclusive(start_page, end_page)
    };

    let flags = PageTableFlags::PRESENT
              | PageTableFlags::WRITABLE
              | PageTableFlags::NO_EXECUTE;

    let mut mapped = 0usize;
    for page in page_range {
        let frame = alloc.allocate_frame()
            .expect("heap init: out of physical frames");
        unsafe {
            mapper.map_to(page, frame, flags, &mut alloc)
                .expect("heap page map failed")
                .flush();
        }
        mapped += 1;
    }

    unsafe {
        ALLOCATOR.lock().init(HEAP_START as *mut u8, HEAP_SIZE);
    }

    crate::serial_println!("    Heap: {} pages ({} KB) at 0x{:x}",
        mapped, HEAP_SIZE / 1024, HEAP_START);
}
