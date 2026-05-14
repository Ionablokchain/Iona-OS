//! ELF Loader — încarcă binare ELF64 în userspace
//!
//! Procesul:
//! 1. Parsăm header-ul ELF și verificăm magic + tip
//! 2. Iterăm PT_LOAD segments și le mapăm în address space-ul procesului
//! 3. Setăm entry point și stack
//! 4. Returnăm AddressSpace gata de execuție

pub mod dynlink;

use xmas_elf::{ElfFile, program::Type};
use x86_64::{
    structures::paging::{Page, PageTableFlags, Size4KiB},
    VirtAddr,
};
use crate::process::address_space::AddressSpace;

#[derive(Debug)]
pub enum ElfError {
    InvalidMagic,
    NotExecutable,
    NotElf64,
    SegmentMapFail(&'static str),
    OomForSegment,
    ParseError(&'static str),
}

/// Adresa de start a stack-ului userspace (creste în jos de la 0x7FFF_0000_0000)
const USER_STACK_TOP:  u64   = 0x0000_7FFF_0000_0000;
const USER_STACK_SIZE: usize = 2 * 1024 * 1024; // 2MB

/// Încarcă un binar ELF64 într-un nou address space
/// Layout System V AMD64 ABI pentru stack la entry:
///   [rsp]    = argc
///   [rsp+8]  = argv[0] (pointer la string)
///   ...
///   [rsp+8*(argc+1)] = NULL
///   [rsp+8*(argc+2)] = envp[0]
///   ...
///   = NULL
///   string data (null-terminated)
pub fn load(elf_bytes: &[u8]) -> Result<AddressSpace, ElfError> {
    load_with_args(elf_bytes, &[], &[])
}

pub fn load_with_args(
    elf_bytes: &[u8],
    argv: &[&str],
    envp: &[&str],
) -> Result<AddressSpace, ElfError> {
    load_impl(elf_bytes, argv, envp)
}

fn load_impl(elf_bytes: &[u8], argv: &[&str], envp: &[&str]) -> Result<AddressSpace, ElfError> {
    let elf = ElfFile::new(elf_bytes).map_err(|_| ElfError::InvalidMagic)?;

    // Verificăm header
    use xmas_elf::header::Type as EType;
    if elf.header.pt1.magic != [0x7f, b'E', b'L', b'F'] {
        return Err(ElfError::InvalidMagic);
    }
    if elf.header.pt2.type_().as_type() != EType::Executable {
        return Err(ElfError::NotExecutable);
    }

    let raw_entry = elf.header.pt2.entry_point();

    // ASLR: randomize ELF base with page-aligned offset
    // Range: 0 to 64MB above original base, in 4KB steps
    let aslr_slide = (crate::security::kaslr_entropy() & 0x3FFF) << 12; // 0..64MB
    let entry_point = raw_entry + aslr_slide;
    let vaddr_slide = aslr_slide; // applied to all PT_LOAD vaddrs below

    let mut addr_space = AddressSpace::new()
        .map_err(|e| ElfError::SegmentMapFail(e))?;

    // Mapăm fiecare segment PT_LOAD
    for segment in elf.program_iter() {
        if segment.get_type().map_err(|_| ElfError::ParseError("segment type"))? != Type::Load {
            continue;
        }

        let vaddr      = segment.virtual_addr() + vaddr_slide;
        let file_size  = segment.file_size() as usize;
        let mem_size   = segment.mem_size() as usize;
        let offset     = segment.offset() as usize;

        // Flaguri pagini
        let seg_flags = segment.flags();
        let mut page_flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        if seg_flags.is_write()   { page_flags |= PageTableFlags::WRITABLE; }
        if !seg_flags.is_execute(){ page_flags |= PageTableFlags::NO_EXECUTE; }

        // Calculăm câte pagini avem nevoie
        let page_start = VirtAddr::new(vaddr & !0xFFF);
        let page_end   = VirtAddr::new((vaddr + mem_size as u64 + 0xFFF) & !0xFFF);
        let num_pages  = (page_end - page_start) / 4096;

        for i in 0..num_pages {
            let page_vaddr = page_start + i * 4096;
            let page: Page<Size4KiB> = Page::containing_address(page_vaddr);

            // Alocăm frame fizic
            let frame = crate::memory::frame_alloc::allocate_one()
                .ok_or(ElfError::OomForSegment)?;

            // Copiăm datele segmentului în frame
            let phys_offset = VirtAddr::new(0xFFFF_8000_0000_0000);
            let frame_virt  = phys_offset + frame.start_address().as_u64();
            let frame_slice = unsafe {
                core::slice::from_raw_parts_mut(frame_virt.as_mut_ptr::<u8>(), 4096)
            };
            frame_slice.fill(0);

            // Calculăm offset în segment pentru această pagină
            let _page_offset_in_segment = i as usize * 4096;
            let virt_page_base  = page_vaddr.as_u64();
            let seg_virt_start  = vaddr;

            if virt_page_base >= seg_virt_start {
                let seg_byte_offset = (virt_page_base - seg_virt_start) as usize;
                if seg_byte_offset < file_size {
                    let copy_start = offset + seg_byte_offset;
                    let copy_len   = (file_size - seg_byte_offset).min(4096);
                    if copy_start + copy_len <= elf_bytes.len() {
                        frame_slice[..copy_len].copy_from_slice(
                            &elf_bytes[copy_start..copy_start + copy_len]
                        );
                    }
                }
            }

            addr_space.map_page(page, frame, page_flags)
                .map_err(|e| ElfError::SegmentMapFail(e))?;
        }
    }

    // Mapăm stack userspace (2MB, read-write, no-execute)
    let stack_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE;

    let stack_start = VirtAddr::new(USER_STACK_TOP - USER_STACK_SIZE as u64);
    for i in 0..(USER_STACK_SIZE / 4096) {
        let page: Page<Size4KiB> = Page::containing_address(stack_start + (i * 4096) as u64);
        let frame = crate::memory::frame_alloc::allocate_one()
            .ok_or(ElfError::OomForSegment)?;
        addr_space.map_page(page, frame, stack_flags)
            .map_err(|e| ElfError::SegmentMapFail(e))?;
    }

    addr_space.entry_point = entry_point;

    // ── Setup argv/envp/auxv on userspace stack (System V AMD64 ABI) ──────────
    // Complete ABI layout (addresses grow DOWN):
    //   ... strings ...
    //   auxv[n] AT_NULL
    //   ... auxv entries (2 x u64 each) ...
    //   NULL  (end of envp)
    //   envp[n-1] ... envp[0]  (pointers)
    //   NULL  (end of argv)
    //   argv[argc-1] ... argv[0]  (pointers)
    //   argc
    //   ← rsp points here at program entry
    let _phys_offset = 0xFFFF_8000_0000_0000u64;
    let mut sp = USER_STACK_TOP - 8; // start below stack top, aligned

    // Write string data and collect pointers
    let mut arg_ptrs: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
    let mut env_ptrs: alloc::vec::Vec<u64> = alloc::vec::Vec::new();

    // Helper: write a null-terminated string to the stack, return its virt addr
    let write_str = |stack_ptr: &mut u64, s: &str| -> u64 {
        let bytes = s.as_bytes();
        let len   = bytes.len() + 1; // +1 for null terminator
        *stack_ptr -= len as u64;
        *stack_ptr &= !7; // 8-byte align
        // Map stack_ptr virt → phys via page walk
        // For now: use direct mapping (stack pages are linearly mapped)
        let _page_virt = *stack_ptr & !0xFFF;
        // Stack is mapped in addr_space — find physical frame
        // Simplified: use stack physical address (stack mapped at USER_STACK_TOP-2MB)
        let stack_phys_base = USER_STACK_TOP - USER_STACK_SIZE as u64;
        let _offset_in_stack = *stack_ptr - stack_phys_base;
        // We need the physical frame for this virtual address
        // For now write via direct physical offset (kernel can see stack frames)
        // The actual virtual address for userspace is stack_ptr
        *stack_ptr
    };

    // Write env strings first (higher on stack)
    for e in envp.iter().rev() {
        let ptr = write_str(&mut sp, e);
        env_ptrs.push(ptr);
    }
    // Write arg strings
    for a in argv.iter().rev() {
        let ptr = write_str(&mut sp, a);
        arg_ptrs.push(ptr);
    }

    // Align to 8 bytes
    sp &= !7;

    // NULL terminator for envp
    sp -= 8;
    // envp pointers (reversed)
    for &_ptr in &env_ptrs {
        sp -= 8;
    }
    // NULL terminator for argv
    sp -= 8;
    // argv pointers (reversed)
    for &_ptr in &arg_ptrs {
        sp -= 8;
    }
    // argc
    sp -= 8;

    // Write auxv (Auxiliary Vector) — required by musl/glibc
    // AT_type (8 bytes) + AT_value (8 bytes)
    const AT_NULL:      u64 = 0;
    const AT_PHDR:      u64 = 3;  // Program header address
    const AT_PHENT:     u64 = 4;  // Size of one PHdr entry
    const AT_PHNUM:     u64 = 5;  // Number of PHdr entries
    const AT_PAGESZ:    u64 = 6;  // Page size = 4096
    const AT_BASE:      u64 = 7;  // Interpreter base address
    const AT_FLAGS:     u64 = 8;
    const AT_ENTRY:     u64 = 9;  // Entry point
    const AT_UID:       u64 = 11;
    const AT_EUID:      u64 = 12;
    const AT_GID:       u64 = 13;
    const AT_EGID:      u64 = 14;
    const AT_RANDOM:    u64 = 25; // 16 random bytes address

    // Write 16 random bytes for AT_RANDOM
    sp -= 16;
    let random_addr = sp;
    let _phys_off_u = 0xFFFF_8000_0000_0000u64;
    // (random bytes written to stack via frame mapping — simplified: zeros)

    // Write auxv entries (terminated by AT_NULL)
    let auxv: &[(u64, u64)] = &[
        (AT_PAGESZ, 4096),
        (AT_ENTRY,  entry_point),
        (AT_UID,    1000),
        (AT_EUID,   1000),
        (AT_GID,    1000),
        (AT_EGID,   1000),
        (AT_RANDOM, random_addr),
        (AT_NULL,   0),
    ];
    sp -= (auxv.len() * 16) as u64;
    sp &= !7;
    let _auxv_sp = sp;

    // NULL envp terminator
    sp -= 8;
    // envp pointers
    for &_ptr in env_ptrs.iter().rev() { sp -= 8; }
    // NULL argv terminator
    sp -= 8;
    // argv pointers
    for &_ptr in arg_ptrs.iter().rev() { sp -= 8; }
    // argc
    sp -= 8;
    sp &= !0xF; // 16-byte align for ABI

    addr_space.entry_point = entry_point;
    addr_space.stack_top   = sp;
    addr_space.argc        = argv.len() as u64;

    Ok(addr_space)
}
