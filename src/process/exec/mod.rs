//! execve() cu argv/envp — pasăm argumente pe stack-ul userspace
//!
//! Layout stack la entry point (conform System V AMD64 ABI):
//!
//!   HIGH ADDRESS (USER_STACK_TOP)
//!   ┌─────────────────────────────┐
//!   │  null terminator (env end)  │
//!   │  envp[n-1] string data      │
//!   │  ...                        │
//!   │  envp[0] string data        │
//!   │  null terminator (arg end)  │
//!   │  argv[n-1] string data      │
//!   │  ...                        │
//!   │  argv[0] string data        │
//!   ├─────────────────────────────┤  ← rsp la entry point (16-byte aligned)
//!   │  0 (null — envp terminator) │
//!   │  &envp[n-1]                 │
//!   │  ...                        │
//!   │  &envp[0]                   │
//!   │  0 (null — argv terminator) │
//!   │  &argv[argc-1]              │
//!   │  ...                        │
//!   │  &argv[0]                   │
//!   │  argc (i64)                 │  ← rsp points here
//!   LOW ADDRESS
//!
//! Entry point receives: rdi=argc, rsi=argv, rdx=envp (per ABI)

use alloc::vec::Vec;

const PHYS_OFFSET: u64 = 0xFFFF_8000_0000_0000;
const USER_STACK_TOP: u64 = 0x0000_7FFF_0000_0000;

/// Push argv + envp onto userspace stack, return new rsp
/// stack_top: virtual address of top of user stack (highest address)
pub fn setup_stack(
    stack_top:   u64,
    args:        &[&str],   // argv[0..n]
    envs:        &[&str],   // envp[0..n]
) -> u64 {
    // We write strings from top downward, then pointers below them
    let mut sp = stack_top;

    // Helper: push bytes onto stack (grows downward)
    macro_rules! push_bytes {
        ($bytes:expr) => {{
            let b: &[u8] = $bytes;
            sp -= b.len() as u64;
            let virt = sp;
            // Write through physical offset mapping
            let phys_virt = PHYS_OFFSET + user_virt_to_phys(virt);
            unsafe {
                core::ptr::copy_nonoverlapping(b.as_ptr(), phys_virt as *mut u8, b.len());
            }
            virt
        }};
    }

    macro_rules! push_u64 {
        ($v:expr) => {{
            sp -= 8;
            let phys_virt = PHYS_OFFSET + user_virt_to_phys(sp);
            unsafe { (phys_virt as *mut u64).write_unaligned($v); }
        }};
    }

    // Push env strings, collect pointers
    let mut env_ptrs: Vec<u64> = Vec::new();
    for &env in envs.iter().rev() {
        let mut s = env.as_bytes().to_vec();
        s.push(0); // null terminator
        let ptr = push_bytes!(&s);
        env_ptrs.push(ptr);
    }
    env_ptrs.reverse();

    // Push arg strings, collect pointers
    let mut arg_ptrs: Vec<u64> = Vec::new();
    for &arg in args.iter().rev() {
        let mut s = arg.as_bytes().to_vec();
        s.push(0);
        let ptr = push_bytes!(&s);
        arg_ptrs.push(ptr);
    }
    arg_ptrs.reverse();

    // Align stack to 16 bytes before pushing pointers
    sp &= !0xF;

    // Push envp array (null-terminated)
    push_u64!(0u64); // null terminator
    for &ptr in env_ptrs.iter().rev() {
        push_u64!(ptr);
    }

    // Push argv array (null-terminated)
    push_u64!(0u64); // null terminator
    for &ptr in arg_ptrs.iter().rev() {
        push_u64!(ptr);
    }

    // Push argc
    push_u64!(args.len() as u64);

    // ABI: at entry, rsp must point to argc
    // and (rsp+8) = argv[0], (rsp+8*(argc+1)+8) = envp[0]
    sp
}

/// Page table entry flag bits (x86_64 4-level paging)
const PTE_PRESENT:   u64 = 1 << 0;
const PTE_WRITABLE:  u64 = 1 << 1;
const PTE_USER:      u64 = 1 << 2;
const PTE_HUGE:      u64 = 1 << 7;  // PS bit: 1GB (L3) or 2MB (L2) page
const PTE_NX:        u64 = 1 << 63; // No-Execute
const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000; // bits 12..51 = physical address

/// Error types for page table walk failures
#[derive(Debug)]
pub enum PageWalkError {
    /// L4 entry not present for the given virtual address
    L4NotPresent,
    /// L3 entry not present
    L3NotPresent,
    /// L2 entry not present
    L2NotPresent,
    /// L1 entry not present
    L1NotPresent,
    /// Virtual address has non-canonical form (bits 48..63 not sign-extended)
    NonCanonical,
    /// Page table entry has reserved bits set
    ReservedBits,
}

/// Result of a successful page table walk
#[derive(Debug)]
pub struct PageWalkResult {
    /// Physical address corresponding to the virtual address
    pub phys_addr: u64,
    /// Page size: 4096 (4KB), 2097152 (2MB), or 1073741824 (1GB)
    pub page_size: u64,
    /// Whether the page is writable
    pub writable: bool,
    /// Whether the page is user-accessible
    pub user: bool,
    /// Whether the page is executable (NX bit NOT set)
    pub executable: bool,
}

/// Translate user virtual address to physical address.
/// Walks CR3 page tables through all 4 levels, handling 4KB/2MB/1GB pages.
fn user_virt_to_phys(virt: u64) -> u64 {
    let (l4_frame, _) = x86_64::registers::control::Cr3::read();
    let l4_phys = l4_frame.start_address().as_u64();
    match walk_page_tables(l4_phys, virt) {
        Ok(result) => result.phys_addr,
        Err(_e) => {
            // Fallback: linear mapping assumption (only safe for kernel-mapped regions)
            crate::serial_println!(
                "  [PAGEWALK] WARN: walk failed for virt=0x{:x}, error={:?}",
                virt, _e
            );
            virt
        }
    }
}

/// Walk 4-level x86_64 page tables to translate a virtual address.
///
/// Correctly handles:
/// - 4KB pages (L1 entry)
/// - 2MB huge pages (L2 entry with PS bit)
/// - 1GB huge pages (L3 entry with PS bit)
/// - Non-canonical address detection
/// - Reserved bit checking
/// - Permission flag extraction
pub fn walk_page_tables(l4_phys: u64, virt: u64) -> Result<PageWalkResult, PageWalkError> {
    // Check canonical form: bits 48..63 must equal bit 47
    let bit47 = (virt >> 47) & 1;
    let upper = virt >> 48;
    if (bit47 == 0 && upper != 0) || (bit47 == 1 && upper != 0xFFFF) {
        return Err(PageWalkError::NonCanonical);
    }

    let phys_off = PHYS_OFFSET;

    // Read a page table entry at (table_phys_base + index * 8)
    let read_entry = |table_phys: u64, idx: u64| -> u64 {
        let ptr = (phys_off + (table_phys & PTE_ADDR_MASK) + idx * 8) as *const u64;
        unsafe { ptr.read_volatile() }
    };

    // Extract indices from virtual address
    let l4i = (virt >> 39) & 0x1FF;
    let l3i = (virt >> 30) & 0x1FF;
    let l2i = (virt >> 21) & 0x1FF;
    let l1i = (virt >> 12) & 0x1FF;

    // Track accumulated permissions (AND of all levels)
    let mut writable = true;
    let mut user = true;
    let mut executable = true;

    // L4 (PML4)
    let l4e = read_entry(l4_phys, l4i);
    if l4e & PTE_PRESENT == 0 { return Err(PageWalkError::L4NotPresent); }
    writable   &= l4e & PTE_WRITABLE != 0;
    user       &= l4e & PTE_USER != 0;
    executable &= l4e & PTE_NX == 0;

    // L3 (PDPT)
    let l3e = read_entry(l4e & PTE_ADDR_MASK, l3i);
    if l3e & PTE_PRESENT == 0 { return Err(PageWalkError::L3NotPresent); }
    writable   &= l3e & PTE_WRITABLE != 0;
    user       &= l3e & PTE_USER != 0;
    executable &= l3e & PTE_NX == 0;

    // Check for 1GB huge page (PS bit set in L3)
    if l3e & PTE_HUGE != 0 {
        // Check reserved bits: bits 12..29 must be zero for 1GB page
        if l3e & 0x3FFFF000 != 0 { return Err(PageWalkError::ReservedBits); }
        let phys_base = l3e & !0x3FFF_FFFF & PTE_ADDR_MASK;
        let offset = virt & 0x3FFF_FFFF; // 30-bit offset within 1GB page
        return Ok(PageWalkResult {
            phys_addr: phys_base | offset,
            page_size: 1 << 30,
            writable, user, executable,
        });
    }

    // L2 (PD)
    let l2e = read_entry(l3e & PTE_ADDR_MASK, l2i);
    if l2e & PTE_PRESENT == 0 { return Err(PageWalkError::L2NotPresent); }
    writable   &= l2e & PTE_WRITABLE != 0;
    user       &= l2e & PTE_USER != 0;
    executable &= l2e & PTE_NX == 0;

    // Check for 2MB huge page (PS bit set in L2)
    if l2e & PTE_HUGE != 0 {
        // Check reserved bits: bits 12..20 must be zero for 2MB page
        if l2e & 0x1FF000 != 0 { return Err(PageWalkError::ReservedBits); }
        let phys_base = l2e & !0x1F_FFFF & PTE_ADDR_MASK;
        let offset = virt & 0x1F_FFFF; // 21-bit offset within 2MB page
        return Ok(PageWalkResult {
            phys_addr: phys_base | offset,
            page_size: 1 << 21,
            writable, user, executable,
        });
    }

    // L1 (PT) — standard 4KB page
    let l1e = read_entry(l2e & PTE_ADDR_MASK, l1i);
    if l1e & PTE_PRESENT == 0 { return Err(PageWalkError::L1NotPresent); }
    writable   &= l1e & PTE_WRITABLE != 0;
    user       &= l1e & PTE_USER != 0;
    executable &= l1e & PTE_NX == 0;

    let phys_base = l1e & PTE_ADDR_MASK;
    let offset = virt & 0xFFF; // 12-bit offset within 4KB page
    Ok(PageWalkResult {
        phys_addr: phys_base | offset,
        page_size: 4096,
        writable, user, executable,
    })
}

/// do_execve: load ELF + setup argv/envp stack + jump to entry
pub fn do_execve(
    _tid:      crate::task::TaskId,
    elf_path: &str,
    args:     &[&str],
    envs:     &[&str],
) -> Result<u64, &'static str> {
    let elf_bytes = crate::fs::ionafs::read(elf_path).ok_or("file not found")?;
    let addr_space = crate::elf::load(&elf_bytes).map_err(|_| "ELF load failed")?;
    addr_space.activate();

    // Setup argv/envp on userspace stack
    let new_sp = setup_stack(addr_space.stack_top, args, envs);

    crate::serial_println!(
        "  [EXEC] '{}' entry=0x{:x} sp=0x{:x} argc={}",
        elf_path, addr_space.entry_point, new_sp, args.len()
    );

    // Return new stack pointer — caller sets rsp before sysretq
    Ok(new_sp)
}
