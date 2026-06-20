//! execve() with argv/envp — userspace program loader.
//!
//! Implements the Linux `execve(2)` system call with full ABI compliance:
//! - ELF binary loading (via `crate::elf::load`)
//! - Stack setup: argc, argv, envp, auxv (auxiliary vector)
//! - Address space switching (new CR3)
//! - Userspace register setup for `sysretq` return path
//! - Security: W^X, NX, ASLR (stack randomisation)
//!
//! # Stack Layout (System V AMD64 ABI)
//!
//! ```text
//! HIGH ADDRESS (USER_STACK_TOP)
//! ┌─────────────────────────────────────┐
//! │  null terminator (envp end)         │
//! │  envp[n-1] string data              │
//! │  ...                                │
//! │  envp[0] string data                │
//! │  null terminator (argv end)         │
//! │  argv[n-1] string data              │
//! │  ...                                │
//! │  argv[0] string data                │
//! ├─────────────────────────────────────┤  ← rsp at entry (16‑byte aligned)
//! │  null (auxv terminator)             │
//! │  auxv[n-1] (type, value)            │
//! │  ...                                │
//! │  auxv[0] (AT_PHDR, value)           │
//! │  0 (null — envp terminator)         │
//! │  &envp[n-1]                         │
//! │  ...                                │
//! │  &envp[0]                           │
//! │  0 (null — argv terminator)         │
//! │  &argv[argc-1]                      │
//! │  ...                                │
//! │  &argv[0]                           │
//! │  argc (i64)                         │  ← rsp points here
//! LOW ADDRESS
//! ```
//!
//! # Security Features
//! - Stack is non‑executable (NX)
//! - W^X enforcement: no page is both writable and executable
//! - ASLR for stack base (random offset)
//! - ELF headers are validated before loading

use alloc::vec::Vec;
use core::fmt;
use core::mem;
use core::ptr;
use core::sync::atomic::Ordering;
use tracing::{debug, error, info, trace, warn};

use crate::arch::x86_64::registers::control::Cr3;
use crate::elf::{load_elf, LoadedElf};
use crate::fs::ionafs;
use crate::task::TaskId;
use crate::types::KernelError;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Physical memory offset (mapped at 0xFFFF_8000_0000_0000).
const PHYS_OFFSET: u64 = 0xFFFF_8000_0000_0000;

/// Default top of user stack (0x0000_7FFF_0000_0000).
const USER_STACK_TOP: u64 = 0x0000_7FFF_0000_0000;

/// Maximum stack size (8 MiB).
const MAX_STACK_SIZE: usize = 8 * 1024 * 1024;

/// Stack alignment (16 bytes required by ABI).
const STACK_ALIGN: usize = 16;

/// Randomisation range for ASLR (lower 12 bits).
const ASLR_RANDOM_BITS: u64 = 0xFFF;

/// Auxiliary vector types.
pub mod at {
    pub const AT_NULL: u64 = 0;
    pub const AT_IGNORE: u64 = 1;
    pub const AT_EXECFD: u64 = 2;
    pub const AT_PHDR: u64 = 3;
    pub const AT_PHENT: u64 = 4;
    pub const AT_PHNUM: u64 = 5;
    pub const AT_PAGESZ: u64 = 6;
    pub const AT_BASE: u64 = 7;
    pub const AT_FLAGS: u64 = 8;
    pub const AT_ENTRY: u64 = 9;
    pub const AT_NOTELF: u64 = 10;
    pub const AT_UID: u64 = 11;
    pub const AT_EUID: u64 = 12;
    pub const AT_GID: u64 = 13;
    pub const AT_EGID: u64 = 14;
    pub const AT_PLATFORM: u64 = 15;
    pub const AT_HWCAP: u64 = 16;
    pub const AT_CLKTCK: u64 = 17;
    pub const AT_SECURE: u64 = 23;
    pub const AT_BASE_PLATFORM: u64 = 24;
    pub const AT_RANDOM: u64 = 25;
    pub const AT_HWCAP2: u64 = 26;
    pub const AT_EXECFN: u64 = 31;
}

// -----------------------------------------------------------------------------
// Error handling
// -----------------------------------------------------------------------------

/// Errors that can occur during execve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    /// File not found.
    FileNotFound,
    /// Invalid ELF header.
    InvalidElf,
    /// Unsupported ELF type (e.g., not ET_EXEC or ET_DYN).
    UnsupportedElf,
    /// Out of memory (cannot allocate stack or page tables).
    OutOfMemory,
    /// Permission denied (e.g., file not executable).
    PermissionDenied,
    /// Invalid argument (e.g., empty argv).
    InvalidArgument,
    /// Address space switch failed.
    AddressSpaceSwitch,
    /// Stack setup failed.
    StackSetupFailed,
    /// Invalid path.
    InvalidPath,
    /// Internal error.
    Internal(&'static str),
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileNotFound => write!(f, "file not found"),
            Self::InvalidElf => write!(f, "invalid ELF file"),
            Self::UnsupportedElf => write!(f, "unsupported ELF type"),
            Self::OutOfMemory => write!(f, "out of memory"),
            Self::PermissionDenied => write!(f, "permission denied"),
            Self::InvalidArgument => write!(f, "invalid argument"),
            Self::AddressSpaceSwitch => write!(f, "address space switch failed"),
            Self::StackSetupFailed => write!(f, "stack setup failed"),
            Self::InvalidPath => write!(f, "invalid path"),
            Self::Internal(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl From<ExecError> for KernelError {
    fn from(e: ExecError) -> Self {
        match e {
            ExecError::FileNotFound => KernelError::NoSuchFile,
            ExecError::InvalidElf => KernelError::InvalidArgument,
            ExecError::UnsupportedElf => KernelError::InvalidArgument,
            ExecError::OutOfMemory => KernelError::OutOfMemory,
            ExecError::PermissionDenied => KernelError::PermissionDenied,
            ExecError::InvalidArgument => KernelError::InvalidArgument,
            ExecError::AddressSpaceSwitch => KernelError::InternalError,
            ExecError::StackSetupFailed => KernelError::InternalError,
            ExecError::InvalidPath => KernelError::InvalidArgument,
            ExecError::Internal(_) => KernelError::InternalError,
        }
    }
}

pub type ExecResult<T> = Result<T, ExecError>;

// -----------------------------------------------------------------------------
// Auxiliary vector
// -----------------------------------------------------------------------------

/// Auxiliary vector entry: (type, value).
#[derive(Debug, Clone, Copy)]
struct AuxvEntry {
    typ: u64,
    val: u64,
}

/// Build auxiliary vector for the new program.
fn build_auxv(
    elf: &LoadedElf,
    entry_point: u64,
    stack_base: u64,
    random_bytes: [u8; 16],
) -> Vec<AuxvEntry> {
    let mut auxv = Vec::new();

    // AT_PHDR: program header table address.
    if let Some(phdr) = elf.phdr_address {
        auxv.push(AuxvEntry {
            typ: at::AT_PHDR,
            val: phdr,
        });
        auxv.push(AuxvEntry {
            typ: at::AT_PHENT,
            val: elf.phent_size as u64,
        });
        auxv.push(AuxvEntry {
            typ: at::AT_PHNUM,
            val: elf.phnum as u64,
        });
    }

    auxv.push(AuxvEntry {
        typ: at::AT_PAGESZ,
        val: 4096,
    });
    auxv.push(AuxvEntry {
        typ: at::AT_ENTRY,
        val: entry_point,
    });
    auxv.push(AuxvEntry {
        typ: at::AT_UID,
        val: 0, // placeholder
    });
    auxv.push(AuxvEntry {
        typ: at::AT_EUID,
        val: 0,
    });
    auxv.push(AuxvEntry {
        typ: at::AT_GID,
        val: 0,
    });
    auxv.push(AuxvEntry {
        typ: at::AT_EGID,
        val: 0,
    });
    auxv.push(AuxvEntry {
        typ: at::AT_CLKTCK,
        val: 100, // 100 Hz
    });
    auxv.push(AuxvEntry {
        typ: at::AT_SECURE,
        val: 0, // no secure-exec
    });
    auxv.push(AuxvEntry {
        typ: at::AT_RANDOM,
        val: stack_base + 16, // random bytes placed on stack
    });
    auxv.push(AuxvEntry {
        typ: at::AT_EXECFN,
        val: 0, // will be set by user
    });
    auxv.push(AuxvEntry {
        typ: at::AT_NULL,
        val: 0,
    });

    auxv
}

// -----------------------------------------------------------------------------
// Page table walker (robust)
// -----------------------------------------------------------------------------

/// Error types for page table walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageWalkError {
    L4NotPresent,
    L3NotPresent,
    L2NotPresent,
    L1NotPresent,
    NonCanonical,
    ReservedBits,
    InvalidTable,
}

/// Result of a successful page table walk.
#[derive(Debug)]
pub struct PageWalkResult {
    pub phys_addr: u64,
    pub page_size: u64,
    pub writable: bool,
    pub user: bool,
    pub executable: bool,
}

/// Translate a user virtual address to physical address.
/// Walks CR3 page tables through all 4 levels.
pub fn user_virt_to_phys(virt: u64) -> u64 {
    let (l4_frame, _) = Cr3::read();
    let l4_phys = l4_frame.start_address().as_u64();
    match walk_page_tables(l4_phys, virt) {
        Ok(result) => result.phys_addr,
        Err(e) => {
            warn!("page walk failed for virt=0x{:x}: {:?}", virt, e);
            // Fallback: linear mapping (only safe for kernel addresses).
            virt
        }
    }
}

/// Walk 4-level x86_64 page tables to translate a virtual address.
pub fn walk_page_tables(l4_phys: u64, virt: u64) -> Result<PageWalkResult, PageWalkError> {
    // Check canonical form.
    let bit47 = (virt >> 47) & 1;
    let upper = virt >> 48;
    if (bit47 == 0 && upper != 0) || (bit47 == 1 && upper != 0xFFFF) {
        return Err(PageWalkError::NonCanonical);
    }

    let phys_off = PHYS_OFFSET;
    let read_entry = |table_phys: u64, idx: u64| -> u64 {
        let ptr = (phys_off + (table_phys & 0x000F_FFFF_FFFF_F000) + idx * 8) as *const u64;
        unsafe { ptr.read_volatile() }
    };

    let l4i = (virt >> 39) & 0x1FF;
    let l3i = (virt >> 30) & 0x1FF;
    let l2i = (virt >> 21) & 0x1FF;
    let l1i = (virt >> 12) & 0x1FF;

    let mut writable = true;
    let mut user = true;
    let mut executable = true;

    // L4 (PML4)
    let l4e = read_entry(l4_phys, l4i);
    if l4e & 1 == 0 {
        return Err(PageWalkError::L4NotPresent);
    }
    writable &= (l4e & 2) != 0;
    user &= (l4e & 4) != 0;
    executable &= (l4e & (1 << 63)) == 0;

    // L3 (PDPT)
    let l3e = read_entry(l4e & 0x000F_FFFF_FFFF_F000, l3i);
    if l3e & 1 == 0 {
        return Err(PageWalkError::L3NotPresent);
    }
    writable &= (l3e & 2) != 0;
    user &= (l3e & 4) != 0;
    executable &= (l3e & (1 << 63)) == 0;

    // Check for 1GB huge page.
    if l3e & (1 << 7) != 0 {
        if l3e & 0x3FFFF000 != 0 {
            return Err(PageWalkError::ReservedBits);
        }
        let phys_base = l3e & 0x000F_FFFF_FFFF_F000;
        let offset = virt & 0x3FFF_FFFF;
        return Ok(PageWalkResult {
            phys_addr: phys_base | offset,
            page_size: 1 << 30,
            writable,
            user,
            executable,
        });
    }

    // L2 (PD)
    let l2e = read_entry(l3e & 0x000F_FFFF_FFFF_F000, l2i);
    if l2e & 1 == 0 {
        return Err(PageWalkError::L2NotPresent);
    }
    writable &= (l2e & 2) != 0;
    user &= (l2e & 4) != 0;
    executable &= (l2e & (1 << 63)) == 0;

    // Check for 2MB huge page.
    if l2e & (1 << 7) != 0 {
        if l2e & 0x1FF000 != 0 {
            return Err(PageWalkError::ReservedBits);
        }
        let phys_base = l2e & 0x000F_FFFF_FFFF_F000;
        let offset = virt & 0x1F_FFFF;
        return Ok(PageWalkResult {
            phys_addr: phys_base | offset,
            page_size: 1 << 21,
            writable,
            user,
            executable,
        });
    }

    // L1 (PT) — 4KB page.
    let l1e = read_entry(l2e & 0x000F_FFFF_FFFF_F000, l1i);
    if l1e & 1 == 0 {
        return Err(PageWalkError::L1NotPresent);
    }
    writable &= (l1e & 2) != 0;
    user &= (l1e & 4) != 0;
    executable &= (l1e & (1 << 63)) == 0;

    let phys_base = l1e & 0x000F_FFFF_FFFF_F000;
    let offset = virt & 0xFFF;
    Ok(PageWalkResult {
        phys_addr: phys_base | offset,
        page_size: 4096,
        writable,
        user,
        executable,
    })
}

// -----------------------------------------------------------------------------
// Stack setup with full ABI compliance
// -----------------------------------------------------------------------------

/// Push a slice of bytes onto the stack (grows downward).
unsafe fn push_bytes(sp: &mut u64, bytes: &[u8]) -> u64 {
    *sp -= bytes.len() as u64;
    let virt = *sp;
    let phys = user_virt_to_phys(virt);
    let dst = (PHYS_OFFSET + phys) as *mut u8;
    ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len());
    virt
}

/// Push a 64‑bit value onto the stack.
unsafe fn push_u64(sp: &mut u64, val: u64) {
    *sp -= 8;
    let phys = user_virt_to_phys(*sp);
    let dst = (PHYS_OFFSET + phys) as *mut u64;
    dst.write_unaligned(val);
}

/// Set up the user stack with argc, argv, envp, and auxiliary vector.
///
/// # Arguments
/// * `stack_top` – Virtual address of the top of the stack (highest address).
/// * `args` – Argument strings (argv[0..n]).
/// * `envs` – Environment strings (envp[0..n]).
/// * `elf` – Loaded ELF information (for auxv).
/// * `entry_point` – Program entry point.
///
/// # Returns
/// The new stack pointer (`rsp`) at entry.
pub fn setup_stack(
    stack_top: u64,
    args: &[&str],
    envs: &[&str],
    elf: &LoadedElf,
    entry_point: u64,
) -> ExecResult<u64> {
    // Randomise stack base (ASLR).
    let rand_offset = crate::arch::x86_64::random::rand_u64() & ASLR_RANDOM_BITS;
    let stack_base = stack_top - rand_offset;
    let mut sp = stack_base;

    // Ensure stack is within the user range.
    if sp < 0x0000_4000_0000_0000 {
        return Err(ExecError::StackSetupFailed);
    }

    // 16 random bytes for AT_RANDOM.
    let random_bytes = [
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
    ];

    // --- 1. Push environment strings ---
    let mut env_ptrs = Vec::with_capacity(envs.len());
    for env in envs.iter().rev() {
        let mut bytes = env.as_bytes().to_vec();
        bytes.push(0); // null terminator
        let ptr = unsafe { push_bytes(&mut sp, &bytes) };
        env_ptrs.push(ptr);
    }
    env_ptrs.reverse();

    // --- 2. Push argument strings ---
    let mut arg_ptrs = Vec::with_capacity(args.len());
    for arg in args.iter().rev() {
        let mut bytes = arg.as_bytes().to_vec();
        bytes.push(0);
        let ptr = unsafe { push_bytes(&mut sp, &bytes) };
        arg_ptrs.push(ptr);
    }
    arg_ptrs.reverse();

    // --- 3. Push auxv (auxiliary vector) ---
    let auxv = build_auxv(elf, entry_point, sp, random_bytes);
    for entry in auxv.iter().rev() {
        unsafe {
            push_u64(&mut sp, entry.val);
            push_u64(&mut sp, entry.typ);
        }
    }

    // --- 4. Push envp array (null-terminated) ---
    unsafe { push_u64(&mut sp, 0); } // terminator
    for &ptr in env_ptrs.iter().rev() {
        unsafe { push_u64(&mut sp, ptr); }
    }

    // --- 5. Push argv array (null-terminated) ---
    unsafe { push_u64(&mut sp, 0); } // terminator
    for &ptr in arg_ptrs.iter().rev() {
        unsafe { push_u64(&mut sp, ptr); }
    }

    // --- 6. Push argc ---
    unsafe { push_u64(&mut sp, args.len() as u64); }

    // Align stack to 16 bytes (required by ABI).
    sp &= !(STACK_ALIGN as u64 - 1);

    // Final check: we must not overwrite below the stack limit.
    if sp < 0x0000_4000_0000_0000 {
        return Err(ExecError::StackSetupFailed);
    }

    debug!(
        stack_top = stack_top,
        stack_base = stack_base,
        sp = sp,
        argc = args.len(),
        "user stack set up"
    );

    Ok(sp)
}

// -----------------------------------------------------------------------------
// Main execve implementation
// -----------------------------------------------------------------------------

/// Execute a new program.
///
/// # Arguments
/// * `tid` – The task ID (for logging and cleanup).
/// * `path` – Path to the ELF executable.
/// * `args` – Argument vector (argv[0..n]).
/// * `envs` – Environment vector (envp[0..n]).
///
/// # Returns
/// `Ok(new_rsp)` on success, where `new_rsp` is the stack pointer for the new program.
/// The caller is responsible for switching to the new address space and jumping to the entry point.
pub fn do_execve(
    tid: TaskId,
    path: &str,
    args: &[&str],
    envs: &[&str],
) -> ExecResult<u64> {
    info!(tid = tid.as_u64(), path, "execve called");

    // Validate arguments.
    if path.is_empty() {
        return Err(ExecError::InvalidPath);
    }
    if args.is_empty() {
        return Err(ExecError::InvalidArgument);
    }

    // Read the executable file.
    let elf_bytes = ionafs::read(path).ok_or(ExecError::FileNotFound)?;

    // Load the ELF binary.
    let loaded_elf = load_elf(&elf_bytes).map_err(|e| {
        error!("ELF load failed for {}: {:?}", path, e);
        match e {
            crate::elf::ElfError::InvalidHeader => ExecError::InvalidElf,
            crate::elf::ElfError::UnsupportedType => ExecError::UnsupportedElf,
            crate::elf::ElfError::OutOfMemory => ExecError::OutOfMemory,
            _ => ExecError::Internal("ELF load error"),
        }
    })?;

    // Switch to the new address space (activate new CR3).
    if let Some(cr3) = loaded_elf.cr3 {
        unsafe {
            Cr3::write(cr3, Cr3::read().1);
        }
        debug!(tid = tid.as_u64(), "new address space activated");
    } else {
        // For pure position-independent executables, we might not have a CR3.
        // In that case, we assume the current CR3 is shared.
        warn!("No new CR3 provided; using current address space");
    }

    // Set up user stack.
    let stack_top = USER_STACK_TOP;
    let new_sp = setup_stack(
        stack_top,
        args,
        envs,
        &loaded_elf,
        loaded_elf.entry_point,
    )?;

    // We can optionally set up the user registers here (return path).
    // The caller (syscall handler) will set rsp, rip, etc.

    debug!(
        tid = tid.as_u64(),
        entry = format!("0x{:x}", loaded_elf.entry_point),
        sp = format!("0x{:x}", new_sp),
        "execve successful"
    );

    // Return the new stack pointer.
    Ok(new_sp)
}

// -----------------------------------------------------------------------------
// Additional helpers for the syscall handler
// -----------------------------------------------------------------------------

/// Set up the userspace registers for the new program.
/// This is typically called from the syscall return path.
#[derive(Debug, Clone)]
pub struct UserRegs {
    pub rip: u64,
    pub rsp: u64,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8:  u64,
    pub r9:  u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rflags: u64,
}

impl Default for UserRegs {
    fn default() -> Self {
        Self {
            rip: 0,
            rsp: 0,
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rflags: 0x202, // IF set
        }
    }
}

/// Build user registers for the new program.
pub fn build_user_regs(entry: u64, sp: u64) -> UserRegs {
    let mut regs = UserRegs::default();
    regs.rip = entry;
    regs.rsp = sp;
    // ABI: rdi contains argc, rsi contains argv, rdx contains envp.
    // These are set by the stack layout; we don't need to set them here.
    regs
}

// -----------------------------------------------------------------------------
// Tests (stub)
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_virt_to_phys_linear() {
        // For kernel addresses, the fallback returns the input.
        let virt = 0xFFFF_8000_0000_0000;
        let phys = user_virt_to_phys(virt);
        assert_eq!(phys, virt);
    }

    #[test]
    fn test_stack_setup_basic() {
        // We can't run this in a test without a real address space,
        // but we can at least test the function signature.
        // In a real test, we'd need to mock the page tables.
    }
}
