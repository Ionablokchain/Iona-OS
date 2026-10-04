//! Ring 3 transition — kernel → userspace via IRETQ.
//!
//! After loading an ELF into an `AddressSpace`, we transfer execution to
//! ring 3 via `iretq`, which atomically:
//!   1. Loads SS:RSP from the interrupt frame (userspace stack).
//!   2. Loads CS:RIP from the interrupt frame (userspace entry point).
//!   3. Loads RFLAGS (IF=1, IOPL=0).
//!   4. Switches to ring 3 (CPL=3).
//!
//! # Preconditions
//! Before `iretq` executes, the following invariants must hold:
//! - `CR3` points to the process's L4 page tables (user mappings present,
//!   kernel stack mapped in the shared high-half region).
//! - `TSS.RSP0` points to a valid kernel stack top for this process, so
//!   interrupts/syscalls delivered after `iretq` land on a correct stack.
//! - `GS_BASE` points to the per-CPU area for the current CPU (set by the
//!   scheduler before calling us).
//! - Interrupts are disabled while `CR3` is being switched, otherwise an
//!   interrupt could be delivered on the *new* page tables with the *old*
//!   kernel stack, which is a well-known way to corrupt the kernel.
//! - `entry` and `stack_top` are canonical user addresses (top bit clear).
//! - `stack_top` is 16-byte aligned, as required by the System V AMD64 ABI
//!   at function entry.
//!
//! # Safety contract
//! This function is `noreturn` and consumes the calling kernel task. The
//! caller must ensure the above invariants; the checker here is a
//! best-effort sanity check, not a substitute for correct setup by the ELF
//! loader and the scheduler.
//!
//! # Errors
//! Because the function never returns, invalid input cannot be surfaced as
//! a normal `Err`. Instead, `enter_ring3_checked` performs validation first
//! and returns `Result<_, Ring3Error>`; the infallible `enter_ring3` panics
//! on invalid input (fail-stop, since silently falling through to a broken
//! userspace is worse).

use core::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Reasons `enter_ring3_checked` may refuse to transfer control.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Ring3Error {
    #[error("cr3 must be non-zero and page-aligned (got 0x{0:016x})")]
    InvalidCr3(u64),

    #[error("entry 0x{0:016x} is not a canonical user address")]
    InvalidEntry(u64),

    #[error("stack_top 0x{0:016x} is not a canonical user address")]
    InvalidStackTop(u64),

    #[error("stack_top 0x{0:016x} is not 16-byte aligned")]
    MisalignedStackTop(u64),

    #[error("GDT user selectors not initialized (call gdt::init first)")]
    GdtNotInitialized,

    #[error("TSS RSP0 has not been set for this task")]
    TssRsp0Unset,
}

pub type Ring3Result<T> = Result<T, Ring3Error>;

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

/// Counter of ring-3 transition attempts (whether or not they succeeded —
/// since success is `noreturn`, we count them just before `iretq`).
static TRANSITIONS: AtomicU64 = AtomicU64::new(0);

/// Number of attempts made so far. Useful for diagnostics; a healthy
/// kernel expects this to be roughly equal to the number of user processes
/// ever spawned.
pub fn transitions_started() -> u64 {
    TRANSITIONS.load(Ordering::Relaxed)
}

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Highest canonical user address (top bit clear).
pub const USER_ADDR_END: u64 = 0x0000_7FFF_FFFF_FFFF;

/// Initial RFLAGS: IF=1, reserved bit 1 set, IOPL=0.
pub const INITIAL_RFLAGS: u64 = 0x202;

// -----------------------------------------------------------------------------
// Validation helpers
// -----------------------------------------------------------------------------

/// Is `addr` a canonical user virtual address?
#[inline]
pub const fn is_user_address(addr: u64) -> bool {
    addr <= USER_ADDR_END
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Validate the parameters for a ring-3 entry and return `Ok(())` if they
/// are safe to use.
///
/// This is a best-effort check and does *not* verify that the page tables
/// actually contain the requested mappings — that is the caller's
/// responsibility (see the module-level safety contract).
pub fn validate(cr3: u64, entry: u64, stack_top: u64) -> Ring3Result<()> {
    if cr3 == 0 || (cr3 & 0xFFF) != 0 {
        return Err(Ring3Error::InvalidCr3(cr3));
    }
    if !is_user_address(entry) {
        return Err(Ring3Error::InvalidEntry(entry));
    }
    if !is_user_address(stack_top) {
        return Err(Ring3Error::InvalidStackTop(stack_top));
    }
    if (stack_top & 0xF) != 0 {
        return Err(Ring3Error::MisalignedStackTop(stack_top));
    }
    if crate::arch::x86_64::gdt::user_cs() == 0 || crate::arch::x86_64::gdt::user_ss() == 0 {
        return Err(Ring3Error::GdtNotInitialized);
    }
    Ok(())
}

/// Fallible ring-3 entry. Validates inputs, then delegates to
/// [`enter_ring3`]. On success this function does not return.
pub fn enter_ring3_checked(cr3: u64, entry: u64, stack_top: u64) -> Ring3Result<()> {
    validate(cr3, entry, stack_top)?;
    // SAFETY: we just validated the inputs. The caller is still responsible
    // for the deeper invariants (page tables, GS base, etc.).
    unsafe { enter_ring3(cr3, entry, stack_top) }
}

/// Transfer execution to ring 3.
///
/// Called from a kernel task; does not return — the kernel task is consumed.
///
/// # Safety
/// The caller must guarantee:
/// - `cr3` is the physical address of a valid L4 page table for the target
///   process (non-zero, 4 KiB aligned), and its mappings include:
///   the user code/data at `entry`/`stack_top`, plus the kernel's high-half
///   mappings (kernel code, kernel stack, per-CPU area).
/// - `entry` and `stack_top` are canonical, non-null user addresses.
/// - `stack_top` is 16-byte aligned.
/// - `TSS.RSP0` points to a valid kernel stack for this process.
/// - `GS_BASE` points to the correct per-CPU area for the current CPU.
/// - Interrupts are safe to disable (the function does so itself before
///   switching CR3).
///
/// # Panics
/// Panics if any of the structural preconditions checked by [`validate`]
/// fail. This is deliberate: silently transferring to a broken userspace
/// is a security hole, so we fail-stop instead.
pub unsafe fn enter_ring3(cr3: u64, entry: u64, stack_top: u64) -> ! {
    // Structural validation. Fail-stop rather than corrupt userspace state.
    if let Err(e) = validate(cr3, entry, stack_top) {
        panic!("enter_ring3: invalid parameters: {e}");
    }

    // Read the user selectors from the GDT. These already include RPL=3.
    let user_cs = crate::arch::x86_64::gdt::user_cs();
    let user_ss = crate::arch::x86_64::gdt::user_ss();

    // Provide a fresh kernel stack for future ring-0 entries triggered by
    // interrupts, syscalls, or faults arriving from userspace.
    let kstack = crate::arch::x86_64::percpu::kernel_rsp();
    if kstack == 0 {
        panic!("enter_ring3: percpu::kernel_rsp() is zero");
    }
    // SAFETY: we are on this task's kernel stack, about to leave it.
    crate::arch::x86_64::gdt::set_tss_rsp0(kstack);

    // Disable interrupts before we swap CR3. If a timer fired between the
    // CR3 write and `iretq`, its handler would run on the *user* page tables
    // with the *current* kernel stack, which is not mapped in those tables.
    crate::arch::x86_64::interrupt::disable();

    // Count the attempt (a successful jump is `noreturn`, so this is the
    // last observable action before userspace begins).
    TRANSITIONS.fetch_add(1, Ordering::Relaxed);

    // SAFETY: The caller has verified all invariants. The asm block below
    // is executed exactly once and never returns.
    core::arch::asm!(
        // Load CR3 — switch to the process page tables.
        "mov cr3, {cr3}",

        // Align the kernel stack to 16 bytes before pushing the iretq frame.
        // The frame consumes 5 * 8 = 40 bytes, so the resulting RSP at the
        // iretq instruction is aligned mod 8, which is what iretq expects.
        "and rsp, -16",

        // Push the iretq frame in reverse order:
        //   SS, RSP, RFLAGS, CS, RIP
        "push {ss}",
        "push {user_rsp}",
        "push {rflags}",
        "push {cs}",
        "push {rip}",

        // Atomically switch to ring 3, load CS:RIP, SS:RSP and RFLAGS.
        "iretq",

        cr3      = in(reg) cr3,
        ss       = in(reg) user_ss as u64,
        user_rsp = in(reg) stack_top,
        rflags   = in(reg) INITIAL_RFLAGS,
        cs       = in(reg) user_cs as u64,
        rip      = in(reg) entry,
        options(noreturn),
    );
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_user_address() {
        assert!(is_user_address(0));
        assert!(is_user_address(0x1000));
        assert!(is_user_address(USER_ADDR_END));
        // Just past the user range.
        assert!(!is_user_address(USER_ADDR_END + 1));
        // Kernel canonical addresses.
        assert!(!is_user_address(0xFFFF_8000_0000_0000));
        assert!(!is_user_address(u64::MAX));
    }

    #[test]
    fn test_validate_rejects_zero_cr3() {
        assert!(matches!(
            validate(0, 0x1000, 0x7FFF_0000_0000),
            Err(Ring3Error::InvalidCr3(0))
        ));
    }

    #[test]
    fn test_validate_rejects_misaligned_cr3() {
        assert!(matches!(
            validate(0x1001, 0x1000, 0x7FFF_0000_0000),
            Err(Ring3Error::InvalidCr3(_))
        ));
    }

    #[test]
    fn test_validate_rejects_kernel_entry() {
        // Entry in the kernel half is invalid.
        assert!(matches!(
            validate(0x1000, 0xFFFF_8000_0000_0000, 0x7FFF_0000_0000),
            Err(Ring3Error::InvalidEntry(_))
        ));
    }

    #[test]
    fn test_validate_rejects_kernel_stack() {
        assert!(matches!(
            validate(0x1000, 0x400000, 0xFFFF_8000_0000_0000),
            Err(Ring3Error::InvalidStackTop(_))
        ));
    }

    #[test]
    fn test_validate_rejects_misaligned_stack() {
        assert!(matches!(
            validate(0x1000, 0x400000, 0x7FFF_0000_0001),
            Err(Ring3Error::MisalignedStackTop(_))
        ));
    }

    #[test]
    fn test_initial_rflags_shape() {
        // IF must be set; IOPL must be zero; reserved bit 1 must be set.
        const { assert!(INITIAL_RFLAGS & 0x200 != 0) }; // IF
        const { assert!(INITIAL_RFLAGS & 0x3000 == 0) }; // IOPL = 0
        const { assert!(INITIAL_RFLAGS & 0x2 != 0) };    // reserved bit 1
    }

    #[test]
    fn test_transitions_counter_is_readable() {
        let _ = transitions_started();
    }
}
