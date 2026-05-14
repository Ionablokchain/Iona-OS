//! Ring 3 transition — kernel → userspace via IRETQ
//!
//! After loading an ELF into an AddressSpace, we need to actually transfer
//! execution to ring 3. This is done via IRETQ which:
//!   1. Loads SS:RSP from interrupt frame (userspace stack)
//!   2. Loads CS:RIP from interrupt frame (userspace entry)
//!   3. Loads RFLAGS (IF=1, IOPL=0)
//!   4. Switches to ring 3 (CPL=3)
//!
//! Before IRETQ:
//!   - CR3 must point to process L4 page tables
//!   - RSP0 in TSS must point to kernel stack for this process
//!   - GS base must point to PerCpu for this CPU
//!   - Stack must have IRET frame: SS RSP RFLAGS CS RIP


/// Launch a process at ring 3.
/// Called from a kernel task; does not return (kernel task is consumed).
///
/// # Safety
/// - `cr3` must be a valid physical frame for a correct page table
/// - `entry` and `stack_top` must be valid user-space virtual addresses
/// - `argc`, `argv` are placed per System V AMD64 ABI on the stack
pub fn enter_ring3(cr3: u64, entry: u64, stack_top: u64) -> ! {
    use crate::arch::x86_64::gdt::{USER_CS, USER_SS};

    // Set RSP0 in TSS to the current kernel stack top
    // so that interrupts/syscalls from ring3 have a valid kernel stack
    let kstack = crate::arch::x86_64::percpu::kernel_rsp();
    crate::arch::x86_64::gdt::set_tss_rsp0(kstack);

    unsafe {
        // Load CR3: switch to process page tables
        core::arch::asm!("mov cr3, {cr3}", cr3 = in(reg) cr3, options(nostack, nomem));

        // IRETQ frame (pushed in reverse order: SS, RSP, RFLAGS, CS, RIP)
        // RFLAGS: IF=1 (enable interrupts), IOPL=0, AC=0
        let rflags: u64 = 0x202; // IF + reserved bit 1

        core::arch::asm!(
            // Align stack to 16 bytes before IRETQ per ABI
            "and rsp, -16",
            // Push IRETQ frame
            "push {ss}",       // SS
            "push {rsp3}",     // RSP (user stack top)
            "push {rflags}",   // RFLAGS
            "push {cs}",       // CS
            "push {rip}",      // RIP (entry point)
            "iretq",
            ss     = in(reg) (USER_SS as u64 | 3),  // DPL=3
            rsp3   = in(reg) stack_top,
            rflags = in(reg) rflags,
            cs     = in(reg) (USER_CS as u64 | 3),  // DPL=3
            rip    = in(reg) entry,
            options(noreturn),
        );
    }
}
