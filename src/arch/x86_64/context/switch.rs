//! Context switch — x86_64 assembly
//!
//! This module provides the low‑level context switching primitive `switch_to`.
//! It saves the current task's callee‑saved registers into a `Context` struct,
//! restores another task's registers, and jumps to the new task.
//!
//! # Function signature
//!
//! `switch_to(current: *mut Context, next: *const Context)`
//!
//! # Register saving policy (per x86_64 System V ABI)
//! - **Callee‑saved** registers (must be preserved across function calls):
//!   `r15`, `r14`, `r13`, `r12`, `rbp`, `rbx`, `rsp` → saved in `Context`.
//! - **Caller‑saved** registers (`rax`, `rcx`, `rdx`, `rsi`, `rdi`, `r8`–`r11`)
//!   are **not** saved – the caller is responsible for them.
//! - The return address (`rip`) is **not** stored explicitly; it is popped from
//!   the stack when the new task executes `ret`.
//!
//! # Context layout (matches `crate::task::context::Context`)
//! ```text
//! offset  0: r15
//! offset  8: r14
//! offset 16: r13
//! offset 24: r12
//! offset 32: rbp
//! offset 40: rbx
//! offset 48: rsp
//! ```
//!
//! # Safety
//!
//! - `current` must be a valid, aligned pointer to a `Context` belonging to the
//!   currently running task. The saved registers will be written there.
//! - `next` must be a valid pointer to an initialised `Context` (either from a
//!   previous `switch_to` call or freshly created by `Context::new_task()`).
//! - The caller must ensure that interrupts are disabled (or at least that the
//!   saved state is consistent) because this function does not save interrupt
//!   flags.
//! - After calling `switch_to`, the current task’s stack may be abandoned.
//!   The function **may not return** to the original caller if the new task
//!   never switches back.
//!
//! # ABI (arguments passed in registers)
//! - `rdi` = `current` (first argument)
//! - `rsi` = `next` (second argument)

use crate::task::context::Context;

/// Perform a context switch from `current` to `next`.
///
/// This function is marked `#[naked]` because we need full control over the
/// prologue and epilogue – the standard Rust function prologue would clobber
/// registers we are trying to save.
///
/// # Panics
/// This function never panics – it is pure assembly. However, if the new
/// context has an invalid stack or return address, the CPU will fault.
#[naked]
pub unsafe extern "C" fn switch_to(current: *mut Context, next: *const Context) {
    core::arch::naked_asm!(
        // ─── Save current context into `*current` (rdi) ─────────────────────
        "mov [rdi + 0x00], r15",
        "mov [rdi + 0x08], r14",
        "mov [rdi + 0x10], r13",
        "mov [rdi + 0x18], r12",
        "mov [rdi + 0x20], rbp",
        "mov [rdi + 0x28], rbx",
        "mov [rdi + 0x30], rsp",      // save current stack pointer

        // ─── Restore next context from `*next` (rsi) ────────────────────────
        "mov r15, [rsi + 0x00]",
        "mov r14, [rsi + 0x08]",
        "mov r13, [rsi + 0x10]",
        "mov r12, [rsi + 0x18]",
        "mov rbp, [rsi + 0x20]",
        "mov rbx, [rsi + 0x28]",
        "mov rsp, [rsi + 0x30]",      // switch to new stack

        // ─── Return into the new task ────────────────────────────────────────
        // `ret` pops the return address from the new stack.
        // - For an already running task, this returns to where it last called `switch_to`.
        // - For a new task, the stack must have been prepared with a trampoline
        //   (e.g., `task_entry_trampoline` pushed by `Context::new_task`).
        "ret",
    );
}

/// Entry trampoline for newly created tasks.
///
/// This function is placed on the stack of a new task by `Context::new_task()`.
/// It calls the task's entry point and, when that returns, switches back to the
/// idle task (or panics).
///
/// # Safety
/// Must be called with the correct stack layout (see `Context::new_task`).
#[no_mangle]
pub unsafe extern "C" fn task_entry_trampoline(entry: extern "C" fn(*mut u8), arg: *mut u8) {
    entry(arg);
    // If the task returns, we should not continue. In a real OS, we would
    // switch to an idle/reaper task. Here we just loop forever.
    loop {
        core::hint::spin_loop();
    }
}
