//! Context switch — assembly x86_64
//!
//! switch_to(current: *mut Context, next: *const Context)
//!
//! Salvează registrele callee-saved ale task-ului curent în `current`,
//! restaurează registrele din `next`, și returnează în noul task.
//!
//! DESIGN:
//! - Nu salvăm rip explicit — adresa de return e pe stack (push-ată de `call switch_to`)
//! - Nu salvăm registrele caller-saved (rax, rcx, rdx, rsi, rdi, r8-r11)
//!   — caller-ul e responsabil pentru ele conform ABI
//! - rsp e salvat/restaurat explicit — fiecare task are stack-ul lui
//!
//! LAYOUT struct Context (din task/context.rs):
//!   offset  0: r15
//!   offset  8: r14
//!   offset 16: r13
//!   offset 24: r12
//!   offset 32: rbp
//!   offset 40: rbx
//!   offset 48: rsp

use crate::task::context::Context;

/// Efectuează context switch de la `current` la `next`.
///
/// # Safety
/// - `current` trebuie să fie un pointer valid la Context al task-ului curent
/// - `next` trebuie să fie un pointer valid la un Context inițializat
/// - Apelantul trebuie să fie conștient că această funcție poate să nu returneze
///   la același stack (dacă `current` este task-ul care rulează)
///
/// # ABI
/// - rdi = current: *mut Context
/// - rsi = next:    *const Context
#[naked]
pub unsafe extern "C" fn switch_to(current: *mut Context, next: *const Context) {
    core::arch::naked_asm!(
        // ── Salvează context curent în *current (rdi) ───────────────────────
        "mov [rdi + 0x00], r15",
        "mov [rdi + 0x08], r14",
        "mov [rdi + 0x10], r13",
        "mov [rdi + 0x18], r12",
        "mov [rdi + 0x20], rbp",
        "mov [rdi + 0x28], rbx",
        "mov [rdi + 0x30], rsp",   // salvăm stack pointer-ul curent

        // ── Restaurează context din *next (rsi) ─────────────────────────────
        "mov r15, [rsi + 0x00]",
        "mov r14, [rsi + 0x08]",
        "mov r13, [rsi + 0x10]",
        "mov r12, [rsi + 0x18]",
        "mov rbp, [rsi + 0x20]",
        "mov rbx, [rsi + 0x28]",
        "mov rsp, [rsi + 0x30]",   // schimbăm stack pointer-ul

        // ── Return în noul task ──────────────────────────────────────────────
        // `ret` sare la adresa de pe noul stack:
        // - la task-uri deja rulate: adresa de return din apelul anterior switch_to
        // - la task-uri noi: task_entry_trampoline (pushat în Context::new_task)
        "ret",
    )
}

// Context::empty() is defined in crate::task::context
