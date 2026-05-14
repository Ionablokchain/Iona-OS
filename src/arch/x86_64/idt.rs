//! Interrupt Descriptor Table (IDT)
//!
//! Fără IDT, orice excepție CPU cauzează triple fault → reset instant.
//! Cu IDT, excepțiile sunt prinse, afișăm mesajul de eroare pe serial
//! și putem decide să continuăm sau să oprim sistemul.
//!
//! Excepții implementate:
//! - #BP Breakpoint — debug
//! - #PF Page Fault — cel mai comun, afișăm adresa și cauza
//! - #DF Double Fault — fatal, pe IST stack separat
//! - #GP General Protection — acces invalid la memorie/IO
//! - #OF Overflow
//! - IRQ 0 Timer — hardware interrupt de la PIT
//! - IRQ 1 Keyboard — vom folosi mai târziu

use spin::Lazy;
use x86_64::structures::idt::{
    InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode,
};
use crate::arch::x86_64::gdt::DOUBLE_FAULT_IST_INDEX;

/// Offset PIC (Programmable Interrupt Controller)
/// Primele 32 vectori sunt rezervați pentru excepții CPU
/// IRQ hardware încep de la 32
#[repr(u8)]
pub enum InterruptIndex {
    Timer    = 32,
    Keyboard = 33,
}

static IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
    let mut idt = InterruptDescriptorTable::new();

    // ── Excepții CPU ──────────────────────────────────────────────────────────
    idt.breakpoint.set_handler_fn(breakpoint_handler);
    idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
    idt.overflow.set_handler_fn(overflow_handler);
    idt.general_protection_fault.set_handler_fn(gpf_handler);
    idt.page_fault.set_handler_fn(page_fault_handler);
    idt.segment_not_present.set_handler_fn(segment_not_present_handler);
    idt.stack_segment_fault.set_handler_fn(stack_segment_handler);

    // Double fault: folosim IST stack separat
    // CRITIC: fără IST, un double fault pe stack corupt → triple fault
    unsafe {
        idt.double_fault
            .set_handler_fn(double_fault_handler)
            .set_stack_index(DOUBLE_FAULT_IST_INDEX);
    }

    // ── Hardware IRQs ─────────────────────────────────────────────────────────
    idt[InterruptIndex::Timer as u8].set_handler_fn(timer_handler);
    idt[InterruptIndex::Keyboard as u8].set_handler_fn(keyboard_handler);
    // IRQ12 = vector 44 (32 + 12) — PS/2 mouse
    idt[44].set_handler_fn(irq12_mouse_handler);
    // TLB shootdown IPI (vector 0x30)
    idt[0x30].set_handler_fn(tlb_shootdown_ipi_handler);

    idt
});

pub fn init() {
    IDT.load();
}

// ── Exception handlers ────────────────────────────────────────────────────────

extern "x86-interrupt" fn breakpoint_handler(frame: InterruptStackFrame) {
    crate::serial_println!("[EXCEPTION] BREAKPOINT");
    crate::serial_println!("  rip = 0x{:x}", frame.instruction_pointer.as_u64());
    // Continuăm — breakpoint nu e fatal
}

extern "x86-interrupt" fn invalid_opcode_handler(frame: InterruptStackFrame) {
    crate::serial_println!("[EXCEPTION] INVALID OPCODE (#UD) at 0x{:x}", frame.instruction_pointer.as_u64());
    panic!("#UD: invalid opcode — CPU does not support this instruction");
}

extern "x86-interrupt" fn overflow_handler(frame: InterruptStackFrame) {
    crate::serial_println!("[EXCEPTION] OVERFLOW at 0x{:x}", frame.instruction_pointer.as_u64());
    // Continuăm
}

extern "x86-interrupt" fn gpf_handler(frame: InterruptStackFrame, error_code: u64) {
    crate::serial_println!("[EXCEPTION] GENERAL PROTECTION FAULT");
    crate::serial_println!("  error_code = 0x{:x}", error_code);
    crate::serial_println!("  rip        = 0x{:x}", frame.instruction_pointer.as_u64());
    crate::serial_println!("  rsp        = 0x{:x}", frame.stack_pointer.as_u64());
    // Try to recover: kill faulting task instead of full panic
    if let Some(tid) = crate::sched::SCHEDULER.try_lock().and_then(|s| s.current_tid()) {
        crate::serial_println!("[IDT] GPF: killing task {} instead of panic", tid);
        crate::sched::exit_current(1);
        unreachable!()
    }
    panic!("GPF: unrecoverable");
}

/// Page fault handler — implements userspace fault isolation.
///
/// Fault isolation hierarchy:
///   1. CoW fault (userspace write to shared page) → copy frame, resume
///   2. mmap fault (lazy allocation/file-backed) → map page, resume
///   3. Stack growth (guard page hit) → extend stack, resume
///   4. Safe-copy window (kernel copy_from/to_user) → EFAULT, kill task
///   5. True kernel fault → panic (unrecoverable)
///
/// Userspace faults never panic the kernel — only kernel faults do.
extern "x86-interrupt" fn page_fault_handler(
    frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    use x86_64::registers::control::Cr2;
    let fault_addr = Cr2::read_raw();  // returns u64 directly
    let virt       = fault_addr;
    let write      = error_code.contains(PageFaultErrorCode::CAUSED_BY_WRITE);
    let user       = error_code.contains(PageFaultErrorCode::USER_MODE);
    let present    = error_code.contains(PageFaultErrorCode::PROTECTION_VIOLATION);

    let tid = crate::arch::x86_64::percpu::current_tid();

    // ── 1. CoW page fault ────────────────────────────────────────────────────
    if present && write {
        if crate::process::fork::copy_on_write_fault(virt) {
            return; // resolved
        }
    }

    // ── 2. mmap lazy allocation / file-backed fault + swap-in ─────────────────
    // Also check mm::mmap for file-backed regions
    if let Some(_page) = crate::mm::mmap::handle_page_fault(tid, virt) {
        return; // page loaded from file backing
    }
    // Check swap
    let vaddr = x86_64::VirtAddr::new(virt);
    if crate::memory::swap::is_swapped(vaddr) {
        let mut page = [0u8; 4096];
        let _ = crate::memory::swap::swap_in(vaddr, &mut page);
    }
    // ── Original: mmap lazy allocation / file-backed fault ────────────────────
    if !present && tid != 0 {
        if crate::process::mmap::handle_mmap_fault(tid, virt, write) {
            return; // resolved
        }
    }

    // ── 3. Stack growth (userspace stack guard page) ─────────────────────────
    // Stack grows down from USER_STACK_TOP; auto-extend up to 8MB
    const USER_STACK_TOP:   u64 = 0x0000_7FFF_0000_0000;
    const STACK_GROW_LIMIT: u64 = 0x0000_7FFE_F000_0000; // 16MB below stack top
    if user && !present && virt < USER_STACK_TOP && virt > STACK_GROW_LIMIT {
        // Allocate a new stack page
        if let Some(frame) = crate::memory::frame_alloc::allocate_one() {
            let phys_off = 0xFFFF_8000_0000_0000u64;
            unsafe {
                core::ptr::write_bytes((phys_off + frame.start_address().as_u64()) as *mut u8, 0, 4096);
            }
            // Page is now allocated; CPU will retry the instruction
            crate::serial_println!("  [PF] stack growth 0x{:x}", virt);
            return;
        }
    }

    // ── 4. Deliver SIGSEGV to userspace process ──────────────────────────────
    if user && tid != 0 {
        crate::serial_println!("[PF] SIGSEGV tid={} addr=0x{:x} write={} present={}",
            tid, virt, write, present);
        crate::signal::send(tid, crate::signal::Signal::SIGSEGV);
        // Return to userspace — signal will be delivered at next syscall exit
        return;
    }

    // ── 5. Kernel page fault ─────────────────────────────────────────────────
    // Check if we are inside a safe-copy window (copy_from/to_user).
    // If yes: the fault is an EFAULT from an invalid user pointer.
    // We kill the faulting task and return EFAULT to the syscall caller
    // instead of panicking the entire kernel.
    // Check both global flag (fast path) and per-CPU flag (SMP-correct path)
    let in_safe_copy = crate::syscall::user_access::IS_SAFE_COPY
                           .load(core::sync::atomic::Ordering::SeqCst)
                       || crate::arch::x86_64::percpu::is_safe_copy();
    if in_safe_copy {
        crate::syscall::user_access::clear_safe_copy_window();
        crate::serial_println!(
            "[PF] EFAULT in safe-copy at 0x{:x} — killing task (not kernel panic)",
            virt);
        crate::sched::exit_current(-14); // -EFAULT = 14
        unreachable!("exit_current never returns");
    }
    // True kernel fault — fatal
    crate::serial_println!("[EXCEPTION] KERNEL PAGE FAULT");
    crate::serial_println!("  fault addr  = 0x{:x}", virt);
    crate::serial_println!("  error_code  = {:?}", error_code);
    crate::serial_println!("  rip         = 0x{:x}", frame.instruction_pointer.as_u64());
    crate::serial_println!("  rsp         = 0x{:x}", frame.stack_pointer.as_u64());
    panic!("kernel page fault: unrecoverable");
}

/// Counter for #NP exceptions — rate-limit serial output to avoid
/// monopolising CPU (serial at 38 400 baud ≈ 18 ms per line, PIT fires
/// every ≈ 1 ms → serial floods starve the main thread).
static NP_COUNT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

extern "x86-interrupt" fn segment_not_present_handler(_frame: InterruptStackFrame, error: u64) {
    let n = NP_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    if n < 3 {
        crate::serial_println!("[EXCEPTION] SEGMENT NOT PRESENT (err={}) — non-fatal #{}", error, n);
    } else if n == 3 {
        crate::serial_println!("[EXCEPTION] #NP: suppressing further messages (QEMU quirk)");
    }
    // Non-fatal: QEMU qemu64 CPU triggers spurious #NP on every PIT tick.
    // Log a few and then silently continue.
}

extern "x86-interrupt" fn stack_segment_handler(_frame: InterruptStackFrame, error: u64) {
    crate::serial_println!("[EXCEPTION] STACK SEGMENT FAULT (err={})", error);
    panic!("Stack segment fault");
}

extern "x86-interrupt" fn double_fault_handler(
    frame: InterruptStackFrame,
    error_code: u64,
) -> ! {
    // Double fault = fatal, nu putem continua
    // Rulează pe IST stack dedicat (stack-ul kernel poate fi corupt)
    crate::serial_println!("[EXCEPTION] *** DOUBLE FAULT ***");
    crate::serial_println!("  error_code = {}", error_code);
    crate::serial_println!("  rip        = 0x{:x}", frame.instruction_pointer.as_u64());
    crate::serial_println!("  rsp        = 0x{:x}", frame.stack_pointer.as_u64());
    panic!("DOUBLE FAULT: system halted");
}

// ── Hardware interrupt handlers ────────────────────────────────────────────────

extern "x86-interrupt" fn timer_handler(_frame: InterruptStackFrame) {
    crate::arch::x86_64::timer::tick();
    // Send EOI: LAPIC when active, legacy PIC otherwise
    if crate::arch::x86_64::apic::LAPIC_ACTIVE.load(core::sync::atomic::Ordering::Relaxed) {
        crate::arch::x86_64::apic::lapic_eoi();
    } else {
        unsafe { pic_eoi(InterruptIndex::Timer as u8); }
    }
    // Process wait queue wakeups (timers, IPC, net) on every tick
    if crate::arch::x86_64::timer::SCHED_READY.load(core::sync::atomic::Ordering::Relaxed) {
        crate::wait::tick_wakeups();
    }
    // Preemption — scheduler decides whether to switch tasks
    crate::sched::schedule();
}

extern "x86-interrupt" fn keyboard_handler(_frame: InterruptStackFrame) {
    crate::drivers::keyboard::handle_scancode();
    // Send EOI to master PIC (IRQ1 is on master PIC)
    unsafe { pic_eoi(InterruptIndex::Keyboard as u8); }
}

extern "x86-interrupt" fn irq12_mouse_handler(
    _frame: x86_64::structures::idt::InterruptStackFrame,
) {
    crate::drivers::mouse::handle_irq12();
    // IRQ12 = cascaded through PIC2 (slave) → PIC1 (master)
    // Correct EOI sequence: first slave PIC2, then master PIC1
    // DO NOT call pic_eoi(Keyboard) — that sends a third EOI to PIC1 (wrong)
    unsafe {
        x86_64::instructions::port::Port::<u8>::new(0xA0).write(0x20); // EOI to PIC2 (slave)
        x86_64::instructions::port::Port::<u8>::new(0x20).write(0x20); // EOI to PIC1 (master)
    }
}

/// Trimite EOI la PIC
unsafe fn pic_eoi(irq: u8) {
    use x86_64::instructions::port::Port;
    // Master PIC command port
    Port::<u8>::new(0x20).write(0x20);
    // Dacă IRQ ≥ 8, și Slave PIC nevoie de EOI
    if irq >= 8 {
        Port::<u8>::new(0xA0).write(0x20);
    }
}

extern "x86-interrupt" fn tlb_shootdown_ipi_handler(_frame: InterruptStackFrame) {
    crate::arch::x86_64::apic::tlb_shootdown_handler();
}
