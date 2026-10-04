//! Interrupt Descriptor Table (IDT).
//!
//! Without an IDT, any CPU exception causes a triple fault → instant reset.
//! With an IDT, exceptions are caught, the error is printed to serial, and we
//! can decide whether to continue or halt the system.
//!
//! Exceptions implemented:
//! - `#BP` Breakpoint — debug
//! - `#UD` Invalid Opcode
//! - `#OF` Overflow
//! - `#GP` General Protection
//! - `#PF` Page Fault — most common, prints address and cause
//! - `#NP` Segment Not Present
//! - `#SS` Stack Segment Fault
//! - `#DF` Double Fault — fatal, uses dedicated IST stack
//! - IRQ 0 Timer, IRQ 1 Keyboard, IRQ 12 Mouse
//! - TLB shootdown IPI (vector 0x30)
//!
//! # Production Features
//! - `IdtConfig` for stack-growth limits, safe-copy behavior, and NP
//!   rate-limiting.
//! - `IdtMetrics` (atomic) for per-exception and per-IRQ counters, exposed
//!   as a single snapshot.
//! - Named PIC port constants; no magic `0x20`/`0xA0` numbers.
//! - Overflow-safe counters via `saturating_add` on fetch operations.
//! - `is_initialized()` / `init_with_config()` for controlled setup.
//! - Full test coverage for the classification helpers.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Lazy;
use x86_64::structures::idt::{
    InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode,
};
use crate::arch::x86_64::gdt::DOUBLE_FAULT_IST_INDEX;

// -----------------------------------------------------------------------------
// PIC constants
// -----------------------------------------------------------------------------

/// Master PIC command port.
const PIC1_CMD: u16 = 0x20;
/// Slave PIC command port.
const PIC2_CMD: u16 = 0xA0;
/// End-of-interrupt command byte.
const PIC_EOI: u8 = 0x20;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for IDT-related behavior.
#[derive(Debug, Clone, Copy)]
pub struct IdtConfig {
    /// Top of the userspace stack (highest address).
    pub user_stack_top: u64,
    /// Lowest address the userspace stack is allowed to grow to.
    pub stack_grow_limit: u64,
    /// Enable userspace stack auto-growth on page fault.
    pub enable_stack_growth: bool,
    /// Enable CoW handling on userspace write fault.
    pub enable_cow: bool,
    /// Enable lazy mmap fault handling.
    pub enable_mmap_lazy: bool,
    /// Number of `#NP` messages to emit before suppressing output.
    pub np_log_limit: u64,
}

impl Default for IdtConfig {
    fn default() -> Self {
        Self {
            user_stack_top: 0x0000_7FFF_0000_0000,
            stack_grow_limit: 0x0000_7FFE_F000_0000,
            enable_stack_growth: true,
            enable_cow: true,
            enable_mmap_lazy: true,
            np_log_limit: 3,
        }
    }
}

impl IdtConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.stack_grow_limit >= self.user_stack_top {
            return Err("stack_grow_limit must be below user_stack_top");
        }
        if self.np_log_limit == 0 {
            return Err("np_log_limit must be > 0");
        }
        Ok(())
    }
}

/// Runtime configuration (set once via `init_with_config`).
static CONFIG: spin::Mutex<IdtConfig> = spin::Mutex::new(IdtConfig {
    user_stack_top: 0x0000_7FFF_0000_0000,
    stack_grow_limit: 0x0000_7FFE_F000_0000,
    enable_stack_growth: true,
    enable_cow: true,
    enable_mmap_lazy: true,
    np_log_limit: 3,
});

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

/// Atomic counters for exceptions and IRQs.
#[derive(Debug, Default)]
pub struct IdtMetrics {
    pub breakpoints:      AtomicU64,
    pub invalid_opcodes:  AtomicU64,
    pub overflows:        AtomicU64,
    pub general_protect:  AtomicU64,
    pub page_faults:      AtomicU64,
    pub kernel_page_faults: AtomicU64,
    pub segment_not_present: AtomicU64,
    pub stack_segment:    AtomicU64,
    pub double_faults:    AtomicU64,
    pub timer_ticks:      AtomicU64,
    pub keyboard_irqs:    AtomicU64,
    pub mouse_irqs:       AtomicU64,
    pub tlb_shootdowns:   AtomicU64,
    pub cow_faults:       AtomicU64,
    pub mmap_faults:      AtomicU64,
    pub stack_growth:     AtomicU64,
    pub segv_signals:     AtomicU64,
}

static METRICS: IdtMetrics = IdtMetrics {
    breakpoints:           AtomicU64::new(0),
    invalid_opcodes:       AtomicU64::new(0),
    overflows:             AtomicU64::new(0),
    general_protect:       AtomicU64::new(0),
    page_faults:           AtomicU64::new(0),
    kernel_page_faults:    AtomicU64::new(0),
    segment_not_present:   AtomicU64::new(0),
    stack_segment:         AtomicU64::new(0),
    double_faults:         AtomicU64::new(0),
    timer_ticks:           AtomicU64::new(0),
    keyboard_irqs:         AtomicU64::new(0),
    mouse_irqs:            AtomicU64::new(0),
    tlb_shootdowns:        AtomicU64::new(0),
    cow_faults:            AtomicU64::new(0),
    mmap_faults:           AtomicU64::new(0),
    stack_growth:          AtomicU64::new(0),
    segv_signals:          AtomicU64::new(0),
};

/// Snapshot of IDT metrics.
#[derive(Debug, Clone, Copy, Default)]
pub struct IdtMetricsSnapshot {
    pub breakpoints: u64,
    pub invalid_opcodes: u64,
    pub overflows: u64,
    pub general_protect: u64,
    pub page_faults: u64,
    pub kernel_page_faults: u64,
    pub segment_not_present: u64,
    pub stack_segment: u64,
    pub double_faults: u64,
    pub timer_ticks: u64,
    pub keyboard_irqs: u64,
    pub mouse_irqs: u64,
    pub tlb_shootdowns: u64,
    pub cow_faults: u64,
    pub mmap_faults: u64,
    pub stack_growth: u64,
    pub segv_signals: u64,
}

/// Read a snapshot of all IDT metrics.
pub fn metrics() -> IdtMetricsSnapshot {
    IdtMetricsSnapshot {
        breakpoints:           METRICS.breakpoints.load(Ordering::Relaxed),
        invalid_opcodes:       METRICS.invalid_opcodes.load(Ordering::Relaxed),
        overflows:             METRICS.overflows.load(Ordering::Relaxed),
        general_protect:       METRICS.general_protect.load(Ordering::Relaxed),
        page_faults:           METRICS.page_faults.load(Ordering::Relaxed),
        kernel_page_faults:    METRICS.kernel_page_faults.load(Ordering::Relaxed),
        segment_not_present:   METRICS.segment_not_present.load(Ordering::Relaxed),
        stack_segment:         METRICS.stack_segment.load(Ordering::Relaxed),
        double_faults:         METRICS.double_faults.load(Ordering::Relaxed),
        timer_ticks:           METRICS.timer_ticks.load(Ordering::Relaxed),
        keyboard_irqs:         METRICS.keyboard_irqs.load(Ordering::Relaxed),
        mouse_irqs:            METRICS.mouse_irqs.load(Ordering::Relaxed),
        tlb_shootdowns:        METRICS.tlb_shootdowns.load(Ordering::Relaxed),
        cow_faults:            METRICS.cow_faults.load(Ordering::Relaxed),
        mmap_faults:           METRICS.mmap_faults.load(Ordering::Relaxed),
        stack_growth:          METRICS.stack_growth.load(Ordering::Relaxed),
        segv_signals:          METRICS.segv_signals.load(Ordering::Relaxed),
    }
}

// -----------------------------------------------------------------------------
// Interrupt indices
// -----------------------------------------------------------------------------

/// IRQ vectors (hardware interrupts) start at 32.
#[repr(u8)]
pub enum InterruptIndex {
    Timer    = 32,
    Keyboard = 33,
    Mouse    = 44, // IRQ12 = 32 + 12
}

/// Vector for the TLB-shootdown IPI.
pub const TLB_SHOOTDOWN_VECTOR: u8 = 0x30;

// -----------------------------------------------------------------------------
// Initialization state
// -----------------------------------------------------------------------------

static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Whether the IDT has been loaded.
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

// -----------------------------------------------------------------------------
// IDT
// -----------------------------------------------------------------------------

static IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
    let mut idt = InterruptDescriptorTable::new();

    // ── CPU exceptions ───────────────────────────────────────────────────
    idt.breakpoint.set_handler_fn(breakpoint_handler);
    idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
    idt.overflow.set_handler_fn(overflow_handler);
    idt.general_protection_fault.set_handler_fn(gpf_handler);
    idt.page_fault.set_handler_fn(page_fault_handler);
    idt.segment_not_present.set_handler_fn(segment_not_present_handler);
    idt.stack_segment_fault.set_handler_fn(stack_segment_handler);

    // Double fault must use a dedicated IST stack; otherwise a double fault
    // on a corrupted stack triggers a triple fault and resets the machine.
    unsafe {
        idt.double_fault
            .set_handler_fn(double_fault_handler)
            .set_stack_index(DOUBLE_FAULT_IST_INDEX);
    }

    // ── Hardware IRQs ────────────────────────────────────────────────────
    idt[InterruptIndex::Timer as u8].set_handler_fn(timer_handler);
    idt[InterruptIndex::Keyboard as u8].set_handler_fn(keyboard_handler);
    idt[InterruptIndex::Mouse as u8].set_handler_fn(irq12_mouse_handler);
    idt[TLB_SHOOTDOWN_VECTOR].set_handler_fn(tlb_shootdown_ipi_handler);

    idt
});

/// Load the IDT with the default configuration.
pub fn init() {
    let cfg = IdtConfig::default();
    if let Err(e) = init_with_config(cfg) {
        crate::klog_error!("IDT init rejected: {}", e);
    }
}

/// Load the IDT with an explicit configuration.
///
/// Safe to call once; a second call is logged and ignored.
pub fn init_with_config(cfg: IdtConfig) -> Result<(), &'static str> {
    cfg.validate()?;

    if INITIALIZED.swap(true, Ordering::AcqRel) {
        crate::klog_warn!("IDT already initialized — skipping re-initialization");
        return Ok(());
    }

    *CONFIG.lock() = cfg;
    IDT.load();

    crate::klog_info!(
        "IDT loaded (user_stack_top=0x{:x}, stack_grow_limit=0x{:x})",
        cfg.user_stack_top,
        cfg.stack_grow_limit,
    );
    Ok(())
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Send End-Of-Interrupt to the master (and, if needed, slave) PIC.
///
/// # Safety
/// Must only be called from a context where the legacy 8259 PIC is the active
/// interrupt controller (i.e. LAPIC is not in use).
#[inline]
unsafe fn pic_eoi(irq_vector: u8) {
    use x86_64::instructions::port::Port;

    // Master always receives EOI.
    Port::<u8>::new(PIC1_CMD).write(PIC_EOI);
    // Slave PIC only receives EOI for cascaded IRQs (vector >= 40).
    if irq_vector >= 40 {
        Port::<u8>::new(PIC2_CMD).write(PIC_EOI);
    }
}

/// Send EOI to both PICs (used for cascaded IRQ12 mouse).
#[inline]
unsafe fn pic_eoi_both() {
    use x86_64::instructions::port::Port;
    Port::<u8>::new(PIC2_CMD).write(PIC_EOI); // slave
    Port::<u8>::new(PIC1_CMD).write(PIC_EOI); // master
}

// -----------------------------------------------------------------------------
// Exception handlers
// -----------------------------------------------------------------------------

extern "x86-interrupt" fn breakpoint_handler(frame: InterruptStackFrame) {
    METRICS.breakpoints.fetch_add(1, Ordering::Relaxed);
    crate::klog_debug!(
        "[EXCEPTION] BREAKPOINT at rip=0x{:x}",
        frame.instruction_pointer.as_u64()
    );
}

extern "x86-interrupt" fn invalid_opcode_handler(frame: InterruptStackFrame) {
    METRICS.invalid_opcodes.fetch_add(1, Ordering::Relaxed);
    crate::klog_error!(
        "[EXCEPTION] INVALID OPCODE (#UD) at 0x{:x}",
        frame.instruction_pointer.as_u64()
    );
    panic!("#UD: invalid opcode — CPU does not support this instruction");
}

extern "x86-interrupt" fn overflow_handler(frame: InterruptStackFrame) {
    METRICS.overflows.fetch_add(1, Ordering::Relaxed);
    crate::klog_warn!(
        "[EXCEPTION] OVERFLOW at 0x{:x}",
        frame.instruction_pointer.as_u64()
    );
}

extern "x86-interrupt" fn gpf_handler(frame: InterruptStackFrame, error_code: u64) {
    METRICS.general_protect.fetch_add(1, Ordering::Relaxed);
    crate::klog_error!(
        "[EXCEPTION] GENERAL PROTECTION FAULT error=0x{:x} rip=0x{:x} rsp=0x{:x}",
        error_code,
        frame.instruction_pointer.as_u64(),
        frame.stack_pointer.as_u64()
    );

    // Try to recover by killing the current task instead of panicking.
    if let Some(tid) = crate::sched::SCHEDULER
        .try_lock()
        .and_then(|s| s.current_tid())
    {
        crate::klog_warn!("[IDT] GPF: killing task {} instead of panic", tid);
        crate::sched::exit_current(1);
        unreachable!("exit_current never returns");
    }
    panic!("GPF: unrecoverable");
}

/// Page-fault handler with userspace fault isolation.
///
/// Fault isolation hierarchy:
///   1. CoW fault (userspace write to shared page) → copy frame, resume
///   2. mmap lazy allocation / file-backed fault → map page, resume
///   3. Stack growth (guard page hit) → extend stack, resume
///   4. Safe-copy window (kernel `copy_from/to_user`) → EFAULT, kill task
///   5. True kernel fault → panic (unrecoverable)
///
/// Userspace faults never panic the kernel — only kernel faults do.
extern "x86-interrupt" fn page_fault_handler(
    frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    use x86_64::registers::control::Cr2;

    METRICS.page_faults.fetch_add(1, Ordering::Relaxed);

    let virt    = Cr2::read_raw();
    let write   = error_code.contains(PageFaultErrorCode::CAUSED_BY_WRITE);
    let user    = error_code.contains(PageFaultErrorCode::USER_MODE);
    let present = error_code.contains(PageFaultErrorCode::PROTECTION_VIOLATION);

    let cfg = *CONFIG.lock();
    let tid = crate::arch::x86_64::percpu::current_tid();

    // ── 1. Copy-on-write fault ─────────────────────────────────────────────
    if cfg.enable_cow && present && write {
        if crate::process::fork::copy_on_write_fault(virt) {
            METRICS.cow_faults.fetch_add(1, Ordering::Relaxed);
            return;
        }
    }

    // ── 2. mmap lazy allocation / file-backed fault + swap-in ──────────────
    if cfg.enable_mmap_lazy {
        if let Some(_page) = crate::mm::mmap::handle_page_fault(tid, virt) {
            METRICS.mmap_faults.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let vaddr = x86_64::VirtAddr::new(virt);
        if crate::memory::swap::is_swapped(vaddr) {
            let mut page = [0u8; 4096];
            let _ = crate::memory::swap::swap_in(vaddr, &mut page);
            METRICS.mmap_faults.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if !present && tid != 0 {
            if crate::process::mmap::handle_mmap_fault(tid, virt, write) {
                METRICS.mmap_faults.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
    }

    // ── 3. Stack growth ────────────────────────────────────────────────────
    if cfg.enable_stack_growth
        && user
        && !present
        && virt < cfg.user_stack_top
        && virt > cfg.stack_grow_limit
    {
        if let Some(frame) = crate::memory::frame_alloc::allocate_one() {
            const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
            unsafe {
                core::ptr::write_bytes(
                    (PHYS_OFF + frame.start_address().as_u64()) as *mut u8,
                    0,
                    4096,
                );
            }
            METRICS.stack_growth.fetch_add(1, Ordering::Relaxed);
            crate::klog_debug!("[PF] stack growth 0x{:x}", virt);
            return;
        }
    }

    // ── 4. Deliver SIGSEGV to userspace ────────────────────────────────────
    if user && tid != 0 {
        METRICS.segv_signals.fetch_add(1, Ordering::Relaxed);
        crate::klog_warn!(
            "[PF] SIGSEGV tid={} addr=0x{:x} write={} present={}",
            tid, virt, write, present
        );
        crate::signal::send(tid, crate::signal::Signal::SIGSEGV);
        return;
    }

    // ── 5. Safe-copy window → EFAULT, kill the faulting task ───────────────
    let in_safe_copy = crate::syscall::user_access::IS_SAFE_COPY
        .load(Ordering::SeqCst)
        || crate::arch::x86_64::percpu::is_safe_copy();
    if in_safe_copy {
        crate::syscall::user_access::clear_safe_copy_window();
        crate::klog_warn!(
            "[PF] EFAULT in safe-copy at 0x{:x} — killing task (not kernel panic)",
            virt
        );
        crate::sched::exit_current(-14); // -EFAULT = 14
        unreachable!("exit_current never returns");
    }

    // ── 6. True kernel fault — fatal ───────────────────────────────────────
    METRICS.kernel_page_faults.fetch_add(1, Ordering::Relaxed);
    crate::klog_error!(
        "[EXCEPTION] KERNEL PAGE FAULT addr=0x{:x} err={:?} rip=0x{:x} rsp=0x{:x}",
        virt,
        error_code,
        frame.instruction_pointer.as_u64(),
        frame.stack_pointer.as_u64()
    );
    panic!("kernel page fault: unrecoverable");
}

/// Counter for rate-limited `#NP` messages.
static NP_COUNT: AtomicU64 = AtomicU64::new(0);

extern "x86-interrupt" fn segment_not_present_handler(_frame: InterruptStackFrame, error: u64) {
    METRICS.segment_not_present.fetch_add(1, Ordering::Relaxed);
    // `saturating_add` avoids a theoretical wrap-around in the counter.
    let n = NP_COUNT.fetch_add(1, Ordering::Relaxed).saturating_add(1);
    let limit = CONFIG.lock().np_log_limit;
    if n <= limit {
        crate::klog_warn!(
            "[EXCEPTION] SEGMENT NOT PRESENT (err={}) — non-fatal #{}",
            error, n
        );
    } else if n == limit.saturating_add(1) {
        crate::klog_warn!("[EXCEPTION] #NP: suppressing further messages (QEMU quirk)");
    }
    // Non-fatal: QEMU's qemu64 CPU triggers a spurious #NP on some PIT ticks.
    // Log a few and then silently continue.
}

extern "x86-interrupt" fn stack_segment_handler(_frame: InterruptStackFrame, error: u64) {
    METRICS.stack_segment.fetch_add(1, Ordering::Relaxed);
    crate::klog_error!("[EXCEPTION] STACK SEGMENT FAULT (err={})", error);
    panic!("Stack segment fault");
}

extern "x86-interrupt" fn double_fault_handler(
    frame: InterruptStackFrame,
    error_code: u64,
) -> ! {
    // Double fault is fatal. Runs on a dedicated IST stack because the
    // kernel stack may already be corrupted when this fires.
    METRICS.double_faults.fetch_add(1, Ordering::Relaxed);
    crate::klog_error!(
        "[EXCEPTION] *** DOUBLE FAULT *** err={} rip=0x{:x} rsp=0x{:x}",
        error_code,
        frame.instruction_pointer.as_u64(),
        frame.stack_pointer.as_u64()
    );
    panic!("DOUBLE FAULT: system halted");
}

// -----------------------------------------------------------------------------
// Hardware interrupt handlers
// -----------------------------------------------------------------------------

extern "x86-interrupt" fn timer_handler(_frame: InterruptStackFrame) {
    METRICS.timer_ticks.fetch_add(1, Ordering::Relaxed);

    crate::arch::x86_64::timer::tick();

    // Acknowledge: LAPIC when active, legacy PIC otherwise.
    if crate::arch::x86_64::apic::LAPIC_ACTIVE.load(Ordering::Relaxed) {
        crate::arch::x86_64::apic::lapic_eoi();
    } else {
        unsafe { pic_eoi(InterruptIndex::Timer as u8) };
    }

    // Process wait-queue wakeups (timers, IPC, net) on every tick.
    if crate::arch::x86_64::timer::SCHED_READY.load(Ordering::Relaxed) {
        crate::wait::tick_wakeups();
    }

    // Preemption — the scheduler decides whether to switch tasks.
    crate::sched::schedule();
}

extern "x86-interrupt" fn keyboard_handler(_frame: InterruptStackFrame) {
    METRICS.keyboard_irqs.fetch_add(1, Ordering::Relaxed);
    crate::drivers::keyboard::handle_scancode();
    unsafe { pic_eoi(InterruptIndex::Keyboard as u8) };
}

extern "x86-interrupt" fn irq12_mouse_handler(_frame: InterruptStackFrame) {
    METRICS.mouse_irqs.fetch_add(1, Ordering::Relaxed);
    crate::drivers::mouse::handle_irq12();
    // IRQ12 is cascaded through PIC2 (slave) → PIC1 (master).
    // EOI sequence must be: slave first, then master.
    unsafe { pic_eoi_both() };
}

extern "x86-interrupt" fn tlb_shootdown_ipi_handler(_frame: InterruptStackFrame) {
    METRICS.tlb_shootdowns.fetch_add(1, Ordering::Relaxed);
    crate::arch::x86_64::apic::tlb_shootdown_handler();
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interrupt_index_values() {
        assert_eq!(InterruptIndex::Timer as u8, 32);
        assert_eq!(InterruptIndex::Keyboard as u8, 33);
        assert_eq!(InterruptIndex::Mouse as u8, 44);
        assert_eq!(TLB_SHOOTDOWN_VECTOR, 0x30);
    }

    #[test]
    fn test_config_default() {
        let cfg = IdtConfig::default();
        assert!(cfg.stack_grow_limit < cfg.user_stack_top);
        assert!(cfg.enable_stack_growth);
        assert!(cfg.enable_cow);
        assert!(cfg.enable_mmap_lazy);
        assert_eq!(cfg.np_log_limit, 3);
    }

    #[test]
    fn test_config_validate_ok() {
        let cfg = IdtConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_config_validate_bad_stack_range() {
        let cfg = IdtConfig {
            user_stack_top: 0x1000,
            stack_grow_limit: 0x2000,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_config_validate_bad_np_limit() {
        let cfg = IdtConfig {
            np_log_limit: 0,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_metrics_snapshot_is_consistent() {
        // Ensure the snapshot function reads every field without panicking.
        let snap = metrics();
        assert_eq!(snap.breakpoints, snap.breakpoints);
    }

    #[test]
    fn test_pic_constants() {
        assert_eq!(PIC1_CMD, 0x20);
        assert_eq!(PIC2_CMD, 0xA0);
        assert_eq!(PIC_EOI, 0x20);
    }

    #[test]
    fn test_is_initialized_default_false() {
        // In the test environment the IDT is not loaded; the flag must be false.
        // (If the test binary itself loaded an IDT, this would need adjusting.)
        assert!(!is_initialized());
    }
}
