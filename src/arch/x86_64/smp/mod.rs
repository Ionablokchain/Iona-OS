//! SMP — Application Processor startup
use core::sync::atomic::{AtomicBool, Ordering};
use crate::arch::x86_64::apic::{send_startup_ipi, CPU_COUNT, APS_ONLINE};

pub static SMP_READY: AtomicBool = AtomicBool::new(false);

pub fn detect_cpu_count() -> usize {
    let result: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {0:e}, ebx",
            "pop rbx",
            out(reg) result,
            in("eax") 0xBu32,
            in("ecx") 0u32,
            options(nostack),
        );
    }
    let n = (result & 0xFFFF) as usize;
    if n == 0 { 1 } else { n.min(64) }
}

pub fn init() {
    let count = detect_cpu_count();
    crate::serial_println!("  [SMP] {} logical CPU(s) detected", count);
    CPU_COUNT.store(count as u64, Ordering::SeqCst);
    if count > 1 {
        for id in 1u8..count as u8 {
            send_startup_ipi(id, 0x08);
            let dl = crate::arch::x86_64::timer::uptime_ms() + 100;
            while crate::arch::x86_64::timer::uptime_ms() < dl {
                if APS_ONLINE.load(Ordering::SeqCst) >= id as u32 { break; }
                core::hint::spin_loop();
            }
        }
    }
    SMP_READY.store(true, Ordering::SeqCst);
    crate::serial_println!("  [SMP] {} APs online", APS_ONLINE.load(Ordering::SeqCst));
}

#[no_mangle]
pub extern "C" fn ap_main(id: u32) -> ! {
    crate::arch::gdt::init();
    crate::arch::idt::init();
    crate::arch::x86_64::apic::init_lapic();
    // Initialize per-CPU data and local scheduler for this AP
    crate::arch::x86_64::percpu::init_for_cpu(id);
    crate::sched::local::init_for_cpu(id);
    APS_ONLINE.fetch_add(1, Ordering::SeqCst);
    crate::serial_println!("  [SMP] AP#{} ready", id);
    x86_64::instructions::interrupts::enable();
    loop { x86_64::instructions::hlt(); }
}
