
//! Crash dump — write kernel state to IONAFS /var/crash/ on panic
use alloc::{format, string::String, vec::Vec};

/// Write crash dump to IONAFS
pub fn write_crash_dump(msg: &str, location: &str) {
    let ts = crate::arch::x86_64::timer::uptime_ms();
    let path = format!("/var/crash/crash-{}.txt", ts);

    // Collect register state and stack
    let rip: u64; let rsp: u64; let rbp: u64;
    unsafe {
        core::arch::asm!("lea {}, [rip]", out(reg) rip, options(nostack));
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack));
        core::arch::asm!("mov {}, rbp", out(reg) rbp, options(nostack));
    }

    let dump = format!(
        "IONA OS Crash Dump
         Time:     {}ms
         Location: {}
         Message:  {}
         RIP: 0x{:016x}
         RSP: 0x{:016x}
         RBP: 0x{:016x}
         Version:  v0.6.0
",
        ts, location, msg, rip, rsp, rbp
    );

    crate::fs::ionafs::write(&path, dump.as_bytes());
    crate::fs::ionafs::sync_to_disk();
    crate::serial_println!("[CRASH] dump written to {}", path);
}

/// Graceful task failure — kill faulting task instead of panic
pub fn handle_task_fault(msg: &str) -> bool {
    crate::serial_println!("[FAULT] task fault: {} — killing task", msg);
    let tid = crate::sched::SCHEDULER.lock().current_tid();
    if let Some(tid) = tid {
        write_crash_dump(msg, "task_fault");
        crate::sched::exit_current(-1);
        return true; // handled
    }
    false // fall through to panic
}
