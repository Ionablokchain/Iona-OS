//! Crash dump — write kernel state to IONAFS /var/crash/ on panic
//!
//! This module provides two main functionalities:
//! 1. On kernel panic, write a comprehensive crash dump to disk.
//! 2. Handle task faults gracefully by killing the offending task instead of panicking.
//!
//! The crash dump includes:
//! - Timestamp and uptime
//! - Panic location (file, line, column)
//! - Panic message
//! - Register state (RIP, RSP, RBP, and optionally more)
//! - Backtrace (if frame pointers are enabled)
//! - Kernel version and build timestamp
//!
//! The dump is written to `/var/crash/crash-<timestamp>.txt` and then synced to disk.
//! Task faults are logged and the task is terminated; if no task is running,
//! the fallback is to panic the whole kernel.

#![allow(unused_variables)]

use alloc::format;
use alloc::string::String;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum number of registers to capture in the dump.
const NUM_GPRS: usize = 16;

/// Whether to include a backtrace in the crash dump.
/// Disable this if the kernel is built without frame pointers.
const INCLUDE_BACKTRACE: bool = true;

/// Crash dump directory (within IONAFS).
const CRASH_DIR: &str = "/var/crash";

/// Path prefix for crash dump files.
const CRASH_FILE_PREFIX: &str = "crash-";

// -----------------------------------------------------------------------------
// Core crash dump writer
// -----------------------------------------------------------------------------

/// Write a crash dump to the filesystem.
///
/// # Arguments
/// * `msg` - The panic message (or fault description)
/// * `location` - Source code location (e.g., "src/kernel/panic.rs:42")
/// * `regs` - Optional register snapshot (if None, current registers are read)
/// * `backtrace` - Optional backtrace frames (if None, captures current backtrace)
pub fn write_crash_dump(
    msg: &str,
    location: &str,
    regs: Option<&Registers>,
    backtrace: Option<&[crate::backtrace::Frame]>,
) {
    // 1. Get timestamp (milliseconds since boot)
    let uptime_ms = crate::arch::x86_64::timer::uptime_ms();

    // 2. Build the file path
    let path = alloc::format!("{}/{}{}.txt", CRASH_DIR, CRASH_FILE_PREFIX, uptime_ms);

    // 3. Capture registers if not provided
    let registers = regs.map_or_else(capture_registers, |r| *r);

    // 4. Capture backtrace if not provided and enabled
    let frames = if INCLUDE_BACKTRACE {
        backtrace.map_or_else(crate::backtrace::capture, |bt| bt.to_vec())
    } else {
        Vec::new()
    };

    // 5. Build the dump content
    let dump = build_dump_string(msg, location, uptime_ms, &registers, &frames);

    // 6. Write to IONAFS
    match crate::fs::ionafs::write(&path, dump.as_bytes()) {
        Ok(_) => {
            crate::fs::ionafs::sync_to_disk();
            crate::serial_println!("[CRASH] dump written to {}", path);
        }
        Err(e) => {
            crate::serial_println!("[CRASH] failed to write dump to {}: {:?}", path, e);
        }
    }
}

/// Build the crash dump as a formatted string.
fn build_dump_string(
    msg: &str,
    location: &str,
    uptime_ms: u64,
    regs: &Registers,
    backtrace: &[crate::backtrace::Frame],
) -> String {
    let mut s = String::new();

    // Header
    s.push_str(&format!(
        "========================================
IONA OS Crash Dump
========================================
Time:       {} ms (uptime)
Location:   {}
Message:    {}
Version:    {}\n",
        uptime_ms,
        location,
        msg,
        env!("CARGO_PKG_VERSION")
    ));

    // Register dump
    s.push_str("\n=== Registers ===\n");
    s.push_str(&format!("RIP: 0x{:016x}\n", regs.rip));
    s.push_str(&format!("RSP: 0x{:016x}\n", regs.rsp));
    s.push_str(&format!("RBP: 0x{:016x}\n", regs.rbp));
    s.push_str(&format!("RAX: 0x{:016x}\n", regs.rax));
    s.push_str(&format!("RBX: 0x{:016x}\n", regs.rbx));
    s.push_str(&format!("RCX: 0x{:016x}\n", regs.rcx));
    s.push_str(&format!("RDX: 0x{:016x}\n", regs.rdx));
    s.push_str(&format!("RSI: 0x{:016x}\n", regs.rsi));
    s.push_str(&format!("RDI: 0x{:016x}\n", regs.rdi));
    s.push_str(&format!("R8:  0x{:016x}\n", regs.r8));
    s.push_str(&format!("R9:  0x{:016x}\n", regs.r9));
    s.push_str(&format!("R10: 0x{:016x}\n", regs.r10));
    s.push_str(&format!("R11: 0x{:016x}\n", regs.r11));
    s.push_str(&format!("R12: 0x{:016x}\n", regs.r12));
    s.push_str(&format!("R13: 0x{:016x}\n", regs.r13));
    s.push_str(&format!("R14: 0x{:016x}\n", regs.r14));
    s.push_str(&format!("R15: 0x{:016x}\n", regs.r15));

    // Backtrace
    if !backtrace.is_empty() {
        s.push_str("\n=== Backtrace ===\n");
        for frame in backtrace {
            s.push_str(&format!("  #{:<2} 0x{:016x}\n", frame.depth, frame.rip));
        }
    } else {
        s.push_str("\n=== Backtrace (not available) ===\n");
    }

    // Footer
    s.push_str("\n========================================\n");
    s
}

// -----------------------------------------------------------------------------
// Register snapshot
// -----------------------------------------------------------------------------

/// A snapshot of general‑purpose registers at the time of the crash.
#[derive(Clone, Copy, Debug)]
pub struct Registers {
    pub rip: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

/// Capture the current register state.
/// Uses inline assembly to read each register.
#[inline(always)]
pub fn capture_registers() -> Registers {
    let rip: u64;
    let rsp: u64;
    let rbp: u64;
    let rax: u64;
    let rbx: u64;
    let rcx: u64;
    let rdx: u64;
    let rsi: u64;
    let rdi: u64;
    let r8: u64;
    let r9: u64;
    let r10: u64;
    let r11: u64;
    let r12: u64;
    let r13: u64;
    let r14: u64;
    let r15: u64;

    unsafe {
        // RIP is not directly readable; we use a small trick: lea [rip] into a register.
        core::arch::asm!(
            "lea {}, [rip]",
            out(reg) rip,
            options(nostack, preserves_flags)
        );
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack, preserves_flags));
        core::arch::asm!("mov {}, rbp", out(reg) rbp, options(nostack, preserves_flags));
        core::arch::asm!("mov {}, rax", out(reg) rax, options(nostack, preserves_flags));
        core::arch::asm!("mov {}, rbx", out(reg) rbx, options(nostack, preserves_flags));
        core::arch::asm!("mov {}, rcx", out(reg) rcx, options(nostack, preserves_flags));
        core::arch::asm!("mov {}, rdx", out(reg) rdx, options(nostack, preserves_flags));
        core::arch::asm!("mov {}, rsi", out(reg) rsi, options(nostack, preserves_flags));
        core::arch::asm!("mov {}, rdi", out(reg) rdi, options(nostack, preserves_flags));
        core::arch::asm!("mov {}, r8", out(reg) r8, options(nostack, preserves_flags));
        core::arch::asm!("mov {}, r9", out(reg) r9, options(nostack, preserves_flags));
        core::arch::asm!("mov {}, r10", out(reg) r10, options(nostack, preserves_flags));
        core::arch::asm!("mov {}, r11", out(reg) r11, options(nostack, preserves_flags));
        core::arch::asm!("mov {}, r12", out(reg) r12, options(nostack, preserves_flags));
        core::arch::asm!("mov {}, r13", out(reg) r13, options(nostack, preserves_flags));
        core::arch::asm!("mov {}, r14", out(reg) r14, options(nostack, preserves_flags));
        core::arch::asm!("mov {}, r15", out(reg) r15, options(nostack, preserves_flags));
    }

    Registers {
        rip,
        rsp,
        rbp,
        rax,
        rbx,
        rcx,
        rdx,
        rsi,
        rdi,
        r8,
        r9,
        r10,
        r11,
        r12,
        r13,
        r14,
        r15,
    }
}

// -----------------------------------------------------------------------------
// Task fault handling
// -----------------------------------------------------------------------------

/// Handle a fault in a user task gracefully: kill the offending task instead of panicking.
///
/// # Returns
/// `true` if the fault was handled by killing the current task,
/// `false` if there was no current task (i.e., fault occurred in kernel context),
/// in which case the caller should panic.
pub fn handle_task_fault(msg: &str) -> bool {
    use crate::sched::SCHEDULER;

    // Log the fault
    crate::serial_println!("[FAULT] Task fault: {} — killing task", msg);

    // Get current task ID
    let maybe_tid = SCHEDULER.lock().current_tid();
    let tid = match maybe_tid {
        Some(tid) => tid,
        None => {
            crate::serial_println!("[FAULT] No current task — fault in kernel context");
            return false;
        }
    };

    // Write crash dump for this task (with backtrace and registers)
    write_crash_dump(msg, "task_fault", None, None);

    // Terminate the task
    crate::sched::exit_current(-1);
    true
}

// -----------------------------------------------------------------------------
// Integration with panic handler
// -----------------------------------------------------------------------------

/// Panic hook that writes a crash dump and then aborts.
/// Can be registered in the kernel's panic handler.
pub fn panic_hook(info: &core::panic::PanicInfo) {
    let location = info
        .location()
        .map(|loc| alloc::format!("{}:{}:{}", loc.file(), loc.line(), loc.column()))
        .unwrap_or_else(|| "unknown".to_string());

    let msg = info
        .message()
        .map(|m| alloc::format!("{}", m))
        .unwrap_or_else(|| "no message".to_string());

    write_crash_dump(&msg, &location, None, None);
}

// -----------------------------------------------------------------------------
// Unit tests (for fuzzing / simulation)
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registers_capture() {
        let regs = capture_registers();
        // We can't assert exact values, but we can check that they are non-zero
        // (except maybe some registers are zero). At least RIP should be non-zero.
        assert_ne!(regs.rip, 0);
    }

    #[test]
    fn test_build_dump_string() {
        let regs = Registers {
            rip: 0xdeadbeef,
            rsp: 0x12345678,
            rbp: 0x87654321,
            rax: 1,
            rbx: 2,
            rcx: 3,
            rdx: 4,
            rsi: 5,
            rdi: 6,
            r8: 7,
            r9: 8,
            r10: 9,
            r11: 10,
            r12: 11,
            r13: 12,
            r14: 13,
            r15: 14,
        };
        let backtrace = Vec::new();
        let dump = build_dump_string("test panic", "test.rs:42", 1234, &regs, &backtrace);
        assert!(dump.contains("RIP: 0xdeadbeef"));
        assert!(dump.contains("Location:   test.rs:42"));
        assert!(dump.contains("Message:    test panic"));
        assert!(dump.contains("Time:       1234 ms"));
    }
}
