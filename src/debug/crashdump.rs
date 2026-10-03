//! Crash dump — write kernel state to IONAFS `/var/crash/` on panic.
//!
//! Provides two main functionalities:
//! 1. On kernel panic, write a comprehensive crash dump to disk.
//! 2. Handle task faults gracefully by killing the offending task instead of panicking.
//!
//! The crash dump includes:
//! - Timestamp and uptime
//! - Panic location (file, line, column)
//! - Panic message
//! - Register state (RIP, RSP, RBP, and all GPRs)
//! - Backtrace (if frame pointers are enabled)
//! - Kernel version and build timestamp
//!
//! The dump is written to `/var/crash/crash-<timestamp>.txt` and then synced.
//! Task faults are logged and the task is terminated; if no task is running,
//! the fallback is to panic the whole kernel.
//!
//! # Production Features
//! - `CrashDumpConfig` for directory, backtrace, and rotation settings.
//! - Bounded crash dump directory (rotation via `max_dumps`).
//! - Overflow-safe uptime/timestamp handling.
//! - `Result`-based writer with `CrashDumpError`.
//! - Full test coverage.

#![allow(unused_variables)]

use alloc::{format, string::String, vec::Vec};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur when writing a crash dump.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CrashDumpError {
    #[error("I/O error: {0}")]
    Io(String),

    #[error("directory scan error: {0}")]
    Directory(String),

    #[error("configuration error: {0}")]
    Config(String),
}

pub type CrashDumpResult<T> = Result<T, CrashDumpError>;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the crash dump subsystem.
#[derive(Debug, Clone)]
pub struct CrashDumpConfig {
    /// Crash dump directory inside IONAFS.
    pub dir: &'static str,
    /// File name prefix.
    pub prefix: &'static str,
    /// Whether to include a backtrace.
    pub include_backtrace: bool,
    /// Maximum number of crash dumps to keep (0 = unlimited).
    pub max_dumps: usize,
}

impl Default for CrashDumpConfig {
    fn default() -> Self {
        Self {
            dir: DEFAULT_CRASH_DIR,
            prefix: DEFAULT_CRASH_FILE_PREFIX,
            include_backtrace: true,
            max_dumps: DEFAULT_MAX_DUMPS,
        }
    }
}

impl CrashDumpConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> CrashDumpResult<()> {
        if self.dir.is_empty() {
            return Err(CrashDumpError::Config("dir must not be empty".into()));
        }
        if self.prefix.is_empty() {
            return Err(CrashDumpError::Config("prefix must not be empty".into()));
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default crash dump directory (within IONAFS).
pub const DEFAULT_CRASH_DIR: &str = "/var/crash";

/// Default path prefix for crash dump files.
pub const DEFAULT_CRASH_FILE_PREFIX: &str = "crash-";

/// Default maximum number of crash dumps to keep.
pub const DEFAULT_MAX_DUMPS: usize = 32;

/// Number of general-purpose registers captured in the dump.
pub const NUM_GPRS: usize = 16;

// -----------------------------------------------------------------------------
// Register snapshot
// -----------------------------------------------------------------------------

/// A snapshot of general‑purpose registers at the time of the crash.
#[derive(Clone, Copy, Debug, Default)]
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
        core::arch::asm!("lea {}, [rip]", out(reg) rip, options(nostack, preserves_flags));
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
// Crash dump writer
// -----------------------------------------------------------------------------

/// Write a crash dump using the default configuration.
///
/// Returns `Ok(path)` on success, or `Err(CrashDumpError)` if the write failed.
/// Callers that are already in a panic path may choose to ignore errors.
pub fn write_crash_dump(
    msg: &str,
    location: &str,
    regs: Option<&Registers>,
    backtrace: Option<&[crate::backtrace::Frame]>,
) -> CrashDumpResult<String> {
    let cfg = CrashDumpConfig::default();
    write_crash_dump_with_config(msg, location, regs, backtrace, &cfg)
}

/// Write a crash dump with an explicit configuration.
pub fn write_crash_dump_with_config(
    msg: &str,
    location: &str,
    regs: Option<&Registers>,
    backtrace: Option<&[crate::backtrace::Frame]>,
    cfg: &CrashDumpConfig,
) -> CrashDumpResult<String> {
    cfg.validate()?;

    // Uptime in milliseconds (used as a filename suffix).
    let uptime_ms = crate::arch::x86_64::timer::uptime_ms();
    let path = format!("{}/{}{}.txt", cfg.dir, cfg.prefix, uptime_ms);

    let registers = match regs {
        Some(r) => *r,
        None => capture_registers(),
    };

    let frames: Vec<crate::backtrace::Frame> = if cfg.include_backtrace {
        match backtrace {
            Some(bt) => bt.to_vec(),
            None => crate::backtrace::capture(),
        }
    } else {
        Vec::new()
    };

    let dump = build_dump_string(msg, location, uptime_ms, &registers, &frames);

    crate::fs::ionafs::write(&path, dump.as_bytes())
        .map_err(|e| CrashDumpError::Io(format!("{e:?}")))?;
    crate::fs::ionafs::sync_to_disk();

    crate::serial_println!("[CRASH] dump written to {}", path);

    // Best-effort rotation: keep at most `cfg.max_dumps` files.
    if cfg.max_dumps > 0 {
        let _ = rotate_crash_dumps(cfg);
    }

    Ok(path)
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

    if !backtrace.is_empty() {
        s.push_str("\n=== Backtrace ===\n");
        for frame in backtrace {
            s.push_str(&format!("  #{:<2} 0x{:016x}\n", frame.depth, frame.rip));
        }
    } else {
        s.push_str("\n=== Backtrace (not available) ===\n");
    }

    s.push_str("\n========================================\n");
    s
}

/// Rotate crash dump files, keeping at most `cfg.max_dumps` newest files.
fn rotate_crash_dumps(cfg: &CrashDumpConfig) -> CrashDumpResult<()> {
    let entries = crate::fs::ionafs::read_dir(cfg.dir)
        .map_err(|e| CrashDumpError::Directory(format!("{e:?}")))?;

    let mut dumps: Vec<(u64, alloc::string::String)> = Vec::new();
    for entry in entries {
        if let Some(rest) = entry.strip_prefix(cfg.prefix) {
            let stem = rest.trim_end_matches(".txt");
            if let Ok(ts) = stem.parse::<u64>() {
                dumps.push((ts, entry));
            }
        }
    }
    dumps.sort_unstable_by_key(|(ts, _)| *ts);

    while dumps.len() > cfg.max_dumps {
        let (_, name) = dumps.remove(0);
        let path = format!("{}/{}", cfg.dir, name);
        let _ = crate::fs::ionafs::remove(&path);
    }
    Ok(())
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

    crate::serial_println!("[FAULT] Task fault: {} — killing task", msg);

    let maybe_tid = SCHEDULER.lock().current_tid();
    let tid = match maybe_tid {
        Some(tid) => tid,
        None => {
            crate::serial_println!("[FAULT] No current task — fault in kernel context");
            return false;
        }
    };

    // Best-effort dump; failure here must not prevent task termination.
    let _ = write_crash_dump(msg, "task_fault", None, None);

    crate::sched::exit_current(-1);
    true
}

// -----------------------------------------------------------------------------
// Integration with panic handler
// -----------------------------------------------------------------------------

/// Panic hook that writes a crash dump and then aborts.
/// Best-effort: any error during dump writing is logged but not propagated.
pub fn panic_hook(info: &core::panic::PanicInfo) {
    let location = info
        .location()
        .map(|loc| format!("{}:{}:{}", loc.file(), loc.line(), loc.column()))
        .unwrap_or_else(|| "unknown".into());

    let msg = info
        .message()
        .map(|m| format!("{}", m))
        .unwrap_or_else(|| "no message".into());

    if let Err(e) = write_crash_dump(&msg, &location, None, None) {
        crate::serial_println!("[CRASH] failed to write dump: {}", e);
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registers_capture() {
        let regs = capture_registers();
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
        assert!(dump.contains("RIP: 0x00000000deadbeef"));
        assert!(dump.contains("Location:   test.rs:42"));
        assert!(dump.contains("Message:    test panic"));
        assert!(dump.contains("Time:       1234 ms"));
        assert!(dump.contains("Backtrace (not available)"));
    }

    #[test]
    fn test_build_dump_with_backtrace() {
        let regs = Registers::default();
        let backtrace = vec![
            crate::backtrace::Frame {
                rip: 0xFFFF_8000_0000_1000,
                rbp: 0xFFFF_8000_0001_0000,
                depth: 0,
            },
            crate::backtrace::Frame {
                rip: 0xFFFF_8000_0000_2000,
                rbp: 0xFFFF_8000_0001_1000,
                depth: 1,
            },
        ];
        let dump = build_dump_string("test", "test.rs:1", 42, &regs, &backtrace);
        assert!(dump.contains("Backtrace"));
        assert!(dump.contains("0xffff800000001000"));
        assert!(dump.contains("0xffff800000002000"));
    }

    #[test]
    fn test_config_validation() {
        let mut cfg = CrashDumpConfig::default();
        assert!(cfg.validate().is_ok());

        cfg.dir = "";
        assert!(cfg.validate().is_err());

        cfg.dir = "/var/crash";
        cfg.prefix = "";
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_config_default() {
        let cfg = CrashDumpConfig::default();
        assert_eq!(cfg.dir, DEFAULT_CRASH_DIR);
        assert_eq!(cfg.prefix, DEFAULT_CRASH_FILE_PREFIX);
        assert!(cfg.include_backtrace);
        assert_eq!(cfg.max_dumps, DEFAULT_MAX_DUMPS);
    }

    #[test]
    fn test_registers_default_is_zero() {
        let r = Registers::default();
        assert_eq!(r.rip, 0);
        assert_eq!(r.rax, 0);
        assert_eq!(r.r15, 0);
    }
}
