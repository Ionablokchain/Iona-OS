//! Kernel structured logging — log levels + ring buffer
//!
//! Usage:
//!   kinfo!("message");
//!   kwarn!("message");
//!   kerr!("message");
//!   kdebug!("message"); // only in debug builds

use alloc::string::String;
use alloc::collections::VecDeque;
use spin::{Lazy, Mutex};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug = 0,
    Info  = 1,
    Warn  = 2,
    Error = 3,
}

impl LogLevel {
    pub fn prefix(self) -> &'static str {
        match self {
            LogLevel::Debug => "[DBG] ",
            LogLevel::Info  => "[INF] ",
            LogLevel::Warn  => "[WRN] ",
            LogLevel::Error => "[ERR] ",
        }
    }
}

pub struct LogEntry {
    pub level:   LogLevel,
    pub ts_ms:   u64,
    pub msg:     String,
}

const RING_CAPACITY: usize = 1024;
static LOG_RING: Lazy<Mutex<VecDeque<LogEntry>>> =
    Lazy::new(|| Mutex::new(VecDeque::with_capacity(RING_CAPACITY)));

static MIN_LEVEL: Mutex<LogLevel> = Mutex::new(LogLevel::Info);

pub fn set_level(level: LogLevel) { *MIN_LEVEL.lock() = level; }

pub fn klog(level: LogLevel, msg: &str) {
    let min = *MIN_LEVEL.lock();
    if level < min { return; }
    let ts = crate::arch::x86_64::timer::uptime_ms();
    let prefix = level.prefix();
    // Always write to serial
    crate::serial_println!("[{:>8}ms]{}{}", ts, prefix, msg);
    // Store in ring buffer
    let mut ring = LOG_RING.lock();
    if ring.len() >= RING_CAPACITY { ring.pop_front(); }
    ring.push_back(LogEntry { level, ts_ms: ts, msg: msg.into() });
    // Persist critical errors to /var/log
    if level == LogLevel::Error {
        let entry = alloc::format!("[{}ms]{}{}\n", ts, prefix, msg);
        crate::fs::ionafs::write("/var/log/kernel.log", entry.as_bytes());
    }
}

/// Drain ring buffer to a string (for dmesg syscall)
pub fn drain_to_string(max_bytes: usize) -> String {
    let ring = LOG_RING.lock();
    let mut out = String::new();
    for entry in ring.iter() {
        let line = alloc::format!("[{:>8}ms]{}{}\n",
            entry.ts_ms, entry.level.prefix(), entry.msg);
        if out.len() + line.len() > max_bytes { break; }
        out.push_str(&line);
    }
    out
}

pub fn entry_count() -> usize { LOG_RING.lock().len() }

// ── Macros ────────────────────────────────────────────────────────────────────

#[macro_export] macro_rules! kinfo  {
    ($($arg:tt)*) => { $crate::io::klog::klog($crate::io::klog::LogLevel::Info,  &alloc::format!($($arg)*)); };
}
#[macro_export] macro_rules! kwarn  {
    ($($arg:tt)*) => { $crate::io::klog::klog($crate::io::klog::LogLevel::Warn,  &alloc::format!($($arg)*)); };
}
#[macro_export] macro_rules! kerr   {
    ($($arg:tt)*) => { $crate::io::klog::klog($crate::io::klog::LogLevel::Error, &alloc::format!($($arg)*)); };
}
#[macro_export] macro_rules! kdebug {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        $crate::io::klog::klog($crate::io::klog::LogLevel::Debug, &alloc::format!($($arg)*));
    };
}
