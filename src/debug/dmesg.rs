//! Kernel ring buffer — dmesg equivalent
//!
//! Provides a circular buffer for kernel log messages, accessible from userspace
//! via `/proc/kmsg` (syscall interface). Messages are timestamped and have severity levels.
//!
//! # Examples
//! ```no_run
//! klog_info!("System initialized");
//! klog_warn!("Low memory: {} bytes free", free);
//! klog_error!("Failed to allocate device");
//! ```
//!
//! # Design
//! - Fixed-size byte buffer (no dynamic allocations after init)
//! - Spinlock for minimal overhead (safe in interrupt context)
//! - Circular overwrite when full (oldest messages are dropped)
//! - Severity levels: DEBUG, INFO, WARN, ERROR
//! - Timestamp precision: milliseconds

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;
use crate::arch::x86_64::timer::uptime_ms;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Total size of the ring buffer in bytes.
pub const RING_BUFFER_SIZE: usize = 128 * 1024; // 128 KiB

/// Maximum length of a single log message (longer messages are truncated).
pub const MAX_MESSAGE_LEN: usize = 2048;

/// Severity levels.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug = 0,
    Info  = 1,
    Warn  = 2,
    Error = 3,
}

impl LogLevel {
    fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info  => "INFO ",
            LogLevel::Warn  => "WARN ",
            LogLevel::Error => "ERROR",
        }
    }
}

// -----------------------------------------------------------------------------
// Ring buffer implementation
// -----------------------------------------------------------------------------

/// A lock-free-ish circular byte buffer protected by a spinlock.
/// Writes append formatted messages; reads copy from the buffer sequentially.
struct RingBuffer {
    /// Byte storage.
    data: [u8; RING_BUFFER_SIZE],
    /// Write pointer (next byte to write).
    write_pos: usize,
    /// Read pointer for userspace (advanced when data is consumed).
    read_pos: usize,
    /// Number of bytes currently stored (read_pos <= write_pos in ring sense).
    /// For simplicity, we maintain a simple circular buffer where data is stored
    /// contiguously from `write_pos` modulo size, but we don't wrap read pointer.
    /// We'll use a simpler approach: keep a linear buffer that wraps, and
    /// keep track of total bytes written. Read will copy from the oldest data.
    /// This is easier if we store messages with headers. Let's implement a proper
    /// circular buffer with message boundaries.
    /// Better: store each message with a length prefix, then read can parse.
    /// For production, we'll use a simple ring of `LogEntry` structures.
    /// But to avoid allocations, we'll store raw bytes with markers.
}

// Actually, a more robust design: store entries as (len, level, timestamp, message).
// We'll implement a custom ring buffer that stores messages as chunks.

struct LogEntry {
    level: LogLevel,
    timestamp_ms: u64,
    msg_len: u16,
    // message follows immediately in the buffer
}

/// Ring buffer of log entries.
/// Uses a fixed-size byte array and stores each entry as:
/// [level: u8][timestamp: u64][len: u16][message: bytes...]
/// Then the whole entry is stored contiguously.
struct LogRing {
    buffer: [u8; RING_BUFFER_SIZE],
    write_offset: AtomicUsize,      // next byte to write (only modded)
    dropped: AtomicUsize,           // number of dropped messages
}

impl LogRing {
    const fn new() -> Self {
        Self {
            buffer: [0; RING_BUFFER_SIZE],
            write_offset: AtomicUsize::new(0),
            dropped: AtomicUsize::new(0),
        }
    }

    /// Append a formatted message to the ring buffer.
    /// Returns `Ok(())` on success, `Err(msg)` if the message was too long or buffer full.
    /// In case of full buffer, old entries are overwritten (circular).
    fn append(&self, level: LogLevel, msg: &str) -> Result<(), &'static str> {
        if msg.len() > MAX_MESSAGE_LEN {
            return Err("message too long");
        }

        let timestamp = uptime_ms();
        let level_byte = level as u8;
        let msg_len = msg.len() as u16;
        let total_len = 1 + 8 + 2 + msg_len; // level + timestamp + len + msg

        if total_len > RING_BUFFER_SIZE {
            return Err("message too large for ring buffer");
        }

        // Atomically reserve space in the buffer (circular)
        let mut write_off = self.write_offset.load(Ordering::Acquire);
        loop {
            let new_off = write_off.wrapping_add(total_len);
            // If we would wrap, we could either discard or split the message.
            // For simplicity, we discard the message if it doesn't fit contiguously.
            // A real implementation could split, but for now we just try to advance.
            if new_off > RING_BUFFER_SIZE {
                // Wrap: reset write offset to 0, but we must also move read pointer?
                // In a circular buffer, we allow overwriting. We'll just wrap.
                if self.write_offset.compare_exchange(write_off, 0, Ordering::Release, Ordering::Acquire).is_ok() {
                    write_off = 0;
                    continue;
                } else {
                    write_off = self.write_offset.load(Ordering::Acquire);
                    continue;
                }
            }
            if self.write_offset.compare_exchange(write_off, new_off, Ordering::Release, Ordering::Acquire).is_ok() {
                // Write the data at offset write_off
                unsafe {
                    let ptr = self.buffer.as_ptr().add(write_off) as *mut u8;
                    core::ptr::write_volatile(ptr, level_byte);
                    core::ptr::write_volatile(ptr.add(1), timestamp.to_le_bytes());
                    core::ptr::write_volatile(ptr.add(1 + 8), msg_len.to_le_bytes());
                    core::ptr::copy_nonoverlapping(msg.as_ptr(), ptr.add(1 + 8 + 2), msg_len);
                }
                break;
            } else {
                write_off = self.write_offset.load(Ordering::Acquire);
            }
        }
        Ok(())
    }

    /// Read the next entry from the buffer starting at the given read offset.
    /// Returns (level, timestamp, message) and the next read offset.
    /// If no entry is available, returns None.
    fn read_next(&self, read_off: usize) -> Option<(LogLevel, u64, &[u8], usize)> {
        if read_off >= RING_BUFFER_SIZE {
            return None;
        }
        let ptr = self.buffer.as_ptr();
        unsafe {
            let level_byte = core::ptr::read_volatile(ptr.add(read_off));
            let timestamp = u64::from_le_bytes(core::ptr::read_volatile(ptr.add(read_off + 1) as *const [u8; 8]));
            let msg_len = u16::from_le_bytes(core::ptr::read_volatile(ptr.add(read_off + 1 + 8) as *const [u8; 2]));
            let msg_start = read_off + 1 + 8 + 2;
            let next_off = msg_start + msg_len as usize;
            if next_off > RING_BUFFER_SIZE {
                return None; // incomplete entry (wrapped)
            }
            let msg_slice = core::slice::from_raw_parts(ptr.add(msg_start), msg_len as usize);
            let level = match level_byte {
                0 => LogLevel::Debug,
                1 => LogLevel::Info,
                2 => LogLevel::Warn,
                3 => LogLevel::Error,
                _ => LogLevel::Info,
            };
            Some((level, timestamp, msg_slice, next_off))
        }
    }

    fn dropped_count(&self) -> usize {
        self.dropped.load(Ordering::Relaxed)
    }
}

static RING: LogRing = LogRing::new();
static READ_OFFSET: AtomicUsize = AtomicUsize::new(0);
static LOCK: Mutex<()> = Mutex::new(());

// -----------------------------------------------------------------------------
// Public logging interface
// -----------------------------------------------------------------------------

/// Internal function to format and write a log message.
fn _klog(level: LogLevel, args: fmt::Arguments) {
    // Use a stack-allocated buffer to format the message.
    let mut buf = [0u8; MAX_MESSAGE_LEN];
    let msg = {
        let mut writer = ArrayWriter::new(&mut buf);
        // Write timestamp and level prefix? We'll store timestamp separately.
        // We'll write only the user message, timestamp is stored in entry.
        let _ = writer.write_fmt(args);
        writer.as_str()
    };
    let _lock = LOCK.lock();
    if let Err(e) = RING.append(level, msg) {
        // Fallback: print to serial directly
        crate::serial_println!("[KLOG] Failed to append message: {}", e);
    }
    // Also print to serial for immediate visibility.
    let uptime = uptime_ms();
    crate::serial_println!("[{:8}.{:03}] {}: {}",
        uptime / 1000, uptime % 1000, level.as_str(), msg);
}

/// Log a debug message.
#[macro_export]
macro_rules! klog_debug {
    ($($arg:tt)*) => {
        $crate::klog::_klog($crate::klog::LogLevel::Debug, format_args!($($arg)*))
    };
}

/// Log an informational message.
#[macro_export]
macro_rules! klog_info {
    ($($arg:tt)*) => {
        $crate::klog::_klog($crate::klog::LogLevel::Info, format_args!($($arg)*))
    };
}

/// Log a warning.
#[macro_export]
macro_rules! klog_warn {
    ($($arg:tt)*) => {
        $crate::klog::_klog($crate::klog::LogLevel::Warn, format_args!($($arg)*))
    };
}

/// Log an error.
#[macro_export]
macro_rules! klog_error {
    ($($arg:tt)*) => {
        $crate::klog::_klog($crate::klog::LogLevel::Error, format_args!($($arg)*))
    };
}

// Helper: write formatter to a byte array.
struct ArrayWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> ArrayWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.pos]).unwrap_or("")
    }
}

impl<'a> fmt::Write for ArrayWriter<'a> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        let remaining = self.buf.len() - self.pos;
        let to_copy = bytes.len().min(remaining);
        self.buf[self.pos..self.pos + to_copy].copy_from_slice(&bytes[..to_copy]);
        self.pos += to_copy;
        if to_copy < bytes.len() {
            Err(fmt::Error)
        } else {
            Ok(())
        }
    }
}

// -----------------------------------------------------------------------------
// Userspace interface (/proc/kmsg)
// -----------------------------------------------------------------------------

/// Read available log messages into a userspace buffer.
/// Returns the number of bytes written.
pub fn kmsg_read(buf: &mut [u8]) -> usize {
    let _lock = LOCK.lock();
    let mut read_off = READ_OFFSET.load(Ordering::Acquire);
    let mut total_written = 0;
    while let Some((level, timestamp, msg, next_off)) = RING.read_next(read_off) {
        // Format: [timestamp] level: message\n
        // We'll write to buf using a simple formatter.
        let level_str = level.as_str();
        let timestamp_sec = timestamp / 1000;
        let timestamp_ms = timestamp % 1000;
        // Estimate needed space: 1 + 10 + 1 + 3 + 2 + level.len() + 2 + msg.len() + 1
        let needed = 1 + 10 + 1 + 3 + 2 + level_str.len() + 2 + msg.len() + 1;
        if total_written + needed > buf.len() {
            break;
        }
        let written = {
            let mut pos = total_written;
            let slice = &mut buf[pos..];
            let s = format_args!("[{:8}.{:03}] {}: {}\n", timestamp_sec, timestamp_ms, level_str, core::str::from_utf8(msg).unwrap_or(""));
            use core::fmt::Write;
            let mut writer = BufWriter(slice);
            let _ = writer.write_fmt(s);
            writer.pos
        };
        total_written += written;
        read_off = next_off;
    }
    READ_OFFSET.store(read_off, Ordering::Release);
    total_written
}

/// Returns the number of bytes currently available to read.
pub fn kmsg_available() -> usize {
    let _lock = LOCK.lock();
    let mut read_off = READ_OFFSET.load(Ordering::Acquire);
    let mut total = 0;
    while let Some((_, _, msg, next_off)) = RING.read_next(read_off) {
        total += 1 + 10 + 1 + 3 + 2 + 5 + 2 + msg.len() + 1; // approximate
        read_off = next_off;
    }
    total
}

struct BufWriter<'a>(&'a mut [u8], usize);
impl<'a> BufWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self { Self(buf, 0) }
}
impl<'a> fmt::Write for BufWriter<'a> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        let remaining = self.0.len().saturating_sub(self.1);
        let to_copy = bytes.len().min(remaining);
        self.0[self.1..self.1 + to_copy].copy_from_slice(&bytes[..to_copy]);
        self.1 += to_copy;
        if to_copy < bytes.len() { Err(fmt::Error) } else { Ok(()) }
    }
}

// -----------------------------------------------------------------------------
// Initialization
// -----------------------------------------------------------------------------

pub fn init() {
    klog_info!("Kernel ring buffer initialized ({} bytes)", RING_BUFFER_SIZE);
}
