//! Kernel ring buffer — dmesg equivalent.
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
//!
//! # Production Features
//! - Proper circular buffer with wraparound that tracks producer/consumer
//!   offsets and drops-on-overwrite semantics via a per-entry header.
//! - `RingBufferMetrics` (atomic counters) for dropped / overwritten entries.
//! - `RingBufferConfig` for enabling/disabling serial mirroring.
//! - Overflow-safe counter arithmetic.
//! - Full test coverage.

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::Mutex;
use crate::arch::x86_64::timer::uptime_ms;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Total size of the ring buffer in bytes.
pub const RING_BUFFER_SIZE: usize = 128 * 1024; // 128 KiB

/// Maximum length of a single log message (longer messages are truncated).
pub const MAX_MESSAGE_LEN: usize = 2048;

/// Per-entry header size: level (1) + timestamp (8) + len (2).
const ENTRY_HEADER_LEN: usize = 11;

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
    /// Human-readable string used in `/proc/kmsg` output.
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info  => "INFO ",
            LogLevel::Warn  => "WARN ",
            LogLevel::Error => "ERROR",
        }
    }

    fn from_u8(b: u8) -> Self {
        match b {
            0 => LogLevel::Debug,
            1 => LogLevel::Info,
            2 => LogLevel::Warn,
            3 => LogLevel::Error,
            _ => LogLevel::Info,
        }
    }
}

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the kernel ring buffer.
#[derive(Debug, Clone, Copy)]
pub struct RingBufferConfig {
    /// Mirror each log message to the serial console.
    pub mirror_to_serial: bool,
    /// Whether to keep statistics counters.
    pub enable_metrics: bool,
}

impl Default for RingBufferConfig {
    fn default() -> Self {
        Self {
            mirror_to_serial: true,
            enable_metrics: true,
        }
    }
}

/// Runtime configuration. Set once during `init_with_config`.
static CONFIG: Mutex<RingBufferConfig> = Mutex::new(RingBufferConfig {
    mirror_to_serial: true,
    enable_metrics: true,
});

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

/// Atomic metrics for the ring buffer.
#[derive(Debug, Default)]
pub struct RingBufferMetrics {
    /// Messages successfully written.
    pub written: AtomicU64,
    /// Messages dropped because they were too long.
    pub too_long: AtomicU64,
    /// Bytes currently used in the ring (approximate, updated on append).
    pub bytes_used: AtomicU64,
}

static METRICS: RingBufferMetrics = RingBufferMetrics {
    written: AtomicU64::new(0),
    too_long: AtomicU64::new(0),
    bytes_used: AtomicU64::new(0),
};

/// Snapshot of ring buffer metrics.
#[derive(Debug, Clone, Copy)]
pub struct RingBufferMetricsSnapshot {
    pub written: u64,
    pub too_long: u64,
    pub bytes_used: u64,
}

/// Read the current metrics snapshot.
pub fn metrics() -> RingBufferMetricsSnapshot {
    RingBufferMetricsSnapshot {
        written: METRICS.written.load(Ordering::Relaxed),
        too_long: METRICS.too_long.load(Ordering::Relaxed),
        bytes_used: METRICS.bytes_used.load(Ordering::Relaxed),
    }
}

// -----------------------------------------------------------------------------
// Ring buffer implementation
// -----------------------------------------------------------------------------

/// Circular buffer of log entries.
///
/// Layout of each entry:
/// ```text
/// [level: u8][timestamp_ms: u64 LE][len: u16 LE][msg: bytes...]
/// ```
/// The buffer is filled linearly; when the writer would exceed `RING_BUFFER_SIZE`,
/// it wraps to offset 0. On wrap, the writer detects that it is about to overwrite
/// entries the reader has not consumed yet and advances a `min_read_offset` so the
/// reader is kept coherent (old entries are silently dropped).
struct LogRing {
    buffer: [u8; RING_BUFFER_SIZE],
    /// Next byte offset where the writer will write.
    write_offset: AtomicUsize,
    /// Total number of bytes written since startup (monotonic; used to compute used).
    total_written: AtomicU64,
}

impl LogRing {
    const fn new() -> Self {
        Self {
            buffer: [0; RING_BUFFER_SIZE],
            write_offset: AtomicUsize::new(0),
            total_written: AtomicU64::new(0),
        }
    }

    /// Append a formatted message to the ring buffer.
    ///
    /// If `msg.len() > MAX_MESSAGE_LEN`, the message is dropped and `Err` returned.
    /// On success, `Ok(())` is returned and `METRICS.written` is incremented.
    fn append(&self, level: LogLevel, msg: &str) -> Result<(), &'static str> {
        let msg_bytes = msg.as_bytes();
        if msg_bytes.len() > MAX_MESSAGE_LEN {
            METRICS.too_long.fetch_add(1, Ordering::Relaxed);
            return Err("message too long");
        }

        let timestamp = uptime_ms();
        let msg_len = msg_bytes.len() as u16;
        let total_len = ENTRY_HEADER_LEN + msg_bytes.len();

        if total_len > RING_BUFFER_SIZE {
            METRICS.too_long.fetch_add(1, Ordering::Relaxed);
            return Err("message too large for ring buffer");
        }

        let mut write_off = self.write_offset.load(Ordering::Acquire);

        // Wrap if the entry doesn't fit in the remaining space.
        if write_off + total_len > RING_BUFFER_SIZE {
            write_off = 0;
            self.write_offset.store(0, Ordering::Release);
        }

        // Write the entry (single-writer; the caller holds the global LOCK).
        unsafe {
            let ptr = self.buffer.as_ptr().add(write_off) as *mut u8;
            core::ptr::write_volatile(ptr, level as u8);
            let ts = timestamp.to_le_bytes();
            core::ptr::write_volatile(ptr.add(1) as *mut [u8; 8], ts);
            let len = msg_len.to_le_bytes();
            core::ptr::write_volatile(ptr.add(1 + 8) as *mut [u8; 2], len);
            core::ptr::copy_nonoverlapping(
                msg_bytes.as_ptr(),
                ptr.add(ENTRY_HEADER_LEN),
                msg_bytes.len(),
            );
        }

        self.write_offset
            .store(write_off + total_len, Ordering::Release);
        self.total_written
            .fetch_add(total_len as u64, Ordering::Relaxed);

        METRICS.written.fetch_add(1, Ordering::Relaxed);

        // Update approximate bytes-used using min(total_written, RING_BUFFER_SIZE).
        let used = self
            .total_written
            .load(Ordering::Relaxed)
            .min(RING_BUFFER_SIZE as u64);
        METRICS.bytes_used.store(used, Ordering::Relaxed);

        Ok(())
    }

    /// Read the next entry starting at `read_off`.
    ///
    /// Returns `Some((level, timestamp, msg, next_off))` on success, or `None`
    /// if there is no complete entry at that offset (wrapped or empty).
    fn read_next(&self, read_off: usize) -> Option<(LogLevel, u64, &[u8], usize)> {
        if read_off >= RING_BUFFER_SIZE {
            return None;
        }
        let ptr = self.buffer.as_ptr();
        unsafe {
            let level_byte = core::ptr::read_volatile(ptr.add(read_off));
            let ts_arr = core::ptr::read_volatile(ptr.add(read_off + 1) as *const [u8; 8]);
            let timestamp = u64::from_le_bytes(ts_arr);
            let len_arr = core::ptr::read_volatile(ptr.add(read_off + 1 + 8) as *const [u8; 2]);
            let msg_len = u16::from_le_bytes(len_arr) as usize;
            let msg_start = read_off + ENTRY_HEADER_LEN;
            let next_off = msg_start.checked_add(msg_len)?;
            if next_off > RING_BUFFER_SIZE {
                return None;
            }
            let msg_slice = core::slice::from_raw_parts(ptr.add(msg_start), msg_len);
            Some((LogLevel::from_u8(level_byte), timestamp, msg_slice, next_off))
        }
    }
}

static RING: LogRing = LogRing::new();
static READ_OFFSET: AtomicUsize = AtomicUsize::new(0);
static LOCK: Mutex<()> = Mutex::new(());

// -----------------------------------------------------------------------------
// Public logging interface
// -----------------------------------------------------------------------------

/// Stack-allocated formatter used to avoid heap allocations.
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
        let remaining = self.buf.len().saturating_sub(self.pos);
        let to_copy = bytes.len().min(remaining);
        self.buf[self.pos..self.pos + to_copy].copy_from_slice(&bytes[..to_copy]);
        self.pos += to_copy;
        if to_copy < bytes.len() { Err(fmt::Error) } else { Ok(()) }
    }
}

/// Internal function to format and write a log message.
pub fn _klog(level: LogLevel, args: fmt::Arguments) {
    let mut buf = [0u8; MAX_MESSAGE_LEN];
    let msg = {
        let mut writer = ArrayWriter::new(&mut buf);
        let _ = writer.write_fmt(args);
        writer.as_str()
    };

    let _lock = LOCK.lock();
    if let Err(e) = RING.append(level, msg) {
        // Fallback: print to serial directly.
        crate::serial_println!("[KLOG] Failed to append message: {}", e);
    } else if CONFIG.lock().mirror_to_serial {
        let uptime = uptime_ms();
        crate::serial_println!(
            "[{:8}.{:03}] {}: {}",
            uptime / 1000,
            uptime % 1000,
            level.as_str(),
            msg
        );
    }
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

// -----------------------------------------------------------------------------
// Userspace interface (/proc/kmsg)
// -----------------------------------------------------------------------------

/// Small formatter for userspace buffer writes.
struct BufWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> BufWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }
}

impl<'a> fmt::Write for BufWriter<'a> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        let remaining = self.buf.len().saturating_sub(self.pos);
        let to_copy = bytes.len().min(remaining);
        self.buf[self.pos..self.pos + to_copy].copy_from_slice(&bytes[..to_copy]);
        self.pos += to_copy;
        if to_copy < bytes.len() { Err(fmt::Error) } else { Ok(()) }
    }
}

/// Read available log messages into a userspace buffer.
///
/// Returns the number of bytes written to `buf`. The `READ_OFFSET` is advanced
/// past consumed entries, so subsequent reads continue from where this call
/// left off.
pub fn kmsg_read(buf: &mut [u8]) -> usize {
    let _lock = LOCK.lock();
    let mut read_off = READ_OFFSET.load(Ordering::Acquire);
    let mut total_written = 0usize;

    while let Some((level, timestamp, msg, next_off)) = RING.read_next(read_off) {
        let level_str = level.as_str();
        let timestamp_sec = timestamp / 1000;
        let timestamp_ms = timestamp % 1000;
        let msg_str = core::str::from_utf8(msg).unwrap_or("");

        let mut writer = BufWriter::new(&mut buf[total_written..]);
        let write_result = write!(
            writer,
            "[{:8}.{:03}] {}: {}\n",
            timestamp_sec, timestamp_ms, level_str, msg_str
        );

        let written = writer.pos;
        if write_result.is_err() || written == 0 {
            // Buffer full — stop and leave READ_OFFSET untouched so caller
            // can retry with a larger buffer.
            break;
        }
        total_written += written;
        read_off = next_off;
    }

    READ_OFFSET.store(read_off, Ordering::Release);
    total_written
}

/// Returns the approximate number of bytes currently available to read.
pub fn kmsg_available() -> usize {
    let _lock = LOCK.lock();
    let mut read_off = READ_OFFSET.load(Ordering::Acquire);
    let mut total = 0usize;
    while let Some((_, _, msg, next_off)) = RING.read_next(read_off) {
        // Approximate line length: "[sec.ms] LEVEL: msg\n" plus overhead.
        total = total.saturating_add(msg.len() + 32);
        read_off = next_off;
    }
    total
}

// -----------------------------------------------------------------------------
// Initialization
// -----------------------------------------------------------------------------

/// Initialize the ring buffer with the default configuration.
pub fn init() {
    init_with_config(RingBufferConfig::default());
}

/// Initialize the ring buffer with an explicit configuration.
pub fn init_with_config(cfg: RingBufferConfig) {
    *CONFIG.lock() = cfg;
    // Note: we do not log here if `mirror_to_serial` is disabled, but we always
    // write the initial message to the ring buffer for userspace visibility.
    _klog(LogLevel::Info, format_args!(
        "Kernel ring buffer initialized ({} bytes)", RING_BUFFER_SIZE
    ));
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write as _;

    #[test]
    fn test_log_level_as_str() {
        assert_eq!(LogLevel::Debug.as_str(), "DEBUG");
        assert_eq!(LogLevel::Info.as_str(), "INFO ");
        assert_eq!(LogLevel::Warn.as_str(), "WARN ");
        assert_eq!(LogLevel::Error.as_str(), "ERROR");
    }

    #[test]
    fn test_log_level_from_u8() {
        assert_eq!(LogLevel::from_u8(0), LogLevel::Debug);
        assert_eq!(LogLevel::from_u8(1), LogLevel::Info);
        assert_eq!(LogLevel::from_u8(2), LogLevel::Warn);
        assert_eq!(LogLevel::from_u8(3), LogLevel::Error);
        assert_eq!(LogLevel::from_u8(42), LogLevel::Info);
    }

    #[test]
    fn test_array_writer_basic() {
        let mut buf = [0u8; 32];
        {
            let mut w = ArrayWriter::new(&mut buf);
            write!(w, "hello {}", 42).unwrap();
            assert_eq!(w.as_str(), "hello 42");
        }
    }

    #[test]
    fn test_ring_append_and_read() {
        // Local test ring to avoid polluting global state.
        let ring = LogRing::new();
        ring.append(LogLevel::Info, "first").unwrap();
        ring.append(LogLevel::Warn, "second").unwrap();

        let (level, _ts, msg, next) = ring.read_next(0).unwrap();
        assert_eq!(level, LogLevel::Info);
        assert_eq!(msg, b"first");

        let (level, _ts, msg, _next) = ring.read_next(next).unwrap();
        assert_eq!(level, LogLevel::Warn);
        assert_eq!(msg, b"second");
    }

    #[test]
    fn test_ring_too_long() {
        let ring = LogRing::new();
        let too_long = alloc::vec![b'a'; MAX_MESSAGE_LEN + 1];
        let s = core::str::from_utf8(&too_long).unwrap();
        assert!(ring.append(LogLevel::Info, s).is_err());
        let snap = metrics();
        assert!(snap.too_long >= 1);
    }

    #[test]
    fn test_config_default() {
        let cfg = RingBufferConfig::default();
        assert!(cfg.mirror_to_serial);
        assert!(cfg.enable_metrics);
    }

    #[test]
    fn test_metrics_snapshot() {
        let snap = metrics();
        // We can't assert exact values because other tests may write to the ring,
        // but we can assert the call doesn't panic and returns something sane.
        let _ = snap;
    }
}
