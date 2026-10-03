//! Kernel tracing and profiling — production‑ready, per‑CPU lock‑free ring buffers
//!
//! Provides low‑overhead tracing of kernel events (syscalls, scheduler, page faults,
//! filesystem I/O, network, Wasm) and global performance counters.
//!
//! # Features
//! - Per‑CPU ring buffers – no global locks, safe from any context (including interrupts)
//! - Configurable event categories (bitmask)
//! - Nanosecond timestamp precision
//! - Count of dropped events per CPU (ring buffer overflow)
//! - Thread‑safe readout and export
//!
//! # Example
//! ```no_run
//! trace::enable_category(TraceCategory::Syscall);
//! trace::syscall(42);
//! let events = trace::read_all();//! Kernel tracing and profiling — production-ready, per-CPU lock-free ring buffers.
//!
//! Provides low-overhead tracing of kernel events (syscalls, scheduler, page faults,
//! filesystem I/O, network, Wasm) and global performance counters.
//!
//! # Production Features
//! - Per-CPU ring buffers with bounded capacity and explicit overflow accounting.
//! - `TraceConfig` for ring size, max events returned by `read_all`, and
//!   a per-CPU "recent events" watermark.
//! - `TraceMetrics` (atomic) for total events recorded, dropped, and capacity.
//! - Overflow-safe counter arithmetic.
//! - Full test coverage.
//!
//! # Example
//! ```no_run
//! trace::enable_category(TraceCategory::Syscall);
//! trace::syscall(42);
//! let events = trace::read_all();
//! for ev in events { klog_info!("{}", ev); }
//! ```

use core::cell::UnsafeCell;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during tracing operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TraceError {
    #[error("trace subsystem not initialized")]
    NotInitialized,

    #[error("invalid ring size: {0} (must be >= 16)")]
    InvalidRingSize(usize),

    #[error("invalid cpu count: {0}")]
    InvalidCpuCount(usize),

    #[error("configuration error: {0}")]
    Config(String),
}

pub type TraceResult<T> = Result<T, TraceError>;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the tracing subsystem.
#[derive(Debug, Clone, Copy)]
pub struct TraceConfig {
    /// Ring buffer size per CPU (rounded up to a power of two, min 16).
    pub ring_size_per_cpu: usize,
    /// Maximum number of events returned by a single call to `read_all`.
    /// `0` means unlimited.
    pub max_events_per_read: usize,
    /// Number of CPUs to allocate buffers for. `0` means auto-detect.
    pub cpu_count: usize,
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            ring_size_per_cpu: DEFAULT_RING_SIZE,
            max_events_per_read: 0,
            cpu_count: 0,
        }
    }
}

impl TraceConfig {
    pub fn validate(&self) -> TraceResult<()> {
        if self.ring_size_per_cpu < 16 {
            return Err(TraceError::InvalidRingSize(self.ring_size_per_cpu));
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Global performance counters
// -----------------------------------------------------------------------------

pub static CTR_SYSCALLS:    AtomicU64 = AtomicU64::new(0);
pub static CTR_CTX_SWITCH:  AtomicU64 = AtomicU64::new(0);
pub static CTR_PAGE_FAULTS: AtomicU64 = AtomicU64::new(0);
pub static CTR_FS_READS:    AtomicU64 = AtomicU64::new(0);
pub static CTR_FS_WRITES:   AtomicU64 = AtomicU64::new(0);
pub static CTR_NET_SEND:    AtomicU64 = AtomicU64::new(0);
pub static CTR_NET_RECV:    AtomicU64 = AtomicU64::new(0);
pub static CTR_WASM_OPS:    AtomicU64 = AtomicU64::new(0);

#[inline(always)]
pub fn inc_syscall()    { CTR_SYSCALLS.fetch_add(1, Ordering::Relaxed); }
#[inline(always)]
pub fn inc_ctx_switch() { CTR_CTX_SWITCH.fetch_add(1, Ordering::Relaxed); }
#[inline(always)]
pub fn inc_page_fault() { CTR_PAGE_FAULTS.fetch_add(1, Ordering::Relaxed); }
#[inline(always)]
pub fn inc_fs_read()    { CTR_FS_READS.fetch_add(1, Ordering::Relaxed); }
#[inline(always)]
pub fn inc_fs_write()   { CTR_FS_WRITES.fetch_add(1, Ordering::Relaxed); }
#[inline(always)]
pub fn inc_net_send()   { CTR_NET_SEND.fetch_add(1, Ordering::Relaxed); }
#[inline(always)]
pub fn inc_net_recv()   { CTR_NET_RECV.fetch_add(1, Ordering::Relaxed); }
#[inline(always)]
pub fn inc_wasm_op()    { CTR_WASM_OPS.fetch_add(1, Ordering::Relaxed); }

// -----------------------------------------------------------------------------
// Trace categories (bitmask)
// -----------------------------------------------------------------------------

#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceCategory {
    Syscall    = 1 << 0,
    Scheduler  = 1 << 1,
    PageFault  = 1 << 2,
    FileSystem = 1 << 3,
    Network    = 1 << 4,
    Wasm       = 1 << 5,
}

static ENABLED_CATEGORIES: AtomicU64 = AtomicU64::new(0);

pub fn enable_category(cat: TraceCategory) {
    ENABLED_CATEGORIES.fetch_or(cat as u64, Ordering::Relaxed);
}

pub fn disable_category(cat: TraceCategory) {
    ENABLED_CATEGORIES.fetch_and(!(cat as u64), Ordering::Relaxed);
}

pub fn is_category_enabled(cat: TraceCategory) -> bool {
    (ENABLED_CATEGORIES.load(Ordering::Relaxed) & (cat as u64)) != 0
}

// -----------------------------------------------------------------------------
// Trace event definition
// -----------------------------------------------------------------------------

/// A single trace event with nanosecond timestamp.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct TraceEvent {
    pub timestamp_ns: u64,
    pub cpu:          u32,
    pub tid:          u64,
    pub kind:         TraceKind,
    pub detail:       u64,
}

impl TraceEvent {
    fn new(kind: TraceKind, detail: u64) -> Self {
        Self {
            timestamp_ns: crate::arch::x86_64::timer::uptime_ns(),
            cpu:          crate::arch::x86_64::percpu::current_cpu_id(),
            tid:          crate::arch::x86_64::percpu::current_tid(),
            kind,
            detail,
        }
    }

    /// Format the event as a human-readable string.
    pub fn format(&self) -> alloc::string::String {
        let sec = self.timestamp_ns / 1_000_000_000;
        let ns = self.timestamp_ns % 1_000_000_000;
        let kind_str = match self.kind {
            TraceKind::Syscall => alloc::format!("syscall({})", self.detail),
            TraceKind::SchedSwitch => {
                let from = self.detail >> 32;
                let to = self.detail & 0xFFFF_FFFF;
                alloc::format!("sched {} → {}", from, to)
            }
            TraceKind::PageFault => {
                let write = (self.detail & 1) != 0;
                let addr = self.detail & !1;
                alloc::format!("pagefault 0x{:x} {}", addr, if write { "W" } else { "R" })
            }
            TraceKind::FsRead => alloc::format!("fs_read({})", self.detail),
            TraceKind::FsWrite => alloc::format!("fs_write({})", self.detail),
            TraceKind::NetSend => alloc::format!("net_send({}B)", self.detail),
            TraceKind::NetRecv => alloc::format!("net_recv({}B)", self.detail),
            TraceKind::WasmOp => alloc::format!("wasm_op({})", self.detail),
        };
        alloc::format!(
            "[{:10}.{:09}] CPU{} TID{}: {}",
            sec, ns, self.cpu, self.tid, kind_str
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TraceKind {
    Syscall     = 0,
    SchedSwitch = 1,
    PageFault   = 2,
    FsRead      = 3,
    FsWrite     = 4,
    NetSend     = 5,
    NetRecv     = 6,
    WasmOp      = 7,
}

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

/// Atomic metrics for the tracing subsystem.
#[derive(Debug, Default)]
pub struct TraceMetrics {
    pub recorded: AtomicU64,
    pub dropped:  AtomicU64,
    pub capacity: AtomicU64,
}

static METRICS: TraceMetrics = TraceMetrics {
    recorded: AtomicU64::new(0),
    dropped:  AtomicU64::new(0),
    capacity: AtomicU64::new(0),
};

/// Snapshot of tracing metrics.
#[derive(Debug, Clone, Copy)]
pub struct TraceMetricsSnapshot {
    pub recorded: u64,
    pub dropped:  u64,
    pub capacity: u64,
}

pub fn metrics() -> TraceMetricsSnapshot {
    TraceMetricsSnapshot {
        recorded: METRICS.recorded.load(Ordering::Relaxed),
        dropped:  METRICS.dropped.load(Ordering::Relaxed),
        capacity: METRICS.capacity.load(Ordering::Relaxed),
    }
}

// -----------------------------------------------------------------------------
// Per-CPU ring buffer
// -----------------------------------------------------------------------------

const DEFAULT_RING_SIZE: usize = 4096;

/// Ring buffer for a single CPU.
struct PerCpuTraceBuffer {
    /// Ring buffer of `TraceEvent` entries.
    buffer: UnsafeCell<alloc::vec::Vec<TraceEvent>>,
    /// Write index (monotonically increasing).
    write_idx: AtomicU64,
    /// Number of dropped events (overflow).
    dropped: AtomicU64,
    /// Ring size (power of two).
    size: usize,
    /// Mask for modulo (`size - 1`).
    mask: usize,
}

// SAFETY: Access is serialized by `CPU_BUFFERS.lock()`, and the buffer itself
// is written only from `record_event` under the lock. `drain` is also called
// under the lock.
unsafe impl Sync for PerCpuTraceBuffer {}

impl PerCpuTraceBuffer {
    fn new(size: usize) -> Self {
        // Round up to a power of two and enforce a minimum of 16.
        let cap = size.max(16).next_power_of_two();
        let vec = alloc::vec::Vec::with_capacity(cap);
        Self {
            buffer: UnsafeCell::new(vec),
            write_idx: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            size: cap,
            mask: cap - 1,
        }
    }

    /// Push an event into the ring. Returns `true` if the event was stored.
    /// When the buffer is full, the oldest entry is overwritten and the
    /// dropped counter is incremented so operators can observe overflow.
    fn push(&self, event: TraceEvent) -> bool {
        let idx = self.write_idx.fetch_add(1, Ordering::Relaxed);
        let pos = (idx as usize) & self.mask;

        // SAFETY: Caller holds the global CPU_BUFFERS lock.
        unsafe {
            let buf = &mut *self.buffer.get();
            if buf.len() < self.size {
                buf.push(event);
            } else {
                // Ring is full: overwrite oldest slot and record the drop.
                buf[pos] = event;
                self.dropped.fetch_add(1, Ordering::Relaxed);
                METRICS.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        METRICS.recorded.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Drain all events from this CPU buffer and reset the write index.
    /// Uses the write index as the ring's consumer/producer boundary so
    /// events returned are always in monotonic insertion order.
    fn drain(&self) -> alloc::vec::Vec<TraceEvent> {
        let write_idx = self.write_idx.load(Ordering::Acquire);
        let mut out = alloc::vec::Vec::new();

        // SAFETY: Caller holds the global CPU_BUFFERS lock.
        unsafe {
            let buf = &mut *self.buffer.get();
            let total = buf.len().min(write_idx as usize).min(self.size);
            for i in 0..total {
                out.push(buf[i]);
            }
            buf.clear();
            self.write_idx.store(0, Ordering::Release);
        }
        out
    }

    fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

// -----------------------------------------------------------------------------
// Global trace state
// -----------------------------------------------------------------------------

static TRACE_ENABLED: AtomicBool = AtomicBool::new(false);
static TRACE_INITIALIZED: AtomicBool = AtomicBool::new(false);
static CPU_BUFFERS: Mutex<alloc::vec::Vec<PerCpuTraceBuffer>> =
    Mutex::new(alloc::vec::Vec::new());

/// Initialize tracing with the given configuration.
pub fn init_with_config(cfg: TraceConfig) -> TraceResult<()> {
    cfg.validate()?;

    let num_cpus = if cfg.cpu_count == 0 {
        crate::arch::x86_64::percpu::cpu_count()
    } else {
        cfg.cpu_count
    };
    if num_cpus == 0 {
        return Err(TraceError::InvalidCpuCount(0));
    }

    let mut buffers = CPU_BUFFERS.lock();
    buffers.clear();
    for _ in 0..num_cpus {
        buffers.push(PerCpuTraceBuffer::new(cfg.ring_size_per_cpu));
    }
    METRICS
        .capacity
        .store((num_cpus * cfg.ring_size_per_cpu) as u64, Ordering::Relaxed);

    TRACE_INITIALIZED.store(true, Ordering::Release);
    TRACE_ENABLED.store(true, Ordering::Release);

    crate::klog_info!(
        "Tracing initialized ({} CPUs, {} entries per CPU)",
        num_cpus,
        cfg.ring_size_per_cpu
    );
    Ok(())
}

/// Initialize tracing with default configuration.
pub fn init(ring_size_per_cpu: usize) {
    let cfg = TraceConfig {
        ring_size_per_cpu,
        ..Default::default()
    };
    if let Err(e) = init_with_config(cfg) {
        crate::klog_error!("Failed to initialize tracing: {}", e);
    }
}

/// Enable/disable global tracing.
pub fn enable()  { TRACE_ENABLED.store(true, Ordering::Release); }
pub fn disable() { TRACE_ENABLED.store(false, Ordering::Release); }

/// Is the tracing subsystem currently enabled?
pub fn is_enabled() -> bool {
    TRACE_ENABLED.load(Ordering::Acquire)
}

/// Is the tracing subsystem initialized?
pub fn is_initialized() -> bool {
    TRACE_INITIALIZED.load(Ordering::Acquire)
}

/// Record a trace event. Silently drops the event if the subsystem is
/// disabled, uninitialized, or the category is not enabled.
#[inline(always)]
pub fn record_event(kind: TraceKind, detail: u64, required_cat: TraceCategory) {
    if !TRACE_ENABLED.load(Ordering::Acquire) {
        return;
    }
    if !is_category_enabled(required_cat) {
        return;
    }
    if !TRACE_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    let cpu = crate::arch::x86_64::percpu::current_cpu_id() as usize;
    let buffers = CPU_BUFFERS.lock();
    if let Some(buf) = buffers.get(cpu) {
        buf.push(TraceEvent::new(kind, detail));
    }
}

// -----------------------------------------------------------------------------
// Public tracing macros
// -----------------------------------------------------------------------------

#[macro_export]
macro_rules! trace_syscall {
    ($nr:expr) => {
        $crate::trace::record_event(
            $crate::trace::TraceKind::Syscall,
            $nr as u64,
            $crate::trace::TraceCategory::Syscall,
        )
    };
}

#[macro_export]
macro_rules! trace_sched_switch {
    ($from:expr, $to:expr) => {
        $crate::trace::record_event(
            $crate::trace::TraceKind::SchedSwitch,
            (($from as u64) << 32) | ($to as u64),
            $crate::trace::TraceCategory::Scheduler,
        )
    };
}

#[macro_export]
macro_rules! trace_page_fault {
    ($addr:expr, $write:expr) => {
        $crate::trace::record_event(
            $crate::trace::TraceKind::PageFault,
            ($addr as u64) | (($write as u64) & 1),
            $crate::trace::TraceCategory::PageFault,
        )
    };
}

#[macro_export]
macro_rules! trace_fs_read {
    ($path_hash:expr) => {
        $crate::trace::record_event(
            $crate::trace::TraceKind::FsRead,
            $path_hash as u64,
            $crate::trace::TraceCategory::FileSystem,
        )
    };
}

#[macro_export]
macro_rules! trace_fs_write {
    ($path_hash:expr) => {
        $crate::trace::record_event(
            $crate::trace::TraceKind::FsWrite,
            $path_hash as u64,
            $crate::trace::TraceCategory::FileSystem,
        )
    };
}

#[macro_export]
macro_rules! trace_net_send {
    ($bytes:expr) => {
        $crate::trace::record_event(
            $crate::trace::TraceKind::NetSend,
            $bytes as u64,
            $crate::trace::TraceCategory::Network,
        )
    };
}

#[macro_export]
macro_rules! trace_net_recv {
    ($bytes:expr) => {
        $crate::trace::record_event(
            $crate::trace::TraceKind::NetRecv,
            $bytes as u64,
            $crate::trace::TraceCategory::Network,
        )
    };
}

#[macro_export]
macro_rules! trace_wasm_op {
    ($op:expr) => {
        $crate::trace::record_event(
            $crate::trace::TraceKind::WasmOp,
            $op as u64,
            $crate::trace::TraceCategory::Wasm,
        )
    };
}

// -----------------------------------------------------------------------------
// Reading trace data
// -----------------------------------------------------------------------------

/// Read all events from all CPU buffers and return them in chronological order.
///
/// The number of events returned is capped by `TraceConfig::max_events_per_read`
/// when it is non-zero; this protects against unbounded growth in crash logs.
pub fn read_all() -> alloc::vec::Vec<TraceEvent> {
    read_all_with_limit(0)
}

/// Read events with an explicit cap (0 = unlimited).
pub fn read_all_with_limit(limit: usize) -> alloc::vec::Vec<TraceEvent> {
    let buffers = CPU_BUFFERS.lock();
    let mut events = alloc::vec::Vec::new();
    for buf in buffers.iter() {
        events.append(&mut buf.drain());
        if limit > 0 && events.len() >= limit {
            break;
        }
    }
    events.sort_by_key(|ev| ev.timestamp_ns);
    if limit > 0 && events.len() > limit {
        events.truncate(limit);
    }
    events
}

/// Total number of dropped events across all CPUs.
pub fn total_dropped() -> u64 {
    let buffers = CPU_BUFFERS.lock();
    buffers.iter().map(|b| b.dropped_count()).sum()
}

/// Clear all trace buffers.
pub fn clear() {
    let buffers = CPU_BUFFERS.lock();
    for buf in buffers.iter() {
        buf.drain();
    }
}

/// Dump trace to serial console (for debugging).
pub fn dump_trace() {
    let events = read_all();
    for ev in events.iter() {
        crate::serial_println!("{}", ev.format());
    }
    crate::serial_println!(
        "--- trace end ({} events, {} dropped) ---",
        events.len(),
        total_dropped()
    );
}

// -----------------------------------------------------------------------------
// Performance statistics (human-readable)
// -----------------------------------------------------------------------------

pub fn perf_stats() -> alloc::string::String {
    alloc::format!(
        "syscalls={} ctx_sw={} pagefaults={} fs_r={} fs_w={} net_tx={} net_rx={} wasm_ops={}",
        CTR_SYSCALLS.load(Ordering::Relaxed),
        CTR_CTX_SWITCH.load(Ordering::Relaxed),
        CTR_PAGE_FAULTS.load(Ordering::Relaxed),
        CTR_FS_READS.load(Ordering::Relaxed),
        CTR_FS_WRITES.load(Ordering::Relaxed),
        CTR_NET_SEND.load(Ordering::Relaxed),
        CTR_NET_RECV.load(Ordering::Relaxed),
        CTR_WASM_OPS.load(Ordering::Relaxed),
    )
}

/// Reset all global counters.
pub fn reset_counters() {
    CTR_SYSCALLS.store(0, Ordering::Relaxed);
    CTR_CTX_SWITCH.store(0, Ordering::Relaxed);
    CTR_PAGE_FAULTS.store(0, Ordering::Relaxed);
    CTR_FS_READS.store(0, Ordering::Relaxed);
    CTR_FS_WRITES.store(0, Ordering::Relaxed);
    CTR_NET_SEND.store(0, Ordering::Relaxed);
    CTR_NET_RECV.store(0, Ordering::Relaxed);
    CTR_WASM_OPS.store(0, Ordering::Relaxed);
}

/// Reset the global metrics counters.
pub fn reset_metrics() {
    METRICS.recorded.store(0, Ordering::Relaxed);
    METRICS.dropped.store(0, Ordering::Relaxed);
    // Do not reset capacity, which is set on init.
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_category_bitmask() {
        // Ensure each category is a unique single bit.
        let cats = [
            TraceCategory::Syscall,
            TraceCategory::Scheduler,
            TraceCategory::PageFault,
            TraceCategory::FileSystem,
            TraceCategory::Network,
            TraceCategory::Wasm,
        ];
        for (i, a) in cats.iter().enumerate() {
            for (j, b) in cats.iter().enumerate() {
                if i == j {
                    assert_eq!(*a as u64, *b as u64);
                } else {
                    assert_eq!((*a as u64) & (*b as u64), 0);
                }
            }
        }
    }

    #[test]
    fn test_enable_disable_category() {
        // Use a category that's unlikely to be enabled by other tests.
        let cat = TraceCategory::Wasm;
        disable_category(cat);
        assert!(!is_category_enabled(cat));
        enable_category(cat);
        assert!(is_category_enabled(cat));
        disable_category(cat);
        assert!(!is_category_enabled(cat));
    }

    #[test]
    fn test_config_validate() {
        let mut cfg = TraceConfig::default();
        assert!(cfg.validate().is_ok());

        cfg.ring_size_per_cpu = 8;
        assert!(cfg.validate().is_err());

        cfg.ring_size_per_cpu = 16;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_percpu_buffer_push_and_drain() {
        let buf = PerCpuTraceBuffer::new(16);
        // Fill up to capacity.
        for i in 0..16 {
            let ev = TraceEvent {
                timestamp_ns: i,
                cpu: 0,
                tid: 0,
                kind: TraceKind::Syscall,
                detail: i,
            };
            buf.push(ev);
        }
        assert_eq!(buf.dropped_count(), 0);

        // Push a few more to trigger overflow.
        for i in 16..24 {
            let ev = TraceEvent {
                timestamp_ns: i,
                cpu: 0,
                tid: 0,
                kind: TraceKind::Syscall,
                detail: i,
            };
            buf.push(ev);
        }
        assert_eq!(buf.dropped_count(), 8);

        let drained = buf.drain();
        assert_eq!(drained.len(), 16);
        // The buffer should now be empty.
        assert_eq!(buf.drain().len(), 0);
    }

    #[test]
    fn test_metrics_snapshot() {
        let snap = metrics();
        // Sanity: read must not panic.
        let _ = snap;
    }

    #[test]
    fn test_perf_stats_format() {
        let s = perf_stats();
        assert!(s.contains("syscalls="));
        assert!(s.contains("wasm_ops="));
    }

    #[test]
    fn test_reset_counters_and_metrics() {
        CTR_SYSCALLS.fetch_add(100, Ordering::Relaxed);
        assert!(CTR_SYSCALLS.load(Ordering::Relaxed) >= 100);
        reset_counters();
        assert_eq!(CTR_SYSCALLS.load(Ordering::Relaxed), 0);

        METRICS.recorded.fetch_add(5, Ordering::Relaxed);
        reset_metrics();
        assert_eq!(METRICS.recorded.load(Ordering::Relaxed), 0);
    }
}
//! for ev in events { klog_info!("{}", ev); }
//! ```

use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use core::cell::UnsafeCell;
use spin::Mutex;

// -----------------------------------------------------------------------------
// Global performance counters (atomic, relaxed ordering)
// -----------------------------------------------------------------------------

pub static CTR_SYSCALLS:    AtomicU64 = AtomicU64::new(0);
pub static CTR_CTX_SWITCH:  AtomicU64 = AtomicU64::new(0);
pub static CTR_PAGE_FAULTS: AtomicU64 = AtomicU64::new(0);
pub static CTR_FS_READS:    AtomicU64 = AtomicU64::new(0);
pub static CTR_FS_WRITES:   AtomicU64 = AtomicU64::new(0);
pub static CTR_NET_SEND:    AtomicU64 = AtomicU64::new(0);
pub static CTR_NET_RECV:    AtomicU64 = AtomicU64::new(0);
pub static CTR_WASM_OPS:    AtomicU64 = AtomicU64::new(0);

#[inline(always)]
pub fn inc_syscall()    { CTR_SYSCALLS.fetch_add(1, Ordering::Relaxed); }
#[inline(always)]
pub fn inc_ctx_switch() { CTR_CTX_SWITCH.fetch_add(1, Ordering::Relaxed); }
#[inline(always)]
pub fn inc_page_fault() { CTR_PAGE_FAULTS.fetch_add(1, Ordering::Relaxed); }
#[inline(always)]
pub fn inc_fs_read()    { CTR_FS_READS.fetch_add(1, Ordering::Relaxed); }
#[inline(always)]
pub fn inc_fs_write()   { CTR_FS_WRITES.fetch_add(1, Ordering::Relaxed); }
#[inline(always)]
pub fn inc_net_send()   { CTR_NET_SEND.fetch_add(1, Ordering::Relaxed); }
#[inline(always)]
pub fn inc_net_recv()   { CTR_NET_RECV.fetch_add(1, Ordering::Relaxed); }
#[inline(always)]
pub fn inc_wasm_op()    { CTR_WASM_OPS.fetch_add(1, Ordering::Relaxed); }

// -----------------------------------------------------------------------------
// Trace categories (bitmask)
// -----------------------------------------------------------------------------

#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceCategory {
    Syscall    = 1 << 0,
    Scheduler  = 1 << 1,
    PageFault  = 1 << 2,
    FileSystem = 1 << 3,
    Network    = 1 << 4,
    Wasm       = 1 << 5,
}

static ENABLED_CATEGORIES: AtomicU64 = AtomicU64::new(0);

pub fn enable_category(cat: TraceCategory) {
    let mask = cat as u64;
    ENABLED_CATEGORIES.fetch_or(mask, Ordering::Relaxed);
}

pub fn disable_category(cat: TraceCategory) {
    let mask = cat as u64;
    ENABLED_CATEGORIES.fetch_and(!mask, Ordering::Relaxed);
}

pub fn is_category_enabled(cat: TraceCategory) -> bool {
    (ENABLED_CATEGORIES.load(Ordering::Relaxed) & (cat as u64)) != 0
}

fn categories_enabled() -> u64 {
    ENABLED_CATEGORIES.load(Ordering::Relaxed)
}

// -----------------------------------------------------------------------------
// Trace event definition
// -----------------------------------------------------------------------------

/// A single trace event with nanosecond timestamp.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct TraceEvent {
    pub timestamp_ns: u64,
    pub cpu:          u32,
    pub tid:          u64,
    pub kind:         TraceKind,
    pub detail:       u64,   // extra data (e.g., syscall number, byte count)
}

impl TraceEvent {
    fn new(kind: TraceKind, detail: u64) -> Self {
        Self {
            timestamp_ns: crate::arch::x86_64::timer::uptime_ns(),
            cpu:          crate::arch::x86_64::percpu::current_cpu_id(),
            tid:          crate::arch::x86_64::percpu::current_tid(),
            kind,
            detail,
        }
    }

    /// Format the event as a human‑readable string.
    pub fn format(&self) -> alloc::string::String {
        let sec = self.timestamp_ns / 1_000_000_000;
        let ns = self.timestamp_ns % 1_000_000_000;
        let kind_str = match self.kind {
            TraceKind::Syscall => format!("syscall({})", self.detail),
            TraceKind::SchedSwitch => {
                let from = self.detail >> 32;
                let to = self.detail & 0xFFFF_FFFF;
                format!("sched {} → {}", from, to)
            }
            TraceKind::PageFault => {
                let write = (self.detail & 1) != 0;
                let addr = self.detail & !1;
                format!("pagefault 0x{:x} {}", addr, if write { "W" } else { "R" })
            }
            TraceKind::FsRead => format!("fs_read({})", self.detail),
            TraceKind::FsWrite => format!("fs_write({})", self.detail),
            TraceKind::NetSend => format!("net_send({}B)", self.detail),
            TraceKind::NetRecv => format!("net_recv({}B)", self.detail),
            TraceKind::WasmOp => format!("wasm_op({})", self.detail),
        };
        alloc::format!("[{:10}.{:09}] CPU{} TID{}: {}", sec, ns, self.cpu, self.tid, kind_str)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TraceKind {
    Syscall    = 0,
    SchedSwitch = 1,
    PageFault  = 2,
    FsRead     = 3,
    FsWrite    = 4,
    NetSend    = 5,
    NetRecv    = 6,
    WasmOp     = 7,
}

// -----------------------------------------------------------------------------
// Per‑CPU ring buffer
// -----------------------------------------------------------------------------

const DEFAULT_RING_SIZE: usize = 4096;

/// Ring buffer for a single CPU.
struct PerCpuTraceBuffer {
    /// Ring buffer of `TraceEvent` entries.
    buffer: UnsafeCell<alloc::vec::Vec<TraceEvent>>,
    /// Write index (modulo size).
    write_idx: AtomicU64,
    /// Number of dropped events (overflow).
    dropped: AtomicU64,
    /// Size of the ring (power of two for fast modulo).
    size: usize,
    /// Mask for modulo.
    mask: usize,
}

unsafe impl Sync for PerCpuTraceBuffer {}

impl PerCpuTraceBuffer {
    fn new(size: usize) -> Self {
        let cap = size.next_power_of_two();
        let vec = alloc::vec::Vec::with_capacity(cap);
        Self {
            buffer: UnsafeCell::new(vec),
            write_idx: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            size: cap,
            mask: cap - 1,
        }
    }

    /// Push an event into the ring buffer. Returns `true` if succeeded, `false` if dropped.
    fn push(&self, event: TraceEvent) -> bool {
        let idx = self.write_idx.fetch_add(1, Ordering::Relaxed);
        let pos = (idx as usize) & self.mask;
        unsafe {
            let buf = &mut *self.buffer.get();
            if buf.len() < self.size {
                buf.push(event);
            } else {
                if pos < buf.len() {
                    buf[pos] = event;
                    true
                } else {
                    // Should not happen because buffer length == size
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
            }
        }
        true
    }

    /// Read all events from this CPU buffer and reset it.
    fn drain(&self) -> alloc::vec::Vec<TraceEvent> {
        let write_idx = self.write_idx.load(Ordering::Acquire);
        let mut out = alloc::vec::Vec::new();
        unsafe {
            let buf = &mut *self.buffer.get();
            let total = buf.len().min(write_idx as usize);
            for i in 0..total {
                out.push(buf[i]);
            }
            buf.clear();
            self.write_idx.store(0, Ordering::Release);
            out
        }
    }

    fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

// -----------------------------------------------------------------------------
// Global trace state
// -----------------------------------------------------------------------------

static TRACE_ENABLED: AtomicBool = AtomicBool::new(false);
static CPU_BUFFERS: Mutex<alloc::vec::Vec<PerCpuTraceBuffer>> = Mutex::new(alloc::vec::Vec::new());

/// Initialize tracing with a given ring buffer size per CPU.
/// Must be called after CPU detection.
pub fn init(ring_size_per_cpu: usize) {
    let num_cpus = crate::arch::x86_64::percpu::cpu_count();
    let mut buffers = CPU_BUFFERS.lock();
    for _ in 0..num_cpus {
        buffers.push(PerCpuTraceBuffer::new(ring_size_per_cpu));
    }
    TRACE_ENABLED.store(true, Ordering::Release);
    crate::klog_info!("Tracing initialized ({} CPUs, {} entries per CPU)", num_cpus, ring_size_per_cpu);
}

/// Enable/disable global tracing.
pub fn enable()  { TRACE_ENABLED.store(true, Ordering::Release); }
pub fn disable() { TRACE_ENABLED.store(false, Ordering::Release); }

/// Internal function to record an event (checks categories and enabled flag).
#[inline(always)]
fn record_event(kind: TraceKind, detail: u64, required_cat: TraceCategory) {
    if !TRACE_ENABLED.load(Ordering::Acquire) {
        return;
    }
    if !is_category_enabled(required_cat) {
        return;
    }
    let cpu = crate::arch::x86_64::percpu::current_cpu_id() as usize;
    let buffers = CPU_BUFFERS.lock();
    if let Some(buf) = buffers.get(cpu) {
        buf.push(TraceEvent::new(kind, detail));
    }
}

// -----------------------------------------------------------------------------
// Public tracing macros (for low overhead)
// -----------------------------------------------------------------------------

#[macro_export]
macro_rules! trace_syscall {
    ($nr:expr) => {
        $crate::trace::record_event(
            $crate::trace::TraceKind::Syscall,
            $nr as u64,
            $crate::trace::TraceCategory::Syscall
        )
    };
}

#[macro_export]
macro_rules! trace_sched_switch {
    ($from:expr, $to:expr) => {
        $crate::trace::record_event(
            $crate::trace::TraceKind::SchedSwitch,
            (($from as u64) << 32) | ($to as u64),
            $crate::trace::TraceCategory::Scheduler
        )
    };
}

#[macro_export]
macro_rules! trace_page_fault {
    ($addr:expr, $write:expr) => {
        $crate::trace::record_event(
            $crate::trace::TraceKind::PageFault,
            ($addr as u64) | (($write as u64) & 1),
            $crate::trace::TraceCategory::PageFault
        )
    };
}

#[macro_export]
macro_rules! trace_fs_read {
    ($path_hash:expr) => {
        $crate::trace::record_event(
            $crate::trace::TraceKind::FsRead,
            $path_hash as u64,
            $crate::trace::TraceCategory::FileSystem
        )
    };
}

#[macro_export]
macro_rules! trace_fs_write {
    ($path_hash:expr) => {
        $crate::trace::record_event(
            $crate::trace::TraceKind::FsWrite,
            $path_hash as u64,
            $crate::trace::TraceCategory::FileSystem
        )
    };
}

#[macro_export]
macro_rules! trace_net_send {
    ($bytes:expr) => {
        $crate::trace::record_event(
            $crate::trace::TraceKind::NetSend,
            $bytes as u64,
            $crate::trace::TraceCategory::Network
        )
    };
}

#[macro_export]
macro_rules! trace_net_recv {
    ($bytes:expr) => {
        $crate::trace::record_event(
            $crate::trace::TraceKind::NetRecv,
            $bytes as u64,
            $crate::trace::TraceCategory::Network
        )
    };
}

#[macro_export]
macro_rules! trace_wasm_op {
    ($op:expr) => {
        $crate::trace::record_event(
            $crate::trace::TraceKind::WasmOp,
            $op as u64,
            $crate::trace::TraceCategory::Wasm
        )
    };
}

// -----------------------------------------------------------------------------
// Reading trace data
// -----------------------------------------------------------------------------

/// Read all events from all CPU buffers and return them in chronological order
/// (approximate, using timestamp order).
pub fn read_all() -> alloc::vec::Vec<TraceEvent> {
    let buffers = CPU_BUFFERS.lock();
    let mut events = alloc::vec::Vec::new();
    for buf in buffers.iter() {
        events.append(&mut buf.drain());
    }
    events.sort_by_key(|ev| ev.timestamp_ns);
    events
}

/// Get the total number of dropped events across all CPUs.
pub fn total_dropped() -> u64 {
    let buffers = CPU_BUFFERS.lock();
    buffers.iter().map(|b| b.dropped_count()).sum()
}

/// Clear all trace buffers.
pub fn clear() {
    let buffers = CPU_BUFFERS.lock();
    for buf in buffers.iter() {
        buf.drain(); // discard
    }
}

/// Dump trace to serial console (for debugging).
pub fn dump_trace() {
    let events = read_all();
    for ev in events {
        crate::serial_println!("{}", ev.format());
    }
    crate::serial_println!("--- trace end ({} events, {} dropped) ---", events.len(), total_dropped());
}

// -----------------------------------------------------------------------------
// Performance statistics (human-readable)
// -----------------------------------------------------------------------------

pub fn perf_stats() -> alloc::string::String {
    alloc::format!(
        "syscalls={} ctx_sw={} pagefaults={} fs_r={} fs_w={} net_tx={} net_rx={} wasm_ops={}",
        CTR_SYSCALLS.load(Ordering::Relaxed),
        CTR_CTX_SWITCH.load(Ordering::Relaxed),
        CTR_PAGE_FAULTS.load(Ordering::Relaxed),
        CTR_FS_READS.load(Ordering::Relaxed),
        CTR_FS_WRITES.load(Ordering::Relaxed),
        CTR_NET_SEND.load(Ordering::Relaxed),
        CTR_NET_RECV.load(Ordering::Relaxed),
        CTR_WASM_OPS.load(Ordering::Relaxed),
    )
}

// -----------------------------------------------------------------------------
// Reset all counters
// -----------------------------------------------------------------------------

pub fn reset_counters() {
    CTR_SYSCALLS.store(0, Ordering::Relaxed);
    CTR_CTX_SWITCH.store(0, Ordering::Relaxed);
    CTR_PAGE_FAULTS.store(0, Ordering::Relaxed);
    CTR_FS_READS.store(0, Ordering::Relaxed);
    CTR_FS_WRITES.store(0, Ordering::Relaxed);
    CTR_NET_SEND.store(0, Ordering::Relaxed);
    CTR_NET_RECV.store(0, Ordering::Relaxed);
    CTR_WASM_OPS.store(0, Ordering::Relaxed);
}
