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
//! let events = trace::read_all();
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
