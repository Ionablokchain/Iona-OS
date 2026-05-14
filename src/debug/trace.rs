//! Kernel tracing and profiling
//!
//! Trace subsystems: syscall, sched, pagefault, fs, net
//! Perf counters: context switches, syscall count, page faults, I/O ops

use alloc::{collections::VecDeque, string::String, format};
use spin::{Lazy, Mutex};
use core::sync::atomic::{AtomicU64, Ordering};

// ── Global perf counters ──────────────────────────────────────────────────────
pub static CTR_SYSCALLS:    AtomicU64 = AtomicU64::new(0);
pub static CTR_CTX_SWITCH:  AtomicU64 = AtomicU64::new(0);
pub static CTR_PAGE_FAULTS: AtomicU64 = AtomicU64::new(0);
pub static CTR_FS_READS:    AtomicU64 = AtomicU64::new(0);
pub static CTR_FS_WRITES:   AtomicU64 = AtomicU64::new(0);
pub static CTR_NET_SEND:    AtomicU64 = AtomicU64::new(0);
pub static CTR_NET_RECV:    AtomicU64 = AtomicU64::new(0);
pub static CTR_WASM_OPS:    AtomicU64 = AtomicU64::new(0);

#[inline] pub fn inc_syscall()    { CTR_SYSCALLS.fetch_add(1, Ordering::Relaxed); }
#[inline] pub fn inc_ctx_switch() { CTR_CTX_SWITCH.fetch_add(1, Ordering::Relaxed); }
#[inline] pub fn inc_page_fault() { CTR_PAGE_FAULTS.fetch_add(1, Ordering::Relaxed); }
#[inline] pub fn inc_fs_read()    { CTR_FS_READS.fetch_add(1, Ordering::Relaxed); }
#[inline] pub fn inc_fs_write()   { CTR_FS_WRITES.fetch_add(1, Ordering::Relaxed); }
#[inline] pub fn inc_net_send()   { CTR_NET_SEND.fetch_add(1, Ordering::Relaxed); }
#[inline] pub fn inc_net_recv()   { CTR_NET_RECV.fetch_add(1, Ordering::Relaxed); }

// ── Trace ring buffer ──────────────────────────────────────────────────────────
const TRACE_CAPACITY: usize = 4096;

#[derive(Clone)]
pub struct TraceEvent {
    pub ms:      u64,
    pub cpu:     u32,
    pub tid:     u64,
    pub kind:    TraceKind,
    pub detail:  u64,
}

#[derive(Clone, Debug)]
pub enum TraceKind {
    Syscall(u64),
    SchedSwitch { from: u64, to: u64 },
    PageFault { virt: u64, write: bool },
    FsRead(u64),   // path_hash
    FsWrite(u64),
    NetSend(u64),  // bytes
    NetRecv(u64),
    WasmOp(u64),
}

static TRACE_BUF: Lazy<Mutex<VecDeque<TraceEvent>>> =
    Lazy::new(|| Mutex::new(VecDeque::new()));
static TRACE_ENABLED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

pub fn trace_enable()  { TRACE_ENABLED.store(true,  Ordering::SeqCst); }
pub fn trace_disable() { TRACE_ENABLED.store(false, Ordering::SeqCst); }

pub fn trace(kind: TraceKind) {
    if !TRACE_ENABLED.load(Ordering::Relaxed) { return; }
    let ev = TraceEvent {
        ms:     crate::arch::x86_64::timer::uptime_ms(),
        cpu:    crate::arch::x86_64::percpu::current_cpu_id(),
        tid:    crate::arch::x86_64::percpu::current_tid(),
        kind,
        detail: 0,
    };
    let mut buf = TRACE_BUF.lock();
    if buf.len() >= TRACE_CAPACITY { buf.pop_front(); }
    buf.push_back(ev);
}

/// Format trace buffer as human-readable text
pub fn dump_trace() -> alloc::vec::Vec<String> {
    TRACE_BUF.lock().iter().map(|ev| {
        let kind = match &ev.kind {
            TraceKind::Syscall(nr)          => format!("syscall({})", nr),
            TraceKind::SchedSwitch{from,to} => format!("sched {} → {}", from, to),
            TraceKind::PageFault{virt,write}=> format!("pagefault 0x{:x} {}", virt, if *write {"W"} else {"R"}),
            TraceKind::FsRead(h)            => format!("fs_read h={:x}", h),
            TraceKind::FsWrite(h)           => format!("fs_write h={:x}", h),
            TraceKind::NetSend(n)           => format!("net_send {}B", n),
            TraceKind::NetRecv(n)           => format!("net_recv {}B", n),
            TraceKind::WasmOp(n)            => format!("wasm_op {}", n),
        };
        format!("[{:8}.{:03}] CPU{} TID{}: {}", ev.ms/1000, ev.ms%1000, ev.cpu, ev.tid, kind)
    }).collect()
}

/// Summary statistics
pub fn perf_stats() -> String {
    format!(
        "syscalls={} ctx_sw={} pagefaults={} fs_r={} fs_w={} net_tx={} net_rx={}",
        CTR_SYSCALLS.load(Ordering::Relaxed),
        CTR_CTX_SWITCH.load(Ordering::Relaxed),
        CTR_PAGE_FAULTS.load(Ordering::Relaxed),
        CTR_FS_READS.load(Ordering::Relaxed),
        CTR_FS_WRITES.load(Ordering::Relaxed),
        CTR_NET_SEND.load(Ordering::Relaxed),
        CTR_NET_RECV.load(Ordering::Relaxed),
    )
}
