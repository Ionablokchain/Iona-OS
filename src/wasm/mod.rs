//! WASM Runtime — wasmi interpreter (`no_std` + `alloc`).
//!
//! Provides a WebAssembly runtime for the IONA OS kernel, based on the
//! `wasmi` interpreter. Features:
//!
//! - Spawning WASM modules as kernel tasks.
//! - A curated set of host functions (see [`host`]).
//! - Resource limits: gas, memory pages, entry-point call nesting, restarts.
//! - Integration with the module supervisor for crash recovery.
//!
//! # Security model
//!
//! A module is **untrusted code**. The runtime enforces:
//!
//! 1. **Bounded memory** — linear memory growth is capped by
//!    [`WasmLimits::memory_pages`] via a [`wasmi::ResourceLimiter`].
//! 2. **Bounded gas** — execution is metered by wasmi's fuel mechanism; a
//!    module that exhausts its budget is terminated.
//! 3. **Bounded spawn queue** — at most [`MAX_PENDING_MODULES`] spawn
//!    requests may be queued at once. Additional `spawn_module` calls fail
//!    with [`SpawnError::QueueFull`].
//! 4. **Sandboxed host functions** — see [`host`] for the pointer and path
//!    validation applied at each entry point.
//!
//! # Restart policy
//!
//! [`WasmLimits::max_restarts`] is the maximum number of times the
//! supervisor ([`supervisor`]) will restart a given module within
//! [`supervisor::RESTART_WINDOW_MS`]. The runtime itself does **not**
//! restart; recovery is the supervisor's responsibility.
//!
//! # Architecture
//!
//! The runtime core is architecture-neutral. Only the idle fallback in
//! [`wasm_task_fn`] uses a per-arch primitive, dispatched through
//! [`crate::arch::cpu_halt`].
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::wasm::spawn_module;
//!
//! let bytecode = crate::fs::ionafs::read("/bin/my_module.wasm")
//!     .ok_or("module not found")?;
//! let tid = spawn_module(&bytecode)?;
//! ```

pub mod host;
pub mod supervisor;

use alloc::{
    collections::BTreeMap,
    format,
    string::String,
    string::ToString,
    vec::Vec,
};
use core::fmt;
use spin::Mutex;

use wasmi::{Engine, Linker, Module, Store};

use crate::task::{next_tid, TaskId};

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum number of spawn requests queued at once.
pub const MAX_PENDING_MODULES: usize = 64;

/// Maximum size of a module's bytecode, in bytes (8 MiB).
pub const MAX_MODULE_BYTES: usize = 8 * 1024 * 1024;

/// Maximum number of memory pages a module may allocate (256 pages = 16 MiB).
pub const MAX_MEMORY_PAGES: u32 = 256;

/// Maximum gas budget any single module may be given.
pub const MAX_GAS_LIMIT: u64 = 10_000_000_000;

/// Per-task key-value budget for [`WasmState::storage`] (1 MiB total).
pub const MAX_STORAGE_BYTES: usize = 1024 * 1024;

/// Per-task event queue cap (4096 entries).
pub const MAX_EVENTS: usize = 4096;

/// Per-task log buffer cap (1024 lines).
pub const MAX_LOG_LINES: usize = 1024;

/// Entry-point names tried, in priority order.
pub const ENTRY_POINTS: &[&str] = &["run", "_start", "main"];

/// Prefix used by [`restart_module`] when looking up a module's bytecode.
pub const MODULE_BIN_DIR: &str = "/bin";

// ── Errors ────────────────────────────────────────────────────────────────

/// Why a module could not be spawned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnError {
    /// The bytecode exceeds [`MAX_MODULE_BYTES`].
    ModuleTooLarge { size: usize, max: usize },
    /// The spawn queue is at [`MAX_PENDING_MODULES`].
    QueueFull,
    /// The module failed to compile.
    Compile(String),
}

impl fmt::Display for SpawnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModuleTooLarge { size, max } => {
                write!(f, "module too large: {size} > {max}")
            }
            Self::QueueFull => write!(f, "spawn queue is full"),
            Self::Compile(msg) => write!(f, "compile error: {msg}"),
        }
    }
}

/// Why module execution failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunError {
    /// Compilation failed.
    Compile(String),
    /// Instantiation failed.
    Instantiate(String),
    /// No entry point was found.
    NoEntryPoint,
    /// The entry point trapped.
    Trap(String),
    /// The module's gas budget was exhausted.
    OutOfGas,
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compile(m) => write!(f, "compile error: {m}"),
            Self::Instantiate(m) => write!(f, "instantiate error: {m}"),
            Self::NoEntryPoint => write!(f, "no entry point"),
            Self::Trap(m) => write!(f, "trap: {m}"),
            Self::OutOfGas => write!(f, "out of gas"),
        }
    }
}

// ── Per-task state ───────────────────────────────────────────────────────

/// Per-task state for a running WASM module.
pub struct WasmState {
    /// Task ID of the running module.
    pub tid: TaskId,
    /// Human-readable module name.
    pub name: String,
    /// Key-value storage. Persistence to IONAFS is the caller's
    /// responsibility — see [`persist_storage`].
    pub storage: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Total bytes currently held in `storage` (bounded by
    /// [`MAX_STORAGE_BYTES`]).
    storage_bytes: usize,
    /// Emitted events (bounded by [`MAX_EVENTS`]).
    pub events: Vec<(String, Vec<u8>)>,
    /// Log buffer (bounded by [`MAX_LOG_LINES`]).
    pub log_buf: Vec<String>,
    /// Remaining gas budget (decremented by wasmi's fuel accounting).
    pub remaining_gas: u64,
}

impl WasmState {
    /// Create a new state for a task.
    #[must_use]
    pub fn new(tid: TaskId, name: String, gas_limit: u64) -> Self {
        Self {
            tid,
            name,
            storage: BTreeMap::new(),
            storage_bytes: 0,
            events: Vec::new(),
            log_buf: Vec::new(),
            remaining_gas: gas_limit,
        }
    }

    /// Insert into the storage map, enforcing [`MAX_STORAGE_BYTES`].
    ///
    /// Returns `Err` if the insert would exceed the budget. On error, the
    /// map is left untouched.
    pub fn storage_insert(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), &'static str> {
        let new_total = self
            .storage_bytes
            .saturating_sub(self.storage.get(&key).map_or(0, |v| v.len()))
            .saturating_add(value.len());
        if new_total > MAX_STORAGE_BYTES {
            return Err("storage budget exceeded");
        }
        self.storage_bytes = new_total;
        self.storage.insert(key, value);
        Ok(())
    }

    /// Push an event, enforcing [`MAX_EVENTS`]. Silently drops on overflow.
    pub fn push_event(&mut self, topic: String, payload: Vec<u8>) {
        if self.events.len() < MAX_EVENTS {
            self.events.push((topic, payload));
        }
    }

    /// Push a log line, enforcing [`MAX_LOG_LINES`]. Silently drops on
    /// overflow.
    pub fn push_log(&mut self, msg: String) {
        if self.log_buf.len() < MAX_LOG_LINES {
            self.log_buf.push(msg);
        }
    }
}

/// Serialize a module's storage to IONAFS under
/// `/wasm/<tid>/storage.dat`.
///
/// Format (little-endian, length-prefixed):
/// ```text
/// u32 entry_count
/// for each entry:
///     u32 key_len   <key bytes>
///     u32 value_len <value bytes>
/// ```
pub fn persist_storage(state: &WasmState) {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&(state.storage.len() as u32).to_le_bytes());
    for (k, v) in &state.storage {
        buf.extend_from_slice(&(k.len() as u32).to_le_bytes());
        buf.extend_from_slice(k);
        buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
        buf.extend_from_slice(v);
    }
    let path = format!("/wasm/{}/storage.dat", state.tid);
    if let Err(e) = crate::fs::ionafs::write(&path, &buf) {
        crate::serial_println!("[WASM:{}] storage persist failed: {e}", state.tid);
    }
}

// ── Resource limits ───────────────────────────────────────────────────────

/// Resource limits for a WASM module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmLimits {
    /// Computation budget (fuel units).
    pub gas_limit: u64,
    /// Maximum number of 64 KiB memory pages.
    pub memory_pages: u32,
    /// Maximum call stack depth (advisory; enforced by wasmi's stack
    /// limiter when compiled in).
    pub stack_depth: u32,
    /// Maximum number of automatic restarts (enforced by the supervisor).
    pub max_restarts: u32,
}

impl Default for WasmLimits {
    fn default() -> Self {
        Self {
            gas_limit: 10_000_000,
            memory_pages: 16,
            stack_depth: 512,
            max_restarts: 3,
        }
    }
}

impl WasmLimits {
    /// Validate the limits against the compile-time maxima.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.gas_limit == 0 {
            return Err("gas_limit must be > 0");
        }
        if self.gas_limit > MAX_GAS_LIMIT {
            return Err("gas_limit exceeds MAX_GAS_LIMIT");
        }
        if self.memory_pages == 0 {
            return Err("memory_pages must be > 0");
        }
        if self.memory_pages > MAX_MEMORY_PAGES {
            return Err("memory_pages exceeds MAX_MEMORY_PAGES");
        }
        if self.stack_depth == 0 {
            return Err("stack_depth must be > 0");
        }
        Ok(())
    }
}

// ── Spawn queue ───────────────────────────────────────────────────────────

/// Pending bytecode waiting for a task to pick it up.
static PENDING: Mutex<Vec<(TaskId, Vec<u8>)>> = Mutex::new(Vec::new());

// ── Spawn ─────────────────────────────────────────────────────────────────

/// Spawn a WASM module as a kernel task.
///
/// The module is **not** compiled here — that happens on the new task, so
/// a slow or malicious compiler workload cannot delay the caller. The
/// bytecode is queued and picked up by [`wasm_task_fn`].
///
/// # Errors
///
/// - [`SpawnError::ModuleTooLarge`] — bytecode exceeds [`MAX_MODULE_BYTES`].
/// - [`SpawnError::QueueFull`] — the spawn queue is at
///   [`MAX_PENDING_MODULES`].
pub fn spawn_module(bytecode: &[u8]) -> Result<TaskId, SpawnError> {
    if bytecode.len() > MAX_MODULE_BYTES {
        return Err(SpawnError::ModuleTooLarge {
            size: bytecode.len(),
            max: MAX_MODULE_BYTES,
        });
    }

    let tid = next_tid();
    let bytes = bytecode.to_vec();

    {
        let mut q = PENDING.lock();
        if q.len() >= MAX_PENDING_MODULES {
            return Err(SpawnError::QueueFull);
        }
        q.push((tid, bytes));
    }

    crate::serial_println!(
        "  [WASM] spawn tid={tid} ({} bytes)",
        bytecode.len()
    );

    // `Task::new` requires an `extern "C" fn(u64) -> !`. `wasm_task_fn`
    // is declared accordingly below.
    let task = crate::task::Task::new("wasm-module", wasm_task_fn, tid, 1);

    // Sandbox the task before it runs.
    crate::security::seccomp::set_wasm_policy(tid);

    crate::sched::SCHEDULER.lock().spawn(task);
    Ok(tid)
}

// ── Task entry point ──────────────────────────────────────────────────────

/// Task entry: fetch the bytecode from the queue and run it.
///
/// # Safety
///
/// Called by the scheduler with `tid` matching a queued entry; the queue
/// entry is removed exactly once.
extern "C" fn wasm_task_fn(tid: u64) -> ! {
    // Take the queued bytecode. If nothing matches, exit cleanly — this
    // can happen if the task was scheduled after a `spawn_module` failure
    // that was later rolled back.
    let bytecode = {
        let mut q = PENDING.lock();
        match q.iter().position(|(t, _)| *t == tid) {
            Some(pos) => q.remove(pos).1,
            None => {
                crate::serial_println!(
                    "  [WASM] tid={tid} scheduled without bytecode; exiting"
                );
                crate::arch::cpu_halt();
            }
        }
    };

    let limits = WasmLimits::default();
    match run_module(tid, &bytecode, &limits) {
        Ok(()) => crate::serial_println!("  [WASM] tid={tid} finished"),
        Err(e) => crate::serial_println!("  [WASM] tid={tid} error: {e}"),
    }

    // Idle until the scheduler tears us down.
    loop {
        crate::arch::cpu_halt();
    }
}

// ── Execution ─────────────────────────────────────────────────────────────

/// Compile and run `bytecode` under `limits`.
pub fn run_module(
    tid: TaskId,
    bytecode: &[u8],
    limits: &WasmLimits,
) -> Result<(), RunError> {
    limits.validate().map_err(RunError::Compile)?;

    let mut config = wasmi::Config::default();
    config.consume_fuel(true);
    config.wasm_mutable_global(true);
    config.wasm_sign_extension(true);
    config.wasm_multi_value(false);

    let engine = Engine::new(&config);
    let module = Module::new(&engine, bytecode).map_err(|e| RunError::Compile(e.to_string()))?;

    let state = WasmState::new(tid, "wasm".to_string(), limits.gas_limit);
    let mut store = Store::new(&engine, state);

    // Enable fuel accounting.
    store
        .add_fuel(limits.gas_limit)
        .map_err(|e| RunError::Instantiate(e.to_string()))?;

    // Bounded linear memory.
    store.limiter(|_state: &mut WasmState| WasmResourceLimiter {
        max_memory_pages: limits.memory_pages,
    });

    let mut linker = Linker::<WasmState>::new(&engine);
    host::register_all(&mut linker).map_err(|e| RunError::Instantiate(e.to_string()))?;

    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| RunError::Instantiate(e.to_string()))?
        .start(&mut store)
        .map_err(|e| RunError::Instantiate(e.to_string()))?;

    // Look for the first matching entry point.
    let entry = ENTRY_POINTS
        .iter()
        .find_map(|name| instance.get_func(&store, name));
    let Some(func) = entry else {
        return Err(RunError::NoEntryPoint);
    };

    let mut results = [wasmi::Value::I32(0); 0];
    func.call(&mut store, &[], &mut results).map_err(|e| {
        let msg = e.to_string();
        if msg.contains("fuel") {
            RunError::OutOfGas
        } else {
            RunError::Trap(msg)
        }
    })?;

    // Persist storage on clean exit.
    let state = store.data();
    persist_storage(state);

    Ok(())
}

// ── Memory sandbox helper ─────────────────────────────────────────────────

/// Check that `[ptr, ptr + len)` lies entirely within `[0, mem_size)`.
///
/// Returns `true` on success and logs a diagnostic on failure. Uses
/// `checked_add` so an overflowing `ptr + len` cannot silently wrap past
/// the bound.
#[must_use]
pub fn wasm_memory_sandbox(ptr: u32, len: u32, mem_size: u32) -> bool {
    match ptr.checked_add(len) {
        Some(end) if end <= mem_size => true,
        Some(end) => {
            crate::serial_println!(
                "[WASM] sandbox violation: ptr={ptr} len={len} end={end} limit={mem_size}"
            );
            false
        }
        None => {
            crate::serial_println!(
                "[WASM] sandbox overflow: ptr={ptr} len={len} limit={mem_size}"
            );
            false
        }
    }
}

// ── Restart ───────────────────────────────────────────────────────────────

/// Restart a crashed module by name.
///
/// The bytecode is expected at `{MODULE_BIN_DIR}/{name}.wasm` in IONAFS.
/// A missing module logs and returns `None`; the supervisor decides
/// whether to give up based on [`WasmLimits::max_restarts`].
#[must_use]
pub fn restart_module(name: &str) -> Option<TaskId> {
    if name.is_empty() || name.contains('/') || name.contains('\0') {
        crate::serial_println!("[WASM] restart: invalid module name {name:?}");
        return None;
    }

    let path = format!("{MODULE_BIN_DIR}/{name}.wasm");
    let bytes = match crate::fs::ionafs::read(&path) {
        Some(b) => b,
        None => {
            crate::serial_println!("[WASM] restart: {path} not found");
            return None;
        }
    };

    crate::serial_println!("[WASM] restarting {name} ({} bytes)", bytes.len());
    match spawn_module(&bytes) {
        Ok(tid) => Some(tid),
        Err(e) => {
            crate::serial_println!("[WASM] restart failed: {e}");
            None
        }
    }
}

// ── Resource limiter ──────────────────────────────────────────────────────

/// Caps a module's linear memory at a fixed number of pages.
struct WasmResourceLimiter {
    max_memory_pages: u32,
}

impl wasmi::ResourceLimiter for WasmResourceLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> Result<bool, wasmi::Error> {
        let page_size = 64 * 1024;
        let desired_pages = desired.div_ceil(page_size) as u64;
        Ok(desired_pages <= self.max_memory_pages as u64)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        _desired: usize,
        _maximum: Option<usize>,
    ) -> Result<bool, wasmi::Error> {
        // Tables are small; no additional cap.
        Ok(true)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_accepts_window_inside_memory() {
        assert!(wasm_memory_sandbox(0, 0, 100));
        assert!(wasm_memory_sandbox(0, 100, 100));
        assert!(wasm_memory_sandbox(50, 50, 100));
    }

    #[test]
    fn sandbox_rejects_out_of_bounds() {
        assert!(!wasm_memory_sandbox(0, 101, 100));
        assert!(!wasm_memory_sandbox(100, 1, 100));
    }

    #[test]
    fn sandbox_rejects_overflow() {
        // ptr + len wraps past u32::MAX.
        assert!(!wasm_memory_sandbox(u32::MAX, 1, u32::MAX));
        assert!(!wasm_memory_sandbox(u32::MAX - 1, 3, u32::MAX));
    }

    #[test]
    fn limits_default_validates() {
        assert!(WasmLimits::default().validate().is_ok());
    }

    #[test]
    fn limits_rejects_out_of_range() {
        let bad = WasmLimits {
            gas_limit: 0,
            ..Default::default()
        };
        assert!(bad.validate().is_err());

        let bad = WasmLimits {
            gas_limit: MAX_GAS_LIMIT + 1,
            ..Default::default()
        };
        assert!(bad.validate().is_err());

        let bad = WasmLimits {
            memory_pages: MAX_MEMORY_PAGES + 1,
            ..Default::default()
        };
        assert!(bad.validate().is_err());

        let bad = WasmLimits {
            stack_depth: 0,
            ..Default::default()
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn storage_insert_enforces_budget() {
        let mut s = WasmState::new(0, "t".to_string(), 0);
        // A huge value is rejected.
        let huge = alloc::vec![0u8; MAX_STORAGE_BYTES + 1];
        assert!(s.storage_insert(b"k".to_vec(), huge).is_err());
        // A small value is accepted.
        assert!(s.storage_insert(b"k".to_vec(), b"v".to_vec()).is_ok());
    }

    #[test]
    fn storage_insert_replaces_count_correctly() {
        let mut s = WasmState::new(0, "t".to_string(), 0);
        s.storage_insert(b"k".to_vec(), alloc::vec![0u8; 100]).unwrap();
        s.storage_insert(b"k".to_vec(), alloc::vec![0u8; 50]).unwrap();
        assert_eq!(s.storage_bytes, 50);
    }

    #[test]
    fn event_queue_is_bounded() {
        let mut s = WasmState::new(0, "t".to_string(), 0);
        for i in 0..(MAX_EVENTS + 10) {
            s.push_event(alloc::format!("t{i}"), alloc::vec![]);
        }
        assert_eq!(s.events.len(), MAX_EVENTS);
    }

    #[test]
    fn log_buffer_is_bounded() {
        let mut s = WasmState::new(0, "t".to_string(), 0);
        for i in 0..(MAX_LOG_LINES + 10) {
            s.push_log(alloc::format!("line {i}"));
        }
        assert_eq!(s.log_buf.len(), MAX_LOG_LINES);
    }

    #[test]
    fn restart_rejects_bad_names() {
        assert!(restart_module("").is_none());
        assert!(restart_module("../etc/passwd").is_none());
        assert!(restart_module("foo/bar").is_none());
        assert!(restart_module("foo\0bar").is_none());
    }
}
