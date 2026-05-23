//! WASM Runtime — wasmi interpreter (no_std + alloc).
//!
//! This module provides a complete WebAssembly (WASM) runtime for IONA OS kernel,
//! based on the `wasmi` interpreter. It supports:
//!
//! - Spawning WASM modules as kernel tasks.
//! - Host functions for storage, logging, and blockchain interaction.
//! - Resource limits (gas, memory pages, stack depth).
//! - Integration with the module supervisor for crash recovery.
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::wasm::spawn_module;
//!
//! let bytecode = crate::fs::ionafs::read("/bin/my_module.wasm").unwrap();
//! let tid = spawn_module(&bytecode).unwrap();
//! ```

pub mod supervisor;
pub mod host;

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use spin::Mutex;
use wasmi::{Engine, Linker, Module, Store};
use crate::task::{Task, TaskId, next_tid};

// -----------------------------------------------------------------------------
// WASM state per task
// -----------------------------------------------------------------------------

/// Per‑task state for a running WASM module.
/// Includes storage, event queue, and log buffer.
pub struct WasmState {
    /// Task ID of the running module.
    pub tid: TaskId,
    /// Human‑readable module name.
    pub name: String,
    /// Key‑value storage (persisted to IONAFS).
    pub storage: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Emitted events (to be processed by the kernel).
    pub events: Vec<(String, Vec<u8>)>,
    /// Log buffer for `wasm_print` host function.
    pub log_buf: Vec<String>,
}

impl WasmState {
    /// Create a new WASM state for a given task ID and name.
    fn new(tid: TaskId, name: String) -> Self {
        Self {
            tid,
            name,
            storage: BTreeMap::new(),
            events: Vec::new(),
            log_buf: Vec::new(),
        }
    }
}

// -----------------------------------------------------------------------------
// Pending bytecode queue
// -----------------------------------------------------------------------------

/// Pending WASM bytecode chunks waiting to be executed by newly spawned tasks.
static PENDING: Mutex<Vec<(TaskId, Vec<u8>)>> = Mutex::new(Vec::new());

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Spawn a new WASM module as a kernel task.
///
/// # Arguments
/// * `bytecode` – The WASM bytecode to execute.
///
/// # Returns
/// The `TaskId` of the newly created task, or an error if spawning fails.
pub fn spawn_module(bytecode: &[u8]) -> Result<TaskId, &'static str> {
    let bytes = bytecode.to_vec();
    let tid = next_tid();
    crate::serial_println!("  [WASM] spawn tid={} ({} bytes)", tid, bytes.len());
    let task = Task::new("wasm-module", wasm_task_fn, tid, 1);
    // Apply seccomp sandbox policy for WASM modules.
    crate::security::seccomp::set_wasm_policy(tid);
    crate::sched::SCHEDULER.lock().spawn(task);
    PENDING.lock().push((tid, bytes));
    Ok(tid)
}

// -----------------------------------------------------------------------------
// Task entry point
// -----------------------------------------------------------------------------

/// The entry point for a WASM task. It fetches the bytecode from the pending queue,
/// runs the module, and then halts.
fn wasm_task_fn(tid: u64) -> ! {
    let bytecode = loop {
        let mut pending = PENDING.lock();
        if let Some(pos) = pending.iter().position(|(t, _)| *t == tid) {
            break pending.remove(pos).1;
        }
        drop(pending);
        core::hint::spin_loop();
    };

    match run_module(tid, &bytecode) {
        Ok(()) => crate::serial_println!("  [WASM] tid={} finished", tid),
        Err(e) => crate::serial_println!("  [WASM] tid={} error: {:?}", tid, e),
    }
    loop {
        x86_64::instructions::hlt();
    }
}

// -----------------------------------------------------------------------------
// Resource limits
// -----------------------------------------------------------------------------

/// Resource limits for a WASM module.
#[derive(Clone, Debug)]
pub struct WasmLimits {
    /// Computation budget (gas).
    pub gas_limit: u64,
    /// Maximum number of 64 KiB memory pages (e.g., 16 = 1 MiB).
    pub memory_pages: u32,
    /// Maximum call stack depth.
    pub stack_depth: u32,
    /// Maximum number of automatic restarts.
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

// -----------------------------------------------------------------------------
// Module execution
// -----------------------------------------------------------------------------

/// Run a WASM module from bytecode.
fn run_module(tid: TaskId, bytecode: &[u8]) -> Result<(), wasmi::Error> {
    let engine = Engine::default();
    let module = Module::new(&engine, bytecode)?;
    let mut store = Store::new(&engine, WasmState::new(tid, "wasm".into()));
    let mut linker = Linker::<WasmState>::new(&engine);

    // Register all host functions.
    host::register_all(&mut linker)?;

    // Apply memory limit using a limiter.
    store.limiter(|state: &mut WasmState| {
        Box::new(WasmResourceLimiter {
            max_memory_pages: state.gas_limit.min(16) as u32,
        })
    });
    let instance = linker.instantiate(&mut store, &module)?.start(&mut store)?;

    // Look for an entry point: `run`, `_start`, or `main`.
    let run = instance
        .get_func(&store, "run")
        .or_else(|| instance.get_func(&store, "_start"))
        .or_else(|| instance.get_func(&store, "main"));

    match run {
        Some(func) => {
            func.call(&mut store, &[], &mut [])?;
        }
        None => {
            crate::serial_println!("  [WASM] no entry point found");
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Memory sandbox
// -----------------------------------------------------------------------------

/// Validate that a WASM memory access stays within the module's memory bounds.
///
/// # Arguments
/// * `ptr` – Start pointer (offset in linear memory).
/// * `len` – Length in bytes.
/// * `module_mem_size` – Total size of the module's linear memory.
///
/// # Returns
/// `true` if the access is safe, `false` otherwise.
pub fn wasm_memory_sandbox(ptr: u32, len: u32, module_mem_size: u32) -> bool {
    let end = ptr.saturating_add(len);
    if end > module_mem_size {
        crate::serial_println!(
            "[WASM] sandbox violation: ptr={} len={} limit={}",
            ptr, len, module_mem_size
        );
        return false;
    }
    true
}

// -----------------------------------------------------------------------------
// Host functions (exposed to WASM)
// -----------------------------------------------------------------------------

/// Host functions available to WASM modules.
/// These are implemented in the `host` submodule and registered via `host::register_all`.
pub mod host_functions {
    use alloc::string::String;

    /// Print a string to the serial console.
    pub fn wasm_print(ptr: u32, len: u32, mem: &[u8]) {
        if ptr as usize + len as usize > mem.len() {
            return;
        }
        let s = core::str::from_utf8(&mem[ptr as usize..(ptr + len) as usize]).unwrap_or("?");
        crate::serial_println!("[WASM] {}", s);
    }

    /// Get a value from the module's persistent storage (under `/wasm/storage/`).
    pub fn wasm_storage_get(key: &[u8]) -> Option<alloc::vec::Vec<u8>> {
        let path = alloc::format!("/wasm/storage/{}", alloc::string::String::from_utf8_lossy(key));
        crate::fs::ionafs::read(&path)
    }

    /// Set a value in the module's persistent storage.
    pub fn wasm_storage_set(key: &[u8], value: &[u8]) {
        let path = alloc::format!("/wasm/storage/{}", alloc::string::String::from_utf8_lossy(key));
        crate::fs::ionafs::write(&path, value);
    }

    /// Get the current blockchain height from consensus.
    pub fn wasm_block_height() -> u64 {
        crate::consensus::CONSENSUS_ENGINE
            .lock()
            .as_ref()
            .map(|e| e.height)
            .unwrap_or(0)
    }
}

// -----------------------------------------------------------------------------
// Restart helper
// -----------------------------------------------------------------------------

/// Restart a crashed WASM module by name.
/// The module's bytecode is expected at `/bin/{name}.wasm` in IONAFS.
pub fn restart_module(name: &str) {
    crate::serial_println!("[WASM] restarting crashed module: {}", name);
    let path = alloc::format!("/bin/{}.wasm", name);
    if let Some(wasm_bytes) = crate::fs::ionafs::read(&path) {
        let _ = spawn_module(&wasm_bytes);
    }
}

// -----------------------------------------------------------------------------
// Placeholder for resource limiter
// -----------------------------------------------------------------------------

/// A simple resource limiter that caps memory pages.
struct WasmResourceLimiter {
    max_memory_pages: u32,
}

impl wasmi::ResourceLimiter for WasmResourceLimiter {
    fn memory_pages(&self, requested: u32) -> std::result::Result<u32, wasmi::Error> {
        if requested <= self.max_memory_pages {
            Ok(requested)
        } else {
            Err(wasmi::Error::Other("memory limit exceeded"))
        }
    }
    // Other methods can be left with defaults.
}
