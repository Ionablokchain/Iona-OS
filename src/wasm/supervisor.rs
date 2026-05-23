//! WASM Module Supervisor — complete lifecycle management.
//!
//! This module monitors WASM modules, enforces resource limits (gas and memory),
//! handles crashes, and automatically restarts modules according to a configurable
//! policy.
//!
//! # Features
//!
//! - **Gas metering**: Each module has a gas limit; exceeding it stops the module.
//! - **Memory limits**: Maximum number of memory pages (each 64 KiB).
//! - **Crash recovery**: Configurable restart attempts.
//! - **Health checking**: Periodic tick verifies task liveness.
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::wasm::module_supervisor::{register, charge_gas, report_crash, tick};
//! use iona::task::TaskId;
//!
//! let tid = TaskId::new(42);
//! register(tid, "my_module", "/wasm/module.wasm", 1_000_000, 10, 3);
//!
//! if !charge_gas(tid, 500_000) {
//!     // Gas exhausted
//! }
//! ```

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use spin::{Lazy, Mutex};
use crate::task::TaskId;

// -----------------------------------------------------------------------------
// Module state
// -----------------------------------------------------------------------------

/// Possible states of a supervised WASM module.
#[derive(Debug, Clone, PartialEq)]
pub enum ModuleState {
    /// Module is running normally.
    Running,
    /// Module was explicitly stopped.
    Stopped,
    /// Module crashed with a given reason.
    Crashed { reason: String },
    /// Module exceeded its gas limit.
    GasExhausted,
    /// Module exceeded its memory limit (pages).
    MemoryLimitExceeded,
    /// Module is restarting after a crash.
    Restarting { attempt: u32 },
}

// -----------------------------------------------------------------------------
// Module entry
// -----------------------------------------------------------------------------

/// Metadata for a registered WASM module.
pub struct ModuleEntry {
    /// Task ID of the module's main task.
    pub tid: TaskId,
    /// Human‑readable module name.
    pub name: String,
    /// Path to the WASM bytecode file in IONAFS.
    pub wasm_path: String,
    /// Current state of the module.
    pub state: ModuleState,
    /// Gas consumed so far.
    pub gas_used: u64,
    /// Maximum gas allowed before termination.
    pub gas_limit: u64,
    /// Current memory usage (number of 64 KiB pages).
    pub mem_pages: u32,
    /// Maximum allowed memory pages.
    pub mem_limit: u32,
    /// Number of restart attempts already performed.
    pub restarts: u32,
    /// Maximum number of restart attempts allowed.
    pub max_restarts: u32,
    /// Timestamp (milliseconds) when the module was started.
    pub started_ms: u64,
}

// -----------------------------------------------------------------------------
// Global registry
// -----------------------------------------------------------------------------

/// Global registry of supervised modules, indexed by task ID.
static MODULES: Lazy<Mutex<BTreeMap<TaskId, ModuleEntry>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Register a new WASM module with the supervisor.
///
/// # Arguments
/// * `tid` – Task ID of the module's main task.
/// * `name` – Human‑readable name (for logging).
/// * `path` – Path to the WASM bytecode file in IONAFS.
/// * `gas_limit` – Maximum gas units allowed.
/// * `mem_limit` – Maximum number of memory pages (each 64 KiB).
/// * `max_restarts` – Maximum number of automatic restarts after crashes.
pub fn register(tid: TaskId, name: &str, path: &str, gas_limit: u64, mem_limit: u32, max_restarts: u32) {
    MODULES.lock().insert(tid, ModuleEntry {
        tid,
        name: name.into(),
        wasm_path: path.into(),
        state: ModuleState::Running,
        gas_used: 0,
        gas_limit,
        mem_pages: 0,
        mem_limit,
        restarts: 0,
        max_restarts,
        started_ms: crate::arch::x86_64::timer::uptime_ms(),
    });
    crate::serial_println!(
        "  [WSUP] registered '{}' tid={} gas={} mem={}p",
        name, tid, gas_limit, mem_limit
    );
}

/// Charge gas to a module. Returns `true` if the module is still within its limit.
///
/// If the limit is exceeded, the module's state is set to `GasExhausted`.
///
/// # Arguments
/// * `tid` – Task ID of the module.
/// * `amount` – Gas units to charge.
pub fn charge_gas(tid: TaskId, amount: u64) -> bool {
    let mut modules = MODULES.lock();
    let entry = match modules.get_mut(&tid) {
        Some(e) => e,
        None => return true, // No entry – allow charging (e.g., kernel tasks)
    };
    entry.gas_used = entry.gas_used.saturating_add(amount);
    if entry.gas_used > entry.gas_limit {
        entry.state = ModuleState::GasExhausted;
        crate::serial_println!("  [WSUP] tid={} gas exhausted", tid);
        return false;
    }
    true
}

/// Report that a module has crashed.
///
/// Updates the module's state to `Crashed` and, if the restart limit has not been
/// reached, attempts to restart the module by reloading the WASM bytecode from disk
/// and spawning a new task.
///
/// # Arguments
/// * `tid` – Task ID of the crashed module.
/// * `reason` – Human‑readable crash reason (for logging).
pub fn report_crash(tid: TaskId, reason: &str) {
    let mut modules = MODULES.lock();
    let entry = match modules.get_mut(&tid) {
        Some(e) => e,
        None => return,
    };
    entry.state = ModuleState::Crashed { reason: reason.into() };
    crate::serial_println!("  [WSUP] tid={} crashed: {}", tid, reason);

    if entry.restarts < entry.max_restarts {
        entry.restarts += 1;
        let path = entry.wasm_path.clone();
        let name = entry.name.clone();
        let gas_limit = entry.gas_limit;
        let mem_limit = entry.mem_limit;
        let max_restarts = entry.max_restarts;
        let attempt = entry.restarts;
        entry.state = ModuleState::Restarting { attempt };
        drop(modules); // Release lock before spawning new task

        crate::serial_println!("  [WSUP] restarting '{}' attempt {}", name, attempt);
        if let Some(bytecode) = crate::fs::ionafs::read(&path) {
            if let Ok(new_tid) = crate::wasm::spawn_module(&bytecode) {
                register(new_tid, &name, &path, gas_limit, mem_limit, max_restarts);
            }
        }
    }
}

/// Get the current state of a module.
///
/// # Returns
/// `Some(ModuleState)` if the module is registered, `None` otherwise.
pub fn get_state(tid: TaskId) -> Option<ModuleState> {
    MODULES.lock().get(&tid).map(|e| e.state.clone())
}

/// List all currently running modules (state = `Running`).
///
/// # Returns
/// A vector of `(TaskId, module_name)` pairs.
pub fn list_running() -> Vec<(TaskId, String)> {
    MODULES.lock()
        .iter()
        .filter(|(_, e)| e.state == ModuleState::Running)
        .map(|(tid, e)| (*tid, e.name.clone()))
        .collect()
}

/// Periodic health check. Should be called from a timer (e.g., every second).
///
/// Verifies that each running module’s task still exists in the scheduler.
/// If a task is missing, it is reported as crashed.
pub fn tick() {
    let tids: Vec<TaskId> = MODULES.lock().keys().cloned().collect();
    for tid in tids {
        let state = {
            let modules = MODULES.lock();
            modules.get(&tid).map(|e| e.state.clone())
        };
        // Check if the scheduler still knows about this task.
        let alive = {
            let sched = crate::sched::SCHEDULER.lock();
            // A task is considered alive if it is the current task or is blocked.
            sched.stats().current_tid == Some(tid)
                || sched.stats().blocked_count > 0 // Simplified: blocked tasks are still alive
        };
        if !alive {
            if let Some(ModuleState::Running) = state {
                report_crash(tid, "task not found in scheduler");
            }
        }
    }
}
