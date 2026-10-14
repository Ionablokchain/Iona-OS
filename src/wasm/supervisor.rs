//! WASM Module Supervisor — complete lifecycle management.
//!
//! Monitors WASM modules, tracks resource consumption (gas, memory pages),
//! records crashes, and restarts modules under a bounded policy.
//!
//! # Model
//!
//! Each supervised module is identified by a **name**, not by a task ID.
//! A single module may be restarted many times; each incarnation runs in a
//! fresh task with a fresh `TaskId`, but the module's restart counter and
//! history are keyed by name and survive the transition.
//!
//! ```text
//!   register(name, path, limits) ─► ModuleEntry { tid, state: Running }
//!              ▲                                │
//!              │                      charge_gas │ report_crash
//!              │                                ▼
//!              │                     state: GasExhausted | Crashed
//!              │                                │
//!              └────── restart (bounded) ───────┘
//! ```
//!
//! # Resource tracking
//!
//! - **Gas**: [`charge_gas`] increments a per-incarnation counter. Once
//!   `gas_used > gas_limit`, the state flips to
//!   [`ModuleState::GasExhausted`] and the function returns `false`.
//! - **Memory**: [`set_memory_pages`] is called by the runtime after a
//!   successful linear-memory growth. If the new page count exceeds
//!   `mem_limit`, the state flips to
//!   [`ModuleState::MemoryLimitExceeded`]. The supervisor does **not**
//!   itself shrink memory; enforcement is at the runtime boundary.
//!
//! # Restart policy
//!
//! A restart is admitted only if **all** of the following hold:
//!
//! 1. `entry.restarts < entry.max_restarts`.
//! 2. The previous restart (if any) was at least
//!    [`MIN_RESTART_INTERVAL_MS`] ago. This bounds crash loops.
//! 3. Reading the bytecode from IONAFS succeeds.
//! 4. `wasm::spawn_module` succeeds.
//!
//! If any step fails, the module's state becomes
//! [`ModuleState::RestartFailed`] with the reason, and no further restarts
//! are attempted automatically.
//!
//! # Concurrency
//!
//! [`MODULES`] is a single global [`spin::Mutex`]. Locks are held only for
//! map lookups; nothing in this module calls out to the scheduler, IONAFS,
//! or the runtime while holding the lock.
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::wasm::supervisor::{self, ModuleLimits};
//!
//! let tid = supervisor::register(
//!     "my_module",
//!     "/bin/my_module.wasm",
//!     ModuleLimits { gas_limit: 1_000_000, mem_pages: 16, max_restarts: 3 },
//!     /* current_tid = */ 42,
//! )?;
//!
//! if !supervisor::charge_gas("my_module", 500_000) {
//!     // Gas exhausted; the module was marked for termination.
//! }
//! ```

use alloc::{collections::BTreeMap, string::String, string::ToString, vec::Vec};
use core::fmt;

use spin::{Lazy, Mutex};

use crate::task::TaskId;

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum number of modules the supervisor will track at once.
pub const MAX_SUPERVISED_MODULES: usize = 1024;

/// Minimum time between two restart attempts of the same module.
pub const MIN_RESTART_INTERVAL_MS: u64 = 1_000;

/// Maximum length of a module name, in bytes.
pub const MAX_MODULE_NAME_BYTES: usize = 128;

/// Maximum number of memory pages any module may request (16 MiB).
pub const MAX_MEMORY_PAGES: u32 = 256;

// ── Limits & state ────────────────────────────────────────────────────────

/// Resource limits and restart policy for a module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleLimits {
    /// Maximum gas units before the module is stopped.
    pub gas_limit: u64,
    /// Maximum number of 64 KiB memory pages.
    pub mem_pages: u32,
    /// Maximum number of automatic restarts.
    pub max_restarts: u32,
}

impl ModuleLimits {
    /// Validate the limits against the compile-time maxima.
    pub fn validate(&self) -> Result<(), SupervisorError> {
        if self.gas_limit == 0 {
            return Err(SupervisorError::InvalidLimits("gas_limit must be > 0"));
        }
        if self.mem_pages == 0 {
            return Err(SupervisorError::InvalidLimits("mem_pages must be > 0"));
        }
        if self.mem_pages > MAX_MEMORY_PAGES {
            return Err(SupervisorError::InvalidLimits(
                "mem_pages exceeds MAX_MEMORY_PAGES",
            ));
        }
        Ok(())
    }
}

/// Possible states of a supervised module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleState {
    /// Module is running normally.
    Running,
    /// Module was explicitly stopped by the operator.
    Stopped { reason: String },
    /// Module crashed with a given reason.
    Crashed { reason: String },
    /// Module exceeded its gas limit.
    GasExhausted,
    /// Module exceeded its memory limit.
    MemoryLimitExceeded { pages: u32, limit: u32 },
    /// A restart is in progress (transient).
    Restarting { attempt: u32 },
    /// A restart was attempted and failed.
    RestartFailed { attempt: u32, reason: String },
}

impl fmt::Display for ModuleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Running => f.write_str("running"),
            Self::Stopped { reason } => write!(f, "stopped ({reason})"),
            Self::Crashed { reason } => write!(f, "crashed ({reason})"),
            Self::GasExhausted => f.write_str("gas exhausted"),
            Self::MemoryLimitExceeded { pages, limit } => {
                write!(f, "memory limit exceeded ({pages}/{limit} pages)")
            }
            Self::Restarting { attempt } => write!(f, "restarting (attempt {attempt})"),
            Self::RestartFailed { attempt, reason } => {
                write!(f, "restart failed (attempt {attempt}: {reason})")
            }
        }
    }
}

impl ModuleState {
    /// Whether the state represents a live, active module.
    #[must_use]
    pub fn is_live(&self) -> bool {
        matches!(self, Self::Running | Self::Restarting { .. })
    }

    /// Whether the state is terminal (no further restarts).
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Stopped { .. }
                | Self::Crashed { .. }
                | Self::GasExhausted
                | Self::MemoryLimitExceeded { .. }
                | Self::RestartFailed { .. }
        )
    }
}

// ── Errors ────────────────────────────────────────────────────────────────

/// Errors returned by supervisor operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisorError {
    /// Invalid limits (see [`ModuleLimits::validate`]).
    InvalidLimits(&'static str),
    /// A module with this name is already registered.
    AlreadyRegistered,
    /// A module with this name is not registered.
    NotRegistered,
    /// The name is empty or contains a forbidden character (`/`, NUL).
    InvalidName,
    /// The supervisor is tracking [`MAX_SUPERVISED_MODULES`] modules.
    RegistryFull,
    /// The module is in a terminal state; the operation is not applicable.
    TerminalState(ModuleState),
}

impl fmt::Display for SupervisorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits(s) => write!(f, "invalid limits: {s}"),
            Self::AlreadyRegistered => f.write_str("module already registered"),
            Self::NotRegistered => f.write_str("module not registered"),
            Self::InvalidName => f.write_str("invalid module name"),
            Self::RegistryFull => f.write_str("supervisor registry is full"),
            Self::TerminalState(s) => write!(f, "module in terminal state: {s}"),
        }
    }
}

// ── Entry ─────────────────────────────────────────────────────────────────

/// Metadata for a supervised WASM module.
///
/// One entry per **module name**. The `tid` is updated on restart.
#[derive(Debug, Clone)]
pub struct ModuleEntry {
    /// Task ID of the current incarnation.
    pub tid: TaskId,
    /// Human-readable module name (the map key).
    pub name: String,
    /// Path to the WASM bytecode in IONAFS.
    pub wasm_path: String,
    /// Current lifecycle state.
    pub state: ModuleState,
    /// Gas consumed by the **current** incarnation.
    pub gas_used: u64,
    /// Maximum gas allowed per incarnation.
    pub gas_limit: u64,
    /// Current memory usage (64 KiB pages).
    pub mem_pages: u32,
    /// Maximum allowed memory pages.
    pub mem_limit: u32,
    /// Number of restarts already performed (across incarnations).
    pub restarts: u32,
    /// Maximum restarts allowed.
    pub max_restarts: u32,
    /// Timestamp of the current incarnation's start (ms since boot).
    pub started_ms: u64,
    /// Timestamp of the last restart attempt (ms since boot). `0` if none.
    pub last_restart_ms: u64,
}

impl ModuleEntry {
    /// Whether the module is eligible for a restart right now.
    fn restart_eligible(&self, now_ms: u64) -> Result<u32, SupervisorError> {
        if self.restarts >= self.max_restarts {
            return Err(SupervisorError::TerminalState(self.state.clone()));
        }
        if self.last_restart_ms != 0
            && now_ms.saturating_sub(self.last_restart_ms) < MIN_RESTART_INTERVAL_MS
        {
            return Err(SupervisorError::TerminalState(
                ModuleState::RestartFailed {
                    attempt: self.restarts,
                    reason: "restart interval not elapsed".to_string(),
                },
            ));
        }
        Ok(self.restarts + 1)
    }
}

// ── Registry ──────────────────────────────────────────────────────────────

/// Global registry, keyed by module name.
static MODULES: Lazy<Mutex<BTreeMap<String, ModuleEntry>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

// ── Helpers ───────────────────────────────────────────────────────────────

fn validate_name(name: &str) -> Result<(), SupervisorError> {
    if name.is_empty() || name.len() > MAX_MODULE_NAME_BYTES {
        return Err(SupervisorError::InvalidName);
    }
    if name.contains('/') || name.contains('\0') {
        return Err(SupervisorError::InvalidName);
    }
    Ok(())
}

fn now_ms() -> u64 {
    // Arch-neutral; see `crate::arch::uptime_ms`.
    crate::arch::uptime_ms()
}

// ── Public API ────────────────────────────────────────────────────────────

/// Register a new module with the supervisor.
///
/// The task identified by `tid` is the module's first incarnation. Further
/// incarnations (from restarts) receive new task IDs but keep the same
/// `name`, and the restart counter is **not** reset — see the module docs.
///
/// # Errors
///
/// - [`SupervisorError::InvalidName`]
/// - [`SupervisorError::InvalidLimits`]
/// - [`SupervisorError::AlreadyRegistered`]
/// - [`SupervisorError::RegistryFull`]
pub fn register(
    name: &str,
    wasm_path: &str,
    limits: ModuleLimits,
    tid: TaskId,
) -> Result<(), SupervisorError> {
    validate_name(name)?;
    limits.validate()?;

    let mut modules = MODULES.lock();
    if modules.contains_key(name) {
        return Err(SupervisorError::AlreadyRegistered);
    }
    if modules.len() >= MAX_SUPERVISED_MODULES {
        return Err(SupervisorError::RegistryFull);
    }

    let entry = ModuleEntry {
        tid,
        name: name.to_string(),
        wasm_path: wasm_path.to_string(),
        state: ModuleState::Running,
        gas_used: 0,
        gas_limit: limits.gas_limit,
        mem_pages: 0,
        mem_limit: limits.mem_pages,
        restarts: 0,
        max_restarts: limits.max_restarts,
        started_ms: now_ms(),
        last_restart_ms: 0,
    };
    modules.insert(name.to_string(), entry);
    drop(modules);

    crate::serial_println!(
        "  [WSUP] registered '{name}' tid={tid} gas={} mem={}p restarts<={}",
        limits.gas_limit,
        limits.mem_pages,
        limits.max_restarts
    );
    Ok(())
}

/// Force-register a module, replacing any existing entry with the same name.
///
/// **This resets the restart counter.** Prefer [`register`] unless you are
/// an operator explicitly bringing a fresh module online.
pub fn register_replacing(
    name: &str,
    wasm_path: &str,
    limits: ModuleLimits,
    tid: TaskId,
) -> Result<(), SupervisorError> {
    validate_name(name)?;
    limits.validate()?;
    MODULES.lock().remove(name);
    register(name, wasm_path, limits, tid)
}

/// Charge `amount` gas against the module named `name`.
///
/// Returns `true` while the module stays within its budget. Once the budget
/// is exceeded, the state flips to [`ModuleState::GasExhausted`], the
/// function returns `false`, and subsequent charges are **no-ops** (the
/// counter is not incremented further, so repeated calls do not saturate).
///
/// Returns `true` for an unknown module (the caller may be a kernel task
/// that the supervisor does not track) but logs a warning the first time.
#[must_use]
pub fn charge_gas(name: &str, amount: u64) -> bool {
    let mut modules = MODULES.lock();
    let Some(entry) = modules.get_mut(name) else {
        // Not supervised: allow, but make the gap visible in logs.
        crate::serial_println!("  [WSUP] charge_gas: unknown module '{name}' (allowed)");
        return true;
    };

    // Idempotent once exhausted — do not saturate the counter.
    if matches!(entry.state, ModuleState::GasExhausted) {
        return false;
    }
    if !matches!(entry.state, ModuleState::Running) {
        // Non-running state: reject further charges rather than silently
        // accumulating on a stopped/crashed module.
        return false;
    }

    entry.gas_used = entry.gas_used.saturating_add(amount);
    if entry.gas_used > entry.gas_limit {
        entry.state = ModuleState::GasExhausted;
        drop(modules);
        crate::serial_println!("  [WSUP] '{name}' gas exhausted");
        return false;
    }
    true
}

/// Record a new memory-page count for `name`.
///
/// Returns `Ok(())` if the new count is within `mem_limit`. Returns
/// `Err(SupervisorError::TerminalState(MemoryLimitExceeded { .. }))` and
/// flips the state if the limit is exceeded.
pub fn set_memory_pages(name: &str, pages: u32) -> Result<(), SupervisorError> {
    let mut modules = MODULES.lock();
    let Some(entry) = modules.get_mut(name) else {
        return Err(SupervisorError::NotRegistered);
    };
    if pages > entry.mem_limit {
        entry.mem_pages = pages;
        entry.state = ModuleState::MemoryLimitExceeded {
            pages,
            limit: entry.mem_limit,
        };
        let state = entry.state.clone();
        drop(modules);
        crate::serial_println!("  [WSUP] '{name}' memory limit exceeded: {pages} pages");
        return Err(SupervisorError::TerminalState(state));
    }
    entry.mem_pages = pages;
    Ok(())
}

/// Explicitly stop a module.
///
/// Moves the module to [`ModuleState::Stopped`]. Does **not** terminate the
/// underlying task — the runtime is expected to observe the state change.
pub fn stop(name: &str, reason: &str) -> Result<(), SupervisorError> {
    let mut modules = MODULES.lock();
    let entry = modules
        .get_mut(name)
        .ok_or(SupervisorError::NotRegistered)?;
    entry.state = ModuleState::Stopped {
        reason: reason.to_string(),
    };
    Ok(())
}

/// Report that a module has crashed.
///
/// Updates the module's state and, subject to the restart policy, spawns a
/// new task from the on-disk bytecode.
///
/// The new incarnation keeps the same **name** and the same restart counter;
/// only `tid`, `started_ms`, and `gas_used` are reset.
pub fn report_crash(name: &str, reason: &str) {
    // Phase 1: record the crash and decide whether to restart.
    let (should_restart, attempt, wasm_path, limits) = {
        let mut modules = MODULES.lock();
        let Some(entry) = modules.get_mut(name) else {
            crate::serial_println!("  [WSUP] report_crash: unknown module '{name}'");
            return;
        };
        entry.state = ModuleState::Crashed {
            reason: reason.to_string(),
        };
        crate::serial_println!("  [WSUP] '{name}' crashed: {reason}");

        let now = now_ms();
        match entry.restart_eligible(now) {
            Ok(attempt) => {
                entry.state = ModuleState::Restarting { attempt };
                entry.last_restart_ms = now;
                entry.restarts = attempt;
                (
                    true,
                    attempt,
                    entry.wasm_path.clone(),
                    ModuleLimits {
                        gas_limit: entry.gas_limit,
                        mem_pages: entry.mem_limit,
                        max_restarts: entry.max_restarts,
                    },
                )
            }
            Err(_) => (false, 0, String::new(), ModuleLimits {
                gas_limit: 0,
                mem_pages: 0,
                max_restarts: 0,
            }),
        }
    };

    if !should_restart {
        return;
    }

    // Phase 2: read the bytecode and spawn (outside the lock).
    let bytecode = match crate::fs::ionafs::read(&wasm_path) {
        Some(b) => b,
        None => {
            mark_restart_failed(name, attempt, "bytecode not found");
            return;
        }
    };
    let new_tid = match crate::wasm::spawn_module(&bytecode) {
        Ok(tid) => tid,
        Err(e) => {
            let reason = alloc::format!("{e}");
            mark_restart_failed(name, attempt, &reason);
            return;
        }
    };

    // Phase 3: install the new incarnation.
    let mut modules = MODULES.lock();
    if let Some(entry) = modules.get_mut(name) {
        entry.tid = new_tid;
        entry.state = ModuleState::Running;
        entry.started_ms = now_ms();
        entry.gas_used = 0;
        entry.mem_pages = 0;
        // `restarts` was already incremented in phase 1.
    }
    drop(modules);

    crate::serial_println!("  [WSUP] '{name}' restarted (attempt {attempt}, tid={new_tid})");

    // Suppress an unused warning on `limits` when the restart path is
    // compiled without the future per-incarnation limit propagation.
    let _ = limits;
}

fn mark_restart_failed(name: &str, attempt: u32, reason: &str) {
    let mut modules = MODULES.lock();
    if let Some(entry) = modules.get_mut(name) {
        entry.state = ModuleState::RestartFailed {
            attempt,
            reason: reason.to_string(),
        };
    }
    drop(modules);
    crate::serial_println!("  [WSUP] '{name}' restart failed: {reason}");
}

/// Current state of a module.
#[must_use]
pub fn get_state(name: &str) -> Option<ModuleState> {
    MODULES.lock().get(name).map(|e| e.state.clone())
}

/// Snapshot of a module's full entry.
#[must_use]
pub fn get_entry(name: &str) -> Option<ModuleEntry> {
    MODULES.lock().get(name).cloned()
}

/// Modules in [`ModuleState::Running`].
#[must_use]
pub fn list_running() -> Vec<(TaskId, String)> {
    MODULES
        .lock()
        .values()
        .filter(|e| matches!(e.state, ModuleState::Running))
        .map(|e| (e.tid, e.name.clone()))
        .collect()
}

/// All supervised modules, in name order.
#[must_use]
pub fn list_all() -> Vec<(String, ModuleState)> {
    MODULES
        .lock()
        .iter()
        .map(|(k, v)| (k.clone(), v.state.clone()))
        .collect()
}

/// Periodic health check; call from a timer (e.g. once per second).
///
/// For every module in a **live** state, verifies that the underlying task
/// is still known to the scheduler. A missing task is reported as a crash.
///
/// The scheduler exposes only a snapshot (`stats`), so this check is
/// best-effort: it catches tasks that have been reaped, not tasks that are
/// stuck. A complementary watchdog on the runtime side (e.g. a heartbeat
/// the module must bump) is recommended for untrusted code.
pub fn tick() {
    // Snapshot the scheduler once. This avoids holding the scheduler lock
    // across the loop below, which calls into `report_crash` (which takes
    // the supervisor lock).
    let live_tids: Vec<TaskId> = {
        let sched = crate::sched::SCHEDULER.lock();
        sched.stats().live_task_ids.clone()
    };

    // Snapshot the modules we care about.
    let candidates: Vec<(String, TaskId, ModuleState)> = {
        let modules = MODULES.lock();
        modules
            .values()
            .filter(|e| e.state.is_live())
            .map(|e| (e.name.clone(), e.tid, e.state.clone()))
            .collect()
    };

    for (name, tid, state) in candidates {
        if !matches!(state, ModuleState::Running) {
            continue;
        }
        if !live_tids.contains(&tid) {
            report_crash(&name, "task not known to the scheduler");
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() {
        MODULES.lock().clear();
    }

    fn limits() -> ModuleLimits {
        ModuleLimits {
            gas_limit: 1_000,
            mem_pages: 4,
            max_restarts: 2,
        }
    }

    // ── Registration ────────────────────────────────────────────────────

    #[test]
    fn register_rejects_empty_and_bad_names() {
        fresh();
        assert_eq!(
            register("", "p", limits(), 1),
            Err(SupervisorError::InvalidName)
        );
        assert_eq!(
            register("a/b", "p", limits(), 1),
            Err(SupervisorError::InvalidName)
        );
        assert_eq!(
            register("a\0b", "p", limits(), 1),
            Err(SupervisorError::InvalidName)
        );
    }

    #[test]
    fn register_rejects_duplicate() {
        fresh();
        register("m", "p", limits(), 1).unwrap();
        assert_eq!(
            register("m", "p", limits(), 2),
            Err(SupervisorError::AlreadyRegistered)
        );
    }

    #[test]
    fn register_replacing_resets_state() {
        fresh();
        register("m", "p", limits(), 1).unwrap();
        charge_gas("m", 10_000);
        assert!(matches!(get_state("m"), Some(ModuleState::GasExhausted)));
        register_replacing("m", "p", limits(), 3).unwrap();
        assert!(matches!(get_state("m"), Some(ModuleState::Running)));
    }

    #[test]
    fn register_rejects_zero_limits() {
        fresh();
        let bad = ModuleLimits {
            gas_limit: 0,
            ..limits()
        };
        assert!(matches!(
            register("m", "p", bad, 1),
            Err(SupervisorError::InvalidLimits(_))
        ));
    }

    // ── Gas ─────────────────────────────────────────────────────────────

    #[test]
    fn charge_gas_within_limit_returns_true() {
        fresh();
        register("m", "p", limits(), 1).unwrap();
        assert!(charge_gas("m", 500));
        assert!(charge_gas("m", 500));
    }

    #[test]
    fn charge_gas_exhausted_returns_false_and_is_idempotent() {
        fresh();
        register("m", "p", limits(), 1).unwrap();
        assert!(!charge_gas("m", 1_001));
        // Subsequent calls do not saturate the counter.
        assert!(!charge_gas("m", 1));
        assert!(!charge_gas("m", 1));
        let entry = get_entry("m").unwrap();
        assert_eq!(entry.gas_used, 1_001);
    }

    #[test]
    fn charge_gas_unknown_module_is_allowed() {
        fresh();
        // Documented behaviour: unknown modules are not supervised.
        assert!(charge_gas("ghost", 999_999));
    }

    // ── Memory ──────────────────────────────────────────────────────────

    #[test]
    fn set_memory_pages_within_limit() {
        fresh();
        register("m", "p", limits(), 1).unwrap();
        assert_eq!(set_memory_pages("m", 2), Ok(()));
        assert_eq!(get_entry("m").unwrap().mem_pages, 2);
    }

    #[test]
    fn set_memory_pages_over_limit_transitions_state() {
        fresh();
        register("m", "p", limits(), 1).unwrap();
        let err = set_memory_pages("m", 10).unwrap_err();
        assert!(matches!(
            err,
            SupervisorError::TerminalState(ModuleState::MemoryLimitExceeded { .. })
        ));
        assert!(matches!(
            get_state("m"),
            Some(ModuleState::MemoryLimitExceeded { .. })
        ));
    }

    // ── Restart policy ──────────────────────────────────────────────────

    #[test]
    fn restart_counter_persists_across_incarnations() {
        // Regression: the previous implementation called `register(...)`
        // on restart, which reset `restarts` to 0 and made `max_restarts`
        // unenforceable.
        fresh();
        let l = ModuleLimits {
            max_restarts: 1,
            ..limits()
        };
        register("m", "/nonexistent", l, 1).unwrap();

        // First crash: eligible, but bytecode read fails → RestartFailed.
        report_crash("m", "boom");
        assert!(matches!(
            get_state("m"),
            Some(ModuleState::RestartFailed { attempt: 1, .. })
        ));

        // The restart counter is 1, and max_restarts is 1: a second crash
        // must NOT attempt a restart.
        report_crash("m", "boom again");
        assert!(matches!(get_state("m"), Some(ModuleState::Crashed { .. })));
        assert_eq!(get_entry("m").unwrap().restarts, 1);
    }

    #[test]
    fn restart_is_rate_limited() {
        fresh();
        register("m", "/nonexistent", limits(), 1).unwrap();

        report_crash("m", "boom");
        // We just recorded a restart attempt; the interval hasn't elapsed.
        let second_crash_ok = {
            let entry = get_entry("m").unwrap();
            let now = now_ms();
            entry.restart_eligible(now).is_err()
        };
        assert!(second_crash_ok, "second restart should be rejected by rate limit");
    }

    // ── Lifecycle ───────────────────────────────────────────────────────

    #[test]
    fn stop_moves_state_to_terminal() {
        fresh();
        register("m", "p", limits(), 1).unwrap();
        stop("m", "operator").unwrap();
        let s = get_state("m").unwrap();
        assert!(matches!(s, ModuleState::Stopped { .. }));
        assert!(s.is_terminal());
        assert!(!s.is_live());
    }

    #[test]
    fn list_running_excludes_terminal_states() {
        fresh();
        register("a", "p", limits(), 1).unwrap();
        register("b", "p", limits(), 2).unwrap();
        stop("b", "operator").unwrap();
        let names: Vec<String> = list_running().into_iter().map(|(_, n)| n).collect();
        assert_eq!(names, vec!["a".to_string()]);
    }

    #[test]
    fn list_all_returns_every_module() {
        fresh();
        register("a", "p", limits(), 1).unwrap();
        register("b", "p", limits(), 2).unwrap();
        assert_eq!(list_all().len(), 2);
    }

    // ── State helpers ───────────────────────────────────────────────────

    #[test]
    fn terminal_and_live_predicates() {
        assert!(ModuleState::Running.is_live());
        assert!(ModuleState::Restarting { attempt: 1 }.is_live());
        assert!(ModuleState::Stopped { reason: "x".into() }.is_terminal());
        assert!(ModuleState::GasExhausted.is_terminal());
        assert!(ModuleState::MemoryLimitExceeded { pages: 9, limit: 4 }.is_terminal());
    }
}
