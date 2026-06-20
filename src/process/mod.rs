//! Process management
//!
//! Provides the core process abstraction for IONA, including:
//! - Process creation, scheduling, and termination.
//! - State management (Running, Ready, Blocked, Zombie, Dead).
//! - Resource accounting (CPU time, memory usage).
//! - Process groups and sessions (job control).
//! - Signal handling integration.
//! - Cleanup on exit.
//! - Metrics and statistics.
//! - Integration with fork, exec, fd, mmap, and IPC.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    Process Manager                     │
//! │  ┌─────────────────────────────────────────────────┐   │
//! │  │  Registry: BTreeMap<TaskId, Process>           │   │
//! │  │  - pid, tgid, pgid, sid                        │   │
//! │  │  - state, name, args, env                      │   │
//! │  │  - resource usage (cpu, memory, I/O)           │   │
//! │  └─────────────────────────────────────────────────┘   │
//! │  ┌─────────────────────────────────────────────────┐   │
//! │  │  Child/Parent relationships                     │   │
//! │  │  - children list, parent pointer               │   │
//! │  └─────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────┘
//! ```

pub mod dynlink;
pub mod exec;
pub mod clone;
pub mod address_space;
pub mod ipc;
pub mod fd;
pub mod fork;
pub mod mmap;
pub mod pipe;
pub mod futex;
pub mod epoll;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::{Lazy, Mutex};
use tracing::{debug, error, info, trace, warn};

use crate::arch::x86_64::timer::uptime_ms;
use crate::sched::{SCHEDULER, wake_task};
use crate::signal::{self, Signal, signal_pending};
use crate::task::TaskId;
use crate::types::KernelError;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum number of processes.
pub const MAX_PROCESSES: usize = 4096;

/// Default process name.
pub const DEFAULT_PROCESS_NAME: &str = "unknown";

/// Maximum process name length.
pub const MAX_PROCESS_NAME_LEN: usize = 256;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during process operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessError {
    /// Process not found.
    ProcessNotFound,
    /// Invalid argument (e.g., bad PID).
    InvalidArgument,
    /// Permission denied.
    PermissionDenied,
    /// Resource limit reached (too many processes).
    ResourceLimit,
    /// Process state invalid for operation.
    InvalidState,
    /// Operation not supported.
    Unsupported,
    /// Interrupted by signal.
    Interrupted,
    /// No child process.
    NoChildProcess,
    /// Not a child.
    NotChild,
    /// Process is dead.
    ProcessDead,
}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProcessNotFound => write!(f, "process not found"),
            Self::InvalidArgument => write!(f, "invalid argument"),
            Self::PermissionDenied => write!(f, "permission denied"),
            Self::ResourceLimit => write!(f, "resource limit reached"),
            Self::InvalidState => write!(f, "invalid process state"),
            Self::Unsupported => write!(f, "operation not supported"),
            Self::Interrupted => write!(f, "interrupted by signal"),
            Self::NoChildProcess => write!(f, "no child process"),
            Self::NotChild => write!(f, "not a child process"),
            Self::ProcessDead => write!(f, "process is dead"),
        }
    }
}

impl From<ProcessError> for KernelError {
    fn from(e: ProcessError) -> Self {
        match e {
            ProcessError::ProcessNotFound => KernelError::NoSuchProcess,
            ProcessError::InvalidArgument => KernelError::InvalidArgument,
            ProcessError::PermissionDenied => KernelError::PermissionDenied,
            ProcessError::ResourceLimit => KernelError::ResourceLimit,
            ProcessError::InvalidState => KernelError::InvalidArgument,
            ProcessError::Unsupported => KernelError::Unsupported,
            ProcessError::Interrupted => KernelError::Interrupted,
            ProcessError::NoChildProcess => KernelError::NoSuchProcess,
            ProcessError::NotChild => KernelError::InvalidArgument,
            ProcessError::ProcessDead => KernelError::InvalidArgument,
        }
    }
}

pub type ProcessResult<T> = Result<T, ProcessError>;

// -----------------------------------------------------------------------------
// Process states
// -----------------------------------------------------------------------------

/// Process state (POSIX-compatible).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// Running (or ready to run).
    Running,
    /// Ready to run (queued).
    Ready,
    /// Blocked (waiting for I/O or event).
    Blocked,
    /// Stopped (by signal, e.g., SIGSTOP).
    Stopped,
    /// Zombie (terminated, waiting for parent to reap).
    Zombie,
    /// Dead (reaped, resources freed).
    Dead,
}

impl fmt::Display for ProcessState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Running => write!(f, "Running"),
            Self::Ready => write!(f, "Ready"),
            Self::Blocked => write!(f, "Blocked"),
            Self::Stopped => write!(f, "Stopped"),
            Self::Zombie => write!(f, "Zombie"),
            Self::Dead => write!(f, "Dead"),
        }
    }
}

// -----------------------------------------------------------------------------
// Process resource usage
// -----------------------------------------------------------------------------

/// Resource usage statistics for a process.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessUsage {
    /// CPU time used (milliseconds).
    pub cpu_time_ms: u64,
    /// User CPU time (milliseconds).
    pub user_time_ms: u64,
    /// System CPU time (milliseconds).
    pub sys_time_ms: u64,
    /// Maximum resident set size (pages).
    pub max_rss: usize,
    /// Number of minor page faults.
    pub minor_faults: u64,
    /// Number of major page faults.
    pub major_faults: u64,
    /// Number of voluntary context switches.
    pub voluntary_switches: u64,
    /// Number of involuntary context switches.
    pub involuntary_switches: u64,
    /// I/O bytes read.
    pub io_read_bytes: u64,
    /// I/O bytes written.
    pub io_write_bytes: u64,
}

impl ProcessUsage {
    /// Accumulate usage from another process.
    pub fn add(&mut self, other: &Self) {
        self.cpu_time_ms += other.cpu_time_ms;
        self.user_time_ms += other.user_time_ms;
        self.sys_time_ms += other.sys_time_ms;
        self.max_rss = self.max_rss.max(other.max_rss);
        self.minor_faults += other.minor_faults;
        self.major_faults += other.major_faults;
        self.voluntary_switches += other.voluntary_switches;
        self.involuntary_switches += other.involuntary_switches;
        self.io_read_bytes += other.io_read_bytes;
        self.io_write_bytes += other.io_write_bytes;
    }
}

// -----------------------------------------------------------------------------
// Process structure
// -----------------------------------------------------------------------------

/// A process in the system.
#[derive(Debug)]
pub struct Process {
    /// Process ID.
    pub pid: TaskId,
    /// Thread group ID (for threads, same as main thread PID).
    pub tgid: TaskId,
    /// Process group ID (for job control).
    pub pgid: TaskId,
    /// Session ID.
    pub sid: TaskId,
    /// Parent process ID.
    pub parent: TaskId,
    /// Process state.
    pub state: ProcessState,
    /// Exit status (if terminated).
    pub exit_code: Option<i32>,
    /// Process name.
    pub name: String,
    /// Command line arguments.
    pub args: Vec<String>,
    /// Environment variables.
    pub env: Vec<String>,
    /// Resource usage.
    pub usage: ProcessUsage,
    /// Children PIDs.
    pub children: Vec<TaskId>,
    /// Start time (milliseconds since boot).
    pub start_time_ms: u64,
    /// Time of last state change.
    pub last_state_change_ms: u64,
    /// Kernel stack pointer (for context switch).
    pub kernel_rsp: u64,
    /// User stack pointer.
    pub user_rsp: u64,
    /// Whether the process is being traced.
    pub traced: bool,
    /// Whether the process is a session leader.
    pub session_leader: bool,
}

impl Process {
    /// Create a new process.
    pub fn new(pid: TaskId, parent: TaskId, name: &str) -> Self {
        Self {
            pid,
            tgid: pid,
            pgid: pid,
            sid: pid,
            parent,
            state: ProcessState::Ready,
            exit_code: None,
            name: name.to_string(),
            args: Vec::new(),
            env: Vec::new(),
            usage: ProcessUsage::default(),
            children: Vec::new(),
            start_time_ms: uptime_ms(),
            last_state_change_ms: uptime_ms(),
            kernel_rsp: 0,
            user_rsp: 0,
            traced: false,
            session_leader: true,
        }
    }

    /// Set the state.
    pub fn set_state(&mut self, state: ProcessState) {
        self.state = state;
        self.last_state_change_ms = uptime_ms();
    }

    /// Terminate the process.
    pub fn terminate(&mut self, code: i32) {
        self.exit_code = Some(code);
        self.set_state(ProcessState::Zombie);
        // Wake parent.
        if let Some(parent) = crate::process::get_process(self.parent) {
            // Send SIGCHLD.
            signal::send(self.parent, Signal::SIGCHLD);
            // Wake parent if waiting.
            wake_task(self.parent);
        }
    }

    /// Reap the process (free resources).
    pub fn reap(&mut self) {
        self.set_state(ProcessState::Dead);
        self.exit_code = None;
        // Clean up resources.
        crate::process::fd::remove_for(self.pid);
        crate::process::ipc::unregister(self.pid);
        crate::process::mmap::cleanup_for(self.pid);
        // Remove from scheduler.
        SCHEDULER.lock().remove(self.pid);
    }

    /// Add a child process.
    pub fn add_child(&mut self, child: TaskId) {
        if !self.children.contains(&child) {
            self.children.push(child);
        }
    }

    /// Remove a child process.
    pub fn remove_child(&mut self, child: TaskId) -> bool {
        let pos = self.children.iter().position(|&c| c == child);
        if let Some(p) = pos {
            self.children.remove(p);
            true
        } else {
            false
        }
    }

    /// Check if the process has children.
    pub fn has_children(&self) -> bool {
        !self.children.is_empty()
    }

    /// Get the number of children.
    pub fn child_count(&self) -> usize {
        self.children.len()
    }

    /// Check if the process is a zombie.
    pub fn is_zombie(&self) -> bool {
        matches!(self.state, ProcessState::Zombie)
    }

    /// Check if the process is dead.
    pub fn is_dead(&self) -> bool {
        matches!(self.state, ProcessState::Dead)
    }

    /// Check if the process is running.
    pub fn is_running(&self) -> bool {
        matches!(self.state, ProcessState::Running) || matches!(self.state, ProcessState::Ready)
    }

    /// Check if the process is blocked.
    pub fn is_blocked(&self) -> bool {
        matches!(self.state, ProcessState::Blocked)
    }

    /// Check if the process is stopped.
    pub fn is_stopped(&self) -> bool {
        matches!(self.state, ProcessState::Stopped)
    }
}

// -----------------------------------------------------------------------------
// Process registry
// -----------------------------------------------------------------------------

/// Global process registry.
static PROCESS_REGISTRY: Lazy<Mutex<BTreeMap<TaskId, Process>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

/// Global children index (parent → children).
static CHILDREN_INDEX: Lazy<Mutex<BTreeMap<TaskId, Vec<TaskId>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

/// Global exit status for zombies (pid → exit code).
static EXIT_STATUS: Lazy<Mutex<BTreeMap<TaskId, i32>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

/// Global metrics.
static METRICS: Lazy<Mutex<ProcessMetrics>> = Lazy::new(|| Mutex::new(ProcessMetrics::default()));

/// Next process ID (already in task module, but we use it via `next_tid`).

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

/// Process subsystem metrics.
#[derive(Debug, Default)]
pub struct ProcessMetrics {
    /// Total processes created.
    pub processes_created: AtomicU64,
    /// Total processes terminated.
    pub processes_terminated: AtomicU64,
    /// Total processes reaped.
    pub processes_reaped: AtomicU64,
    /// Current number of processes.
    pub current_processes: AtomicUsize,
    /// Total CPU time used across all processes (milliseconds).
    pub total_cpu_time_ms: AtomicU64,
}

impl ProcessMetrics {
    /// Record a process creation.
    pub fn record_create(&self) {
        self.processes_created.fetch_add(1, Ordering::Relaxed);
        self.current_processes.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a process termination.
    pub fn record_terminate(&self) {
        self.processes_terminated.fetch_add(1, Ordering::Relaxed);
        self.current_processes.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record a process reap.
    pub fn record_reap(&self) {
        self.processes_reaped.fetch_add(1, Ordering::Relaxed);
    }

    /// Add CPU time.
    pub fn add_cpu_time(&self, ms: u64) {
        self.total_cpu_time_ms.fetch_add(ms, Ordering::Relaxed);
    }
}

/// Get the current metrics.
pub fn get_metrics() -> ProcessMetrics {
    METRICS.lock().clone()
}

/// Reset metrics.
pub fn reset_metrics() {
    *METRICS.lock() = ProcessMetrics::default();
}

// -----------------------------------------------------------------------------
// Core process management functions
// -----------------------------------------------------------------------------

/// Register a new process in the registry.
pub fn register(pid: TaskId, kernel_rsp: u64, parent: TaskId, name: &str) -> ProcessResult<()> {
    let mut registry = PROCESS_REGISTRY.lock();

    if registry.len() >= MAX_PROCESSES {
        return Err(ProcessError::ResourceLimit);
    }

    if registry.contains_key(&pid) {
        return Err(ProcessError::InvalidArgument);
    }

    let mut process = Process::new(pid, parent, name);
    process.kernel_rsp = kernel_rsp;
    process.start_time_ms = uptime_ms();

    // Add to children list of parent.
    if let Some(parent_process) = registry.get_mut(&parent) {
        parent_process.add_child(pid);
    }

    registry.insert(pid, process);

    METRICS.lock().record_create();

    trace!(
        pid = pid.as_u64(),
        parent = parent.as_u64(),
        name,
        "process registered"
    );

    Ok(())
}

/// Unregister a process (mark as dead and remove from registry).
pub fn unregister(pid: TaskId) -> ProcessResult<()> {
    let mut registry = PROCESS_REGISTRY.lock();
    let process = registry.remove(&pid).ok_or(ProcessError::ProcessNotFound)?;

    // Remove from parent's children list.
    if let Some(parent_process) = registry.get_mut(&process.parent) {
        parent_process.remove_child(pid);
    }

    // Clean up.
    process.reap();

    METRICS.lock().record_terminate();

    trace!(pid = pid.as_u64(), "process unregistered");

    Ok(())
}

/// Get a process by PID.
pub fn get_process(pid: TaskId) -> Option<Process> {
    PROCESS_REGISTRY.lock().get(&pid).cloned()
}

/// Get a mutable reference to a process.
pub fn get_process_mut(pid: TaskId) -> Option<impl FnOnce(&mut Process)> {
    // We can't return a mutable reference directly because of the lock.
    // We'll provide a function that takes a closure.
    None // Placeholder; we'll use a different approach.
}

/// Update a process with a closure.
pub fn with_process<F, R>(pid: TaskId, f: F) -> ProcessResult<R>
where
    F: FnOnce(&mut Process) -> R,
{
    let mut registry = PROCESS_REGISTRY.lock();
    let process = registry.get_mut(&pid).ok_or(ProcessError::ProcessNotFound)?;
    Ok(f(process))
}

/// Get the parent PID of a process.
pub fn get_parent(pid: TaskId) -> ProcessResult<TaskId> {
    let registry = PROCESS_REGISTRY.lock();
    let process = registry.get(&pid).ok_or(ProcessError::ProcessNotFound)?;
    Ok(process.parent)
}

/// Get the children PIDs of a process.
pub fn get_children(pid: TaskId) -> ProcessResult<Vec<TaskId>> {
    let registry = PROCESS_REGISTRY.lock();
    let process = registry.get(&pid).ok_or(ProcessError::ProcessNotFound)?;
    Ok(process.children.clone())
}

/// Get the process name.
pub fn get_name(pid: TaskId) -> ProcessResult<String> {
    let registry = PROCESS_REGISTRY.lock();
    let process = registry.get(&pid).ok_or(ProcessError::ProcessNotFound)?;
    Ok(process.name.clone())
}

/// Set the process name.
pub fn set_name(pid: TaskId, name: &str) -> ProcessResult<()> {
    with_process(pid, |p| {
        if name.len() > MAX_PROCESS_NAME_LEN {
            p.name = name[..MAX_PROCESS_NAME_LEN].to_string();
        } else {
            p.name = name.to_string();
        }
    })
}

/// Get the process state.
pub fn get_state(pid: TaskId) -> ProcessResult<ProcessState> {
    let registry = PROCESS_REGISTRY.lock();
    let process = registry.get(&pid).ok_or(ProcessError::ProcessNotFound)?;
    Ok(process.state)
}

/// Set the process state.
pub fn set_state(pid: TaskId, state: ProcessState) -> ProcessResult<()> {
    with_process(pid, |p| p.set_state(state))
}

/// Get the process exit code (if zombie).
pub fn get_exit_code(pid: TaskId) -> ProcessResult<Option<i32>> {
    let registry = PROCESS_REGISTRY.lock();
    let process = registry.get(&pid).ok_or(ProcessError::ProcessNotFound)?;
    Ok(process.exit_code)
}

/// Get the process usage.
pub fn get_usage(pid: TaskId) -> ProcessResult<ProcessUsage> {
    let registry = PROCESS_REGISTRY.lock();
    let process = registry.get(&pid).ok_or(ProcessError::ProcessNotFound)?;
    Ok(process.usage)
}

/// Update the process usage.
pub fn update_usage(pid: TaskId, usage: ProcessUsage) -> ProcessResult<()> {
    with_process(pid, |p| {
        p.usage = usage;
        METRICS.lock().add_cpu_time(usage.cpu_time_ms);
    })
}

/// Add CPU time to a process.
pub fn add_cpu_time(pid: TaskId, ms: u64) -> ProcessResult<()> {
    with_process(pid, |p| {
        p.usage.cpu_time_ms += ms;
        p.usage.user_time_ms += ms; // Simplification; differentiate later.
        METRICS.lock().add_cpu_time(ms);
    })
}

/// Add page fault count.
pub fn add_page_fault(pid: TaskId, major: bool) -> ProcessResult<()> {
    with_process(pid, |p| {
        if major {
            p.usage.major_faults += 1;
        } else {
            p.usage.minor_faults += 1;
        }
    })
}

// -----------------------------------------------------------------------------
// Process listing
// -----------------------------------------------------------------------------

/// Get a list of all process IDs.
pub fn list_processes() -> Vec<TaskId> {
    PROCESS_REGISTRY.lock().keys().copied().collect()
}

/// Get a list of running processes.
pub fn list_running() -> Vec<TaskId> {
    let registry = PROCESS_REGISTRY.lock();
    registry
        .iter()
        .filter(|(_, p)| p.is_running())
        .map(|(pid, _)| *pid)
        .collect()
}

/// Get a list of zombie processes.
pub fn list_zombies() -> Vec<TaskId> {
    let registry = PROCESS_REGISTRY.lock();
    registry
        .iter()
        .filter(|(_, p)| p.is_zombie())
        .map(|(pid, _)| *pid)
        .collect()
}

/// Get the number of processes.
pub fn process_count() -> usize {
    PROCESS_REGISTRY.lock().len()
}

// -----------------------------------------------------------------------------
// Process exit and notification
// -----------------------------------------------------------------------------

/// Terminate a process with an exit code.
pub fn exit_process(pid: TaskId, code: i32) -> ProcessResult<()> {
    with_process(pid, |p| {
        p.terminate(code);
        // Store exit status.
        EXIT_STATUS.lock().insert(pid, code);
        // Send SIGCHLD to parent.
        signal::send(p.parent, Signal::SIGCHLD);
        // Wake parent if waiting.
        wake_task(p.parent);
        // Remove from scheduler.
        SCHEDULER.lock().remove(pid);
        METRICS.lock().record_terminate();
    })
}

/// Wait for a child process to exit.
pub fn wait_for_child(parent: TaskId, child: Option<TaskId>, options: WaitOptions) -> ProcessResult<(TaskId, i32)> {
    let registry = PROCESS_REGISTRY.lock();
    let parent_proc = registry.get(&parent).ok_or(ProcessError::ProcessNotFound)?;

    let children = if let Some(c) = child {
        if !parent_proc.children.contains(&c) {
            return Err(ProcessError::NotChild);
        }
        vec![c]
    } else {
        parent_proc.children.clone()
    };

    if children.is_empty() {
        return Err(ProcessError::NoChildProcess);
    }

    // Check for zombies.
    let mut zombie = None;
    for &c in &children {
        if let Some(proc) = registry.get(&c) {
            if proc.is_zombie() {
                zombie = Some(c);
                break;
            }
        }
    }

    if let Some(pid) = zombie {
        let exit_code = EXIT_STATUS.lock().remove(&pid).unwrap_or(0);
        // Reap the child.
        // We need to remove from registry.
        drop(registry);
        // The child is reaped in the unregister call.
        // But we don't want to unregister it yet if we need to keep it for waitpid.
        // In standard POSIX, waitpid reaps the zombie.
        // We'll just return the exit code.
        // The zombie will be reaped when the parent calls waitpid again or when the parent exits.
        // We'll remove from children list.
        let mut registry = PROCESS_REGISTRY.lock();
        if let Some(parent_proc) = registry.get_mut(&parent) {
            parent_proc.remove_child(pid);
        }
        // Mark as dead.
        if let Some(proc) = registry.get_mut(&pid) {
            proc.reap();
        }
        METRICS.lock().record_reap();
        return Ok((pid, exit_code));
    }

    // No zombies: if WNOHANG, return error.
    if options.contains(WaitOptions::WNOHANG) {
        return Err(ProcessError::NoChildProcess);
    }

    // Block until a child exits.
    // We'll use the wait subsystem.
    drop(registry);
    let cond = crate::wait::WakeCondition::IpcMessage;
    crate::wait::block_current(parent, cond);

    // After wake, loop again.
    wait_for_child(parent, child, options)
}

/// Wait options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitOptions {
    bits: u32,
}

impl WaitOptions {
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }
    pub const fn wnohang(mut self) -> Self {
        self.bits |= 1;
        self
    }
    pub const fn wuntraced(mut self) -> Self {
        self.bits |= 2;
        self
    }
    pub const fn wcontinued(mut self) -> Self {
        self.bits |= 8;
        self
    }
    pub const fn is_wnohang(&self) -> bool {
        (self.bits & 1) != 0
    }
    pub const fn is_wuntraced(&self) -> bool {
        (self.bits & 2) != 0
    }
    pub const fn from_raw(bits: i32) -> Self {
        Self { bits: bits as u32 }
    }
}

// -----------------------------------------------------------------------------
// Initialization
// -----------------------------------------------------------------------------

/// Initialize the process subsystem.
pub fn init() {
    // Create the init process (PID 1).
    let init_pid = TaskId::from_u64(1);
    let init_process = Process::new(init_pid, init_pid, "init");
    PROCESS_REGISTRY.lock().insert(init_pid, init_process);
    METRICS.lock().record_create();
    info!("process subsystem initialized");
}

// -----------------------------------------------------------------------------
// Re-export submodules
// -----------------------------------------------------------------------------

// The submodules are already defined at the top.

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_creation_and_lifecycle() {
        let pid = TaskId::from_u64(100);
        let parent = TaskId::from_u64(1);
        register(pid, 0, parent, "test").unwrap();

        let proc = get_process(pid).unwrap();
        assert_eq!(proc.name, "test");
        assert_eq!(proc.state, ProcessState::Ready);
        assert_eq!(proc.parent, parent);
        assert!(proc.children.is_empty());

        // Add a child.
        let child = TaskId::from_u64(101);
        with_process(pid, |p| p.add_child(child)).unwrap();

        let children = get_children(pid).unwrap();
        assert_eq!(children, vec![child]);

        // Terminate.
        exit_process(pid, 0).unwrap();
        let proc = get_process(pid).unwrap();
        assert!(proc.is_zombie());
        assert_eq!(proc.exit_code, Some(0));

        // Wait for child.
        let result = wait_for_child(parent, Some(pid), WaitOptions::empty()).unwrap();
        assert_eq!(result.0, pid);
        assert_eq!(result.1, 0);

        // Process should be dead.
        let proc = get_process(pid).unwrap();
        assert!(proc.is_dead());
    }

    #[test]
    fn test_metrics() {
        reset_metrics();
        let pid = TaskId::from_u64(200);
        register(pid, 0, TaskId::from_u64(1), "test").unwrap();
        let metrics = get_metrics();
        assert_eq!(metrics.processes_created.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.current_processes.load(Ordering::Relaxed), 1);

        exit_process(pid, 0).unwrap();
        let metrics = get_metrics();
        assert_eq!(metrics.processes_terminated.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.current_processes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_process_state() {
        let pid = TaskId::from_u64(300);
        register(pid, 0, TaskId::from_u64(1), "test").unwrap();
        set_state(pid, ProcessState::Blocked).unwrap();
        let state = get_state(pid).unwrap();
        assert_eq!(state, ProcessState::Blocked);
    }
}
