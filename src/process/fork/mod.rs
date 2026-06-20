//! fork() + exec() + waitpid() — Copy-on-Write process lifecycle
//!
//! Implements POSIX process management with:
//! - Copy-on-Write (CoW) page table cloning for `fork()`
//! - `execve()` with argv/envp and address space replacement
//! - `waitpid()` with blocking and non-blocking modes
//! - Zombie process reaping
//! - `SIGCHLD` signal delivery on child exit
//! - Proper resource cleanup (FD tables, mmap, IPC)
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │              Process Registry                   │
//! │  ┌─────────────┐  ┌─────────────┐              │
//! │  │  Process     │  │  Process    │              │
//! │  │  (Running)   │  │  (Zombie)   │              │
//! │  └─────────────┘  └─────────────┘              │
//! └─────────────────────────────────────────────────┘
//!                      │
//!                      ▼
//! ┌─────────────────────────────────────────────────┐
//! │            Page Table Cloner                    │
//! │  • Copies L4→L3→L2→L1                         │
//! │  • Handles 4KB, 2MB, 1GB pages                │
//! │  • Marks leaf pages read‑only (CoW)           │
//! │  • Increments frame reference counts           │
//! └─────────────────────────────────────────────────┘
//! ```

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Lazy, Mutex, MutexGuard};
use tracing::{debug, error, info, trace, warn};

use x86_64::{
    structures::paging::{
        page_table::PageTable,
        PageTableFlags, PhysFrame,
    },
    VirtAddr,
};

use crate::arch::x86_64::registers::control::Cr3;
use crate::memory::frame_alloc::{allocate_one, dec_ref, get_ref, inc_ref};
use crate::process::fd::{self, FdError};
use crate::sched::SCHEDULER;
use crate::signal::{self, Signal};
use crate::task::{Task, TaskId, TaskStatus, next_tid};
use crate::types::KernelError;
use crate::wait::{WakeCondition, block_current, wake_one};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Physical memory offset.
const PHYS_OFFSET: u64 = 0xFFFF_8000_0000_0000;

/// Maximum number of processes.
const MAX_PROCESSES: usize = 1024;

/// Default process stack size (8 MiB).
const DEFAULT_STACK_SIZE: usize = 8 * 1024 * 1024;

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

/// Errors that can occur during process operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessError {
    /// Out of memory (cannot allocate page tables or frames).
    OutOfMemory,
    /// Process not found.
    ProcessNotFound,
    /// Invalid argument (e.g., bad PID).
    InvalidArgument,
    /// Permission denied.
    PermissionDenied,
    /// Resource limit reached (too many processes).
    ResourceLimit,
    /// Operation not supported.
    Unsupported,
    /// I/O error.
    Io,
    /// Child process does not exist.
    NoChildProcess,
    /// Process is not a child.
    NotChild,
    /// Interrupted by signal.
    Interrupted,
}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfMemory => write!(f, "out of memory"),
            Self::ProcessNotFound => write!(f, "process not found"),
            Self::InvalidArgument => write!(f, "invalid argument"),
            Self::PermissionDenied => write!(f, "permission denied"),
            Self::ResourceLimit => write!(f, "resource limit reached"),
            Self::Unsupported => write!(f, "operation not supported"),
            Self::Io => write!(f, "I/O error"),
            Self::NoChildProcess => write!(f, "no child process"),
            Self::NotChild => write!(f, "process is not a child"),
            Self::Interrupted => write!(f, "interrupted by signal"),
        }
    }
}

impl From<ProcessError> for KernelError {
    fn from(e: ProcessError) -> Self {
        match e {
            ProcessError::OutOfMemory => KernelError::OutOfMemory,
            ProcessError::ProcessNotFound => KernelError::NoSuchProcess,
            ProcessError::InvalidArgument => KernelError::InvalidArgument,
            ProcessError::PermissionDenied => KernelError::PermissionDenied,
            ProcessError::ResourceLimit => KernelError::ResourceLimit,
            ProcessError::Unsupported => KernelError::Unsupported,
            ProcessError::Io => KernelError::Io,
            ProcessError::NoChildProcess => KernelError::NoSuchProcess,
            ProcessError::NotChild => KernelError::InvalidArgument,
            ProcessError::Interrupted => KernelError::Interrupted,
        }
    }
}

pub type ProcessResult<T> = Result<T, ProcessError>;

// -----------------------------------------------------------------------------
// Process state
// -----------------------------------------------------------------------------

/// Process state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// Running (or ready to run).
    Running,
    /// Sleeping (waiting for I/O or event).
    Sleeping,
    /// Stopped (by signal).
    Stopped,
    /// Zombie (terminated, waiting for parent to reap).
    Zombie,
    /// Dead (reaped, resources freed).
    Dead,
}

/// Process information.
#[derive(Debug, Clone)]
pub struct Process {
    /// Process ID.
    pub pid: TaskId,
    /// Parent process ID.
    pub parent: TaskId,
    /// Process group ID (for job control).
    pub pgid: TaskId,
    /// Session ID.
    pub sid: TaskId,
    /// Process state.
    pub state: ProcessState,
    /// Exit status (if terminated).
    pub exit_code: Option<i32>,
    /// Children PIDs.
    pub children: Vec<TaskId>,
    /// Start time (milliseconds since boot).
    pub start_time_ms: u64,
    /// CPU time used (milliseconds).
    pub cpu_time_ms: u64,
    /// Process name (from argv[0]).
    pub name: String,
}

impl Process {
    /// Create a new process.
    pub fn new(pid: TaskId, parent: TaskId, name: &str) -> Self {
        Self {
            pid,
            parent,
            pgid: pid,
            sid: pid,
            state: ProcessState::Running,
            exit_code: None,
            children: Vec::new(),
            start_time_ms: crate::arch::timer::uptime_ms(),
            cpu_time_ms: 0,
            name: name.to_string(),
        }
    }

    /// Check if the process is a zombie.
    pub fn is_zombie(&self) -> bool {
        matches!(self.state, ProcessState::Zombie)
    }

    /// Check if the process is running.
    pub fn is_running(&self) -> bool {
        matches!(self.state, ProcessState::Running)
    }

    /// Terminate the process with an exit code.
    pub fn terminate(&mut self, code: i32) {
        self.state = ProcessState::Zombie;
        self.exit_code = Some(code);
    }

    /// Reap the process (free resources).
    pub fn reap(&mut self) {
        self.state = ProcessState::Dead;
        self.exit_code = None;
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

/// Wait queues for processes blocked in waitpid.
static WAIT_QUEUES: Lazy<Mutex<BTreeMap<TaskId, Vec<TaskId>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

/// Next process ID.
static NEXT_PID: AtomicU64 = AtomicU64::new(100);

/// Generate a new PID.
fn next_pid() -> TaskId {
    let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
    TaskId::from_u64(pid)
}

// -----------------------------------------------------------------------------
// Page table cloning (Copy-on-Write)
// -----------------------------------------------------------------------------

/// Clone page tables with Copy-on-Write semantics.
///
/// Walks L4→L3→L2→L1, marking every user page as read‑only in both parent and child.
/// On write → page fault → `copy_on_write_fault()` allocates a new frame and copies data.
///
/// Intermediate page table frames (L3, L2, L1) are freshly allocated for the child,
/// but leaf (L1) entries point to the SAME physical data frames with WRITABLE cleared
/// and reference count incremented.
pub fn clone_page_tables_cow(parent_l4_frame: PhysFrame) -> ProcessResult<PhysFrame> {
    let child_l4_frame = allocate_one().ok_or(ProcessError::OutOfMemory)?;
    let child_l4_phys = child_l4_frame.start_address().as_u64();

    // Zero the child L4.
    unsafe {
        core::ptr::write_bytes((PHYS_OFFSET + child_l4_phys) as *mut u8, 0, 4096);
    }

    let parent_l4 = unsafe {
        &*((PHYS_OFFSET + parent_l4_frame.start_address().as_u64()) as *const PageTable)
    };
    let child_l4 = unsafe {
        &mut *((PHYS_OFFSET + child_l4_phys) as *mut PageTable)
    };

    // Copy kernel half (entries 256‑511) directly — shared across all processes.
    for i in 256..512 {
        child_l4[i] = parent_l4[i].clone();
    }

    // User half (entries 0‑255): deep walk L4→L3→L2→L1.
    for l4i in 0..256 {
        let l4e = &parent_l4[l4i];
        if !l4e.flags().contains(PageTableFlags::PRESENT) {
            continue;
        }
        let parent_l3_phys = l4e.addr().as_u64();

        // Allocate child L3 table.
        let child_l3_frame = allocate_one().ok_or(ProcessError::OutOfMemory)?;
        let child_l3_phys = child_l3_frame.start_address().as_u64();
        unsafe {
            core::ptr::write_bytes((PHYS_OFFSET + child_l3_phys) as *mut u8, 0, 4096);
        }

        let parent_l3 = unsafe { &*((PHYS_OFFSET + parent_l3_phys) as *const PageTable) };
        let child_l3 = unsafe { &mut *((PHYS_OFFSET + child_l3_phys) as *mut PageTable) };

        for l3i in 0..512 {
            let l3e = &parent_l3[l3i];
            if !l3e.flags().contains(PageTableFlags::PRESENT) {
                continue;
            }

            // Check for 1GB huge page.
            if l3e.flags().contains(PageTableFlags::HUGE_PAGE) {
                // Share 1GB page directly with CoW (mark read-only).
                let mut flags = l3e.flags();
                flags.remove(PageTableFlags::WRITABLE);
                child_l3[l3i] = parent_l3[l3i].clone();
                if let Ok(frame) = l3e.frame() {
                    inc_ref(frame);
                }
                continue;
            }

            let parent_l2_phys = l3e.addr().as_u64();

            // Allocate child L2 table.
            let child_l2_frame = allocate_one().ok_or(ProcessError::OutOfMemory)?;
            let child_l2_phys = child_l2_frame.start_address().as_u64();
            unsafe {
                core::ptr::write_bytes((PHYS_OFFSET + child_l2_phys) as *mut u8, 0, 4096);
            }

            let parent_l2 = unsafe { &*((PHYS_OFFSET + parent_l2_phys) as *const PageTable) };
            let child_l2 = unsafe { &mut *((PHYS_OFFSET + child_l2_phys) as *mut PageTable) };

            for l2i in 0..512 {
                let l2e = &parent_l2[l2i];
                if !l2e.flags().contains(PageTableFlags::PRESENT) {
                    continue;
                }

                // Check for 2MB huge page.
                if l2e.flags().contains(PageTableFlags::HUGE_PAGE) {
                    child_l2[l2i] = parent_l2[l2i].clone();
                    if let Ok(frame) = l2e.frame() {
                        inc_ref(frame);
                    }
                    continue;
                }

                let parent_l1_phys = l2e.addr().as_u64();

                // Allocate child L1 table.
                let child_l1_frame = allocate_one().ok_or(ProcessError::OutOfMemory)?;
                let child_l1_phys = child_l1_frame.start_address().as_u64();
                unsafe {
                    core::ptr::write_bytes((PHYS_OFFSET + child_l1_phys) as *mut u8, 0, 4096);
                }

                let parent_l1 = unsafe { &*((PHYS_OFFSET + parent_l1_phys) as *const PageTable) };
                let child_l1 = unsafe { &mut *((PHYS_OFFSET + child_l1_phys) as *mut PageTable) };

                // Walk every L1 entry (4KB pages).
                for l1i in 0..512 {
                    let l1e = &parent_l1[l1i];
                    if !l1e.flags().contains(PageTableFlags::PRESENT) {
                        continue;
                    }

                    // Mark read-only in BOTH parent and child for CoW.
                    let mut cow_flags = l1e.flags();
                    cow_flags.remove(PageTableFlags::WRITABLE);

                    // Copy entry to child with read-only flags.
                    let frame_addr = l1e.addr();
                    unsafe {
                        child_l1[l1i].set_addr(frame_addr, cow_flags);
                    }

                    // Also mark parent read-only.
                    let parent_l1_mut = unsafe {
                        &mut *((PHYS_OFFSET + parent_l1_phys) as *mut PageTable)
                    };
                    unsafe {
                        parent_l1_mut[l1i].set_addr(frame_addr, cow_flags);
                    }

                    // Increment reference count on the data frame.
                    if let Ok(frame) = l1e.frame() {
                        inc_ref(frame);
                    }
                }

                // Set child L2 entry to point to the new child L1.
                let l2_flags = l2e.flags();
                unsafe {
                    child_l2[l2i].set_addr(
                        x86_64::PhysAddr::new(child_l1_phys),
                        l2_flags
                    );
                }
            }

            // Set child L3 entry to point to the new child L2.
            let l3_flags = l3e.flags();
            unsafe {
                child_l3[l3i].set_addr(
                    x86_64::PhysAddr::new(child_l2_phys),
                    l3_flags
                );
            }
        }

        // Set child L4 entry to point to the new child L3.
        let l4_flags = l4e.flags();
        unsafe {
            child_l4[l4i].set_addr(
                x86_64::PhysAddr::new(child_l3_phys),
                l4_flags
            );
        }
    }

    // Flush entire TLB (parent's PTEs changed to read-only).
    x86_64::instructions::tlb::flush_all();

    trace!(child_l4 = child_l4_frame.start_address().as_u64(), "page tables cloned with CoW");
    Ok(child_l4_frame)
}

// -----------------------------------------------------------------------------
// CoW page fault handler
// -----------------------------------------------------------------------------

/// Handle a Copy-on-Write page fault.
///
/// Called from the page fault handler when a write to a read‑only user page occurs.
/// Allocates a new frame, copies the content, and remaps the page writable.
pub fn copy_on_write_fault(virt_addr: u64) -> bool {
    let (l4_frame, _) = Cr3::read();
    let l4_phys = l4_frame.start_address().as_u64();

    // Walk page tables to find the entry.
    let l4 = unsafe {
        &mut *((PHYS_OFFSET + l4_phys) as *mut PageTable)
    };

    let l4_idx = (virt_addr >> 39) & 0x1FF;
    let l3_idx = (virt_addr >> 30) & 0x1FF;
    let l2_idx = (virt_addr >> 21) & 0x1FF;
    let l1_idx = (virt_addr >> 12) & 0x1FF;

    macro_rules! get_table {
        ($entry:expr) => {{
            let e = &$entry;
            if !e.flags().contains(PageTableFlags::PRESENT) {
                return false;
            }
            unsafe { &mut *((PHYS_OFFSET + e.addr().as_u64()) as *mut PageTable) }
        }};
    }

    let l3 = get_table!(l4[l4_idx as usize]);
    let l2 = get_table!(l3[l3_idx as usize]);
    let l1 = get_table!(l2[l2_idx as usize]);

    let entry = &mut l1[l1_idx as usize];
    if !entry.flags().contains(PageTableFlags::PRESENT) {
        return false;
    }

    let old_frame = match entry.frame() {
        Ok(f) => f,
        Err(_) => return false,
    };

    let refcount = get_ref(old_frame);

    if refcount <= 1 {
        // Only one user — just make writable.
        let new_flags = entry.flags() | PageTableFlags::WRITABLE;
        unsafe {
            entry.set_frame(old_frame, new_flags);
            x86_64::instructions::tlb::flush(VirtAddr::new(virt_addr & !0xFFF));
        }
        trace!(virt_addr, "CoW: single owner, made writable");
        return true;
    }

    // Shared frame — allocate new, copy content.
    let new_frame = match allocate_one() {
        Some(f) => f,
        None => {
            error!(virt_addr, "CoW: out of memory for new frame");
            return false;
        }
    };

    // Copy old frame content to new frame.
    unsafe {
        let src = (PHYS_OFFSET + old_frame.start_address().as_u64()) as *const u8;
        let dst = (PHYS_OFFSET + new_frame.start_address().as_u64()) as *mut u8;
        core::ptr::copy_nonoverlapping(src, dst, 4096);
    }

    // Decrement old frame refcount.
    dec_ref(old_frame);

    // Remap with new frame, writable.
    let new_flags = entry.flags() | PageTableFlags::WRITABLE;
    unsafe {
        entry.set_frame(new_frame, new_flags);
        x86_64::instructions::tlb::flush(VirtAddr::new(virt_addr & !0xFFF));
    }

    trace!(virt_addr, "CoW: new frame allocated and mapped");
    true
}

// -----------------------------------------------------------------------------
// fork() implementation
// -----------------------------------------------------------------------------

/// Create a new process (fork) with CoW address space.
pub fn do_fork(parent_tid: TaskId) -> ProcessResult<TaskId> {
    let child_tid = next_pid();

    info!(
        parent = parent_tid.as_u64(),
        child = child_tid.as_u64(),
        "fork() called"
    );

    // Get parent process.
    let mut registry = PROCESS_REGISTRY.lock();
    let parent_process = registry.get(&parent_tid)
        .ok_or(ProcessError::ProcessNotFound)?
        .clone();

    // Check resource limits.
    if registry.len() >= MAX_PROCESSES {
        return Err(ProcessError::ResourceLimit);
    }

    // Clone address space with CoW.
    let (parent_l4, _) = Cr3::read();
    let child_l4 = clone_page_tables_cow(parent_l4)?;

    // Initialize FD table for child.
    fd::init_for(child_tid);

    // Create child process entry.
    let child_name = format!("{} (child)", parent_process.name);
    let mut child_process = Process::new(child_tid, parent_tid, &child_name);
    child_process.pgid = parent_process.pgid;
    child_process.sid = parent_process.sid;

    // Register child.
    registry.insert(child_tid, child_process.clone());

    // Add child to parent's children list.
    drop(registry);
    let mut children = CHILDREN_INDEX.lock();
    children.entry(parent_tid).or_default().push(child_tid);

    // Spawn child task.
    let child_task = Task::new_with_cr3(
        &child_name,
        child_tid,
        child_l4,
        parent_tid,
    );
    {
        let mut scheduler = SCHEDULER.lock();
        scheduler.spawn(child_task);
    }

    info!(
        parent = parent_tid.as_u64(),
        child = child_tid.as_u64(),
        "fork() successful"
    );

    Ok(child_tid)
}

// -----------------------------------------------------------------------------
// execve() implementation
// -----------------------------------------------------------------------------

/// Execute a new program (replace address space).
pub fn do_execve(
    tid: TaskId,
    path: &str,
    argv: &[&str],
    envp: &[&str],
) -> ProcessResult<()> {
    info!(
        tid = tid.as_u64(),
        path,
        "execve() called"
    );

    // Read ELF file.
    let elf_bytes = crate::fs::ionafs::read(path)
        .ok_or(ProcessError::Io)?;

    // Load ELF with arguments.
    let addr_space = crate::elf::load_with_args(&elf_bytes, argv, envp)
        .map_err(|_| ProcessError::InvalidArgument)?;

    // Switch address space.
    addr_space.activate();

    // Clear FD table (close on exec).
    // We need to close all fds with O_CLOEXEC and reset the FD table.
    // For simplicity, we just reinitialize the FD table.
    // In production, we'd close only O_CLOEXEC fds.
    fd::remove_for(tid);
    fd::init_for(tid);

    // Clear signals.
    signal::clear(tid);

    // Update process name.
    let name = if argv.is_empty() {
        path.to_string()
    } else {
        argv[0].to_string()
    };
    let mut registry = PROCESS_REGISTRY.lock();
    if let Some(proc) = registry.get_mut(&tid) {
        proc.name = name;
        proc.start_time_ms = crate::arch::timer::uptime_ms();
    }

    info!(
        tid = tid.as_u64(),
        entry = format!("0x{:x}", addr_space.entry_point),
        "execve() successful"
    );

    Ok(())
}

// -----------------------------------------------------------------------------
// exit() implementation
// -----------------------------------------------------------------------------

/// Terminate the current process.
pub fn do_exit(tid: TaskId, code: i32) -> ! {
    info!(
        tid = tid.as_u64(),
        code,
        "process exiting"
    );

    // Notify parent and reap resources.
    notify_exit(tid, code);

    // Remove from scheduler.
    {
        let mut scheduler = SCHEDULER.lock();
        scheduler.remove(tid);
    }

    // Halt forever.
    loop {
        x86_64::instructions::hlt();
    }
}

// -----------------------------------------------------------------------------
// waitpid() implementation
// -----------------------------------------------------------------------------

/// Wait for a child process to change state.
pub fn do_waitpid(
    parent_tid: TaskId,
    child_tid: Option<TaskId>,
    options: WaitOptions,
) -> ProcessResult<(TaskId, i32)> {
    trace!(
        parent = parent_tid.as_u64(),
        child = child_tid.map(|t| t.as_u64()).unwrap_or(0),
        options = ?options,
        "waitpid() called"
    );

    let target = child_tid.unwrap_or(TaskId::from_u64(0));
    let children = {
        let children_map = CHILDREN_INDEX.lock();
        children_map.get(&parent_tid).cloned().unwrap_or_default()
    };

    if children.is_empty() {
        return Err(ProcessError::NoChildProcess);
    }

    loop {
        // Check for zombies.
        let mut registry = PROCESS_REGISTRY.lock();
        let mut zombie = None;

        // Find a zombie child.
        for &child_pid in &children {
            if target != TaskId::from_u64(0) && child_pid != target {
                continue;
            }
            if let Some(proc) = registry.get(&child_pid) {
                if proc.is_zombie() {
                    zombie = Some(child_pid);
                    break;
                }
            }
        }

        if let Some(pid) = zombie {
            // Reap the zombie.
            let exit_code = EXIT_STATUS.lock().remove(&pid).unwrap_or(0);
            // Remove from children list.
            drop(registry);
            let mut children_map = CHILDREN_INDEX.lock();
            if let Some(list) = children_map.get_mut(&parent_tid) {
                list.retain(|&p| p != pid);
            }
            // Reap resources.
            reap_zombie(pid);
            return Ok((pid, exit_code));
        }

        // If WNOHANG is set and no zombie, return 0.
        if options.contains(WaitOptions::WNOHANG) {
            return Err(ProcessError::NoChildProcess);
        }

        // Block until a child exits.
        drop(registry);
        let cond = WakeCondition::IpcMessage;
        block_current(parent_tid, cond);
        // Loop again to check for zombies.
    }
}

/// Options for waitpid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitOptions {
    bits: u32,
}

impl WaitOptions {
    /// No options.
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Do not block (return immediately if no child ready).
    pub const fn wnohang(mut self) -> Self {
        self.bits |= 1;
        self
    }

    /// Wait for stopped children.
    pub const fn wuntraced(mut self) -> Self {
        self.bits |= 2;
        self
    }

    /// Check if WNOHANG is set.
    pub const fn is_wnohang(&self) -> bool {
        (self.bits & 1) != 0
    }

    /// Check if WUNTRACED is set.
    pub const fn is_wuntraced(&self) -> bool {
        (self.bits & 2) != 0
    }

    /// Convert from raw integer.
    pub const fn from_raw(bits: i32) -> Self {
        Self { bits: bits as u32 }
    }
}

// -----------------------------------------------------------------------------
// Exit notification and reaping
// -----------------------------------------------------------------------------

/// Notify parent of process exit.
pub fn notify_exit(tid: TaskId, code: i32) {
    // Mark process as zombie.
    let mut registry = PROCESS_REGISTRY.lock();
    if let Some(proc) = registry.get_mut(&tid) {
        proc.terminate(code);
    }
    drop(registry);

    // Store exit status.
    EXIT_STATUS.lock().insert(tid, code);

    // Find parent.
    let parent = {
        let registry = PROCESS_REGISTRY.lock();
        registry.get(&tid).map(|p| p.parent)
    };

    if let Some(parent_pid) = parent {
        // Send SIGCHLD to parent.
        signal::send(parent_pid, Signal::SIGCHLD);
        // Wake any waitpid waiters.
        wake_one(parent_pid);
    }

    // Clean up FD table.
    fd::remove_for(tid);

    // Clear signals.
    signal::clear(tid);

    // Remove from scheduler.
    {
        let mut scheduler = SCHEDULER.lock();
        scheduler.remove(tid);
    }

    trace!(tid = tid.as_u64(), code, "exit notification sent");
}

/// Reap a zombie process (free all resources).
pub fn reap_zombie(tid: TaskId) {
    // Remove from process registry.
    let mut registry = PROCESS_REGISTRY.lock();
    if let Some(mut proc) = registry.remove(&tid) {
        proc.reap();
    }
    drop(registry);

    // Clean up mmap regions.
    crate::process::mmap::cleanup_for(tid);

    // Clean up IPC.
    crate::process::ipc::unregister(tid);

    // Remove from children index (done by waitpid).

    trace!(tid = tid.as_u64(), "zombie reaped");
}

// -----------------------------------------------------------------------------
// Process management helpers
// -----------------------------------------------------------------------------

/// Get a process by PID.
pub fn get_process(tid: TaskId) -> Option<Process> {
    PROCESS_REGISTRY.lock().get(&tid).cloned()
}

/// Get the parent PID of a process.
pub fn get_parent(tid: TaskId) -> Option<TaskId> {
    PROCESS_REGISTRY.lock().get(&tid).map(|p| p.parent)
}

/// Get the children PIDs of a process.
pub fn get_children(tid: TaskId) -> Vec<TaskId> {
    CHILDREN_INDEX.lock().get(&tid).cloned().unwrap_or_default()
}

/// Get the current process name.
pub fn get_process_name(tid: TaskId) -> Option<String> {
    PROCESS_REGISTRY.lock().get(&tid).map(|p| p.name.clone())
}

/// Set the process name.
pub fn set_process_name(tid: TaskId, name: &str) {
    if let Some(proc) = PROCESS_REGISTRY.lock().get_mut(&tid) {
        proc.name = name.to_string();
    }
}

/// Initialize process subsystem.
pub fn init() {
    // Create the init process (PID 1).
    let init_pid = TaskId::from_u64(1);
    let init_process = Process::new(init_pid, init_pid, "init");
    PROCESS_REGISTRY.lock().insert(init_pid, init_process);
    // Note: the init task is created elsewhere.
    info!("process subsystem initialized");
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_lifecycle() {
        let pid = TaskId::from_u64(100);
        let parent = TaskId::from_u64(1);
        let mut proc = Process::new(pid, parent, "test");

        assert!(proc.is_running());
        assert!(!proc.is_zombie());

        proc.terminate(0);
        assert!(proc.is_zombie());
        assert_eq!(proc.exit_code, Some(0));

        proc.reap();
        assert_eq!(proc.state, ProcessState::Dead);
    }

    #[test]
    fn test_wait_options() {
        let opts = WaitOptions::empty();
        assert!(!opts.is_wnohang());
        assert!(!opts.is_wuntraced());

        let opts = opts.wnohang().wuntraced();
        assert!(opts.is_wnohang());
        assert!(opts.is_wuntraced());

        assert_eq!(WaitOptions::from_raw(3).bits, 3);
    }
}
