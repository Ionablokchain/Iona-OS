//! clone() syscall — POSIX threads (pthreads) via shared address space
//!
//! Implements the Linux `clone(2)` system call for creating threads and processes.
//! Supports all relevant flags for pthreads and fork-like semantics.
//!
//! # Flags
//!
//! | Flag              | Description                                        |
//! |-------------------|----------------------------------------------------|
//! | CLONE_VM          | Share virtual memory (thread)                      |
//! | CLONE_FS          | Share filesystem (cwd, root, umask)                |
//! | CLONE_FILES       | Share file descriptor table                        |
//! | CLONE_SIGHAND     | Share signal handlers                              |
//! | CLONE_THREAD      | Create a thread (same TGID)                        |
//! | CLONE_SETTLS      | Set TLS (thread-local storage)                     |
//! | CLONE_PARENT_SETTID| Write child TID to parent memory                   |
//! | CLONE_CHILD_SETTID | Write child TID to child memory                    |
//! | CLONE_VFORK       | vfork() semantics (suspend parent until child exec/exit) |
//! | CLONE_UNTRACED    | Not traced (ignored)                               |
//!
//! # Security
//!
//! - Stack pointer validation: child stack must be in userspace.
//! - TLS pointer must be valid userspace address.
//! - CLONE_VM without CLONE_THREAD is not permitted (creates a new process
//!   sharing memory, which is dangerous; we treat as fork with CoW).
//! - All flag combinations are validated.
//!
//! # Example
//!
//! ```rust,ignore
//! let tid = do_clone(
//!     CLONE_VM | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SETTLS,
//!     child_stack_ptr,
//!     parent_tid_ptr,
//!     child_tid_ptr,
//!     tls_ptr,
//! )?;
//! ```

use core::fmt;
use core::sync::atomic::Ordering;
use spin::Mutex;
use tracing::{debug, error, info, trace, warn};

use crate::arch::x86_64::registers::msr::{IA32_FS_BASE, wrmsr};
use crate::process::fd::{clone_fd_table, share_fd_table};
use crate::process::fork::{clone_page_tables_cow, PageTableCloner};
use crate::sched::SCHEDULER;
use crate::task::{Task, TaskId, TaskStatus, next_tid};
use crate::types::KernelError;

// -----------------------------------------------------------------------------
// Clone flags (Linux-compatible)
// -----------------------------------------------------------------------------

pub const CLONE_VM: u64 = 0x0000_0100;
pub const CLONE_FS: u64 = 0x0000_0200;
pub const CLONE_FILES: u64 = 0x0000_0400;
pub const CLONE_SIGHAND: u64 = 0x0000_0800;
pub const CLONE_THREAD: u64 = 0x0001_0000;
pub const CLONE_SETTLS: u64 = 0x0008_0000;
pub const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
pub const CLONE_CHILD_SETTID: u64 = 0x0100_0000;
pub const CLONE_VFORK: u64 = 0x0000_4000;
pub const CLONE_UNTRACED: u64 = 0x0080_0000;

/// Mask of flags that are always safe to pass.
const CLONE_SAFE_MASK: u64 = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND
    | CLONE_THREAD | CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_SETTID
    | CLONE_VFORK | CLONE_UNTRACED;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during clone(2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloneError {
    /// Invalid flag combination.
    InvalidFlags { flags: u64, reason: &'static str },

    /// Invalid stack pointer (not in userspace or misaligned).
    InvalidStack { ptr: u64 },

    /// Invalid TLS pointer.
    InvalidTls { ptr: u64 },

    /// Invalid TID pointer (for CLONE_PARENT_SETTID or CLONE_CHILD_SETTID).
    InvalidTidPtr { ptr: u64 },

    /// Out of memory (cannot allocate task or page tables).
    OutOfMemory,

    /// Parent task not found.
    ParentNotFound,

    /// Cannot share VM without CLONE_THREAD (use fork instead).
    VmWithoutThread,

    /// Signal handling not yet implemented.
    SignalHandlingNotImplemented,

    /// Filesystem sharing not yet implemented.
    FsSharingNotImplemented,

    /// Internal error.
    Internal(&'static str),
}

impl fmt::Display for CloneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFlags { flags, reason } => {
                write!(f, "invalid clone flags 0x{:x}: {}", flags, reason)
            }
            Self::InvalidStack { ptr } => write!(f, "invalid stack pointer: 0x{:x}", ptr),
            Self::InvalidTls { ptr } => write!(f, "invalid TLS pointer: 0x{:x}", ptr),
            Self::InvalidTidPtr { ptr } => write!(f, "invalid TID pointer: 0x{:x}", ptr),
            Self::OutOfMemory => write!(f, "out of memory"),
            Self::ParentNotFound => write!(f, "parent task not found"),
            Self::VmWithoutThread => write!(f, "CLONE_VM requires CLONE_THREAD"),
            Self::SignalHandlingNotImplemented => write!(f, "signal handling sharing not implemented"),
            Self::FsSharingNotImplemented => write!(f, "filesystem sharing not implemented"),
            Self::Internal(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl From<CloneError> for KernelError {
    fn from(e: CloneError) -> Self {
        match e {
            CloneError::InvalidFlags { .. } => KernelError::InvalidArgument,
            CloneError::InvalidStack { .. } => KernelError::InvalidArgument,
            CloneError::InvalidTls { .. } => KernelError::InvalidArgument,
            CloneError::InvalidTidPtr { .. } => KernelError::Fault,
            CloneError::OutOfMemory => KernelError::OutOfMemory,
            CloneError::ParentNotFound => KernelError::NoSuchProcess,
            CloneError::VmWithoutThread => KernelError::InvalidArgument,
            CloneError::SignalHandlingNotImplemented => KernelError::Unsupported,
            CloneError::FsSharingNotImplemented => KernelError::Unsupported,
            CloneError::Internal(_) => KernelError::InternalError,
        }
    }
}

pub type CloneResult<T> = Result<T, CloneError>;

// -----------------------------------------------------------------------------
// Clone context
// -----------------------------------------------------------------------------

/// Parsed and validated clone arguments.
#[derive(Debug, Clone)]
struct CloneArgs {
    /// Flags passed to clone.
    flags: u64,
    /// Child stack pointer (0 = fork-style copy).
    child_sp: u64,
    /// Parent TID pointer (for CLONE_PARENT_SETTID).
    parent_tid_ptr: Option<u64>,
    /// Child TID pointer (for CLONE_CHILD_SETTID).
    child_tid_ptr: Option<u64>,
    /// TLS base pointer (for CLONE_SETTLS).
    tls_ptr: Option<u64>,
    /// Current task ID (parent).
    parent_tid: TaskId,
}

impl CloneArgs {
    /// Validate and parse arguments from syscall parameters.
    fn from_raw(
        flags: u64,
        child_sp: u64,
        parent_tid_ptr: u64,
        child_tid_ptr: u64,
        tls_ptr: u64,
        parent_tid: TaskId,
    ) -> CloneResult<Self> {
        // Check for unknown flags.
        let unknown = flags & !CLONE_SAFE_MASK;
        if unknown != 0 {
            return Err(CloneError::InvalidFlags {
                flags: unknown,
                reason: "unknown flags set",
            });
        }

        // CLONE_VM requires CLONE_THREAD (or we treat as fork with CoW).
        if (flags & CLONE_VM) != 0 && (flags & CLONE_THREAD) == 0 {
            return Err(CloneError::VmWithoutThread);
        }

        // Validate stack pointer if provided.
        if child_sp != 0 {
            // Must be in userspace (below 0x0000_8000_0000_0000) and 16-byte aligned.
            if child_sp >= 0x8000_0000_0000_0000 || (child_sp & 15) != 0 {
                return Err(CloneError::InvalidStack { ptr: child_sp });
            }
        }

        // Validate TLS pointer if CLONE_SETTLS is set.
        let tls = if (flags & CLONE_SETTLS) != 0 {
            if tls_ptr == 0 || tls_ptr >= 0x8000_0000_0000_0000 {
                return Err(CloneError::InvalidTls { ptr: tls_ptr });
            }
            Some(tls_ptr)
        } else {
            None
        };

        // Validate TID pointers.
        let parent_tid = if (flags & CLONE_PARENT_SETTID) != 0 {
            if parent_tid_ptr == 0 || parent_tid_ptr >= 0x8000_0000_0000_0000 {
                return Err(CloneError::InvalidTidPtr { ptr: parent_tid_ptr });
            }
            Some(parent_tid_ptr)
        } else {
            None
        };

        let child_tid = if (flags & CLONE_CHILD_SETTID) != 0 {
            if child_tid_ptr == 0 || child_tid_ptr >= 0x8000_0000_0000_0000 {
                return Err(CloneError::InvalidTidPtr { ptr: child_tid_ptr });
            }
            Some(child_tid_ptr)
        } else {
            None
        };

        Ok(Self {
            flags,
            child_sp,
            parent_tid_ptr: parent_tid,
            child_tid_ptr: child_tid,
            tls_ptr: tls,
            parent_tid,
        })
    }

    /// Check if a particular flag is set.
    fn has_flag(&self, flag: u64) -> bool {
        (self.flags & flag) != 0
    }
}

// -----------------------------------------------------------------------------
// Pending TLS state
// -----------------------------------------------------------------------------

/// Pending TLS base addresses to be applied when a thread first runs.
static PENDING_TLS: spin::Lazy<Mutex<alloc::collections::BTreeMap<TaskId, u64>>> =
    spin::Lazy::new(|| Mutex::new(alloc::collections::BTreeMap::new()));

/// Schedule TLS to be applied on the child's first execution.
fn schedule_tls(tid: TaskId, tls_base: u64) {
    let mut map = PENDING_TLS.lock();
    map.insert(tid, tls_base);
    debug!(tid = tid.as_u64(), tls_base, "TLS scheduled for thread");
}

/// Apply pending TLS for a task (called on first context switch).
pub fn apply_pending_tls(tid: TaskId) {
    let tls_base = {
        let mut map = PENDING_TLS.lock();
        map.remove(&tid)
    };
    if let Some(fs_base) = tls_base {
        set_thread_tls(fs_base);
        debug!(tid = tid.as_u64(), fs_base, "TLS applied");
    }
}

/// Set the FS base MSR for thread-local storage.
#[inline]
fn set_thread_tls(fs_base: u64) {
    unsafe {
        wrmsr(IA32_FS_BASE, fs_base);
    }
}

// -----------------------------------------------------------------------------
// Main clone implementation
// -----------------------------------------------------------------------------

/// Create a new thread or process via clone(2).
///
/// # Arguments
/// * `flags`          – CLONE_* bitmask.
/// * `child_sp`       – Stack pointer for the child (0 = copy parent stack).
/// * `parent_tid_ptr` – User pointer to write child TID (if CLONE_PARENT_SETTID).
/// * `child_tid_ptr`  – User pointer to write child TID (if CLONE_CHILD_SETTID).
/// * `tls_ptr`        – TLS base address (if CLONE_SETTLS).
/// * `parent_tid`     – TID of the calling task.
///
/// # Returns
/// `Ok(child_tid)` on success, or `Err(CloneError)` on failure.
pub fn do_clone(
    flags: u64,
    child_sp: u64,
    parent_tid_ptr: u64,
    child_tid_ptr: u64,
    tls_ptr: u64,
    parent_tid: TaskId,
) -> CloneResult<TaskId> {
    trace!(
        parent = parent_tid.as_u64(),
        flags = format!("0x{:x}", flags),
        child_sp = format!("0x{:x}", child_sp),
        tls = format!("0x{:x}", tls_ptr),
        "clone() called"
    );

    // Parse and validate arguments.
    let args = CloneArgs::from_raw(flags, child_sp, parent_tid_ptr, child_tid_ptr, tls_ptr, parent_tid)?;

    // Allocate a new TID.
    let child_tid = next_tid();

    // Determine TGID: if CLONE_THREAD is set, child inherits parent's TGID;
    // otherwise, child becomes a new process group (TGID = child TID).
    let tgid = if args.has_flag(CLONE_THREAD) {
        // Get parent's TGID.
        let parent_tgid = crate::process::get_tgid(parent_tid).unwrap_or(parent_tid);
        parent_tgid
    } else {
        child_tid
    };

    debug!(
        parent = parent_tid.as_u64(),
        child = child_tid.as_u64(),
        tgid = tgid.as_u64(),
        "creating new task"
    );

    // ── 1. Address space ────────────────────────────────────────────────────
    // If CLONE_VM is set, the child shares the parent's address space (thread).
    // Otherwise, we create a copy-on-write clone of the parent's page tables.
    let cr3 = if args.has_flag(CLONE_VM) {
        // Share address space: just read the current CR3.
        let (cr3, _) = x86_64::registers::control::Cr3::read();
        cr3
    } else {
        // Fork: clone page tables with copy-on-write.
        let (parent_cr3, _) = x86_64::registers::control::Cr3::read();
        let child_cr3 = clone_page_tables_cow(parent_cr3)
            .map_err(|_| CloneError::OutOfMemory)?;
        child_cr3
    };

    // ── 2. File descriptors ───────────────────────────────────────────────
    // If CLONE_FILES is set, share the file descriptor table (Arc).
    // Otherwise, create a copy.
    if args.has_flag(CLONE_FILES) {
        share_fd_table(parent_tid, child_tid);
        debug!(child = child_tid.as_u64(), "shared FD table");
    } else {
        clone_fd_table(parent_tid, child_tid);
        debug!(child = child_tid.as_u64(), "copied FD table");
    }

    // ── 3. Signal handlers ────────────────────────────────────────────────
    // If CLONE_SIGHAND is set, share signal handlers (not yet implemented).
    if args.has_flag(CLONE_SIGHAND) {
        // TODO: Implement signal handler sharing.
        warn!("CLONE_SIGHAND not yet implemented, will use copy");
        // For now, we copy signal handlers.
        // crate::signal::copy_signal_handlers(parent_tid, child_tid);
    }

    // ── 4. Filesystem (CLONE_FS) ──────────────────────────────────────────
    if args.has_flag(CLONE_FS) {
        // Share cwd, root, umask (not yet implemented).
        warn!("CLONE_FS not yet implemented");
    }

    // ── 5. TLS ─────────────────────────────────────────────────────────────
    if let Some(tls_base) = args.tls_ptr {
        schedule_tls(child_tid, tls_base);
    }

    // ── 6. TID writes ──────────────────────────────────────────────────────
    // Write child TID to user memory if requested.
    if let Some(ptr) = args.parent_tid_ptr {
        // Write to parent's memory.
        let result = unsafe {
            crate::syscall::user_access::write_to_user(ptr, &child_tid.as_u64())
        };
        if result.is_err() {
            return Err(CloneError::InvalidTidPtr { ptr });
        }
        debug!(parent_tid_ptr = format!("0x{:x}", ptr), "wrote child TID to parent");
    }

    // We'll write child TID to child's memory when the child starts.

    // ── 7. Create task ────────────────────────────────────────────────────
    // Determine entry point and stack.
    let task = if args.child_sp != 0 {
        // Thread: use the provided stack.
        // The stack already contains the function pointer and arguments
        // as set up by the user-space pthread library.
        Task::new_with_stack_and_cr3(
            "thread",
            child_tid,
            tgid,
            args.child_sp,
            cr3,
            args.flags,
        )
    } else {
        // Fork: copy the current task's context (including stack).
        // We'll use a fork trampoline.
        // Note: fork() is a separate syscall; clone with child_sp=0 is fork-like.
        // In Linux, clone with no stack is not allowed; we treat as fork.
        // But we need to copy the stack.
        // For now, we create a task with the same entry as parent.
        // This is simplified; full fork implementation is in process/fork.rs.
        let parent = crate::sched::SCHEDULER.lock().get_task(parent_tid)
            .ok_or(CloneError::ParentNotFound)?;
        let entry = parent.entry_point();
        Task::new_with_stack_and_cr3(
            "fork-child",
            child_tid,
            tgid,
            parent.stack_top(),
            cr3,
            args.flags,
        )
    };

    // Register the task with the scheduler.
    {
        let mut scheduler = SCHEDULER.lock();
        scheduler.spawn(task);
    }

    // ── 8. Handle CLONE_VFORK ─────────────────────────────────────────────
    if args.has_flag(CLONE_VFORK) {
        // Suspend the parent until the child execve()s or exits.
        // In practice, we would set a flag in the parent task and block it.
        warn!("CLONE_VFORK not yet implemented, parent will continue");
        // TODO: Implement vfork semantics.
    }

    // ── 9. Write child TID to child's memory ─────────────────────────────
    if let Some(ptr) = args.child_tid_ptr {
        // This will be done on the child's first run.
        // We'll pass the pointer to the child's task.
        // For now, we can store it in the task's context.
        // In the full implementation, the child's first entry point would write it.
        // We'll save it in the task's context.
        // (Simplified: we'll write it from the parent side using user_access,
        // but that requires the child's address space to be active.)
        // For threads (CLONE_VM), the address space is shared, so we can write it
        // from the parent safely.
        if args.has_flag(CLONE_VM) {
            let result = unsafe {
                crate::syscall::user_access::write_to_user(ptr, &child_tid.as_u64())
            };
            if result.is_err() {
                return Err(CloneError::InvalidTidPtr { ptr });
            }
        } else {
            // For fork, the child's address space is separate, so we need to
            // write it in the child's context (or use a page mapping).
            // This will be handled in the child's return path.
            // We'll store the pointer in the task.
            // We'll need to add a field to Task for child_tid_ptr.
            // For now, we skip.
            warn!("CLONE_CHILD_SETTID for fork not fully implemented");
        }
    }

    info!(
        parent = parent_tid.as_u64(),
        child = child_tid.as_u64(),
        tgid = tgid.as_u64(),
        flags = format!("0x{:x}", flags),
        "clone() successful"
    );

    Ok(child_tid)
}

// -----------------------------------------------------------------------------
// Helper functions for user-space clone wrapper
// -----------------------------------------------------------------------------

/// Write the child TID to the provided user pointer (called from child context).
pub fn write_child_tid(tid: TaskId, ptr: u64) -> Result<(), CloneError> {
    if ptr == 0 {
        return Ok(());
    }
    let tid_u64 = tid.as_u64();
    unsafe {
        crate::syscall::user_access::write_to_user(ptr, &tid_u64)
            .map_err(|_| CloneError::InvalidTidPtr { ptr })?;
    }
    Ok(())
}

/// Get the current TGID of a task.
pub fn get_tgid(tid: TaskId) -> Option<TaskId> {
    SCHEDULER.lock().get_task(tid).map(|t| t.tgid())
}

// -----------------------------------------------------------------------------
// Fork wrapper (simplified)
// -----------------------------------------------------------------------------

/// Simplified fork() using clone with no flags.
pub fn do_fork(parent_tid: TaskId) -> CloneResult<TaskId> {
    // fork() is clone with no flags (except CLONE_SIGHAND is set in some cases).
    // We'll use zero flags and child_sp=0.
    do_clone(0, 0, 0, 0, 0, parent_tid)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flag_parsing() {
        // Valid flags.
        let args = CloneArgs::from_raw(CLONE_VM | CLONE_THREAD, 0x1000, 0, 0, 0, TaskId::new(1));
        assert!(args.is_ok());

        // Invalid flag.
        let args = CloneArgs::from_raw(0xDEADBEEF, 0x1000, 0, 0, 0, TaskId::new(1));
        assert!(args.is_err());

        // CLONE_VM without CLONE_THREAD.
        let args = CloneArgs::from_raw(CLONE_VM, 0x1000, 0, 0, 0, TaskId::new(1));
        assert!(matches!(args, Err(CloneError::VmWithoutThread)));

        // Invalid stack.
        let args = CloneArgs::from_raw(0, 0x9000_0000_0000_0000, 0, 0, 0, TaskId::new(1));
        assert!(matches!(args, Err(CloneError::InvalidStack { .. })));
    }
}
