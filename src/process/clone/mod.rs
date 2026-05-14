//! clone() syscall — POSIX threads (pthreads) via shared address space
//!
//! clone() flags (subset relevant pentru pthreads):
//!   CLONE_VM        (0x100)  — share virtual memory (address space)
//!   CLONE_FS        (0x200)  — share filesystem (cwd, root, umask)
//!   CLONE_FILES     (0x400)  — share file descriptor table
//!   CLONE_SIGHAND   (0x800)  — share signal handlers
//!   CLONE_THREAD    (0x10000)— thread (same process, same TGID)
//!   CLONE_SETTLS    (0x80000)— set TLS (thread local storage) via TLS ptr
//!
//! pthread_create() calls clone(CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SETTLS)
//!
//! Implementare:
//! - CLONE_VM: child shares CR3 (page tables) cu parent — NU face CoW
//! - CLONE_FILES: child are ACEEAȘI fd_table ca parent (shared Arc)
//! - CLONE_THREAD: child are același TGID ca parent
//! - Stack nou: child primește un stack dedicat (trecut ca argument)

use spin::Mutex;
use crate::task::{Task, TaskId, next_tid};

pub const CLONE_VM:      u64 = 0x0000_0100;
pub const CLONE_FS:      u64 = 0x0000_0200;
pub const CLONE_FILES:   u64 = 0x0000_0400;
pub const CLONE_SIGHAND: u64 = 0x0000_0800;
pub const CLONE_THREAD:  u64 = 0x0001_0000;
pub const CLONE_SETTLS:  u64 = 0x0008_0000;
pub const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
pub const CLONE_CHILD_SETTID:  u64 = 0x0100_0000;

pub struct ThreadInfo {
    pub tid:    TaskId,
    pub tgid:   TaskId, // thread group ID (= main thread TID for threads)
    pub flags:  u64,
    pub tls:    u64,    // thread-local storage pointer
}

/// do_clone — create a new thread or process
///
/// # Arguments
/// * `flags`     — CLONE_* bitmask
/// * `child_sp`  — stack pointer for child (0 = fork-style, copy parent stack)
/// * `parent_tid`— ptr to write child TID in parent (CLONE_PARENT_SETTID)
/// * `child_tid` — ptr to write child TID in child  (CLONE_CHILD_SETTID)
/// * `tls`       — thread-local storage base (CLONE_SETTLS)
pub fn do_clone(
    parent_tid: TaskId,
    flags:      u64,
    child_sp:   u64,
    tls:        u64,
) -> Option<TaskId> {
    let new_tid = next_tid();

    crate::serial_println!(
        "  [CLONE] parent={} → child={} flags=0x{:x} sp=0x{:x}",
        parent_tid, new_tid, flags, child_sp
    );

    // FD table: share if CLONE_FILES, else clone independently
    if flags & CLONE_FILES != 0 {
        // Shared FD table — both threads see same descriptors via Arc
        crate::process::fd::share_fd_table(parent_tid, new_tid);
    } else {
        // Independent copy of FD table (fork semantics)
        crate::process::fd::clone_fd_table(parent_tid, new_tid);
    }

    // Address space: share if CLONE_VM (thread), CoW if not (fork)
    // CLONE_VM: child uses SAME CR3 — writes go to shared memory immediately
    // (no CoW needed — threads share memory by design)
    if flags & CLONE_VM == 0 {
        // Fork semantics: clone page tables with CoW
        let (parent_l4, _) = x86_64::registers::control::Cr3::read();
        crate::process::fork::clone_page_tables_cow(parent_l4)?;
    }
    // CLONE_VM: child inherits current CR3 automatically (same address space)

    // Set TLS if requested (write TLS base to FS.base MSR for child)
    // Will be applied when child first runs via set_thread_tls()
    if flags & CLONE_SETTLS != 0 && tls != 0 {
        // Store TLS to be applied on first context switch to child
        PENDING_TLS.lock().push((new_tid, tls));
    }

    // Create child task
    // If child_sp != 0: use provided stack (thread)
    // If child_sp == 0: copy current stack (fork-style)
    let task = if child_sp != 0 {
        // Thread: starts at fork_return_trampoline with provided stack
        // musl calls: clone(flags, new_stack, ...)
        // new_stack already has fn_ptr + arg set up by musl
        Task::new_with_stack("thread", new_tid, child_sp)
    } else {
        Task::new("fork-child", task_fork_return, new_tid, 1)
    };

    crate::sched::SCHEDULER.lock().spawn(task);

    crate::serial_println!("  [CLONE] thread {} spawned", new_tid);
    Some(new_tid)
}

/// Pending TLS (fs_base) to apply on first run
static PENDING_TLS: spin::Lazy<Mutex<alloc::vec::Vec<(TaskId, u64)>>> =
    spin::Lazy::new(|| Mutex::new(alloc::vec![]));

/// Apply TLS for a task (call on first run of that task)
pub fn apply_pending_tls(tid: TaskId) {
    let tls = {
        let mut p = PENDING_TLS.lock();
        let pos = p.iter().position(|(t, _)| *t == tid);
        pos.map(|i| p.remove(i).1)
    };
    if let Some(fs_base) = tls {
        set_thread_tls(fs_base);
    }
}

/// Set FS.base MSR (thread-local storage pointer for musl/glibc)
fn set_thread_tls(fs_base: u64) {
    unsafe {
        // IA32_FS_BASE MSR = 0xC000_0100
        x86_64::registers::model_specific::Msr::new(0xC000_0100).write(fs_base);
    }
    crate::serial_println!("  [TLS] fs_base=0x{:x}", fs_base);
}

/// Trampoline for fork-style children (returns 0 as child TID)
fn task_fork_return(_: u64) -> ! {
    // Child process returns 0 from fork
    // In real impl: restore saved registers from fork() syscall
    loop { x86_64::instructions::hlt(); }
}
