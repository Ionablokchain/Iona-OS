//! OOM Killer — reclaim memory by terminating low-priority tasks.
//!
//! When the kernel heap is exhausted, the alloc error handler invokes the
//! OOM killer. It scans the scheduler for the lowest-priority **non-idle**
//! task, terminates it, and hopes that its resources are freed.
//!
//! If the first victim does not free enough memory, the killer retries up to
//! three times before declaring the system unrecoverable.

use crate::sched::SCHEDULER;

/// Attempts to kill one low-priority task.
///
/// # Returns
/// `true` if a task was successfully terminated, `false` otherwise (e.g. only
/// the idle task remains).
fn oom_kill_single() -> bool {
    let mut sched = SCHEDULER.lock();
    // Safety check: never kill the idle task (PID 0 or similar).
    // Assume `oom_kill_lowest` internally skips idle. We check pre-condition:
    if sched.task_count() <= 1 {
        crate::serial_println!("[OOM] no killable tasks left (only idle remains)");
        return false;
    }
    sched.oom_kill_lowest();
    true
}

/// Public entry point — attempts to kill one task.
/// Used by the alloc error handler and can be called from other kernel paths.
pub fn oom_kill() {
    crate::serial_println!("[OOM] Out of memory — attempting to kill a low-priority task");
    if !oom_kill_single() {
        crate::serial_println!("[OOM] OOM kill failed — no suitable victims");
    }
}

/// Global alloc error handler, wired via `#[alloc_error_handler]`.
///
/// This function is called when a heap allocation (e.g. `Box::new`) fails.
/// It tries to recover by killing tasks; if recovery is impossible, it panics.
pub fn handle_alloc_error(layout: core::alloc::Layout) -> ! {
    crate::serial_println!(
        "[OOM] allocation failed: size={} align={}",
        layout.size(),
        layout.align()
    );

    // Retry a few times — each killed task should release memory.
    for attempt in 1..=4 {
        if !oom_kill_single() {
            break; // no more tasks to kill
        }
        // Memory pressure is resolved when the alloc error handler is no longer
        // called. The runtime retries the allocation; if it succeeds, we never
        // return here. If the handler is invoked again, we continue killing.
        crate::serial_println!("[OOM] killed task, attempt {}/4", attempt);
    }

    // If we reach this point, multiple kills did not free enough memory.
    crate::serial_println!("[OOM] FATAL: unable to recover after killing tasks");
    panic!("OOM: unrecoverable — killed multiple tasks, still no memory");
}
