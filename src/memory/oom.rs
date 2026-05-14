//! OOM Killer — kill lowest-priority task when heap is exhausted
use crate::sched::SCHEDULER;

/// Called from alloc_error_handler when heap allocation fails.
/// Kills the lowest-priority task and retries.
pub fn oom_kill() {
    crate::serial_println!("[OOM] Out of memory — killing lowest priority task");
    let mut sched = SCHEDULER.lock();
    sched.oom_kill_lowest();
}

/// Global alloc error — called by #[alloc_error_handler]
pub fn handle_alloc_error(layout: core::alloc::Layout) -> ! {
    crate::serial_println!(
        "[OOM] allocation failed: size={} align={}", layout.size(), layout.align());
    oom_kill();
    // Try killing more tasks before final panic
    for _ in 0..3 {
        let mut s = crate::sched::SCHEDULER.lock();
        s.oom_kill_lowest();
        drop(s);
    }
    // If we reach here, the system is unrecoverable
    crate::serial_println!("[OOM] FATAL: unable to recover after killing tasks");
    panic!("OOM: unrecoverable — killed multiple tasks, still no memory");
}
