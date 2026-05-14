//! futex() — Fast Userspace muTEX
//!
//! Operații:
//!   FUTEX_WAIT(addr, expected): atomically check *addr==expected, if so block
//!   FUTEX_WAKE(addr, n):        wake up to N tasks waiting on addr
//!
//! Addr este o adresă virtuală în userspace. Kernelul NU citește valoarea
//! (deja verificată în userspace) — doar gestionează coada de așteptare.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::{Lazy, Mutex};
use crate::task::TaskId;

pub const FUTEX_WAIT:         u32 = 0;
pub const FUTEX_WAKE:         u32 = 1;
pub const FUTEX_WAIT_PRIVATE: u32 = 128;
pub const FUTEX_WAKE_PRIVATE: u32 = 129;

/// Futex wait queue: virtual address → list of waiting TIDs
static FUTEX_QUEUES: Lazy<Mutex<BTreeMap<u64, Vec<TaskId>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

/// FUTEX_WAIT: block current task on address if *addr == expected
/// Returns: 0 = woken up, -1 = *addr != expected (EAGAIN), -2 = timeout
///
/// Memory ordering: uses SeqCst fence before reading the futex word to ensure
/// all prior stores from other cores are visible. The check-and-enqueue is
/// done atomically under the FUTEX_QUEUES lock to prevent lost wakeups.
pub fn futex_wait(addr: u64, expected: u32, timeout_ms: u64) -> i64 {
    // Full memory barrier: ensure all prior stores from other cores are visible
    // before we read the futex word. This prevents a scenario where:
    //   Core A: store data; store futex_word; FUTEX_WAKE
    //   Core B: FUTEX_WAIT sees old futex_word but misses the data update
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

    let tid = crate::arch::x86_64::percpu::current_tid();

    // Critical section: check value AND enqueue atomically under lock.
    // This prevents the lost-wakeup race where:
    //   Thread A checks *addr == expected (true)
    //   Thread B stores new value + calls FUTEX_WAKE (finds empty queue)
    //   Thread A enqueues itself (missed the wake!)
    {
        let mut queues = FUTEX_QUEUES.lock();

        // Read value at addr in userspace while holding the lock
        let actual = unsafe { (addr as *const core::sync::atomic::AtomicU32).as_ref() }
            .map(|a| a.load(core::sync::atomic::Ordering::Acquire))
            .unwrap_or(u32::MAX);

        if actual != expected {
            return -1; // EAGAIN — value changed before we could block
        }

        // Enqueue while still holding the lock — wake cannot race with us
        queues.entry(addr).or_default().push(tid);
    }
    // Lock released here — now safe for FUTEX_WAKE to find us

    // Memory barrier after enqueue: ensure the queue update is visible
    // to other cores before we enter the blocked state
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

    // Block with optional timeout
    let cond = if timeout_ms > 0 {
        crate::wait::WakeCondition::Timer(crate::arch::x86_64::timer::uptime_ms() + timeout_ms)
    } else {
        crate::wait::WakeCondition::Any
    };

    crate::wait::block_current(tid, cond);

    // Memory barrier on wakeup: ensure we see all stores made by the waker
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

    // Check if we were actually woken or timed out
    // (remove ourselves from queue if still there — timeout case)
    {
        let mut queues = FUTEX_QUEUES.lock();
        if let Some(waiters) = queues.get_mut(&addr) {
            if let Some(pos) = waiters.iter().position(|t| *t == tid) {
                waiters.remove(pos);
                return -2; // timeout — we removed ourselves
            }
        }
    }
    0 // successfully woken by FUTEX_WAKE
}

/// FUTEX_WAKE: wake up to n tasks waiting on address
///
/// Memory ordering: uses SeqCst fence to ensure all stores made before
/// the wake call are visible to woken threads.
pub fn futex_wake(addr: u64, n: u32) -> i64 {
    // Full barrier: ensure stores to shared data are visible before we wake
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

    let mut queues = FUTEX_QUEUES.lock();
    let waiters = match queues.get_mut(&addr) {
        Some(w) => w,
        None    => return 0,
    };

    let count = (n as usize).min(waiters.len());
    let to_wake: Vec<TaskId> = waiters.drain(..count).collect();

    // Clean up empty entries
    if waiters.is_empty() {
        queues.remove(&addr);
    }
    drop(queues);

    // Memory barrier before waking: ensure queue updates are committed
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

    for tid in &to_wake {
        crate::sched::wake_task(*tid);
    }
    to_wake.len() as i64
}

/// FUTEX_REQUEUE: move waiters from one address to another
/// Used for condition variable implementation (pthread_cond_broadcast)
pub fn futex_requeue(addr: u64, new_addr: u64, wake_n: u32, requeue_n: u32) -> i64 {
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

    let mut queues = FUTEX_QUEUES.lock();
    let waiters = match queues.get_mut(&addr) {
        Some(w) => w,
        None    => return 0,
    };

    // Wake up to wake_n
    let wake_count = (wake_n as usize).min(waiters.len());
    let to_wake: Vec<TaskId> = waiters.drain(..wake_count).collect();

    // Requeue up to requeue_n to new_addr
    let requeue_count = (requeue_n as usize).min(waiters.len());
    let to_requeue: Vec<TaskId> = waiters.drain(..requeue_count).collect();

    if waiters.is_empty() { queues.remove(&addr); }

    // Add requeued waiters to new address
    let new_waiters = queues.entry(new_addr).or_default();
    for tid in &to_requeue {
        new_waiters.push(*tid);
    }
    drop(queues);

    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

    for tid in &to_wake {
        crate::sched::wake_task(*tid);
    }
    (to_wake.len() + to_requeue.len()) as i64
}
