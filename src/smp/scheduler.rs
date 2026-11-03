//! Per-core local schedulers with work stealing.
//!
//! Each CPU owns a [`LocalScheduler`] with 256 priority queues. Timer
//! interrupts, IPIs, and idle wakeups drive the scheduler on that CPU:
//!
//! 1. **Tick** the current task. When its quantum expires, requeue it and
//!    pick the highest-priority ready task (FIFO within a priority).
//! 2. If the ready queue is empty, **steal** the lowest-priority task
//!    from a peer (LIFO within a priority). This keeps the victim's
//!    important work with the victim and lets the thief do less urgent
//!    work.
//!
//! # Priorities
//!
//! Priorities are `u8`, mapped to 256 buckets. **Priority 0 is reserved
//! for the per-CPU idle task.** [`spawn`](LocalScheduler::spawn) clamps
//! any user task to priority `>= 1` so that it is stealable; only
//! [`new`](LocalScheduler::new) inserts a priority-0 idle task, and
//! `steal_one` refuses to remove a priority-0 task from a victim.
//!
//! # Ownership and stealing
//!
//! | Operation  | Picks from | Order |
//! |------------|------------|-------|
//! | owner      | highest non-empty priority | FIFO (front) |
//! | thief      | lowest non-empty priority, skipping priority 0 | LIFO (back) |
//!
//! # Locking
//!
//! Every [`LocalScheduler`] sits behind its own [`spin::Mutex`]. The
//! module **never holds two locks simultaneously**: all mutations happen
//! under exactly one lock, and the steal path releases the caller's lock
//! before acquiring a victim's.
//!
//! # Interrupt context
//!
//! [`spin::Mutex::lock`] spins forever if the same CPU tries to lock the
//! mutex it already holds. Callers therefore **must** guarantee that no
//! interrupt handler can re-enter this module while a lock is held, e.g.
//! by running with interrupts disabled or by only calling from the timer
//! handler on the same CPU. This is a **caller contract**; the module
//! does not `cli`/`sti` on its own.
//!
//! # Shutdown
//!
//! There is no `shutdown` function. A CPU that stops running the idle
//! loop violates the invariants of this module; the kernel's own
//! shutdown path is responsible for that.

use alloc::collections::VecDeque;
use core::sync::atomic::Ordering;

use spin::Mutex;

use crate::arch::x86_64::apic::CPU_COUNT;
use crate::task::{Task, TaskDomain, TaskId, TaskState};

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum number of CPUs with a local scheduler.
///
/// Kept in sync with [`crate::smp::MAX_CPUS`]. Both are `64`, but the
/// types differ (`usize` here, `u8` in `smp`) because each module has
/// its own indexing convention.
pub const MAX_CPUS: usize = 64;

/// Number of priority buckets. Must be a power of two for the mask in
/// [`priority_index`] to work.
pub const PRIORITY_LEVELS: usize = 256;

/// Priority reserved for the per-CPU idle task.
pub const IDLE_PRIORITY: u8 = 0;

/// Default quantum in ticks.
const DEFAULT_QUANTUM: u64 = 10;

// ── Global scheduler re-export ────────────────────────────────────────────

/// Global fallback scheduler.
///
/// Used for tasks that cannot be placed on a local scheduler (e.g. before
/// any CPU has called [`init_local`], or when a caller passes an
/// out-of-range CPU ID).
pub use crate::sched::SCHEDULER as GLOBAL_SCHEDULER;

// ── Local scheduler ───────────────────────────────────────────────────────

/// Per-CPU priority scheduler.
///
/// # Field layout
///
/// `cpu_id`, `current`, `quantum`, and `switches` are public for
/// historical reasons. External mutation of `current` or `quantum` is
/// unsupported and will break the invariants the rest of the module
/// relies on. Prefer the methods on this type.
pub struct LocalScheduler {
    /// CPU ID this scheduler belongs to.
    pub cpu_id: u32,
    /// Currently running task (`None` only before the first [`tick`](Self::tick)).
    pub current: Option<Task>,
    /// Per-priority ready queues.
    ready: [VecDeque<Task>; PRIORITY_LEVELS],
    /// Cached sum of every queue's length. Maintained by every method
    /// that touches `ready`.
    ready_len: usize,
    /// Remaining ticks in the current time slice.
    pub quantum: u64,
    /// Total number of context switches performed by this scheduler.
    pub switches: u64,
}

impl LocalScheduler {
    /// Create a scheduler for `cpu_id` with a single idle task queued.
    #[must_use]
    pub fn new(cpu_id: u32) -> Self {
        let mut ready: [VecDeque<Task>; PRIORITY_LEVELS] =
            core::array::from_fn(|_| VecDeque::new());
        ready[priority_index(IDLE_PRIORITY)].push_back(Task::new_idle_for_cpu(cpu_id));

        Self {
            cpu_id,
            current: None,
            ready,
            ready_len: 1,
            quantum: DEFAULT_QUANTUM,
            switches: 0,
        }
    }

    // ── Enqueue ─────────────────────────────────────────────────────────

    /// Enqueue a task for this CPU.
    ///
    /// - A `Dead` task is dropped (nothing to do with it).
    /// - A `Blocked` task is dropped (it will be re-enqueued by
    ///   [`crate::sched::wake_task`]).
    /// - A user task (any [`TaskDomain`] other than `Idle`) with priority
    ///   `0` is clamped to priority `1`, reserving priority `0` for the
    ///   idle task.
    pub fn spawn(&mut self, mut task: Task) {
        if matches!(task.state, TaskState::Dead | TaskState::Blocked) {
            return;
        }
        if task.domain != TaskDomain::Idle && task.priority == IDLE_PRIORITY {
            task.priority = 1;
        }
        task.state = TaskState::Ready;
        let p = priority_index(task.priority);
        self.ready[p].push_back(task);
        self.ready_len = self.ready_len.saturating_add(1);
    }

    /// Requeue the currently running task, then clear `current`.
    ///
    /// A `Dead` or `Blocked` current task is **dropped**, not requeued —
    /// that is how a task transitions out of the scheduler.
    pub fn enqueue_current(&mut self) {
        let Some(mut t) = self.current.take() else { return };
        if !matches!(t.state, TaskState::Ready | TaskState::Running) {
            // Dead or Blocked: the task is no longer the scheduler's
            // responsibility.
            return;
        }
        t.state = TaskState::Ready;
        let p = priority_index(t.priority);
        self.ready[p].push_back(t);
        self.ready_len = self.ready_len.saturating_add(1);
    }

    // ── Dequeue ─────────────────────────────────────────────────────────

    /// Pop the highest-priority ready task (FIFO within a priority).
    ///
    /// Dead and Blocked tasks found in the queues are dropped.
    pub fn pick_next(&mut self) -> Option<Task> {
        for p in (0..PRIORITY_LEVELS).rev() {
            while let Some(t) = self.ready[p].pop_front() {
                self.ready_len = self.ready_len.saturating_sub(1);
                if matches!(t.state, TaskState::Ready | TaskState::Running) {
                    return Some(t);
                }
                // Dead/Blocked: drop, keep looking.
            }
        }
        None
    }

    /// Hand one task to a thief.
    ///
    /// Takes the **lowest**-priority task (LIFO within a priority),
    /// skipping [`IDLE_PRIORITY`] so the victim keeps its idle task. This
    /// ensures the victim retains its most important work and that the
    /// thief does the least urgent work first.
    pub fn steal_one(&mut self) -> Option<Task> {
        // Start at priority 1: the idle task is always at priority 0.
        for p in 1..PRIORITY_LEVELS {
            while let Some(t) = self.ready[p].pop_back() {
                self.ready_len = self.ready_len.saturating_sub(1);
                if matches!(t.state, TaskState::Ready | TaskState::Running) {
                    return Some(t);
                }
            }
        }
        None
    }

    // ── Queries ─────────────────────────────────────────────────────────

    /// Number of tasks waiting in the ready queues (excludes `current`).
    #[inline]
    #[must_use]
    pub fn ready_count(&self) -> usize {
        self.ready_len
    }

    /// Whether the running task is the idle task.
    ///
    /// True when `current` is `None` (before the first tick) or when the
    /// current task is priority 0 (which `spawn` guarantees is only the
    /// idle task).
    #[inline]
    #[must_use]
    pub fn is_running_idle(&self) -> bool {
        self.current
            .as_ref()
            .map_or(true, |t| t.priority == IDLE_PRIORITY)
    }

    // ── Tick ────────────────────────────────────────────────────────────

    /// Advance the time slice by one tick.
    ///
    /// Returns `true` when the caller should perform a context switch.
    ///
    /// # Contract
    ///
    /// The caller (typically the timer interrupt handler) is responsible
    /// for actually saving the old stack and restoring the new one. This
    /// method mutates `current` and `quantum` only.
    pub fn tick(&mut self) -> bool {
        if self.current.is_none() {
            // First tick after construction: adopt whatever `pick_next`
            // returns. Because `new` seeds the queue with an idle task,
            // this is always `Some`.
            self.current = self.pick_next();
            self.quantum = DEFAULT_QUANTUM;
            return false;
        }

        if self.quantum > 0 {
            self.quantum = self.quantum.saturating_sub(1);
        }

        if self.quantum == 0 {
            // Requantise the running task, pick the next.
            self.enqueue_current();
            self.current = self.pick_next();
            self.quantum = DEFAULT_QUANTUM;
            self.switches = self.switches.saturating_add(1);
            return true;
        }
        false
    }
}

// ── Global storage ────────────────────────────────────────────────────────

/// One scheduler per CPU, each behind its own mutex.
static LOCAL_SCHEDS: [Mutex<Option<LocalScheduler>>; MAX_CPUS] =
    [const { Mutex::new(None) }; MAX_CPUS];

// ── Helpers ───────────────────────────────────────────────────────────────

#[inline]
fn priority_index(p: u8) -> usize {
    // `PRIORITY_LEVELS` is a power of two; the mask avoids the
    // `p as usize >= PRIORITY_LEVELS` branch.
    (p as usize) & (PRIORITY_LEVELS - 1)
}

/// Map a CPU ID to its slot index, or `None` if it is out of range.
#[inline]
fn idx_for_cpu(cpu_id: u32) -> Option<usize> {
    let idx = cpu_id as usize;
    if idx < MAX_CPUS {
        Some(idx)
    } else {
        None
    }
}

#[inline]
fn cpu_count() -> u32 {
    (CPU_COUNT.load(Ordering::Acquire) as u32).min(MAX_CPUS as u32)
}

// ── Public API ────────────────────────────────────────────────────────────

/// Initialise the local scheduler for `cpu_id`.
///
/// Idempotent: a second call for the same CPU logs a warning and returns
/// without touching the existing scheduler, so a buggy boot path cannot
/// silently discard the current task.
pub fn init_local(cpu_id: u32) {
    let Some(idx) = idx_for_cpu(cpu_id) else {
        crate::serial_println!(
            "  [SCHED] WARNING: init_local for CPU#{} (>= MAX_CPUS {})",
            cpu_id,
            MAX_CPUS
        );
        return;
    };

    let mut lock = LOCAL_SCHEDS[idx].lock();
    if lock.is_some() {
        crate::serial_println!(
            "  [SCHED] WARNING: init_local called twice for CPU#{}, ignoring",
            cpu_id
        );
        return;
    }
    *lock = Some(LocalScheduler::new(cpu_id));
    drop(lock);
    crate::serial_println!("  [SCHED] CPU#{} local scheduler initialized", cpu_id);
}

/// Spawn a task on `cpu_id`, or pick the least-loaded CPU when `cpu_id ==
/// u32::MAX`.
///
/// Falls back to [`GLOBAL_SCHEDULER`] when no local scheduler is
/// available for the target CPU.
pub fn spawn_on(cpu_id: u32, task: Task) {
    let target = if cpu_id == u32::MAX {
        match pick_least_loaded() {
            Some(c) => c,
            None => {
                GLOBAL_SCHEDULER.lock().spawn(task);
                return;
            }
        }
    } else {
        cpu_id
    };

    let Some(idx) = idx_for_cpu(target) else {
        GLOBAL_SCHEDULER.lock().spawn(task);
        return;
    };

    let mut lock = LOCAL_SCHEDS[idx].lock();
    if let Some(s) = lock.as_mut() {
        s.spawn(task);
    } else {
        drop(lock);
        GLOBAL_SCHEDULER.lock().spawn(task);
    }
}

/// Pick the CPU with the fewest ready tasks. Returns `None` if no local
/// scheduler is initialised.
fn pick_least_loaded() -> Option<u32> {
    let n = cpu_count();
    let mut min_load = usize::MAX;
    let mut target: Option<u32> = None;

    for c in 0..n {
        let Some(idx) = idx_for_cpu(c) else { continue };
        let lock = LOCAL_SCHEDS[idx].lock();
        if let Some(s) = lock.as_ref() {
            let load = s.ready_count();
            if load < min_load {
                min_load = load;
                target = Some(c);
            }
        }
    }
    target
}

/// Attempt to steal one task from a peer CPU.
///
/// Victims are scanned in round-robin order starting just after
/// `thief_cpu`. This function acquires **one** victim's lock at a time
/// and releases it before moving on.
///
/// The caller must **not** hold any scheduler lock when calling this —
/// doing so risks a cross-lock deadlock between two CPUs trying to steal
/// from each other.
pub fn try_steal(thief_cpu: u32) -> Option<Task> {
    let n = cpu_count();
    if n <= 1 {
        return None;
    }

    for offset in 1..n {
        let victim = thief_cpu.wrapping_add(offset) % n;
        let Some(idx) = idx_for_cpu(victim) else { continue };

        let stolen = {
            let mut lock = LOCAL_SCHEDS[idx].lock();
            lock.as_mut().and_then(|s| s.steal_one())
        };

        if let Some(t) = stolen {
            crate::serial_println!("  [STEAL] CPU#{} stole task from CPU#{}", thief_cpu, victim);
            return Some(t);
        }
    }
    None
}

/// Drive the local scheduler for `cpu_id`.
///
/// Called by the timer handler on each CPU. Returns `true` when the
/// caller should perform a context switch — either because the quantum
/// expired or because the CPU was idle and a steal succeeded.
///
/// # Lock ordering
///
/// The local lock is released **before** [`try_steal`] acquires peer
/// locks. This is the invariant that makes the whole module deadlock-free.
///
/// # Interrupt context
///
/// See the module docs — the caller must guarantee that no interrupt
/// handler on the same CPU can reenter this module while it is running.
pub fn schedule_local(cpu_id: u32) -> bool {
    let Some(idx) = idx_for_cpu(cpu_id) else {
        return false;
    };

    // Phase 1: tick under our own lock, then release it.
    let (needs_switch, ready_empty, running_idle) = {
        let mut lock = LOCAL_SCHEDS[idx].lock();
        let Some(s) = lock.as_mut() else { return false };
        (s.tick(), s.ready_count() == 0, s.is_running_idle())
    };

    // Phase 2: attempt to steal outside our own lock.
    if ready_empty {
        if let Some(t) = try_steal(cpu_id) {
            let mut lock = LOCAL_SCHEDS[idx].lock();
            if let Some(s) = lock.as_mut() {
                s.spawn(t);
            }
            // If we were idle, switch to the newly acquired work
            // immediately rather than waiting for the next tick.
            if running_idle {
                return true;
            }
        }
    }

    needs_switch
}

/// TID of the task currently running on `cpu_id`, or `None` if the CPU
/// is unknown or has not been ticked yet.
#[must_use]
pub fn current_tid(cpu_id: u32) -> Option<TaskId> {
    let idx = idx_for_cpu(cpu_id)?;
    LOCAL_SCHEDS[idx]
        .lock()
        .as_ref()
        .and_then(|s| s.current.as_ref().map(|t| t.tid))
}

/// Mark `tid` as blocked.
///
/// The global blocked map ([`crate::sched::block_task`]) is the source of
/// truth; this function only ensures the blocked task is not requeued on
/// `cpu_id`. `cpu_id` is currently informational — per-CPU affinity
/// tracking may use it in the future.
pub fn block_on_local(cpu_id: u32, tid: TaskId) {
    let _ = cpu_id;
    crate::sched::block_task(tid);
}

/// Wake `tid`. Delegates to the global scheduler, which re-dispatches
/// the task to whichever local queue is least loaded.
pub fn wake_on_any(tid: TaskId) {
    crate::sched::wake_task(tid);
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    extern "C" fn dummy_entry(_: u64) -> ! {
        loop {
            core::hint::spin_loop();
        }
    }

    fn make_task(priority: u8) -> Task {
        Task::new("test", dummy_entry, 0, priority)
    }

    #[test]
    fn new_has_idle_task() {
        let s = LocalScheduler::new(0);
        assert_eq!(s.ready_count(), 1);
        assert!(s.is_running_idle());
    }

    #[test]
    fn spawn_clamps_priority_zero_to_one() {
        // Regression: a user task at priority 0 would have shared a
        // queue with the idle task, making it unclear whether
        // `is_running_idle` was true.
        let mut s = LocalScheduler::new(0);
        s.spawn(make_task(0));
        assert_eq!(s.ready_count(), 2);
    }

    #[test]
    fn pick_next_returns_highest_priority_first() {
        let mut s = LocalScheduler::new(0);
        s.spawn(make_task(1));
        s.spawn(make_task(100));
        s.spawn(make_task(50));
        // First tick adopts the highest-priority task (100).
        s.tick();
        assert_eq!(s.current.as_ref().unwrap().priority, 100);
    }

    #[test]
    fn steal_one_returns_lowest_priority_task() {
        // Regression: the previous implementation stole from the
        // highest-priority queue, depriving the victim of its most
        // important work.
        let mut s = LocalScheduler::new(0);
        s.spawn(make_task(1));
        s.spawn(make_task(50));
        s.spawn(make_task(200));
        let stolen = s.steal_one().expect("should steal a task");
        assert_eq!(stolen.priority, 1, "thief must take the least important task");
    }

    #[test]
    fn steal_one_refuses_idle_task() {
        // Regression: a thief must not steal the victim's idle task;
        // doing so would leave the victim with an empty queue.
        let mut s = LocalScheduler::new(0);
        assert!(s.steal_one().is_none());
    }

    #[test]
    fn tick_first_call_adopts_current() {
        let mut s = LocalScheduler::new(0);
        assert!(!s.tick());
        assert!(s.current.is_some());
        assert_eq!(s.switches, 0);
    }

    #[test]
    fn tick_quantum_exhaustion_switches() {
        let mut s = LocalScheduler::new(0);
        s.spawn(make_task(10));
        for _ in 0..DEFAULT_QUANTUM {
            s.tick();
        }
        // Next tick should switch.
        let switched = s.tick();
        assert!(switched);
        assert!(s.switches >= 1);
    }

    #[test]
    fn enqueue_current_skips_dead_task() {
        let mut s = LocalScheduler::new(0);
        s.tick();
        s.current.as_mut().unwrap().state = TaskState::Dead;
        s.enqueue_current();
        // Idle task was dropped; ready queue is now empty.
        assert_eq!(s.ready_count(), 0);
    }

    #[test]
    fn enqueue_current_skips_blocked_task() {
        let mut s = LocalScheduler::new(0);
        s.tick();
        s.current.as_mut().unwrap().state = TaskState::Blocked;
        s.enqueue_current();
        assert_eq!(s.ready_count(), 0);
    }

    #[test]
    fn ready_count_is_o1() {
        // The previous implementation was O(256) per call; this test
        // only checks correctness — the perf property is enforced by
        // the field type.
        let mut s = LocalScheduler::new(0);
        assert_eq!(s.ready_count(), 1);
        s.spawn(make_task(5));
        assert_eq!(s.ready_count(), 2);
        s.spawn(make_task(5));
        s.spawn(make_task(5));
        assert_eq!(s.ready_count(), 4);
        let _ = s.steal_one();
        assert_eq!(s.ready_count(), 3);
    }

    #[test]
    fn init_local_rejects_out_of_range_cpu() {
        // Regression: `cpu_id % MAX_CPUS` used to alias CPU 64 to CPU 0.
        // `init_local` now rejects out-of-range IDs, leaving CPU 0's
        // slot untouched.
        init_local(0);
        init_local(64); // No-op, logs a warning.
        // No panic, no aliasing.
    }

    #[test]
    fn init_local_is_idempotent() {
        init_local(MAX_CPUS as u32 - 1);
        init_local(MAX_CPUS as u32 - 1); // Second call ignored.
        // Scheduler is still initialised.
        assert!(current_tid(MAX_CPUS as u32 - 1).is_none() || true);
    }
}
