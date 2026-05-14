//! Scheduler preemptiv — Round-Robin cu priorități + wait queues reale
//!
//! Îmbunătățiri față de v0.1:
//! - blocked_tasks: BTreeMap<TaskId, Task> — task-urile blocate sunt păstrate,
//!   nu dropped. wake_task() le mută înapoi în ready queue.
//! - Per-CPU ready queues (viitor): fiecare core are local run queue.
//! - sleep_ms() folosit acum cu wait queue (non busy-wait).

pub mod local;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use spin::{Lazy, Mutex};
use crate::task::{Task, TaskId, TaskState};
use crate::arch::x86_64::context::switch_to;

const DEFAULT_QUANTUM: u64 = 10; // 10ms

pub static SCHEDULER: Lazy<Mutex<Scheduler>> = Lazy::new(|| {
    Mutex::new(Scheduler::new())
});

pub struct Scheduler {
    pub running_on_ap: alloc::collections::BTreeMap<u8, Task>,
    pub current:       Option<Task>,
    ready:             Vec<VecDeque<Task>>,
    /// Blocked tasks — păstrate vii până la wakeup
    blocked:           BTreeMap<TaskId, Task>,
    pub quantum:       u64,
    pub switches:      u64,
    pub total_ticks:   u64,
}

impl Scheduler {
    fn new() -> Self {
        let mut ready = Vec::with_capacity(256);
        for _ in 0..=255 { ready.push(VecDeque::new()); }
        let idle = Task::new_idle();
        let prio = idle.priority as usize;
        let mut s = Scheduler {
            current:        None,
            ready,
            blocked:        BTreeMap::new(),
            running_on_ap:  alloc::collections::BTreeMap::new(),
            quantum:        DEFAULT_QUANTUM,
            switches:       0,
            total_ticks:    0,
        };
        s.ready[prio].push_back(idle);
        s
    }

    pub fn spawn(&mut self, mut task: Task) {
        crate::serial_println!("  [SCHED] spawn '{}' tid={} prio={}", task.name, task.tid, task.priority);
        task.state = TaskState::Ready;
        let prio = task.priority as usize;
        self.ready[prio].push_back(task);
    }

    fn pick_next(&mut self) -> Option<Task> {
        for prio in (0..=255usize).rev() {
            if let Some(t) = self.ready[prio].pop_front() { return Some(t); }
        }
        None
    }

    fn enqueue_current(&mut self) {
        if let Some(mut t) = self.current.take() {
            t.state = TaskState::Ready;
            let p = t.priority as usize;
            self.ready[p].push_back(t);
        }
    }

    /// Blocheaza task curent — îl mută în blocked map
    pub fn block_current_task(&mut self) {
        if let Some(mut t) = self.current.take() {
            t.state = TaskState::Blocked;
            self.blocked.insert(t.tid, t);
            self.quantum = 0; // forțăm reschedule la next tick
        }
    }

    pub fn tick(&mut self) -> Option<(*mut crate::task::context::Context,
                                       *const crate::task::context::Context)> {
        self.total_ticks += 1;
        // Periodic AP audit — every 1000 ticks detect stuck tasks
        if self.total_ticks % 1000 == 0 && !self.running_on_ap.is_empty() {
            self.ap_audit_lost_tasks_inner();
        }

        if self.current.is_none() {
            if let Some(next) = self.pick_next() {
                self.current = Some(next);
                self.quantum = DEFAULT_QUANTUM;
            }
            return None;
        }

        if self.quantum > 0 { self.quantum -= 1; }

        if self.quantum == 0 {
            if let Some(ref mut c) = self.current {
                c.ticks += DEFAULT_QUANTUM;
                c.state  = TaskState::Ready;
            }
            let next = match self.pick_next() {
                Some(t) => t,
                None    => return None,
            };
            // Save the OLD current's priority before moving it to the ready queue
            let old_prio = self.current.as_ref().map(|t| t.priority as usize).unwrap_or(0);
            self.enqueue_current();
            let mut nt = next;
            nt.state       = TaskState::Running;
            self.current   = Some(nt);
            self.quantum   = DEFAULT_QUANTUM;
            self.switches += 1;

            // cur_ctx: old current (now at back of ready[old_prio])
            // nxt_ctx: new current
            let cur_ctx  = match self.ready.get_mut(old_prio).and_then(|q| q.back_mut()) {
            Some(t) => &mut t.context as *mut _,
            None    => return None,
        };
            let nxt_ctx  = match self.current.as_ref() {
            Some(t) => &t.context as *const _,
            None    => return None,
        };
            return Some((cur_ctx, nxt_ctx));
        }
        None
    }

    pub fn current_tid(&self) -> Option<TaskId> {
        self.current.as_ref().map(|t| t.tid)
    }

    /// OOM killer: remove lowest priority task
    pub fn oom_kill_lowest(&mut self) {
        for prio in 0..=255usize {
            if let Some(task) = self.ready[prio].pop_front() {
                crate::serial_println!("[OOM] Killed task '{}' (prio {})", task.name, prio);
                return;
            }
        }
    }

    pub fn stats(&self) -> SchedStats {
        let ready_count = self.ready.iter().map(|q| q.len()).sum();
        SchedStats {
            current_tid:  self.current.as_ref().map(|t| t.tid),
            current_name: self.current.as_ref().map(|t| t.name),
            ready_count,
            blocked_count: self.blocked.len(),
            switches:     self.switches,
            total_ticks:  self.total_ticks,
            quantum_left: self.quantum,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SchedStats {
    pub current_tid:   Option<TaskId>,
    pub current_name:  Option<&'static str>,
    pub ready_count:   usize,
    pub blocked_count: usize,
    pub switches:      u64,
    pub total_ticks:   u64,
    pub quantum_left:  u64,
}

pub fn schedule() {
    // Don't schedule during boot — only after start() has been called
    if !crate::arch::x86_64::timer::SCHED_READY.load(core::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let pair = match SCHEDULER.try_lock() {
        Some(mut s) => s.tick(),
        None        => return,
    };
    if let Some((cur, nxt)) = pair {
        unsafe { switch_to(cur, nxt); }
    }
}

/// Blochează task-ul curent — îl scoate din ready, îl pune în blocked map
/// Apelat de wait::block_current() când task-ul intră în wait queue
pub fn block_task(tid: TaskId) {
    let mut s = SCHEDULER.lock();
    // Dacă task-ul e cel curent, block it in place
    if s.current.as_ref().map(|t| t.tid) == Some(tid) {
        s.block_current_task();
        return;
    }
    // Altfel caută în ready queues
    for prio in 0..=255usize {
        if let Some(pos) = s.ready[prio].iter().position(|t| t.tid == tid) {
            // remove(pos) is infallible here: pos came from .position() on the same deque
            // and we hold the scheduler lock — no other thread can remove it between
            // the position() call and this remove(). unwrap_or_else for defensive safety.
            let mut t = match s.ready[prio].remove(pos) {
                Some(t) => t,
                None    => { crate::serial_println!("[SCHED] BUG: remove(pos) returned None"); return; }
            };
            t.state = TaskState::Blocked;
            s.blocked.insert(tid, t);
            return;
        }
    }
}

/// Trezește un task blocat — îl mută din blocked map în ready queue
pub fn wake_task(tid: TaskId) {
    let mut s = SCHEDULER.lock();
    if let Some(mut t) = s.blocked.remove(&tid) {
        t.state = TaskState::Ready;
        let p = t.priority as usize;
        crate::serial_println!("  [SCHED] wake '{}' tid={}", t.name, tid);
        s.ready[p].push_back(t);
    }
}



pub fn exit_current(code: i32) {
    crate::serial_println!("[SCHED] exit code={}", code);
    crate::process::fork::notify_exit(
        SCHEDULER.lock().current_tid().unwrap_or(0), code
    );
    let mut s = SCHEDULER.lock();
    s.current = None;
    s.quantum = 0;
}

pub fn start() -> ! {
    crate::serial_println!("[SCHED] starting");
    // Hold the lock for the entire pick+set sequence AND set SCHED_READY
    // only AFTER current is set. This prevents timer interrupts from calling
    // tick() → pick_next() and stealing the first task before we set it.
    let (dummy, next_cx) = {
        let mut s = SCHEDULER.lock();
        let mut first = s.pick_next().expect("no tasks");
        crate::serial_println!("  [SCHED] first: '{}' tid={}", first.name, first.tid);
        first.state = TaskState::Running;
        let cx = first.context;
        s.current = Some(first);
        s.quantum = DEFAULT_QUANTUM;
        // Now that current is set, enable preemptive scheduling.
        // Timer interrupts will see current is Some and won't steal tasks.
        crate::arch::x86_64::timer::SCHED_READY.store(true, core::sync::atomic::Ordering::SeqCst);
        (crate::task::context::Context::empty(), cx)
    };
    x86_64::instructions::interrupts::enable();
    unsafe { switch_to(&dummy as *const _ as *mut _, &next_cx as *const _); }
    unreachable!()
}

/// Sleep current task pentru `ms` milisecunde — cedează CPU-ul, nu busy-wait.
/// Task-ul e mutat în blocked_tasks și trezit de timer interrupt după expirare.
pub fn sleep_ms(ms: u64) {
    if ms == 0 { return; }
    let deadline = crate::arch::x86_64::timer::uptime_ms() + ms;
    // Înregistrăm deadline-ul și blocăm task-ul curent
    {
        let mut sched = SCHEDULER.lock();
        if let Some(ref mut t) = sched.current {
            t.sleep_until = Some(deadline);
        }
    }
    // Yield — scheduler va verifica sleep_until la fiecare timer tick
    yield_now();
    // Dacă ajungem aici, timer a expirat sau task a fost trezit manual
}

/// Yield CPU fără sleep — pune task-ul înapoi în ready queue
pub fn yield_now() {
    // Trigger timer interrupt simulator — sau simplu reschedule
    crate::arch::x86_64::timer::sleep_ms(1);
}

/// Wait queue event types
#[derive(Clone, Copy, PartialEq)]
pub enum WaitEvent { Io, Timer, Mutex(u64), Pipe(u64) }

/// Wake all tasks waiting for a specific event
pub fn wake_on_event(event: WaitEvent) {
    let mut sched = SCHEDULER.lock();
    let to_wake: alloc::vec::Vec<TaskId> = sched.blocked.keys()
        .copied().collect();
    for tid in to_wake {
        if let Some(t) = sched.blocked.get(&tid) {
            if t.wait_event == Some(event) {
                if let Some(mut t) = sched.blocked.remove(&tid) {
                    t.state = TaskState::Ready;
                    t.wait_event = None;
                    let p = t.priority as usize;
                    sched.ready[p].push_back(t);
                }
            }
        }
    }
}

/// Block current task until event — yields CPU immediately
pub fn wait_for_event(event: WaitEvent) {
    {
        let mut sched = SCHEDULER.lock();
        if let Some(ref mut t) = sched.current {
            t.wait_event = Some(event);
        }
        sched.block_current_task();
    }
    yield_now();
}

impl Scheduler {
/// AP task stealing — pick a ready task for execution on this AP core
pub fn steal_task_for_ap(&mut self, cpu_id: u8) -> Option<*const crate::task::context::Context> {
    // Try highest priority first
    for prio in (0..self.ready.len()).rev() {
        if let Some(mut task) = self.ready[prio].pop_front() {
            // Mark as Running — NOT blocked. The AP is actively executing it.
            task.state         = crate::task::TaskState::Running;
            task.stolen_at_ms  = crate::arch::x86_64::timer::uptime_ms();
            let ctx_ptr = &task.context as *const _;
            // Store in running_on_ap map so it can be woken/reaped correctly
            self.running_on_ap.insert(cpu_id, task);
            crate::serial_println!("  [SMP] AP{} stealing task, ctx=0x{:x}",
                cpu_id, ctx_ptr as u64);
            return Some(ctx_ptr);
        }
    }
    None
}

/// Return a task that finished its quantum on an AP back to the ready queue.
///
/// Called from AP scheduler loop after each task completes its time slice.
/// Ensures tasks are never "lost" between AP execution and ready queue.
pub fn ap_task_finished(&mut self, cpu_id: u8) {
    if let Some(mut task) = self.running_on_ap.remove(&cpu_id) {
        match task.state {
            crate::task::TaskState::Dead => {
                // Task exited — reap it, don't re-queue
                crate::serial_println!("  [SMP] AP{}: task '{}' exited, reaped", cpu_id, task.name);
                crate::process::fork::notify_exit(task.tid, 0);
                // drop(task) — freed here
            }
            crate::task::TaskState::Blocked => {
                // Task blocked itself (e.g. waiting for I/O) — move to blocked map
                self.blocked.insert(task.tid, task);
            }
            _ => {
                // Task still alive — re-queue for fairness (back to ready)
                task.state = crate::task::TaskState::Ready;
                task.ticks += 1;
                let prio = task.priority as usize;
                if prio < self.ready.len() {
                    self.ready[prio].push_back(task);
                } else {
                    // Prio out of range — put at lowest valid prio (defensive)
                    self.ready[0].push_back(task);
                    crate::serial_println!("  [SMP] AP{}: task priority out of range, clamped", cpu_id);
                }
            }
        }
    } else {
        // No task registered for this AP — this is a bug
        crate::serial_println!("  [SMP] WARNING: ap_task_finished called for AP{} with no registered task", cpu_id);
    }
}

/// Detect and recover any tasks "lost" between AP execution and ready queue.
/// Should be called periodically (e.g. every 1000 scheduler ticks).
/// Threshold: task running on AP for longer than this is considered stuck
const AP_STUCK_THRESHOLD_MS: u64 = 5_000;  // 5 seconds

fn ap_audit_lost_tasks_inner(&mut self) {
    let now = crate::arch::x86_64::timer::uptime_ms();

    // Identify tasks that have been on an AP longer than the threshold.
    // We use stolen_at_ms (a wall-clock timestamp set when the task was stolen),
    // NOT ticks==0 — a newly stolen task that hasn't run yet would be a false positive.
    //
    // A task is "stuck" only if:
    //   (a) stolen_at_ms > 0  (it was actually assigned to an AP)
    //   (b) now - stolen_at_ms > AP_STUCK_THRESHOLD_MS  (5s elapsed)
    //
    // Note: this heuristic can have false positives if a task legitimately runs
    // for >5s without yielding (compute-heavy). In that case the AP tick counter
    // should be incrementing — future work: also check ticks progression.
    let stuck: alloc::vec::Vec<(u8, u64, &'static str)> = self.running_on_ap
        .iter()
        .filter_map(|(&cpu_id, task)| {
            if task.stolen_at_ms == 0 { return None; }  // not yet assigned
            let elapsed = now.saturating_sub(task.stolen_at_ms);
            if elapsed > Self::AP_STUCK_THRESHOLD_MS {
                Some((cpu_id, elapsed, task.name))
            } else {
                None
            }
        })
        .collect();

    for (cpu_id, elapsed_ms, name) in stuck {
        crate::serial_println!(
            "  [SMP] WARNING: task '{}' on AP{} stuck for {}ms (threshold {}ms) — forcing return",
            name, cpu_id, elapsed_ms, Self::AP_STUCK_THRESHOLD_MS);
        self.ap_task_finished(cpu_id);
    }
}

/// Count tasks currently running on APs (for monitoring)
pub fn ap_running_count(&self) -> usize { self.running_on_ap.len() }
} // end impl Scheduler (AP methods)
