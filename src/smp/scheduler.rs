//! Per-core local schedulers cu work stealing
//!
//! Fiecare core are propriul LocalScheduler, accesibil fără lock global.
//! La fiecare tick, core-ul ia task-uri din LOCAL queue.
//! Dacă e goală → work stealing: inspectăm queue-urile altor core-uri.
//!
//! Avantaje față de scheduler global:
//! - Zero contention pe lock pentru task-uri locale
//! - Cache-friendly: task-ul rulează pe același core → L1/L2 cache hot
//! - Work stealing asigură load balancing automat

use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;
use crate::task::{Task, TaskId, TaskState};
use crate::arch::x86_64::apic::CPU_COUNT;

pub const MAX_CPUS: usize = 64;
const DEFAULT_QUANTUM: u64 = 10;

/// Un scheduler local per core
pub struct LocalScheduler {
    pub cpu_id:   u32,
    pub current:  Option<Task>,
    ready:        [VecDeque<Task>; 256], // per-priority queues
    pub quantum:  u64,
    pub switches: u64,
}

impl LocalScheduler {
    pub fn new(cpu_id: u32) -> Self {
        const EMPTY: VecDeque<Task> = VecDeque::new();
        let mut s = LocalScheduler {
            cpu_id, current: None,
            ready: [EMPTY; 256],
            quantum: DEFAULT_QUANTUM, switches: 0,
        };
        // Each core starts with its own idle task
        let idle = Task::new_idle_for_cpu(cpu_id);
        s.ready[0].push_back(idle);
        s
    }

    pub fn spawn(&mut self, mut t: Task) {
        t.state = TaskState::Ready;
        let p = t.priority as usize;
        self.ready[p].push_back(t);
    }

    pub fn pick_next(&mut self) -> Option<Task> {
        for p in (0..=255usize).rev() {
            if let Some(t) = self.ready[p].pop_front() { return Some(t); }
        }
        None
    }

    pub fn steal_one(&mut self) -> Option<Task> {
        // Returns the highest-priority task from our ready queue (for another core to steal)
        for p in (0..=255usize).rev() {
            if let Some(t) = self.ready[p].pop_back() { return Some(t); }
        }
        None
    }

    pub fn enqueue_current(&mut self) {
        if let Some(mut t) = self.current.take() {
            t.state = TaskState::Ready;
            let p = t.priority as usize;
            self.ready[p].push_back(t);
        }
    }

    pub fn ready_count(&self) -> usize {
        self.ready.iter().map(|q| q.len()).sum()
    }

    pub fn tick(&mut self) -> bool { // returns true if we need context switch
        if self.current.is_none() {
            self.current = self.pick_next();
            self.quantum = DEFAULT_QUANTUM;
            return false;
        }
        if self.quantum > 0 { self.quantum -= 1; }
        if self.quantum == 0 {
            if let Some(ref mut c) = self.current { c.state = TaskState::Ready; }
            self.enqueue_current();
            self.current = self.pick_next();
            self.quantum = DEFAULT_QUANTUM;
            self.switches += 1;
            return true;
        }
        false
    }
}

/// Global array of per-core schedulers (protected by individual Mutexes)
static LOCAL_SCHEDS: [Mutex<Option<LocalScheduler>>; MAX_CPUS] =
    [const { Mutex::new(None) }; MAX_CPUS];

/// Global fallback scheduler (for tasks not yet assigned to a core)
pub use crate::sched::SCHEDULER as GLOBAL_SCHEDULER;

/// Initialize local scheduler for a CPU
pub fn init_local(cpu_id: u32) {
    let idx = cpu_id as usize % MAX_CPUS;
    *LOCAL_SCHEDS[idx].lock() = Some(LocalScheduler::new(cpu_id));
    crate::serial_println!("  [SMP-SCHED] CPU#{} local scheduler initialized", cpu_id);
}

/// Spawn a task on a specific CPU (or load-balance if cpu_id = u32::MAX)
pub fn spawn_on(cpu_id: u32, task: Task) {
    let target = if cpu_id == u32::MAX {
        // Load balance: pick CPU with fewest ready tasks
        let mut min_load = usize::MAX;
        let mut target = 0u32;
        let n = CPU_COUNT.load(Ordering::Relaxed) as u32;
        for c in 0..n {
            let idx = c as usize % MAX_CPUS;
            if let Some(ref s) = *LOCAL_SCHEDS[idx].lock() {
                let load = s.ready_count();
                if load < min_load { min_load = load; target = c; }
            }
        }
        target
    } else { cpu_id };

    let idx = target as usize % MAX_CPUS;
    if let Some(ref mut s) = *LOCAL_SCHEDS[idx].lock() {
        s.spawn(task);
    } else {
        // Fallback to global scheduler
        crate::sched::SCHEDULER.lock().spawn(task);
    }
}

/// Work stealing: try to steal a task from another CPU
pub fn try_steal(thief_cpu: u32) -> Option<Task> {
    let n = CPU_COUNT.load(Ordering::Relaxed) as u32;
    // Try steal from CPUs in round-robin order starting after our own
    for offset in 1..n {
        let victim = (thief_cpu + offset) % n;
        let idx = victim as usize % MAX_CPUS;
        if let Some(ref mut s) = *LOCAL_SCHEDS[idx].lock() {
            if let Some(t) = s.steal_one() {
                crate::serial_println!("  [STEAL] CPU#{} stole task from CPU#{}", thief_cpu, victim);
                return Some(t);
            }
        }
    }
    None
}

/// Called by timer handler on each CPU — schedules next task
pub fn schedule_local(cpu_id: u32) {
    let idx = cpu_id as usize % MAX_CPUS;
    let needs_switch = {
        let mut lock = LOCAL_SCHEDS[idx].lock();
        if let Some(ref mut s) = *lock {
            let sw = s.tick();
            // If queue empty after tick → try work stealing
            if s.current.is_none() {
                drop(lock);
                if let Some(stolen) = try_steal(cpu_id) {
                    LOCAL_SCHEDS[idx].lock().as_mut().map(|s| s.spawn(stolen));
                }
                return;
            }
            sw
        } else {
            return;
        }
    };
    // Context switch handled by APIC timer handler per core
}

/// Get current TID on this CPU
pub fn current_tid(cpu_id: u32) -> Option<TaskId> {
    let idx = cpu_id as usize % MAX_CPUS;
    LOCAL_SCHEDS[idx].lock().as_ref().and_then(|s| s.current.as_ref().map(|t| t.tid))
}

/// Block a task (move to blocked — it will be in global blocked map)
pub fn block_on_local(cpu_id: u32, tid: TaskId) {
    crate::sched::block_task(tid); // delegate to global blocked map
}

/// Wake a task — find which CPU has it blocked and return it to its home queue
pub fn wake_on_any(tid: TaskId) {
    crate::sched::wake_task(tid); // global wake → goes back to global scheduler
    // In full impl: track which CPU owns each task → wake on that CPU
}
