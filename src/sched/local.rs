//! Per-core local scheduler — fiecare core are propria run queue
//!
//! Avantaj față de global SCHEDULER Mutex:
//! - Zero lock contention la schedule() — fiecare core accesează propria coadă
//! - Work stealing: dacă local queue e goală, furăm task de la alt core
//!
//! Accesat prin GS segment (PerCpu.local_sched_ptr) sau prin
//! LOCAL_SCHEDULERS[cpu_id].

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use spin::Mutex;
use crate::task::{Task, TaskId, TaskState};

const DEFAULT_QUANTUM: u64 = 10;
const MAX_CPUS:        usize = 64;

pub struct LocalScheduler {
    pub cpu_id:    u32,
    pub current:   Option<Task>,
    pub ready:     Vec<VecDeque<Task>>,  // 256 priority levels
    pub quantum:   u64,
    pub switches:  u64,
    /// Tasks pinned to this CPU (affinity)
    pub pinned:    alloc::vec::Vec<crate::task::TaskId>,
}

impl LocalScheduler {
    pub fn new(cpu_id: u32) -> Self {
        let mut ready = Vec::with_capacity(256);
        for _ in 0..=255 { ready.push(VecDeque::new()); }
        Self { cpu_id, current: None, ready, quantum: DEFAULT_QUANTUM, switches: 0, pinned: alloc::vec::Vec::new() }
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

    pub fn tick(&mut self) -> bool {
        if self.current.is_none() {
            if let Some(t) = self.pick_next().or_else(|| steal_from_others(self.cpu_id)) {
                self.current = Some(t);
                self.quantum = DEFAULT_QUANTUM;
            }
            return false;
        }
        if self.quantum > 0 { self.quantum -= 1; return false; }

        // Quantum expired — preempt
        if let Some(ref mut c) = self.current {
            c.ticks += DEFAULT_QUANTUM;
            c.state  = TaskState::Ready;
        }
        let next = self.pick_next()
            .or_else(|| steal_from_others(self.cpu_id));
        let next = match next { Some(t) => t, None => return false };

        // Enqueue current
        if let Some(mut old) = self.current.take() {
            old.state = TaskState::Ready;
            let p = old.priority as usize;
            self.ready[p].push_back(old);
        }
        let mut nt = next;
        nt.state     = TaskState::Running;
        self.current = Some(nt);
        self.quantum = DEFAULT_QUANTUM;
        self.switches += 1;
        true // context switch needed
    }

    pub fn current_tid(&self) -> Option<TaskId> {
        self.current.as_ref().map(|t| t.tid)
    }

    pub fn ready_count(&self) -> usize {
        self.ready.iter().map(|q| q.len()).sum()
    }
}

/// Global array of per-core schedulers
static LOCAL_SCHEDS: [Mutex<Option<LocalScheduler>>; MAX_CPUS] =
    [const { Mutex::new(None) }; MAX_CPUS];

pub fn init_for_cpu(cpu_id: u32) {
    let idx = cpu_id as usize % MAX_CPUS;
    *LOCAL_SCHEDS[idx].lock() = Some(LocalScheduler::new(cpu_id));
    crate::serial_println!("  [LSCHED] CPU#{} local scheduler initialized", cpu_id);
}

pub fn spawn_on(cpu_id: u32, task: Task) {
    let idx = cpu_id as usize % MAX_CPUS;
    if let Some(ref mut ls) = *LOCAL_SCHEDS[idx].lock() {
        ls.spawn(task);
    }
}

/// Spawn on least-loaded CPU (simple load balancing)
pub fn spawn_balanced(task: Task) {
    let ncpus = crate::arch::x86_64::apic::CPU_COUNT.load(
        core::sync::atomic::Ordering::Relaxed) as usize;
    let mut best_cpu = 0usize;
    let mut best_load = usize::MAX;
    for i in 0..ncpus.min(MAX_CPUS) {
        let load = LOCAL_SCHEDS[i].lock().as_ref().map(|s| s.ready_count()).unwrap_or(0);
        if load < best_load { best_load = load; best_cpu = i; }
    }
    spawn_on(best_cpu as u32, task);
}

/// Work stealing: try to steal one task from another core's queue
fn steal_from_others(my_cpu: u32) -> Option<Task> {
    let ncpus = crate::arch::x86_64::apic::CPU_COUNT.load(
        core::sync::atomic::Ordering::Relaxed) as usize;
    for i in 0..ncpus.min(MAX_CPUS) {
        if i == my_cpu as usize { continue; }
        if let Some(mut victim) = LOCAL_SCHEDS[i].try_lock() {
            if let Some(ref mut ls) = *victim {
                // Steal from lowest priority queue of victim
                for p in 0..=255usize {
                    if !ls.ready[p].is_empty() {
                        let mut t = match ls.ready[p].pop_back() { Some(t) => t, None => continue };
                        t.state = TaskState::Ready;
                        crate::serial_println!(
                            "  [LSCHED] CPU#{} stole task '{}' from CPU#{}",
                            my_cpu, t.name, i);
                        return Some(t);
                    }
                }
            }
        }
    }
    None
}

pub fn schedule_on_current_cpu() {
    let cpu_id = crate::arch::x86_64::percpu::current_cpu_id();
    let idx    = cpu_id as usize % MAX_CPUS;
    let needs_switch = {
        match LOCAL_SCHEDS[idx].try_lock() {
            Some(mut g) => g.as_mut().map(|s| s.tick()).unwrap_or(false),
            None        => false,
        }
    };
    if needs_switch {
        // Full per-CPU context switch: save current task ctx, restore next
        // This runs in timer interrupt context (interrupts disabled)
        let (cur_ctx, nxt_ctx) = {
            let idx = (crate::arch::x86_64::percpu::current_cpu_id() as usize) % MAX_CPUS;
            let mut g = match LOCAL_SCHEDS[idx].try_lock() { Some(g) => g, None => return };
            let ls = match g.as_mut() { Some(ls) => ls, None => return };
            // Get context pointers from current and next tasks
            // current was just moved to ready queue by tick()
            // we need current (prev, now in ready) and new current
            let cur_prio = ls.current.as_ref().map(|t| t.priority as usize).unwrap_or(0);
            let cur_ptr: *mut crate::task::context::Context = ls.ready[cur_prio].back_mut()
                .map(|t| &mut t.context as *mut _)
                .unwrap_or(core::ptr::null_mut());
            let nxt_ptr: *const crate::task::context::Context = ls.current.as_ref()
                .map(|t| &t.context as *const _)
                .unwrap_or(core::ptr::null());
            if cur_ptr.is_null() || nxt_ptr.is_null() { return; }
            (cur_ptr, nxt_ptr)
        };
        unsafe { crate::arch::x86_64::context::switch_to(cur_ctx, nxt_ctx); }
    }
}

pub fn current_tid_on(cpu_id: u32) -> Option<TaskId> {
    let idx = cpu_id as usize % MAX_CPUS;
    LOCAL_SCHEDS[idx].lock().as_ref().and_then(|s| s.current_tid())
}

/// Pin a task to a specific CPU (affinity = must run on this core)
pub fn pin_task(cpu_id: u32, tid: crate::task::TaskId) {
    let idx = cpu_id as usize % MAX_CPUS;
    if let Some(ref mut ls) = *LOCAL_SCHEDS[idx].lock() {
        if !ls.pinned.contains(&tid) { ls.pinned.push(tid); }
    }
}

/// Migrate a task from one CPU to another (used by load balancer)
pub fn migrate(from_cpu: u32, to_cpu: u32, tid: crate::task::TaskId) -> bool {
    let fi = from_cpu as usize % MAX_CPUS;
    let _ti = to_cpu   as usize % MAX_CPUS;

    // Find and remove task from source
    let task = {
        let mut g = LOCAL_SCHEDS[fi].lock();
        let ls = match g.as_mut() { Some(ls) => ls, None => return false };
        let mut found = None;
        'outer: for p in 0..=255usize {
            for i in 0..ls.ready[p].len() {
                if ls.ready[p][i].tid == tid {
                    found = ls.ready[p].remove(i);
                    break 'outer;
                }
            }
        }
        found
    };

    match task {
        Some(t) => { spawn_on(to_cpu, t); true }
        None    => false,
    }
}
