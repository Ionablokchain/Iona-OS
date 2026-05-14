//! Task subsystem
//!
//! Un task = o unitate de execuție independentă cu:
//! - propriul stack kernel (4 pages = 16KB)
//! - propriul context CPU (registre callee-saved)
//! - stare: New, Running, Ready, Blocked, Dead
//!
//! În Faza 1: toate task-urile rulează în ring 0 (kernel space).
//! Faza 2 adaugă ring 3 (userspace) cu syscalls.

pub mod context;

use alloc::boxed::Box;
use core::sync::atomic::{AtomicU64, Ordering};
use context::Context;

/// ID unic per task — monoton crescător
static NEXT_TID: AtomicU64 = AtomicU64::new(1);

pub type TaskId = u64;

pub fn next_tid() -> TaskId {
    NEXT_TID.fetch_add(1, Ordering::Relaxed)
}

/// Dimensiunea stack-ului per task: 16KB (4 pagini de 4KB)
pub const TASK_STACK_SIZE: usize = 4 * 4096;

/// Starea unui task
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// Nou creat, niciodată rulat
    New,
    /// Rulează acum pe CPU
    Running,
    /// Gata de rulat, în coada scheduler-ului
    Ready,
    /// Blocat — așteaptă un eveniment (sleep, I/O etc.)
    Blocked,
    /// Terminat — resurse vor fi eliberate
    Dead,
}

/// Stack alocat pentru un task
///
/// repr(C) + align(16) — stack-ul trebuie aliniat la 16 bytes (ABI x86_64)
#[repr(C, align(16))]
pub struct TaskStack {
    data: Box<[u8; TASK_STACK_SIZE]>,
}

impl TaskStack {
    pub fn new() -> Self {
        // Alocăm pe heap ca să nu consumăm stack-ul kernelului
        Self {
            data: Box::new([0u8; TASK_STACK_SIZE]),
        }
    }

    /// Adresa vârfului stack-ului (stack crește în jos pe x86)
    pub fn top(&self) -> u64 {
        let ptr = self.data.as_ptr() as u64;
        // Aliniem la 16 bytes — cerință ABI pentru apeluri de funcții
        (ptr + TASK_STACK_SIZE as u64) & !0xF
    }
}

/// Un task kernel
pub struct Task {
    pub sleep_until:   Option<u64>,  // uptime_ms deadline for sleep_ms()
    pub wait_event:    Option<crate::sched::WaitEvent>,
    pub tid:           TaskId,
    pub name:          &'static str,
    pub state:         TaskState,
    pub context:       Context,
    /// Stack-ul task-ului — păstrat viu cât timp task-ul există
    _stack:            TaskStack,
    /// Prioritate: 0 = normal, 1 = high, 255 = realtime
    pub priority:      u8,
    /// Tick-uri CPU consumate (heartbeat — incrementat periodic de scheduler)
    pub ticks:         u64,
    /// uptime_ms when this task was stolen by an AP (0 = not stolen)
    pub stolen_at_ms:  u64,
}

impl Task {
    /// Creează un task nou care va apela `entry(arg)` la prima rulare
    pub fn new(name: &'static str, entry: fn(u64) -> !, arg: u64, priority: u8) -> Self {
        let stack   = TaskStack::new();
        let stack_top = stack.top();
        let context = Context::new_task(stack_top, entry as u64, arg);
        let tid     = next_tid();

        crate::serial_println!("  [TASK] created '{}' tid={} stack_top=0x{:x}",
            name, tid, stack_top);

        Task {
            tid,
            name,
            state:    TaskState::New,
            context,
            _stack:   stack,
            priority,
            ticks:    0,
            sleep_until: None,
            wait_event: None,
            stolen_at_ms: 0,
        }
    }

    /// Create a task with a pre-existing stack pointer (used by clone/threads)
    pub fn new_with_stack(name: &'static str, tid: TaskId, stack_ptr: u64) -> Self {
        let stack   = TaskStack::new();
        let context = Context::empty();
        crate::serial_println!("  [TASK] created '{}' tid={} sp=0x{:x}", name, tid, stack_ptr);
        Task {
            tid,
            name,
            state:    TaskState::New,
            context,
            _stack:   stack,
            priority: 1,
            ticks:    0,
            sleep_until: None,
            wait_event: None,
            stolen_at_ms: 0,
        }
    }

    /// Creează task-ul idle — rulează când nu există altceva de rulat
    pub fn new_idle() -> Self {
        let stack   = TaskStack::new();
        let stack_top = stack.top();
        let context = Context::new_task(stack_top, idle_task as *const () as u64, 0);
        Task {
            tid:      0,  // idle are TID 0 întotdeauna
            name:     "idle",
            state:    TaskState::Ready,
            context,
            _stack:   stack,
            priority: 0,
            ticks:    0,
            sleep_until: None,
            wait_event: None,
            stolen_at_ms: 0,
        }
    }
}

/// Task-ul idle — rulează când nu există alt task Ready
fn idle_task(_arg: u64) -> ! {
    loop {
        // hlt: CPU doarme până la următorul interrupt (economisim energie)
        x86_64::instructions::hlt();
    }
}
