//! Signal handling — POSIX-style async process notification
use alloc::collections::BTreeMap;
use spin::{Lazy, Mutex};
use crate::task::TaskId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Signal {
    SIGHUP  =  1,
    SIGINT  =  2,
    SIGQUIT =  3,
    SIGILL  =  4,
    SIGTRAP =  5,
    SIGABRT =  6,
    SIGFPE  =  8,
    SIGKILL =  9,
    SIGSEGV = 11,
    SIGPIPE = 13,
    SIGALRM = 14,
    SIGTERM = 15,
    SIGCHLD = 17,
    SIGCONT = 18,
    SIGSTOP = 19,
}

/// Pending signals per task (bitmask for speed)
static PENDING: Lazy<Mutex<BTreeMap<TaskId, u32>>> = Lazy::new(|| Mutex::new(BTreeMap::new()));

/// Signal handler addresses per task (0 = default action)
static HANDLERS: Lazy<Mutex<BTreeMap<TaskId, BTreeMap<u8, u64>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

/// Send signal to a task
pub fn send(tid: TaskId, sig: Signal) {
    let bit = 1u32 << (sig as u8);
    let mut p = PENDING.lock();
    *p.entry(tid).or_insert(0) |= bit;
    crate::serial_println!("  [SIG] → TID={} {:?}", tid, sig);

    // SIGKILL/SIGSTOP cannot be caught — handle immediately
    if sig == Signal::SIGKILL {
        crate::sched::exit_current(128 + sig as i32);
    }
}

/// Deliver pending signals to current task — called at syscall return
pub fn deliver_pending(tid: TaskId) {
    let pending = {
        let mut p = PENDING.lock();
        let v = p.get_mut(&tid).copied().unwrap_or(0);
        if let Some(e) = p.get_mut(&tid) { *e = 0; }
        v
    };
    if pending == 0 { return; }

    for bit in 0..32u8 {
        if pending & (1 << bit) == 0 { continue; }
        match bit {
            9  => { /* SIGKILL — already handled */ }
            11 => { /* SIGSEGV — terminate */
                crate::serial_println!("  [SIG] SIGSEGV TID={} — terminated", tid);
                crate::sched::exit_current(139);
            }
            2 | 15 => { /* SIGINT/SIGTERM */
                crate::serial_println!("  [SIG] SIGTERM TID={}", tid);
                crate::sched::exit_current(0);
            }
            _ => {}
        }
    }
}

/// Register a signal handler (sigaction)
pub fn set_handler(tid: TaskId, sig: u8, handler_addr: u64) {
    HANDLERS.lock().entry(tid).or_default().insert(sig, handler_addr);
}

/// Clear all signals for a task (on exec)
pub fn clear(tid: TaskId) {
    PENDING.lock().remove(&tid);
    HANDLERS.lock().remove(&tid);
}

pub fn init() { crate::serial_println!("  [SIGNAL] initialized"); }
