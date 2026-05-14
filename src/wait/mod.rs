//! Wait queues — block tasks until an event fires
//!
//! When a task calls sleep_ms(N) or tcp_recv() with no data:
//!   1. task is removed from ready queue
//!   2. placed in wait queue with a wakeup condition
//!   3. scheduler picks next task
//!   4. when condition fires (timer, IRQ), task returns to ready queue
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use spin::{Lazy, Mutex};
use crate::task::TaskId;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WakeCondition {
    Timer(u64),       // wake at uptime_ms >= this value
    IpcMessage,       // wake when IPC message arrives for this TID
    NetData(u64),     // wake when socket fd has data
    Any,              // wake immediately (used for yield)
}

pub struct WaitEntry {
    pub tid:       TaskId,
    pub condition: WakeCondition,
}

static WAIT_QUEUE: Lazy<Mutex<VecDeque<WaitEntry>>> =
    Lazy::new(|| Mutex::new(VecDeque::new()));

/// Block the current task until condition is met.
/// Called from sleep_ms, tcp_recv, ipc_recv, etc.
pub fn block_current(tid: TaskId, cond: WakeCondition) {
    WAIT_QUEUE.lock().push_back(WaitEntry { tid, condition: cond });
    // Remove from scheduler ready queue
    crate::sched::block_task(tid);
}

/// Called from timer interrupt (1ms) — wake tasks whose condition is met.
pub fn tick_wakeups() {
    let now = crate::arch::x86_64::timer::uptime_ms();
    let mut wq = WAIT_QUEUE.lock();
    let mut i = 0;
    while i < wq.len() {
        let should_wake = match wq[i].condition {
            WakeCondition::Timer(t)    => now >= t,
            WakeCondition::Any         => true,
            WakeCondition::IpcMessage  => crate::process::ipc::has_message(wq[i].tid),
            WakeCondition::NetData(fd) => crate::net::socket_has_data(fd),
        };
        if should_wake {
            let entry = match wq.remove(i) { Some(e) => e, None => continue };
            drop(wq);
            crate::sched::wake_task(entry.tid);
            wq = WAIT_QUEUE.lock();
        } else {
            i += 1;
        }
    }
}

/// Wake all tasks waiting on IPC for a specific TID
pub fn wake_ipc(tid: TaskId) {
    let mut wq = WAIT_QUEUE.lock();
    let mut to_wake = Vec::new();
    wq.retain(|e| {
        if e.tid == tid && e.condition == WakeCondition::IpcMessage {
            to_wake.push(e.tid); false
        } else { true }
    });
    drop(wq);
    for tid in to_wake { crate::sched::wake_task(tid); }
}

/// Wake tasks waiting on a socket fd
pub fn wake_net(fd: u64) {
    let mut wq = WAIT_QUEUE.lock();
    let mut to_wake = Vec::new();
    wq.retain(|e| {
        if e.condition == WakeCondition::NetData(fd) {
            to_wake.push(e.tid); false
        } else { true }
    });
    drop(wq);
    for tid in to_wake { crate::sched::wake_task(tid); }
}
