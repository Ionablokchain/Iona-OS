//! Process management

pub mod dynlink;
pub mod exec;
pub mod clone;
pub mod address_space;
pub mod ipc;
pub mod fd;
pub mod fork;
pub mod mmap;
pub mod pipe;
pub mod futex;
pub mod epoll;

use alloc::collections::BTreeMap;
use spin::{Lazy, Mutex};
use crate::task::TaskId;

pub struct Process {
    pub pid:          TaskId,
    pub state:        ProcessState,
    pub kernel_rsp:   u64,
    pub user_rsp:     u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProcessState { Running, Ready, Blocked, Dead }

static PROCESSES: Lazy<Mutex<BTreeMap<TaskId, Process>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

pub fn register(pid: TaskId, kernel_rsp: u64) {
    PROCESSES.lock().insert(pid, Process {
        pid, state: ProcessState::Running, kernel_rsp, user_rsp: 0,
    });
}

pub fn get_kernel_rsp(pid: TaskId) -> Option<u64> {
    PROCESSES.lock().get(&pid).map(|p| p.kernel_rsp)
}
