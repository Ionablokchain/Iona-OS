//! IPC — Inter-Process Communication
//! Simplificat: message queue per task (tokio mpsc equivalent fără async)

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use spin::{Lazy, Mutex};
use crate::task::TaskId;

type Message = Vec<u8>;

static QUEUES: Lazy<Mutex<BTreeMap<TaskId, VecDeque<Message>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

pub fn send(to: TaskId, data: &[u8]) {
    let mut qs = QUEUES.lock();
    qs.entry(to).or_default().push_back(data.to_vec());
}

pub fn recv(tid: TaskId) -> Option<Message> {
    QUEUES.lock().get_mut(&tid)?.pop_front()
}

pub fn register(tid: TaskId) {
    QUEUES.lock().entry(tid).or_default();
}

pub fn unregister(tid: TaskId) {
    QUEUES.lock().remove(&tid);
}

pub fn has_message(tid: TaskId) -> bool {
    QUEUES.lock().get(&tid).map(|q| !q.is_empty()).unwrap_or(false)
}
