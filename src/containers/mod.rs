//! Container subsystem — cgroups + namespaces
pub mod cgroups;
pub mod namespaces;

pub fn init() {
    cgroups::init();
    namespaces::init();
}

use alloc::{string::String, collections::BTreeMap, vec::Vec};
use spin::{Lazy, Mutex};
use crate::task::TaskId;

#[derive(Clone, Debug)]
pub struct Container {
    pub id:      u64,
    pub name:    String,
    pub tasks:   Vec<TaskId>,
    pub fs_root: String,   // chroot path in IONAFS
    pub net_ns:  bool,     // isolated network namespace
}

static CONTAINERS: Lazy<Mutex<BTreeMap<u64, Container>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));
static NEXT_CID: spin::Mutex<u64> = spin::Mutex::new(1);

pub fn container_create(name: &str, fs_root: &str, net_isolate: bool) -> u64 {
    let cid = { let mut n = NEXT_CID.lock(); let v = *n; *n += 1; v };
    let c = Container {
        id: cid, name: name.into(),
        tasks: Vec::new(), fs_root: fs_root.into(), net_ns: net_isolate,
    };
    CONTAINERS.lock().insert(cid, c);
    crate::serial_println!("[CONTAINER] created: {} (id={} root={})", name, cid, fs_root);
    cid
}

pub fn container_add_task(cid: u64, tid: TaskId) -> bool {
    let mut cs = CONTAINERS.lock();
    if let Some(c) = cs.get_mut(&cid) { c.tasks.push(tid); true } else { false }
}

pub fn container_destroy(cid: u64) {
    let mut cs = CONTAINERS.lock();
    if let Some(c) = cs.remove(&cid) {
        // Kill all tasks in container
        for tid in &c.tasks { crate::sched::block_task(*tid); }
        crate::serial_println!("[CONTAINER] destroyed: {} (id={})", c.name, cid);
    }
}

pub fn get_container_root(tid: TaskId) -> Option<String> {
    let cs = CONTAINERS.lock();
    for c in cs.values() {
        if c.tasks.contains(&tid) { return Some(c.fs_root.clone()); }
    }
    None
}
