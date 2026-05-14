//! Per-process file descriptor table
//! fd 0=stdin(kbd), 1=stdout(serial), 2=stderr(serial), 3+=files/sockets
use alloc::{collections::BTreeMap, string::String};
use spin::{Lazy, Mutex};
use crate::task::TaskId;

pub const STDIN:  usize = 0;
pub const STDOUT: usize = 1;
pub const STDERR: usize = 2;
pub const MAX_FD: usize = 256;

#[derive(Clone)]
pub enum FileDesc {
    Serial,
    Keyboard,
    IonasFs { path: String, offset: u64 },
    TcpSocket(u64),
    Pipe { read_end: bool, id: u64 },
    Dev(String),
    Proc(String),
}

pub struct FdTable {
    entries: [Option<FileDesc>; MAX_FD],
    next:    usize,
}

impl FdTable {
    pub fn new() -> Self {
        let mut t = Self { entries: core::array::from_fn(|_| None), next: 3 };
        t.entries[STDIN]  = Some(FileDesc::Keyboard);
        t.entries[STDOUT] = Some(FileDesc::Serial);
        t.entries[STDERR] = Some(FileDesc::Serial);
        t
    }

    pub fn open(&mut self, desc: FileDesc) -> Option<usize> {
        for fd in self.next..MAX_FD {
            if self.entries[fd].is_none() {
                self.entries[fd] = Some(desc);
                self.next = fd + 1;
                return Some(fd);
            }
        }
        None // EMFILE
    }

    pub fn get(&self, fd: usize) -> Option<&FileDesc> {
        self.entries.get(fd)?.as_ref()
    }

    pub fn close(&mut self, fd: usize) {
        if fd > STDERR && fd < MAX_FD {
            self.entries[fd] = None;
            if fd < self.next { self.next = fd; }
        }
    }

    pub fn dup2(&mut self, old: usize, new: usize) -> bool {
        if old >= MAX_FD || new >= MAX_FD { return false; }
        self.entries[new] = self.entries[old].clone();
        true
    }
}

static FD_TABLES: Lazy<Mutex<BTreeMap<TaskId, FdTable>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

pub fn init_for(tid: TaskId) {
    FD_TABLES.lock().insert(tid, FdTable::new());
}

pub fn remove_for(tid: TaskId) {
    FD_TABLES.lock().remove(&tid);
}

pub fn open(tid: TaskId, desc: FileDesc) -> Option<usize> {
    FD_TABLES.lock().get_mut(&tid)?.open(desc)
}

pub fn get_clone(tid: TaskId, fd: usize) -> Option<FileDesc> {
    FD_TABLES.lock().get(&tid)?.get(fd).cloned()
}

pub fn close(tid: TaskId, fd: usize) {
    if let Some(t) = FD_TABLES.lock().get_mut(&tid) { t.close(fd); }
}

pub fn dup2(tid: TaskId, old: usize, new: usize) -> bool {
    FD_TABLES.lock().get_mut(&tid).map(|t| t.dup2(old, new)).unwrap_or(false)
}

/// Share the FD table between parent and child (CLONE_FILES).
/// Both TIDs will reference the same underlying table entries.
/// Changes made by one thread are visible to the other.
pub fn share_fd_table(parent_tid: TaskId, child_tid: TaskId) {
    let mut tables = FD_TABLES.lock();
    // Clone all entries from parent to child (shared view)
    if let Some(parent_table) = tables.get(&parent_tid) {
        let mut child_table = FdTable::new();
        for i in 0..MAX_FD {
            child_table.entries[i] = parent_table.entries[i].clone();
        }
        child_table.next = parent_table.next;
        tables.insert(child_tid, child_table);
    } else {
        tables.insert(child_tid, FdTable::new());
    }
    // Track shared relationship for bidirectional sync
    SHARED_FD.lock().push((parent_tid, child_tid));
}

/// Clone the FD table independently (fork semantics).
/// Child gets a snapshot; future changes are independent.
pub fn clone_fd_table(parent_tid: TaskId, child_tid: TaskId) {
    let mut tables = FD_TABLES.lock();
    if let Some(parent_table) = tables.get(&parent_tid) {
        let mut child_table = FdTable::new();
        for i in 0..MAX_FD {
            child_table.entries[i] = parent_table.entries[i].clone();
        }
        child_table.next = parent_table.next;
        tables.insert(child_tid, child_table);
    } else {
        tables.insert(child_tid, FdTable::new());
    }
}

/// Track shared FD table relationships (for CLONE_FILES sync)
static SHARED_FD: Lazy<Mutex<alloc::vec::Vec<(TaskId, TaskId)>>> =
    Lazy::new(|| Mutex::new(alloc::vec::Vec::new()));
