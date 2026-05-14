//! pipe() — unidirectional inter-process byte stream
//!
//! Fiecare pipe = un ring buffer de 4KB în kernel.
//! write end → buffer → read end
//! read blocks (via wait queue) dacă buffer e gol
//! write blocks dacă buffer e plin

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::{Lazy, Mutex};
use crate::task::TaskId;

const PIPE_BUF_SIZE: usize = 65536; // 64KB — POSIX standard minimum (Linux default)
const MAX_PIPES:     usize = 1024;

pub type PipeId = u64;

pub struct PipeBuffer {
    pub buf:   Vec<u8>,
    pub head:  usize,   // read position
    pub tail:  usize,   // write position
    pub count: usize,   // bytes available
    /// TIDs waiting to read (blocked)
    pub readers_waiting: Vec<TaskId>,
    /// TIDs waiting to write (blocked)
    pub writers_waiting: Vec<TaskId>,
    pub write_closed: bool,
    pub read_closed:  bool,
}

impl PipeBuffer {
    fn new() -> Self {
        Self {
            buf: alloc::vec![0u8; PIPE_BUF_SIZE],
            head: 0, tail: 0, count: 0,
            readers_waiting: Vec::new(),
            writers_waiting: Vec::new(),
            write_closed: false,
            read_closed:  false,
        }
    }

    pub fn is_empty(&self) -> bool { self.count == 0 }
    pub fn is_full(&self)  -> bool { self.count == PIPE_BUF_SIZE }
    pub fn available(&self)-> usize { self.count }
    pub fn space(&self)    -> usize { PIPE_BUF_SIZE - self.count }

    pub fn write_bytes(&mut self, data: &[u8]) -> usize {
        let n = data.len().min(self.space());
        for i in 0..n {
            self.buf[self.tail] = data[i];
            self.tail = (self.tail + 1) % PIPE_BUF_SIZE;
        }
        self.count += n;
        n
    }

    pub fn read_bytes(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.count);
        for i in 0..n {
            buf[i] = self.buf[self.head];
            self.head = (self.head + 1) % PIPE_BUF_SIZE;
        }
        self.count -= n;
        n
    }
}

static PIPES: Lazy<Mutex<BTreeMap<PipeId, PipeBuffer>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

static NEXT_PIPE_ID: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(1);

/// Creates a new pipe. Returns (read_fd, write_fd) or (MAX, MAX) on error.
/// The returned values are PipeIds; caller wraps them in FileDesc::Pipe
pub fn create() -> (PipeId, PipeId) {
    let id = NEXT_PIPE_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    PIPES.lock().insert(id, PipeBuffer::new());
    (id, id) // same ID, read/write distinguished by FileDesc::Pipe.read_end flag
}

/// Write to pipe. Blocks if full. Returns bytes written or 0 on closed.
pub fn write(id: PipeId, tid: TaskId, data: &[u8]) -> usize {
    loop {
        let mut pipes = PIPES.lock();
        let pipe = match pipes.get_mut(&id) { Some(p) => p, None => return 0 };

        if pipe.read_closed { return 0; } // SIGPIPE
        if !pipe.is_full() {
            let n = pipe.write_bytes(data);
            // Wake blocked readers
            let readers: Vec<TaskId> = pipe.readers_waiting.drain(..).collect();
            drop(pipes);
            for r in readers { crate::sched::wake_task(r); }
            return n;
        }
        // Buffer full — block writer
        pipe.writers_waiting.push(tid);
        drop(pipes);
        // Block until reader drains some data
        crate::wait::block_current(tid, crate::wait::WakeCondition::Any);
    }
}

/// Read from pipe. Blocks if empty. Returns bytes read or 0 on EOF.
pub fn read(id: PipeId, tid: TaskId, buf: &mut [u8]) -> usize {
    loop {
        let mut pipes = PIPES.lock();
        let pipe = match pipes.get_mut(&id) { Some(p) => p, None => return 0 };

        if !pipe.is_empty() {
            let n = pipe.read_bytes(buf);
            let writers: Vec<TaskId> = pipe.writers_waiting.drain(..).collect();
            drop(pipes);
            for w in writers { crate::sched::wake_task(w); }
            return n;
        }
        if pipe.write_closed { return 0; } // EOF
        // Empty and write end open — block reader
        pipe.readers_waiting.push(tid);
        drop(pipes);
        crate::wait::block_current(tid, crate::wait::WakeCondition::Any);
    }
}

/// Non-blocking write to pipe (for shell pipeline use).
/// Writes as much as possible without blocking. Returns bytes written.
pub fn write_nonblock(id: PipeId, data: &[u8]) -> usize {
    let mut pipes = PIPES.lock();
    let pipe = match pipes.get_mut(&id) { Some(p) => p, None => return 0 };
    if pipe.read_closed { return 0; }
    pipe.write_bytes(data)
}

pub fn close_write(id: PipeId) {
    let mut pipes = PIPES.lock();
    if let Some(p) = pipes.get_mut(&id) {
        p.write_closed = true;
        let readers: Vec<TaskId> = p.readers_waiting.drain(..).collect();
        drop(pipes);
        for r in readers { crate::sched::wake_task(r); }
    }
}

pub fn close_read(id: PipeId) {
    let mut pipes = PIPES.lock();
    if let Some(p) = pipes.get_mut(&id) {
        p.read_closed = true;
        let writers: Vec<TaskId> = p.writers_waiting.drain(..).collect();
        drop(pipes);
        for w in writers { crate::sched::wake_task(w); }
    }
}

pub fn has_data(id: PipeId) -> bool {
    PIPES.lock().get(&id).map(|p| !p.is_empty()).unwrap_or(false)
}
