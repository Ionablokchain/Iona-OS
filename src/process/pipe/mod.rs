//! pipe() — unidirectional inter-process byte stream
//!
//! Implements POSIX pipes with:
//! - Ring buffer (configurable size, default 64 KiB)
//! - Blocking and non-blocking I/O
//! - O_NONBLOCK support with EAGAIN
//! - SIGPIPE generation on write to closed read end
//! - Proper wait queue management with timeouts
//! - epoll integration (read/write readiness notifications)
//! - Metrics for monitoring
//! - Configurable maximum pipes
//! - Thread-safe with spin locks
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                       PipeBuffer                       │
//! │  ┌─────────────────────────────────────────────────┐   │
//! │  │  Ring buffer (circular) with head/tail/count   │   │
//! │  └─────────────────────────────────────────────────┘   │
//! │  ┌─────────────────────────────────────────────────┐   │
//! │  │  Wait queues (readers, writers)                 │   │
//! │  └─────────────────────────────────────────────────┘   │
//! │  ┌─────────────────────────────────────────────────┐   │
//! │  │  Flags: write_closed, read_closed, nonblock    │   │
//! │  └─────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────┘
//! ```

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::{Lazy, Mutex};
use tracing::{debug, error, info, trace, warn};

use crate::sched::wake_task;
use crate::signal::{send_signal, Signal};
use crate::task::TaskId;
use crate::wait::{WakeCondition, block_current};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default pipe buffer size (64 KiB).
pub const DEFAULT_PIPE_BUF_SIZE: usize = 65_536;

/// Minimum pipe buffer size (4 KiB).
pub const MIN_PIPE_BUF_SIZE: usize = 4096;

/// Maximum pipe buffer size (1 MiB).
pub const MAX_PIPE_BUF_SIZE: usize = 1_048_576;

/// Default maximum number of pipes.
pub const DEFAULT_MAX_PIPES: usize = 1024;

/// Maximum pipe count limit.
pub const MAX_PIPES_LIMIT: usize = 4096;

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

/// Errors that can occur during pipe operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeError {
    /// Operation would block (EAGAIN).
    WouldBlock,
    /// Broken pipe (EPIPE) — write to read-closed pipe.
    BrokenPipe,
    /// Invalid pipe ID.
    InvalidPipe,
    /// Too many pipes (ENFILE/EMFILE).
    TooManyPipes,
    /// Pipe buffer full (EAGAIN).
    BufferFull,
    /// Pipe buffer empty (EAGAIN).
    BufferEmpty,
    /// Interrupted by signal (EINTR).
    Interrupted,
    /// I/O error.
    Io,
    /// Invalid argument (e.g., zero-length write).
    InvalidArgument,
    /// Operation not supported.
    Unsupported,
}

impl fmt::Display for PipeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WouldBlock => write!(f, "operation would block"),
            Self::BrokenPipe => write!(f, "broken pipe"),
            Self::InvalidPipe => write!(f, "invalid pipe"),
            Self::TooManyPipes => write!(f, "too many pipes"),
            Self::BufferFull => write!(f, "buffer full"),
            Self::BufferEmpty => write!(f, "buffer empty"),
            Self::Interrupted => write!(f, "interrupted by signal"),
            Self::Io => write!(f, "I/O error"),
            Self::InvalidArgument => write!(f, "invalid argument"),
            Self::Unsupported => write!(f, "operation not supported"),
        }
    }
}

impl From<PipeError> for i64 {
    fn from(e: PipeError) -> Self {
        match e {
            PipeError::WouldBlock => -1,
            PipeError::BrokenPipe => -2,
            PipeError::InvalidPipe => -3,
            PipeError::TooManyPipes => -4,
            PipeError::BufferFull => -5,
            PipeError::BufferEmpty => -6,
            PipeError::Interrupted => -7,
            PipeError::Io => -8,
            PipeError::InvalidArgument => -9,
            PipeError::Unsupported => -10,
        }
    }
}

pub type PipeResult<T> = Result<T, PipeError>;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the pipe subsystem.
#[derive(Debug, Clone)]
pub struct PipeConfig {
    /// Default pipe buffer size.
    pub default_buffer_size: usize,
    /// Maximum number of pipes allowed.
    pub max_pipes: usize,
    /// Whether to enable metrics collection.
    pub collect_metrics: bool,
    /// Whether to log debug events.
    pub debug_logging: bool,
}

impl Default for PipeConfig {
    fn default() -> Self {
        Self {
            default_buffer_size: DEFAULT_PIPE_BUF_SIZE,
            max_pipes: DEFAULT_MAX_PIPES,
            collect_metrics: true,
            debug_logging: false,
        }
    }
}

impl PipeConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> PipeResult<()> {
        if self.default_buffer_size < MIN_PIPE_BUF_SIZE || self.default_buffer_size > MAX_PIPE_BUF_SIZE {
            return Err(PipeError::InvalidArgument);
        }
        if self.max_pipes == 0 || self.max_pipes > MAX_PIPES_LIMIT {
            return Err(PipeError::InvalidArgument);
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

/// Pipe subsystem metrics.
#[derive(Debug, Default)]
pub struct PipeMetrics {
    /// Total number of pipes created.
    pub pipes_created: AtomicU64,
    /// Total number of pipes closed.
    pub pipes_closed: AtomicU64,
    /// Total bytes written to pipes.
    pub bytes_written: AtomicU64,
    /// Total bytes read from pipes.
    pub bytes_read: AtomicU64,
    /// Total number of write operations.
    pub write_ops: AtomicU64,
    /// Total number of read operations.
    pub read_ops: AtomicU64,
    /// Total number of times a writer blocked.
    pub writer_blocks: AtomicU64,
    /// Total number of times a reader blocked.
    pub reader_blocks: AtomicU64,
    /// Total number of broken pipe errors.
    pub broken_pipes: AtomicU64,
}

/// Global metrics instance.
static METRICS: Lazy<Mutex<PipeMetrics>> = Lazy::new(|| Mutex::new(PipeMetrics::default()));

/// Get the current metrics.
pub fn get_metrics() -> PipeMetrics {
    METRICS.lock().clone()
}

/// Reset metrics.
pub fn reset_metrics() {
    *METRICS.lock() = PipeMetrics::default();
}

// -----------------------------------------------------------------------------
// Pipe buffer
// -----------------------------------------------------------------------------

/// A pipe buffer (ring buffer) with wait queues.
#[derive(Debug)]
pub struct PipeBuffer {
    /// The ring buffer data.
    buf: Vec<u8>,
    /// Read position.
    head: usize,
    /// Write position.
    tail: usize,
    /// Number of bytes currently in the buffer.
    count: usize,
    /// Size of the buffer.
    capacity: usize,
    /// TIDs waiting to read (blocked).
    readers_waiting: Vec<TaskId>,
    /// TIDs waiting to write (blocked).
    writers_waiting: Vec<TaskId>,
    /// Whether the write end is closed.
    pub write_closed: bool,
    /// Whether the read end is closed.
    pub read_closed: bool,
    /// Whether the pipe is non-blocking (per-pipe flag).
    pub nonblock: bool,
    /// Unique pipe ID.
    id: PipeId,
}

impl PipeBuffer {
    /// Create a new pipe buffer with the given capacity.
    pub fn new(id: PipeId, capacity: usize) -> Self {
        let capacity = capacity.clamp(MIN_PIPE_BUF_SIZE, MAX_PIPE_BUF_SIZE);
        Self {
            buf: vec![0u8; capacity],
            head: 0,
            tail: 0,
            count: 0,
            capacity,
            readers_waiting: Vec::new(),
            writers_waiting: Vec::new(),
            write_closed: false,
            read_closed: false,
            nonblock: false,
            id,
        }
    }

    /// Check if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Check if the buffer is full.
    pub fn is_full(&self) -> bool {
        self.count == self.capacity
    }

    /// Number of bytes currently available to read.
    pub fn available(&self) -> usize {
        self.count
    }

    /// Number of bytes that can be written without blocking.
    pub fn space(&self) -> usize {
        self.capacity - self.count
    }

    /// Write bytes to the buffer. Returns the number of bytes written.
    pub fn write_bytes(&mut self, data: &[u8]) -> usize {
        let n = data.len().min(self.space());
        for i in 0..n {
            self.buf[self.tail] = data[i];
            self.tail = (self.tail + 1) % self.capacity;
        }
        self.count += n;
        n
    }

    /// Read bytes from the buffer. Returns the number of bytes read.
    pub fn read_bytes(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.count);
        for i in 0..n {
            buf[i] = self.buf[self.head];
            self.head = (self.head + 1) % self.capacity;
        }
        self.count -= n;
        n
    }

    /// Read bytes without consuming them (peek).
    pub fn peek_bytes(&self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.count);
        let mut pos = self.head;
        for i in 0..n {
            buf[i] = self.buf[pos];
            pos = (pos + 1) % self.capacity;
        }
        n
    }

    /// Wake all readers waiting on this pipe.
    pub fn wake_readers(&mut self) -> Vec<TaskId> {
        self.readers_waiting.drain(..).collect()
    }

    /// Wake all writers waiting on this pipe.
    pub fn wake_writers(&mut self) -> Vec<TaskId> {
        self.writers_waiting.drain(..).collect()
    }

    /// Add a reader to the wait queue.
    pub fn add_reader(&mut self, tid: TaskId) {
        if !self.readers_waiting.contains(&tid) {
            self.readers_waiting.push(tid);
        }
    }

    /// Add a writer to the wait queue.
    pub fn add_writer(&mut self, tid: TaskId) {
        if !self.writers_waiting.contains(&tid) {
            self.writers_waiting.push(tid);
        }
    }

    /// Remove a reader from the wait queue (timeout case).
    pub fn remove_reader(&mut self, tid: TaskId) -> bool {
        let pos = self.readers_waiting.iter().position(|&t| t == tid);
        if let Some(p) = pos {
            self.readers_waiting.remove(p);
            true
        } else {
            false
        }
    }

    /// Remove a writer from the wait queue (timeout case).
    pub fn remove_writer(&mut self, tid: TaskId) -> bool {
        let pos = self.writers_waiting.iter().position(|&t| t == tid);
        if let Some(p) = pos {
            self.writers_waiting.remove(p);
            true
        } else {
            false
        }
    }

    /// Set non-blocking mode.
    pub fn set_nonblock(&mut self, nonblock: bool) {
        self.nonblock = nonblock;
    }
}

// -----------------------------------------------------------------------------
// Global state
// -----------------------------------------------------------------------------

/// Global pipe registry.
static PIPES: Lazy<Mutex<BTreeMap<PipeId, PipeBuffer>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

/// Next pipe ID.
static NEXT_PIPE_ID: AtomicU64 = AtomicU64::new(1);

/// Global configuration.
static CONFIG: Lazy<Mutex<PipeConfig>> = Lazy::new(|| Mutex::new(PipeConfig::default()));

/// Initialize the pipe subsystem with a configuration.
pub fn init(config: PipeConfig) -> PipeResult<()> {
    config.validate()?;
    *CONFIG.lock() = config;
    info!("pipe subsystem initialized");
    Ok(())
}

/// Generate a new pipe ID.
fn next_pipe_id() -> PipeId {
    NEXT_PIPE_ID.fetch_add(1, Ordering::Relaxed)
}

/// Get the current configuration.
pub fn get_config() -> PipeConfig {
    CONFIG.lock().clone()
}

// -----------------------------------------------------------------------------
// Core pipe operations
// -----------------------------------------------------------------------------

/// Create a new pipe. Returns the pipe ID (both read and write ends use the same ID,
/// distinguished by the `read_end` flag in the file descriptor).
pub fn create_pipe() -> PipeResult<PipeId> {
    let config = CONFIG.lock();
    let id = next_pipe_id();

    // Check max pipes.
    {
        let pipes = PIPES.lock();
        if pipes.len() >= config.max_pipes {
            return Err(PipeError::TooManyPipes);
        }
    }

    let buffer_size = config.default_buffer_size;
    let pipe = PipeBuffer::new(id, buffer_size);

    PIPES.lock().insert(id, pipe);

    if config.collect_metrics {
        METRICS.lock().pipes_created.fetch_add(1, Ordering::Relaxed);
    }

    trace!(pipe_id = id, "pipe created");
    Ok(id)
}

/// Close the write end of a pipe.
pub fn close_write_end(pipe_id: PipeId) -> PipeResult<()> {
    let mut pipes = PIPES.lock();
    let pipe = pipes.get_mut(&pipe_id).ok_or(PipeError::InvalidPipe)?;

    if pipe.write_closed {
        return Ok(());
    }

    pipe.write_closed = true;

    // Wake all readers waiting for data.
    let readers = pipe.wake_readers();
    drop(pipes);

    for tid in readers {
        wake_task(tid);
    }

    if CONFIG.lock().collect_metrics {
        // We could increment closed count, but only when both ends are closed.
        // We'll track in the close function.
    }

    trace!(pipe_id, "write end closed");
    Ok(())
}

/// Close the read end of a pipe.
pub fn close_read_end(pipe_id: PipeId) -> PipeResult<()> {
    let mut pipes = PIPES.lock();
    let pipe = pipes.get_mut(&pipe_id).ok_or(PipeError::InvalidPipe)?;

    if pipe.read_closed {
        return Ok(());
    }

    pipe.read_closed = true;

    // Wake all writers waiting for space.
    let writers = pipe.wake_writers();
    drop(pipes);

    for tid in writers {
        // For writers, waking with read_closed will cause them to get EPIPE.
        wake_task(tid);
    }

    trace!(pipe_id, "read end closed");
    Ok(())
}

/// Close a pipe completely (both ends).
pub fn close_pipe(pipe_id: PipeId) -> PipeResult<()> {
    let mut pipes = PIPES.lock();
    let pipe = pipes.get_mut(&pipe_id).ok_or(PipeError::InvalidPipe)?;

    // Wake all waiters.
    let readers = pipe.wake_readers();
    let writers = pipe.wake_writers();
    drop(pipes);

    for tid in readers {
        wake_task(tid);
    }
    for tid in writers {
        wake_task(tid);
    }

    // Remove the pipe.
    PIPES.lock().remove(&pipe_id);

    if CONFIG.lock().collect_metrics {
        METRICS.lock().pipes_closed.fetch_add(1, Ordering::Relaxed);
    }

    trace!(pipe_id, "pipe closed");
    Ok(())
}

/// Write to a pipe.
///
/// # Arguments
/// * `pipe_id` – The pipe ID.
/// * `tid` – The task ID of the writer.
/// * `data` – The data to write.
/// * `nonblock` – Whether to use non-blocking mode.
/// * `timeout_ms` – Optional timeout (0 = no timeout, none = infinite).
///
/// # Returns
/// The number of bytes written, or an error.
pub fn pipe_write(
    pipe_id: PipeId,
    tid: TaskId,
    data: &[u8],
    nonblock: bool,
    timeout_ms: Option<u64>,
) -> PipeResult<usize> {
    if data.is_empty() {
        return Err(PipeError::InvalidArgument);
    }

    let mut pipes = PIPES.lock();
    let pipe = match pipes.get_mut(&pipe_id) {
        Some(p) => p,
        None => return Err(PipeError::InvalidPipe),
    };

    // Check if read end is closed.
    if pipe.read_closed {
        // Generate SIGPIPE.
        send_signal(tid, Signal::SIGPIPE);
        if CONFIG.lock().collect_metrics {
            METRICS.lock().broken_pipes.fetch_add(1, Ordering::Relaxed);
        }
        return Err(PipeError::BrokenPipe);
    }

    // Check if write end is closed.
    if pipe.write_closed {
        return Err(PipeError::BrokenPipe);
    }

    // If non-blocking and buffer is full, return EAGAIN.
    if nonblock && pipe.is_full() {
        return Err(PipeError::WouldBlock);
    }

    // If buffer has space, write immediately.
    if !pipe.is_full() {
        let n = pipe.write_bytes(data);
        // Wake readers.
        let readers = pipe.wake_readers();
        drop(pipes);

        if CONFIG.lock().collect_metrics {
            let mut metrics = METRICS.lock();
            metrics.bytes_written.fetch_add(n as u64, Ordering::Relaxed);
            metrics.write_ops.fetch_add(1, Ordering::Relaxed);
        }

        for tid in readers {
            wake_task(tid);
        }

        // Notify epoll that the pipe is readable.
        crate::syscall::epoll::epoll_notify_fd(pipe_id as usize);

        trace!(pipe_id, bytes = n, "pipe write");
        return Ok(n);
    }

    // Buffer is full — need to block.
    if CONFIG.lock().collect_metrics {
        METRICS.lock().writer_blocks.fetch_add(1, Ordering::Relaxed);
    }

    // Set up deadline.
    let deadline = timeout_ms.map(|ms| {
        if ms == 0 {
            // Non-blocking with zero timeout is handled above (nonblock flag).
            // For timeout_ms == 0, we would have returned WouldBlock earlier.
            // We'll treat as infinite if nonblock is false.
            u64::MAX
        } else {
            crate::arch::timer::uptime_ms() + ms
        }
    });

    // Add writer to wait queue.
    pipe.add_writer(tid);
    drop(pipes);

    // Block the writer.
    let cond = match deadline {
        Some(d) => WakeCondition::Timer(d),
        None => WakeCondition::Any,
    };
    block_current(tid, cond);

    // After waking, try again.
    // We need to re-acquire the lock and check conditions.
    let mut pipes = PIPES.lock();
    let pipe = match pipes.get_mut(&pipe_id) {
        Some(p) => p,
        None => return Err(PipeError::InvalidPipe),
    };

    // Remove from wait queue (if still there — timeout case).
    let was_removed = pipe.remove_writer(tid);

    // Check for read end closed (SIGPIPE).
    if pipe.read_closed {
        send_signal(tid, Signal::SIGPIPE);
        return Err(PipeError::BrokenPipe);
    }

    // Check for write end closed.
    if pipe.write_closed {
        return Err(PipeError::BrokenPipe);
    }

    // If we were removed from the queue (timeout), return WouldBlock.
    if !was_removed {
        // We were woken by a reader.
        // Try to write again.
        if !pipe.is_full() {
            let n = pipe.write_bytes(data);
            let readers = pipe.wake_readers();
            drop(pipes);

            if CONFIG.lock().collect_metrics {
                let mut metrics = METRICS.lock();
                metrics.bytes_written.fetch_add(n as u64, Ordering::Relaxed);
                metrics.write_ops.fetch_add(1, Ordering::Relaxed);
            }

            for tid in readers {
                wake_task(tid);
            }
            crate::syscall::epoll::epoll_notify_fd(pipe_id as usize);

            trace!(pipe_id, bytes = n, "pipe write after wake");
            return Ok(n);
        } else {
            // Still full — this should not happen often.
            return Err(PipeError::WouldBlock);
        }
    } else {
        // Timed out.
        return Err(PipeError::WouldBlock);
    }
}

/// Read from a pipe.
///
/// # Arguments
/// * `pipe_id` – The pipe ID.
/// * `tid` – The task ID of the reader.
/// * `buf` – The buffer to read into.
/// * `nonblock` – Whether to use non-blocking mode.
/// * `timeout_ms` – Optional timeout (0 = no timeout, none = infinite).
///
/// # Returns
/// The number of bytes read, or an error.
pub fn pipe_read(
    pipe_id: PipeId,
    tid: TaskId,
    buf: &mut [u8],
    nonblock: bool,
    timeout_ms: Option<u64>,
) -> PipeResult<usize> {
    if buf.is_empty() {
        return Err(PipeError::InvalidArgument);
    }

    let mut pipes = PIPES.lock();
    let pipe = match pipes.get_mut(&pipe_id) {
        Some(p) => p,
        None => return Err(PipeError::InvalidPipe),
    };

    // Check if write end is closed and buffer is empty -> EOF.
    if pipe.write_closed && pipe.is_empty() {
        return Ok(0);
    }

    // Check if read end is closed.
    if pipe.read_closed {
        return Err(PipeError::BrokenPipe);
    }

    // If non-blocking and buffer is empty, return EAGAIN.
    if nonblock && pipe.is_empty() {
        return Err(PipeError::WouldBlock);
    }

    // If buffer has data, read immediately.
    if !pipe.is_empty() {
        let n = pipe.read_bytes(buf);
        // Wake writers.
        let writers = pipe.wake_writers();
        drop(pipes);

        if CONFIG.lock().collect_metrics {
            let mut metrics = METRICS.lock();
            metrics.bytes_read.fetch_add(n as u64, Ordering::Relaxed);
            metrics.read_ops.fetch_add(1, Ordering::Relaxed);
        }

        for tid in writers {
            wake_task(tid);
        }

        // Notify epoll that the pipe is writable.
        crate::syscall::epoll::epoll_notify_fd(pipe_id as usize);

        trace!(pipe_id, bytes = n, "pipe read");
        return Ok(n);
    }

    // Buffer is empty — need to block.
    if CONFIG.lock().collect_metrics {
        METRICS.lock().reader_blocks.fetch_add(1, Ordering::Relaxed);
    }

    // Set up deadline.
    let deadline = timeout_ms.map(|ms| {
        if ms == 0 {
            u64::MAX
        } else {
            crate::arch::timer::uptime_ms() + ms
        }
    });

    // Add reader to wait queue.
    pipe.add_reader(tid);
    drop(pipes);

    // Block the reader.
    let cond = match deadline {
        Some(d) => WakeCondition::Timer(d),
        None => WakeCondition::Any,
    };
    block_current(tid, cond);

    // After waking, try again.
    let mut pipes = PIPES.lock();
    let pipe = match pipes.get_mut(&pipe_id) {
        Some(p) => p,
        None => return Err(PipeError::InvalidPipe),
    };

    // Remove from wait queue (if still there — timeout case).
    let was_removed = pipe.remove_reader(tid);

    // Check for read end closed.
    if pipe.read_closed {
        return Err(PipeError::BrokenPipe);
    }

    // Check for write end closed and empty -> EOF.
    if pipe.write_closed && pipe.is_empty() {
        return Ok(0);
    }

    // If we were removed from the queue (timeout), return WouldBlock.
    if !was_removed {
        // We were woken by a writer.
        // Try to read again.
        if !pipe.is_empty() {
            let n = pipe.read_bytes(buf);
            let writers = pipe.wake_writers();
            drop(pipes);

            if CONFIG.lock().collect_metrics {
                let mut metrics = METRICS.lock();
                metrics.bytes_read.fetch_add(n as u64, Ordering::Relaxed);
                metrics.read_ops.fetch_add(1, Ordering::Relaxed);
            }

            for tid in writers {
                wake_task(tid);
            }
            crate::syscall::epoll::epoll_notify_fd(pipe_id as usize);

            trace!(pipe_id, bytes = n, "pipe read after wake");
            return Ok(n);
        } else {
            // Still empty — this should not happen often.
            return Err(PipeError::WouldBlock);
        }
    } else {
        // Timed out.
        return Err(PipeError::WouldBlock);
    }
}

/// Check if a pipe has data available (for epoll).
pub fn pipe_has_data(pipe_id: PipeId) -> bool {
    PIPES.lock().get(&pipe_id).map(|p| !p.is_empty()).unwrap_or(false)
}

/// Check if a pipe has space available (for epoll).
pub fn pipe_has_space(pipe_id: PipeId) -> bool {
    PIPES.lock().get(&pipe_id).map(|p| !p.is_full()).unwrap_or(false)
}

/// Get the number of bytes available in a pipe.
pub fn pipe_available(pipe_id: PipeId) -> usize {
    PIPES.lock().get(&pipe_id).map(|p| p.available()).unwrap_or(0)
}

/// Get the number of bytes of space in a pipe.
pub fn pipe_space(pipe_id: PipeId) -> usize {
    PIPES.lock().get(&pipe_id).map(|p| p.space()).unwrap_or(0)
}

/// Set non-blocking mode on a pipe.
pub fn pipe_set_nonblock(pipe_id: PipeId, nonblock: bool) -> PipeResult<()> {
    let mut pipes = PIPES.lock();
    let pipe = pipes.get_mut(&pipe_id).ok_or(PipeError::InvalidPipe)?;
    pipe.set_nonblock(nonblock);
    Ok(())
}

/// Check if a pipe is non-blocking.
pub fn pipe_is_nonblock(pipe_id: PipeId) -> bool {
    PIPES.lock().get(&pipe_id).map(|p| p.nonblock).unwrap_or(false)
}

/// Get the buffer size of a pipe.
pub fn pipe_buffer_size(pipe_id: PipeId) -> usize {
    PIPES.lock().get(&pipe_id).map(|p| p.capacity).unwrap_or(0)
}

// -----------------------------------------------------------------------------
// Additional helpers
// -----------------------------------------------------------------------------

/// Write to a pipe with a timeout.
pub fn pipe_write_timeout(
    pipe_id: PipeId,
    tid: TaskId,
    data: &[u8],
    timeout_ms: u64,
) -> PipeResult<usize> {
    pipe_write(pipe_id, tid, data, false, Some(timeout_ms))
}

/// Read from a pipe with a timeout.
pub fn pipe_read_timeout(
    pipe_id: PipeId,
    tid: TaskId,
    buf: &mut [u8],
    timeout_ms: u64,
) -> PipeResult<usize> {
    pipe_read(pipe_id, tid, buf, false, Some(timeout_ms))
}

/// Non-blocking write.
pub fn pipe_write_nonblock(pipe_id: PipeId, tid: TaskId, data: &[u8]) -> PipeResult<usize> {
    pipe_write(pipe_id, tid, data, true, None)
}

/// Non-blocking read.
pub fn pipe_read_nonblock(pipe_id: PipeId, tid: TaskId, buf: &mut [u8]) -> PipeResult<usize> {
    pipe_read(pipe_id, tid, buf, true, None)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::TaskId;

    // Mock task ID for testing.
    fn mock_tid(id: u64) -> TaskId {
        TaskId::from_u64(id)
    }

    #[test]
    fn test_pipe_create_close() {
        let id = create_pipe().unwrap();
        assert!(PIPES.lock().contains_key(&id));

        close_pipe(id).unwrap();
        assert!(!PIPES.lock().contains_key(&id));
    }

    #[test]
    fn test_pipe_write_read() {
        let id = create_pipe().unwrap();
        let tid = mock_tid(1);

        let data = b"hello world";
        let n = pipe_write(id, tid, data, false, None).unwrap();
        assert_eq!(n, data.len());

        let mut buf = [0u8; 1024];
        let n = pipe_read(id, tid, &mut buf, false, None).unwrap();
        assert_eq!(n, data.len());
        assert_eq!(&buf[..n], data);

        close_pipe(id).unwrap();
    }

    #[test]
    fn test_pipe_nonblock_empty() {
        let id = create_pipe().unwrap();
        let tid = mock_tid(2);

        let mut buf = [0u8; 1024];
        let result = pipe_read_nonblock(id, tid, &mut buf);
        assert!(matches!(result, Err(PipeError::WouldBlock)));

        close_pipe(id).unwrap();
    }

    #[test]
    fn test_pipe_nonblock_full() {
        let id = create_pipe().unwrap();
        let tid = mock_tid(3);

        // Fill the pipe.
        let data = vec![0u8; DEFAULT_PIPE_BUF_SIZE + 100];
        let n = pipe_write_nonblock(id, tid, &data).unwrap();
        assert_eq!(n, DEFAULT_PIPE_BUF_SIZE);

        // Next write should block.
        let result = pipe_write_nonblock(id, tid, &[1u8; 1]);
        assert!(matches!(result, Err(PipeError::WouldBlock)));

        close_pipe(id).unwrap();
    }

    #[test]
    fn test_pipe_broken_pipe() {
        let id = create_pipe().unwrap();
        let tid = mock_tid(4);

        // Close read end.
        close_read_end(id).unwrap();

        // Write should fail with BrokenPipe.
        let result = pipe_write(id, tid, b"data", false, None);
        assert!(matches!(result, Err(PipeError::BrokenPipe)));

        close_pipe(id).unwrap();
    }

    #[test]
    fn test_pipe_eof() {
        let id = create_pipe().unwrap();
        let tid = mock_tid(5);

        // Write some data, then close write end.
        pipe_write(id, tid, b"data", false, None).unwrap();
        close_write_end(id).unwrap();

        // Read should get the data then EOF.
        let mut buf = [0u8; 1024];
        let n = pipe_read(id, tid, &mut buf, false, None).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf[..4], b"data");

        // Next read should return 0 (EOF).
        let n = pipe_read(id, tid, &mut buf, false, None).unwrap();
        assert_eq!(n, 0);

        close_pipe(id).unwrap();
    }

    #[test]
    fn test_metrics() {
        reset_metrics();
        let metrics = get_metrics();
        assert_eq!(metrics.pipes_created.load(Ordering::Relaxed), 0);

        let id = create_pipe().unwrap();
        let metrics = get_metrics();
        assert_eq!(metrics.pipes_created.load(Ordering::Relaxed), 1);

        close_pipe(id).unwrap();
        let metrics = get_metrics();
        assert_eq!(metrics.pipes_closed.load(Ordering::Relaxed), 1);
    }
}
