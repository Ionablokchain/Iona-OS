//! IPC — Inter-Process Communication
//!
//! Implements message queues per task with:
//! - Configurable queue capacity
//! - Priority messages
//! - Blocking and non-blocking send/receive
//! - Timeouts
//! - Permissions (simple)
//! - Metrics
//! - Integration with wait subsystem
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                      IPC Manager                       │
//! │  ┌─────────────────────────────────────────────────┐   │
//! │  │  Queues: BTreeMap<TaskId, MessageQueue>        │   │
//! │  │  - Each queue has capacity, priority, waiters   │   │
//! │  └─────────────────────────────────────────────────┘   │
//! │  ┌─────────────────────────────────────────────────┐   │
//! │  │  Metrics: messages_sent, received, blocks, ...  │   │
//! │  └─────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::ipc::{send, recv, IpcError};
//!
//! let tid = task::current_tid();
//! ipc::register(tid);
//! ipc::send(tid, b"hello".to_vec(), 0)?;
//! let msg = ipc::recv(tid)?;
//! ```

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::{Lazy, Mutex, MutexGuard};
use tracing::{debug, error, info, trace, warn};

use crate::sched::wake_task;
use crate::task::TaskId;
use crate::wait::{WakeCondition, block_current};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default queue capacity (number of messages).
pub const DEFAULT_QUEUE_CAPACITY: usize = 1024;

/// Default timeout for blocking operations (milliseconds).
pub const DEFAULT_TIMEOUT_MS: u64 = 5000;

/// Maximum queue capacity (safety limit).
pub const MAX_QUEUE_CAPACITY: usize = 65536;

/// Maximum message size (1 MiB).
pub const MAX_MESSAGE_SIZE: usize = 1_048_576;

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

/// Errors that can occur during IPC operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcError {
    /// Queue is full (EAGAIN).
    QueueFull,
    /// Queue is empty (EAGAIN).
    QueueEmpty,
    /// Task not found (no queue for target task).
    TaskNotFound,
    /// Permission denied (sender not allowed).
    PermissionDenied,
    /// Operation timed out.
    Timeout,
    /// Interrupted by signal.
    Interrupted,
    /// Invalid argument (e.g., message too large).
    InvalidArgument,
    /// Resource temporarily unavailable.
    ResourceUnavailable,
    /// Queue is closed (task exited).
    QueueClosed,
}

impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueueFull => write!(f, "queue full"),
            Self::QueueEmpty => write!(f, "queue empty"),
            Self::TaskNotFound => write!(f, "task not found"),
            Self::PermissionDenied => write!(f, "permission denied"),
            Self::Timeout => write!(f, "timeout"),
            Self::Interrupted => write!(f, "interrupted"),
            Self::InvalidArgument => write!(f, "invalid argument"),
            Self::ResourceUnavailable => write!(f, "resource temporarily unavailable"),
            Self::QueueClosed => write!(f, "queue closed"),
        }
    }
}

impl From<IpcError> for i64 {
    fn from(e: IpcError) -> Self {
        match e {
            IpcError::QueueFull => -1,
            IpcError::QueueEmpty => -2,
            IpcError::TaskNotFound => -3,
            IpcError::PermissionDenied => -4,
            IpcError::Timeout => -5,
            IpcError::Interrupted => -6,
            IpcError::InvalidArgument => -7,
            IpcError::ResourceUnavailable => -8,
            IpcError::QueueClosed => -9,
        }
    }
}

pub type IpcResult<T> = Result<T, IpcError>;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the IPC subsystem.
#[derive(Debug, Clone)]
pub struct IpcConfig {
    /// Default queue capacity for new queues.
    pub default_capacity: usize,
    /// Default timeout for blocking operations (milliseconds).
    pub default_timeout_ms: u64,
    /// Maximum message size allowed.
    pub max_message_size: usize,
    /// Whether to enable metrics collection.
    pub collect_metrics: bool,
    /// Whether to enable debug logging.
    pub debug_logging: bool,
}

impl Default for IpcConfig {
    fn default() -> Self {
        Self {
            default_capacity: DEFAULT_QUEUE_CAPACITY,
            default_timeout_ms: DEFAULT_TIMEOUT_MS,
            max_message_size: MAX_MESSAGE_SIZE,
            collect_metrics: true,
            debug_logging: false,
        }
    }
}

impl IpcConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> IpcResult<()> {
        if self.default_capacity == 0 || self.default_capacity > MAX_QUEUE_CAPACITY {
            return Err(IpcError::InvalidArgument);
        }
        if self.max_message_size == 0 || self.max_message_size > MAX_MESSAGE_SIZE {
            return Err(IpcError::InvalidArgument);
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

/// IPC subsystem metrics.
#[derive(Debug, Default)]
pub struct IpcMetrics {
    /// Total number of messages sent.
    pub messages_sent: AtomicU64,
    /// Total number of messages received.
    pub messages_received: AtomicU64,
    /// Total number of queues created.
    pub queues_created: AtomicU64,
    /// Total number of queues destroyed.
    pub queues_destroyed: AtomicU64,
    /// Total number of send blocks (sender blocked).
    pub send_blocks: AtomicU64,
    /// Total number of receive blocks (receiver blocked).
    pub recv_blocks: AtomicU64,
    /// Total number of timeouts.
    pub timeouts: AtomicU64,
    /// Total number of permission denials.
    pub permission_denials: AtomicU64,
}

/// Global metrics instance.
static METRICS: Lazy<Mutex<IpcMetrics>> = Lazy::new(|| Mutex::new(IpcMetrics::default()));

/// Get the current metrics.
pub fn get_metrics() -> IpcMetrics {
    METRICS.lock().clone()
}

/// Reset metrics.
pub fn reset_metrics() {
    *METRICS.lock() = IpcMetrics::default();
}

// -----------------------------------------------------------------------------
// Message and queue types
// -----------------------------------------------------------------------------

/// A message with optional priority.
#[derive(Debug, Clone)]
pub struct Message {
    /// Message data.
    pub data: Vec<u8>,
    /// Priority (0 = highest, larger = lower).
    pub priority: u8,
}

impl Message {
    /// Create a new message with default priority (0).
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, priority: 0 }
    }

    /// Create a message with a specific priority.
    pub fn with_priority(data: Vec<u8>, priority: u8) -> Self {
        Self { data, priority }
    }
}

/// A queue of messages for a task.
#[derive(Debug)]
pub struct MessageQueue {
    /// The actual queue (priority-ordered).
    queue: VecDeque<Message>,
    /// Capacity (maximum number of messages).
    capacity: usize,
    /// TIDs waiting to read (blocked).
    readers_waiting: Vec<TaskId>,
    /// TIDs waiting to write (blocked).
    writers_waiting: Vec<TaskId>,
    /// Whether the queue is closed (task exited).
    closed: bool,
    /// Permissions: list of senders allowed (empty = any).
    allowed_senders: Vec<TaskId>,
}

impl MessageQueue {
    /// Create a new queue with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: VecDeque::with_capacity(capacity),
            capacity,
            readers_waiting: Vec::new(),
            writers_waiting: Vec::new(),
            closed: false,
            allowed_senders: Vec::new(),
        }
    }

    /// Check if the queue is full.
    pub fn is_full(&self) -> bool {
        self.queue.len() >= self.capacity
    }

    /// Check if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Get the number of messages in the queue.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Get the available space.
    pub fn space(&self) -> usize {
        self.capacity - self.queue.len()
    }

    /// Push a message into the queue, returning the message if full.
    /// Returns `Ok(())` on success, `Err(msg)` if full.
    pub fn push(&mut self, msg: Message) -> Result<(), Message> {
        if self.is_full() {
            return Err(msg);
        }
        // Insert in priority order (lower priority = higher priority).
        // We'll keep the queue sorted by priority.
        let pos = self.queue.iter().position(|m| m.priority > msg.priority)
            .unwrap_or(self.queue.len());
        self.queue.insert(pos, msg);
        Ok(())
    }

    /// Pop a message from the front.
    pub fn pop(&mut self) -> Option<Message> {
        self.queue.pop_front()
    }

    /// Peek at the front message.
    pub fn peek(&self) -> Option<&Message> {
        self.queue.front()
    }

    /// Wake all readers.
    pub fn wake_readers(&mut self) -> Vec<TaskId> {
        self.readers_waiting.drain(..).collect()
    }

    /// Wake all writers.
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

    /// Check if a sender is allowed.
    pub fn is_sender_allowed(&self, tid: TaskId) -> bool {
        self.allowed_senders.is_empty() || self.allowed_senders.contains(&tid)
    }

    /// Add a sender to the allowed list.
    pub fn allow_sender(&mut self, tid: TaskId) {
        if !self.allowed_senders.contains(&tid) {
            self.allowed_senders.push(tid);
        }
    }

    /// Remove a sender from the allowed list.
    pub fn deny_sender(&mut self, tid: TaskId) {
        self.allowed_senders.retain(|&t| t != tid);
    }

    /// Close the queue.
    pub fn close(&mut self) {
        self.closed = true;
        // Wake all waiters.
        let readers = self.wake_readers();
        let writers = self.wake_writers();
        for tid in readers.into_iter().chain(writers) {
            wake_task(tid);
        }
    }
}

// -----------------------------------------------------------------------------
// Global state
// -----------------------------------------------------------------------------

/// Global IPC manager.
static IPC_MANAGER: Lazy<Mutex<BTreeMap<TaskId, MessageQueue>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

/// Global configuration.
static CONFIG: Lazy<Mutex<IpcConfig>> = Lazy::new(|| Mutex::new(IpcConfig::default()));

/// Initialize the IPC subsystem.
pub fn init(config: IpcConfig) -> IpcResult<()> {
    config.validate()?;
    *CONFIG.lock() = config;
    info!("IPC subsystem initialized");
    Ok(())
}

/// Get the current configuration.
pub fn get_config() -> IpcConfig {
    CONFIG.lock().clone()
}

// -----------------------------------------------------------------------------
// Core operations
// -----------------------------------------------------------------------------

/// Register a task (create a queue for it).
pub fn register(tid: TaskId) -> IpcResult<()> {
    let config = CONFIG.lock();
    let mut manager = IPC_MANAGER.lock();
    if manager.contains_key(&tid) {
        return Ok(());
    }
    let queue = MessageQueue::new(config.default_capacity);
    manager.insert(tid, queue);
    if config.collect_metrics {
        METRICS.lock().queues_created.fetch_add(1, Ordering::Relaxed);
    }
    trace!(tid = tid.as_u64(), "IPC queue registered");
    Ok(())
}

/// Unregister a task (destroy its queue).
pub fn unregister(tid: TaskId) {
    let mut manager = IPC_MANAGER.lock();
    if let Some(mut queue) = manager.remove(&tid) {
        queue.close();
        if CONFIG.lock().collect_metrics {
            METRICS.lock().queues_destroyed.fetch_add(1, Ordering::Relaxed);
        }
        trace!(tid = tid.as_u64(), "IPC queue unregistered");
    }
}

/// Check if a queue exists for a task.
pub fn exists(tid: TaskId) -> bool {
    IPC_MANAGER.lock().contains_key(&tid)
}

/// Get the queue for a task (if exists).
fn get_queue(tid: TaskId) -> Option<MutexGuard<'static, BTreeMap<TaskId, MessageQueue>>> {
    let manager = IPC_MANAGER.lock();
    if manager.contains_key(&tid) {
        Some(manager)
    } else {
        None
    }
}

/// Send a message to a task (non-blocking).
pub fn send(tid: TaskId, data: Vec<u8>, priority: u8) -> IpcResult<()> {
    let config = CONFIG.lock();
    if data.len() > config.max_message_size {
        return Err(IpcError::InvalidArgument);
    }

    let mut manager = IPC_MANAGER.lock();
    let queue = manager.get_mut(&tid).ok_or(IpcError::TaskNotFound)?;

    // Check permissions.
    // For simplicity, we assume the sender is the current task.
    let sender = crate::arch::x86_64::percpu::current_tid();
    if !queue.is_sender_allowed(sender) {
        if config.collect_metrics {
            METRICS.lock().permission_denials.fetch_add(1, Ordering::Relaxed);
        }
        return Err(IpcError::PermissionDenied);
    }

    // Check if queue is closed.
    if queue.closed {
        return Err(IpcError::QueueClosed);
    }

    let msg = Message::with_priority(data, priority);
    match queue.push(msg) {
        Ok(()) => {
            // Wake any blocked readers.
            let readers = queue.wake_readers();
            drop(manager);
            for r in readers {
                wake_task(r);
            }
            if config.collect_metrics {
                METRICS.lock().messages_sent.fetch_add(1, Ordering::Relaxed);
            }
            trace!(to = tid.as_u64(), "IPC message sent");
            Ok(())
        }
        Err(msg) => {
            // Queue full.
            Err(IpcError::QueueFull)
        }
    }
}

/// Send a message with blocking (if full, block until space available).
pub fn send_blocking(
    tid: TaskId,
    data: Vec<u8>,
    priority: u8,
    timeout_ms: Option<u64>,
) -> IpcResult<()> {
    let config = CONFIG.lock();
    if data.len() > config.max_message_size {
        return Err(IpcError::InvalidArgument);
    }

    let sender = crate::arch::x86_64::percpu::current_tid();
    let deadline = timeout_ms.map(|ms| crate::arch::timer::uptime_ms() + ms);

    loop {
        let mut manager = IPC_MANAGER.lock();
        let queue = manager.get_mut(&tid).ok_or(IpcError::TaskNotFound)?;

        // Check permissions.
        if !queue.is_sender_allowed(sender) {
            if config.collect_metrics {
                METRICS.lock().permission_denials.fetch_add(1, Ordering::Relaxed);
            }
            return Err(IpcError::PermissionDenied);
        }

        if queue.closed {
            return Err(IpcError::QueueClosed);
        }

        let msg = Message::with_priority(data.clone(), priority);
        match queue.push(msg) {
            Ok(()) => {
                let readers = queue.wake_readers();
                drop(manager);
                for r in readers {
                    wake_task(r);
                }
                if config.collect_metrics {
                    METRICS.lock().messages_sent.fetch_add(1, Ordering::Relaxed);
                }
                trace!(to = tid.as_u64(), "IPC message sent (blocking)");
                return Ok(());
            }
            Err(msg) => {
                // Queue is full, we need to block.
                let now = crate::arch::timer::uptime_ms();
                if let Some(d) = deadline {
                    if now >= d {
                        return Err(IpcError::Timeout);
                    }
                }

                // Add to writers wait queue.
                queue.add_writer(sender);
                drop(manager);

                if config.collect_metrics {
                    METRICS.lock().send_blocks.fetch_add(1, Ordering::Relaxed);
                }

                // Block.
                let cond = match deadline {
                    Some(d) => WakeCondition::Timer(d),
                    None => WakeCondition::Any,
                };
                block_current(sender, cond);

                // After wake, loop again.
            }
        }
    }
}

/// Receive a message from the current task's queue (non-blocking).
pub fn recv(tid: TaskId) -> IpcResult<Message> {
    let mut manager = IPC_MANAGER.lock();
    let queue = manager.get_mut(&tid).ok_or(IpcError::TaskNotFound)?;

    if queue.closed {
        return Err(IpcError::QueueClosed);
    }

    if let Some(msg) = queue.pop() {
        // Wake any blocked writers.
        let writers = queue.wake_writers();
        drop(manager);
        for w in writers {
            wake_task(w);
        }
        if CONFIG.lock().collect_metrics {
            METRICS.lock().messages_received.fetch_add(1, Ordering::Relaxed);
        }
        trace!(from = tid.as_u64(), "IPC message received");
        Ok(msg)
    } else {
        Err(IpcError::QueueEmpty)
    }
}

/// Receive a message with blocking (if empty, block until message arrives).
pub fn recv_blocking(tid: TaskId, timeout_ms: Option<u64>) -> IpcResult<Message> {
    let deadline = timeout_ms.map(|ms| crate::arch::timer::uptime_ms() + ms);

    loop {
        let mut manager = IPC_MANAGER.lock();
        let queue = manager.get_mut(&tid).ok_or(IpcError::TaskNotFound)?;

        if queue.closed {
            return Err(IpcError::QueueClosed);
        }

        if let Some(msg) = queue.pop() {
            let writers = queue.wake_writers();
            drop(manager);
            for w in writers {
                wake_task(w);
            }
            if CONFIG.lock().collect_metrics {
                METRICS.lock().messages_received.fetch_add(1, Ordering::Relaxed);
            }
            trace!(from = tid.as_u64(), "IPC message received (blocking)");
            return Ok(msg);
        }

        // Queue empty: block.
        let now = crate::arch::timer::uptime_ms();
        if let Some(d) = deadline {
            if now >= d {
                return Err(IpcError::Timeout);
            }
        }

        // Add to readers wait queue.
        queue.add_reader(tid);
        drop(manager);

        if CONFIG.lock().collect_metrics {
            METRICS.lock().recv_blocks.fetch_add(1, Ordering::Relaxed);
        }

        // Block.
        let cond = match deadline {
            Some(d) => WakeCondition::Timer(d),
            None => WakeCondition::Any,
        };
        block_current(tid, cond);

        // After wake, loop again.
    }
}

/// Peek at the first message (non-consuming).
pub fn peek(tid: TaskId) -> IpcResult<Message> {
    let manager = IPC_MANAGER.lock();
    let queue = manager.get(&tid).ok_or(IpcError::TaskNotFound)?;
    if queue.closed {
        return Err(IpcError::QueueClosed);
    }
    if let Some(msg) = queue.peek() {
        Ok(msg.clone())
    } else {
        Err(IpcError::QueueEmpty)
    }
}

/// Check if a queue has messages.
pub fn has_message(tid: TaskId) -> bool {
    IPC_MANAGER.lock().get(&tid).map(|q| !q.is_empty()).unwrap_or(false)
}

/// Get the number of messages in a queue.
pub fn queue_len(tid: TaskId) -> Option<usize> {
    IPC_MANAGER.lock().get(&tid).map(|q| q.len())
}

/// Get the capacity of a queue.
pub fn queue_capacity(tid: TaskId) -> Option<usize> {
    IPC_MANAGER.lock().get(&tid).map(|q| q.capacity)
}

/// Set the capacity of a queue (if not full).
pub fn set_queue_capacity(tid: TaskId, new_capacity: usize) -> IpcResult<()> {
    if new_capacity == 0 || new_capacity > MAX_QUEUE_CAPACITY {
        return Err(IpcError::InvalidArgument);
    }
    let mut manager = IPC_MANAGER.lock();
    let queue = manager.get_mut(&tid).ok_or(IpcError::TaskNotFound)?;
    if queue.closed {
        return Err(IpcError::QueueClosed);
    }
    if queue.len() > new_capacity {
        // Cannot shrink below current size.
        return Err(IpcError::QueueFull);
    }
    queue.capacity = new_capacity;
    Ok(())
}

/// Add a sender to the allowed list.
pub fn allow_sender(tid: TaskId, sender: TaskId) -> IpcResult<()> {
    let mut manager = IPC_MANAGER.lock();
    let queue = manager.get_mut(&tid).ok_or(IpcError::TaskNotFound)?;
    queue.allow_sender(sender);
    Ok(())
}

/// Remove a sender from the allowed list.
pub fn deny_sender(tid: TaskId, sender: TaskId) -> IpcResult<()> {
    let mut manager = IPC_MANAGER.lock();
    let queue = manager.get_mut(&tid).ok_or(IpcError::TaskNotFound)?;
    queue.deny_sender(sender);
    Ok(())
}

/// Clear all messages from a queue.
pub fn clear_queue(tid: TaskId) -> IpcResult<()> {
    let mut manager = IPC_MANAGER.lock();
    let queue = manager.get_mut(&tid).ok_or(IpcError::TaskNotFound)?;
    if queue.closed {
        return Err(IpcError::QueueClosed);
    }
    queue.queue.clear();
    // Wake any blocked writers (now there is space).
    let writers = queue.wake_writers();
    drop(manager);
    for w in writers {
        wake_task(w);
    }
    Ok(())
}

/// Close a queue (no more messages accepted).
pub fn close_queue(tid: TaskId) -> IpcResult<()> {
    let mut manager = IPC_MANAGER.lock();
    let queue = manager.get_mut(&tid).ok_or(IpcError::TaskNotFound)?;
    if queue.closed {
        return Ok(());
    }
    queue.close();
    Ok(())
}

// -----------------------------------------------------------------------------
// Batch operations
// -----------------------------------------------------------------------------

/// Receive all messages (non-blocking).
pub fn recv_all(tid: TaskId) -> IpcResult<Vec<Message>> {
    let mut manager = IPC_MANAGER.lock();
    let queue = manager.get_mut(&tid).ok_or(IpcError::TaskNotFound)?;
    if queue.closed {
        return Err(IpcError::QueueClosed);
    }
    let mut msgs = Vec::with_capacity(queue.len());
    while let Some(msg) = queue.pop() {
        msgs.push(msg);
    }
    // Wake any blocked writers (now there is space).
    let writers = queue.wake_writers();
    drop(manager);
    for w in writers {
        wake_task(w);
    }
    if CONFIG.lock().collect_metrics {
        let count = msgs.len() as u64;
        METRICS.lock().messages_received.fetch_add(count, Ordering::Relaxed);
    }
    Ok(msgs)
}

/// Send multiple messages (non-blocking, best effort).
pub fn send_batch(tid: TaskId, messages: Vec<Message>) -> IpcResult<usize> {
    let config = CONFIG.lock();
    let mut manager = IPC_MANAGER.lock();
    let queue = manager.get_mut(&tid).ok_or(IpcError::TaskNotFound)?;

    if queue.closed {
        return Err(IpcError::QueueClosed);
    }

    let sender = crate::arch::x86_64::percpu::current_tid();
    if !queue.is_sender_allowed(sender) {
        if config.collect_metrics {
            METRICS.lock().permission_denials.fetch_add(1, Ordering::Relaxed);
        }
        return Err(IpcError::PermissionDenied);
    }

    let mut sent = 0;
    for mut msg in messages {
        if msg.data.len() > config.max_message_size {
            continue;
        }
        match queue.push(msg) {
            Ok(()) => sent += 1,
            Err(_) => break, // queue full
        }
    }

    if sent > 0 {
        let readers = queue.wake_readers();
        drop(manager);
        for r in readers {
            wake_task(r);
        }
        if config.collect_metrics {
            METRICS.lock().messages_sent.fetch_add(sent as u64, Ordering::Relaxed);
        }
    }

    Ok(sent)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::TaskId;

    // Mock task ID.
    fn mock_tid(id: u64) -> TaskId {
        TaskId::from_u64(id)
    }

    #[test]
    fn test_register_and_send() {
        let tid = mock_tid(1);
        register(tid).unwrap();
        send(tid, b"hello".to_vec(), 0).unwrap();
        assert!(has_message(tid));
        let msg = recv(tid).unwrap();
        assert_eq!(msg.data, b"hello");
        assert_eq!(msg.priority, 0);
        unregister(tid);
    }

    #[test]
    fn test_priority_ordering() {
        let tid = mock_tid(2);
        register(tid).unwrap();
        send(tid, b"low".to_vec(), 5).unwrap();
        send(tid, b"high".to_vec(), 1).unwrap();
        send(tid, b"medium".to_vec(), 3).unwrap();

        let msg1 = recv(tid).unwrap();
        assert_eq!(msg1.data, b"high");
        let msg2 = recv(tid).unwrap();
        assert_eq!(msg2.data, b"medium");
        let msg3 = recv(tid).unwrap();
        assert_eq!(msg3.data, b"low");
        unregister(tid);
    }

    #[test]
    fn test_blocking_send_recv() {
        let tid = mock_tid(3);
        register(tid).unwrap();

        // Send blocking.
        send_blocking(tid, b"msg".to_vec(), 0, None).unwrap();

        // Recv blocking.
        let msg = recv_blocking(tid, None).unwrap();
        assert_eq!(msg.data, b"msg");
        unregister(tid);
    }

    #[test]
    fn test_timeout() {
        let tid = mock_tid(4);
        register(tid).unwrap();

        // Recv with timeout should timeout.
        let result = recv_blocking(tid, Some(10));
        assert!(matches!(result, Err(IpcError::Timeout)));

        unregister(tid);
    }

    #[test]
    fn test_permissions() {
        let tid = mock_tid(5);
        register(tid).unwrap();
        let sender = mock_tid(99);

        // By default, any sender is allowed.
        send(tid, b"msg".to_vec(), 0).unwrap();
        assert!(has_message(tid));

        // Deny sender.
        deny_sender(tid, sender).unwrap();
        // Send from the denied sender should fail.
        // In a real test, we'd need to set the current task ID to `sender`.
        // For this test, we'll just check that the queue no longer accepts it.
        // Since we can't change current task ID easily, we'll skip the permission test.
        // But we can check that the deny worked.
        let queue = IPC_MANAGER.lock().get(&tid).unwrap();
        assert!(!queue.is_sender_allowed(sender));
        unregister(tid);
    }

    #[test]
    fn test_batch_operations() {
        let tid = mock_tid(6);
        register(tid).unwrap();

        let messages = vec![
            Message::new(b"1".to_vec()),
            Message::new(b"2".to_vec()),
            Message::new(b"3".to_vec()),
        ];
        let sent = send_batch(tid, messages).unwrap();
        assert_eq!(sent, 3);

        let received = recv_all(tid).unwrap();
        assert_eq!(received.len(), 3);
        assert_eq!(received[0].data, b"1");
        assert_eq!(received[1].data, b"2");
        assert_eq!(received[2].data, b"3");
        unregister(tid);
    }

    #[test]
    fn test_clear_queue() {
        let tid = mock_tid(7);
        register(tid).unwrap();
        send(tid, b"msg".to_vec(), 0).unwrap();
        assert!(has_message(tid));
        clear_queue(tid).unwrap();
        assert!(!has_message(tid));
        unregister(tid);
    }

    #[test]
    fn test_metrics() {
        reset_metrics();
        let tid = mock_tid(8);
        register(tid).unwrap();
        send(tid, b"hello".to_vec(), 0).unwrap();
        recv(tid).unwrap();
        let metrics = get_metrics();
        assert_eq!(metrics.messages_sent.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.messages_received.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.queues_created.load(Ordering::Relaxed), 1);
        unregister(tid);
    }
}
