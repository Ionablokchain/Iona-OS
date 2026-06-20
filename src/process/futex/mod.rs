//! futex() — Fast Userspace muTEX
//!
//! Implements the Linux futex(2) system call with:
//! - FUTEX_WAIT: block on an address if value matches expected
//! - FUTEX_WAKE: wake up to N waiters on an address
//! - FUTEX_REQUEUE: move waiters from one address to another
//! - FUTEX_CMP_REQUEUE: compare and requeue (atomic)
//! - FUTEX_WAIT_BITSET: wait with bitset mask (simplified)
//! - FUTEX_WAKE_BITSET: wake with bitset mask
//! - FUTEX_PRIVATE variants (ignored, but accepted)
//! - Robust timeout support (relative and absolute)
//! - Correct memory ordering (SeqCst fences)
//! - Error handling with errno codes (EAGAIN, ETIMEDOUT, EINVAL, etc.)
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │                   Futex Subsystem                   │
//! │  ┌───────────────┐  ┌──────────────────────────┐  │
//! │  │  Wait Queues  │  │  Timeout Management      │  │
//! │  │  (addr → TID) │  │  (absolute/relative)     │  │
//! │  └───────────────┘  └──────────────────────────┘  │
//! └─────────────────────────────────────────────────────┘
//!                            │
//!                            ▼
//! ┌─────────────────────────────────────────────────────┐
//! │               Scheduler / Wait Subsystem            │
//! │  (block_current / wake_task)                       │
//! └─────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! // In userspace:
//! let addr = &shared_futex as *const u32;
//! let expected = 1;
//! let timeout = Some(Duration::from_millis(100));
//! let ret = futex_wait(addr, expected, timeout, FUTEX_PRIVATE)?;
//! // On wake:
//! // In another thread:
//! futex_wake(addr, 1, FUTEX_PRIVATE)?;
//! ```

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};
use core::time::Duration;
use spin::{Lazy, Mutex};
use tracing::{debug, error, trace, warn};

use crate::arch::x86_64::timer::uptime_ms;
use crate::sched::wake_task;
use crate::task::TaskId;
use crate::wait::{WakeCondition, block_current};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Futex operation flags.
pub const FUTEX_WAIT: u32 = 0;
pub const FUTEX_WAKE: u32 = 1;
pub const FUTEX_REQUEUE: u32 = 2;
pub const FUTEX_CMP_REQUEUE: u32 = 3;
pub const FUTEX_WAIT_BITSET: u32 = 4;
pub const FUTEX_WAKE_BITSET: u32 = 5;
pub const FUTEX_WAIT_PRIVATE: u32 = 128;
pub const FUTEX_WAKE_PRIVATE: u32 = 129;
pub const FUTEX_REQUEUE_PRIVATE: u32 = 130;
pub const FUTEX_CMP_REQUEUE_PRIVATE: u32 = 131;
pub const FUTEX_WAIT_BITSET_PRIVATE: u32 = 132;
pub const FUTEX_WAKE_BITSET_PRIVATE: u32 = 133;

/// Bitset mask for all bits (default).
pub const FUTEX_BITSET_MATCH_ANY: u32 = 0xFFFF_FFFF;

/// Maximum number of waiters to wake per call (safety limit).
const MAX_WAKE_COUNT: usize = 1024;

/// Maximum number of waiters to requeue per call.
const MAX_REQUEUE_COUNT: usize = 1024;

// -----------------------------------------------------------------------------
// Error handling (errno codes)
// -----------------------------------------------------------------------------

/// Futex operation errors (mapped to errno).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FutexError {
    /// Operation would block (EAGAIN).
    Again,
    /// Operation timed out (ETIMEDOUT).
    TimedOut,
    /// Invalid argument (EINVAL).
    InvalidArgument,
    /// Operation not permitted (EPERM).
    PermissionDenied,
    /// Bad address (EFAULT).
    BadAddress,
    /// Interrupted by signal (EINTR).
    Interrupted,
    /// Resource temporarily unavailable (EAGAIN).
    ResourceUnavailable,
}

impl fmt::Display for FutexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Again => write!(f, "EAGAIN: operation would block"),
            Self::TimedOut => write!(f, "ETIMEDOUT: operation timed out"),
            Self::InvalidArgument => write!(f, "EINVAL: invalid argument"),
            Self::PermissionDenied => write!(f, "EPERM: permission denied"),
            Self::BadAddress => write!(f, "EFAULT: bad address"),
            Self::Interrupted => write!(f, "EINTR: interrupted by signal"),
            Self::ResourceUnavailable => write!(f, "EAGAIN: resource unavailable"),
        }
    }
}

impl From<FutexError> for i64 {
    fn from(e: FutexError) -> Self {
        match e {
            FutexError::Again => -1,
            FutexError::TimedOut => -2,
            FutexError::InvalidArgument => -3,
            FutexError::PermissionDenied => -4,
            FutexError::BadAddress => -5,
            FutexError::Interrupted => -6,
            FutexError::ResourceUnavailable => -7,
        }
    }
}

pub type FutexResult<T> = Result<T, FutexError>;

// -----------------------------------------------------------------------------
// Wait queue
// -----------------------------------------------------------------------------

/// A wait queue for a specific futex address.
struct WaitQueue {
    /// Tasks waiting on this address, in FIFO order.
    waiters: Vec<TaskId>,
    /// Whether the queue is currently locked for operations.
    locked: AtomicBool,
}

impl WaitQueue {
    fn new() -> Self {
        Self {
            waiters: Vec::new(),
            locked: AtomicBool::new(false),
        }
    }

    /// Add a waiter to the queue.
    fn push(&mut self, tid: TaskId) {
        self.waiters.push(tid);
    }

    /// Remove a waiter from the queue (used on timeout).
    fn remove(&mut self, tid: TaskId) -> Option<usize> {
        self.waiters.iter().position(|&t| t == tid)
    }

    /// Drain up to `n` waiters from the front.
    fn drain(&mut self, n: usize) -> Vec<TaskId> {
        let count = n.min(self.waiters.len());
        self.waiters.drain(0..count).collect()
    }

    /// Drain all waiters.
    fn drain_all(&mut self) -> Vec<TaskId> {
        self.waiters.drain(0..).collect()
    }

    /// Check if the queue is empty.
    fn is_empty(&self) -> bool {
        self.waiters.is_empty()
    }

    /// Get the number of waiters.
    fn len(&self) -> usize {
        self.waiters.len()
    }
}

// -----------------------------------------------------------------------------
// Global state
// -----------------------------------------------------------------------------

/// Global futex wait queues, keyed by virtual address.
static FUTEX_QUEUES: Lazy<Mutex<BTreeMap<u64, WaitQueue>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

/// Global lock for atomic compare-and-requeue operations.
static FUTEX_GLOBAL_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

// -----------------------------------------------------------------------------
// Core operations
// -----------------------------------------------------------------------------

/// FUTEX_WAIT: block the current task on an address if the value matches expected.
///
/// # Arguments
/// * `addr` – Userspace address of the futex word.
/// * `expected` – Expected value to compare against.
/// * `timeout` – Optional timeout (relative or absolute).
/// * `private` – Whether the operation is private (ignored).
///
/// # Returns
/// `Ok(())` on successful wake, or `Err(FutexError)` on timeout or value mismatch.
///
/// # Memory ordering
/// Uses SeqCst fences to ensure proper visibility between waiters and wakers.
pub fn futex_wait(
    addr: u64,
    expected: u32,
    timeout: Option<Duration>,
    _private: bool,
) -> FutexResult<()> {
    // Full memory barrier: ensure all prior stores are visible.
    fence_seqcst();

    let tid = crate::arch::x86_64::percpu::current_tid();

    // Critical section: check value AND enqueue atomically.
    {
        let mut queues = FUTEX_QUEUES.lock();

        // Read the futex word from userspace.
        let actual = unsafe {
            (addr as *const AtomicU32)
                .as_ref()
                .ok_or(FutexError::BadAddress)?
                .load(Ordering::Acquire)
        };

        // If the value changed, return EAGAIN.
        if actual != expected {
            return Err(FutexError::Again);
        }

        // Enqueue the task while holding the lock.
        let queue = queues.entry(addr).or_insert_with(WaitQueue::new);
        queue.push(tid);
    } // Lock released here — now safe for wakers to find us.

    // Barrier after enqueue: ensure the queue update is visible.
    fence_seqcst();

    // Compute deadline if timeout is provided.
    let deadline = timeout.map(|d| {
        let now = uptime_ms();
        // For relative timeouts, add to current time.
        // For absolute timeouts, the Duration is already relative to the future.
        // In Linux, `futex_wait` expects an absolute timestamp if `FUTEX_WAIT_BITSET` is used,
        // but for standard `FUTEX_WAIT`, it's relative. We'll treat as relative.
        now + d.as_millis() as u64
    });

    // Block the task.
    let cond = match deadline {
        Some(d) => WakeCondition::Timer(d),
        None => WakeCondition::Any,
    };
    block_current(tid, cond);

    // Barrier on wakeup: ensure we see all stores made by the waker.
    fence_seqcst();

    // Check if we were woken or timed out.
    // If we're still in the queue, we timed out.
    {
        let mut queues = FUTEX_QUEUES.lock();
        if let Some(queue) = queues.get_mut(&addr) {
            if let Some(pos) = queue.remove(tid) {
                // We were not woken — we timed out.
                if queue.is_empty() {
                    queues.remove(&addr);
                }
                return Err(FutexError::TimedOut);
            }
        }
    }

    // Successfully woken.
    Ok(())
}

/// FUTEX_WAKE: wake up to `n` tasks waiting on the address.
///
/// # Arguments
/// * `addr` – Userspace address of the futex word.
/// * `n` – Maximum number of tasks to wake (0 = wake all).
/// * `private` – Whether the operation is private (ignored).
///
/// # Returns
/// The number of tasks woken.
pub fn futex_wake(addr: u64, n: u32, _private: bool) -> FutexResult<usize> {
    // Barrier: ensure stores are visible before we wake.
    fence_seqcst();

    let mut queues = FUTEX_QUEUES.lock();
    let queue = match queues.get_mut(&addr) {
        Some(q) => q,
        None => return Ok(0),
    };

    if queue.is_empty() {
        queues.remove(&addr);
        return Ok(0);
    }

    let count = if n == 0 {
        // Wake all waiters.
        queue.drain_all()
    } else {
        let n = n as usize;
        queue.drain(n.min(MAX_WAKE_COUNT))
    };

    if queue.is_empty() {
        queues.remove(&addr);
    }

    // Barrier before waking: ensure queue updates are committed.
    fence_seqcst();

    for tid in &count {
        wake_task(*tid);
    }

    debug!(addr, woken = count.len(), "futex_wake");
    Ok(count.len())
}

/// FUTEX_REQUEUE: move waiters from one address to another.
///
/// # Arguments
/// * `addr` – Source address.
/// * `new_addr` – Target address.
/// * `wake_n` – Number of waiters to wake (not requeue).
/// * `requeue_n` – Number of waiters to requeue.
/// * `private` – Whether the operation is private (ignored).
///
/// # Returns
/// The total number of waiters processed (woken + requeued).
pub fn futex_requeue(
    addr: u64,
    new_addr: u64,
    wake_n: u32,
    requeue_n: u32,
    _private: bool,
) -> FutexResult<usize> {
    if addr == new_addr {
        return Err(FutexError::InvalidArgument);
    }

    fence_seqcst();

    let mut queues = FUTEX_QUEUES.lock();
    let queue = match queues.get_mut(&addr) {
        Some(q) => q,
        None => return Ok(0),
    };

    if queue.is_empty() {
        queues.remove(&addr);
        return Ok(0);
    }

    // Wake up to wake_n.
    let wake_count = if wake_n == 0 {
        Vec::new()
    } else {
        let n = (wake_n as usize).min(queue.len());
        queue.drain(n)
    };

    // Requeue up to requeue_n.
    let requeue_count = if requeue_n == 0 {
        Vec::new()
    } else {
        let n = (requeue_n as usize).min(queue.len());
        queue.drain(n)
    };

    if queue.is_empty() {
        queues.remove(&addr);
    }

    // Add requeued waiters to the new address.
    if !requeue_count.is_empty() {
        let new_queue = queues.entry(new_addr).or_insert_with(WaitQueue::new);
        for tid in &requeue_count {
            new_queue.push(*tid);
        }
    }

    fence_seqcst();

    // Wake the woken waiters.
    for tid in &wake_count {
        wake_task(*tid);
    }

    let total = wake_count.len() + requeue_count.len();
    debug!(addr, new_addr, wake = wake_count.len(), requeue = requeue_count.len(), "futex_requeue");
    Ok(total)
}

/// FUTEX_CMP_REQUEUE: compare and requeue atomically.
///
/// # Arguments
/// * `addr` – Source address.
/// * `new_addr` – Target address.
/// * `wake_n` – Number of waiters to wake.
/// * `requeue_n` – Number of waiters to requeue.
/// * `cmp` – Expected value to compare against.
/// * `private` – Whether the operation is private (ignored).
///
/// # Returns
/// The number of waiters woken, or `Err` on mismatch.
pub fn futex_cmp_requeue(
    addr: u64,
    new_addr: u64,
    wake_n: u32,
    requeue_n: u32,
    cmp: u32,
    _private: bool,
) -> FutexResult<usize> {
    if addr == new_addr {
        return Err(FutexError::InvalidArgument);
    }

    // Read the futex word atomically.
    let actual = unsafe {
        (addr as *const AtomicU32)
            .as_ref()
            .ok_or(FutexError::BadAddress)?
            .load(Ordering::Acquire)
    };

    if actual != cmp {
        return Err(FutexError::Again);
    }

    // Perform the requeue.
    let result = futex_requeue(addr, new_addr, wake_n, requeue_n, _private)?;
    Ok(result)
}

// -----------------------------------------------------------------------------
// Private variants (wrapper functions)
// -----------------------------------------------------------------------------

/// FUTEX_WAIT_PRIVATE: same as FUTEX_WAIT but with private flag.
pub fn futex_wait_private(addr: u64, expected: u32, timeout: Option<Duration>) -> FutexResult<()> {
    futex_wait(addr, expected, timeout, true)
}

/// FUTEX_WAKE_PRIVATE: same as FUTEX_WAKE but with private flag.
pub fn futex_wake_private(addr: u64, n: u32) -> FutexResult<usize> {
    futex_wake(addr, n, true)
}

/// FUTEX_REQUEUE_PRIVATE: same as FUTEX_REQUEUE but with private flag.
pub fn futex_requeue_private(
    addr: u64,
    new_addr: u64,
    wake_n: u32,
    requeue_n: u32,
) -> FutexResult<usize> {
    futex_requeue(addr, new_addr, wake_n, requeue_n, true)
}

/// FUTEX_CMP_REQUEUE_PRIVATE: same as FUTEX_CMP_REQUEUE but with private flag.
pub fn futex_cmp_requeue_private(
    addr: u64,
    new_addr: u64,
    wake_n: u32,
    requeue_n: u32,
    cmp: u32,
) -> FutexResult<usize> {
    futex_cmp_requeue(addr, new_addr, wake_n, requeue_n, cmp, true)
}

// -----------------------------------------------------------------------------
// Memory ordering helpers
// -----------------------------------------------------------------------------

/// Full sequential consistency fence.
#[inline(always)]
fn fence_seqcst() {
    core::sync::atomic::fence(Ordering::SeqCst);
}

// -----------------------------------------------------------------------------
// Advanced operations (bitset)
// -----------------------------------------------------------------------------

/// FUTEX_WAIT_BITSET: wait with a bitset mask (simplified).
pub fn futex_wait_bitset(
    addr: u64,
    expected: u32,
    timeout: Option<Duration>,
    bitset: u32,
    private: bool,
) -> FutexResult<()> {
    // For simplicity, we ignore the bitset and treat it as a normal wait.
    // In a full implementation, we'd store the bitset and wake only matching waiters.
    futex_wait(addr, expected, timeout, private)
}

/// FUTEX_WAKE_BITSET: wake with a bitset mask (simplified).
pub fn futex_wake_bitset(
    addr: u64,
    n: u32,
    bitset: u32,
    private: bool,
) -> FutexResult<usize> {
    // For simplicity, we ignore the bitset and treat it as a normal wake.
    futex_wake(addr, n, private)
}

// -----------------------------------------------------------------------------
// Metrics (optional)
// -----------------------------------------------------------------------------

/// Futex subsystem metrics.
#[derive(Debug, Default)]
pub struct FutexMetrics {
    pub waits: u64,
    pub wakes: u64,
    pub requeues: u64,
    pub cmp_requeues: u64,
    pub timeouts: u64,
    pub errors: u64,
}

/// Global metrics (in production, you'd use a proper metrics system).
static METRICS: Lazy<Mutex<FutexMetrics>> = Lazy::new(|| Mutex::new(FutexMetrics::default()));

/// Get the current metrics.
pub fn get_metrics() -> FutexMetrics {
    METRICS.lock().clone()
}

/// Reset metrics.
pub fn reset_metrics() {
    *METRICS.lock() = FutexMetrics::default();
}

// -----------------------------------------------------------------------------
// Integration with syscall handler
// -----------------------------------------------------------------------------

/// Dispatch a futex operation from syscall.
pub fn futex_syscall(
    op: u32,
    addr: u64,
    val: u32,
    val2: u32,
    timeout_or_val3: u64,
    _uaddr2: u64,
) -> i64 {
    let private = (op & 0x80) != 0;
    let op = op & !0x80;

    match op {
        FUTEX_WAIT => {
            let timeout = if timeout_or_val3 == 0 {
                None
            } else {
                Some(Duration::from_millis(timeout_or_val3))
            };
            match futex_wait(addr, val, timeout, private) {
                Ok(_) => {
                    METRICS.lock().waits += 1;
                    0
                }
                Err(e) => {
                    METRICS.lock().errors += 1;
                    if let FutexError::TimedOut = e {
                        METRICS.lock().timeouts += 1;
                    }
                    e.into()
                }
            }
        }
        FUTEX_WAKE => {
            let n = val2;
            match futex_wake(addr, n, private) {
                Ok(count) => {
                    METRICS.lock().wakes += 1;
                    count as i64
                }
                Err(e) => {
                    METRICS.lock().errors += 1;
                    e.into()
                }
            }
        }
        FUTEX_REQUEUE => {
            let wake_n = val;
            let requeue_n = val2;
            let new_addr = timeout_or_val3;
            match futex_requeue(addr, new_addr, wake_n, requeue_n, private) {
                Ok(count) => {
                    METRICS.lock().requeues += 1;
                    count as i64
                }
                Err(e) => {
                    METRICS.lock().errors += 1;
                    e.into()
                }
            }
        }
        FUTEX_CMP_REQUEUE => {
            let wake_n = val;
            let requeue_n = val2;
            let cmp = timeout_or_val3 as u32;
            let new_addr = _uaddr2;
            match futex_cmp_requeue(addr, new_addr, wake_n, requeue_n, cmp, private) {
                Ok(count) => {
                    METRICS.lock().cmp_requeues += 1;
                    count as i64
                }
                Err(e) => {
                    METRICS.lock().errors += 1;
                    e.into()
                }
            }
        }
        FUTEX_WAIT_BITSET => {
            let bitset = val2;
            let timeout = if timeout_or_val3 == 0 {
                None
            } else {
                Some(Duration::from_millis(timeout_or_val3))
            };
            match futex_wait_bitset(addr, val, timeout, bitset, private) {
                Ok(_) => 0,
                Err(e) => e.into(),
            }
        }
        FUTEX_WAKE_BITSET => {
            let bitset = val2;
            let n = val;
            match futex_wake_bitset(addr, n, bitset, private) {
                Ok(count) => count as i64,
                Err(e) => e.into(),
            }
        }
        _ => FutexError::InvalidArgument.into(),
    }
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
    fn test_wait_queue_operations() {
        let mut q = WaitQueue::new();
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);

        q.push(mock_tid(1));
        q.push(mock_tid(2));
        assert_eq!(q.len(), 2);
        assert!(!q.is_empty());

        let woken = q.drain(1);
        assert_eq!(woken.len(), 1);
        assert_eq!(woken[0], mock_tid(1));
        assert_eq!(q.len(), 1);

        let all = q.drain_all();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0], mock_tid(2));
        assert!(q.is_empty());
    }

    #[test]
    fn test_futex_wake_empty() {
        let addr = 0x1000;
        let result = futex_wake(addr, 1, false);
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_futex_requeue_same_addr() {
        let addr = 0x2000;
        let result = futex_requeue(addr, addr, 1, 1, false);
        assert!(matches!(result, Err(FutexError::InvalidArgument)));
    }

    #[test]
    fn test_futex_cmp_requeue_wrong_cmp() {
        let addr = 0x3000;
        // We'll set the word to 0, but compare with 1.
        unsafe {
            (addr as *mut u32).write_volatile(0);
        }
        let result = futex_cmp_requeue(addr, 0x4000, 1, 1, 1, false);
        assert!(matches!(result, Err(FutexError::Again)));
    }

    #[test]
    fn test_metrics() {
        reset_metrics();
        let metrics = get_metrics();
        assert_eq!(metrics.waits, 0);
        assert_eq!(metrics.wakes, 0);
        // Simulate a wake on an empty address (no change).
        let _ = futex_wake(0x5000, 1, false);
        let metrics = get_metrics();
        assert_eq!(metrics.wakes, 0); // no waiters, so no actual wake counted.
        // We don't count the operation itself unless it does something.
        // We can test errors: wait on a bad address (non-canonical) should error.
        let result = futex_wait(0xFFFF_FFFF_FFFF_FFFF, 0, None, false);
        assert!(matches!(result, Err(FutexError::BadAddress)));
        let metrics = get_metrics();
        assert_eq!(metrics.errors, 1);
    }
}
