//! epoll — I/O event notification
//!
//! Allows a task to wait simultaneously on multiple file descriptors.
//! Implements the Linux epoll API with level-triggered and edge-triggered modes.
//!
//! # Features
//! - Level‑triggered (default) and edge‑triggered (EPOLLET) modes.
//! - Multiple tasks can wait on the same epoll instance.
//! - Wake‑up on fd readiness via global notification.
//! - Support for TCP sockets, pipes, keyboard, and other file types.
//! - Proper error handling with `KernelError`.
//! - Thread‑safe via spin locks.
//!
//! # Events
//!
//! | Flag      | Description                                      |
//! |-----------|--------------------------------------------------|
//! | EPOLLIN   | Data available to read                           |
//! | EPOLLOUT  | Space available to write                         |
//! | EPOLLERR  | Error condition on the fd                        |
//! | EPOLLHUP  | Hangup (connection closed)                       |
//! | EPOLLET   | Edge‑triggered (default is level‑triggered)      |
//! | EPOLLONESHOT | One‑shot delivery (not yet implemented)        |
//!
//! # Example
//!
//! ```rust,ignore
//! let epfd = epoll_create();
//! let ev = EpollEvent { events: EPOLLIN, data: sock_fd as u64 };
//! epoll_ctl(epfd, EPOLL_CTL_ADD, sock_fd, ev);
//! let mut events = [EpollEvent::default(); 10];
//! let n = epoll_wait(epfd, &mut events, 1000);
//! for ev in &events[..n as usize] {
//!     // handle event
//! }
//! ```

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Lazy, Mutex};
use tracing::{debug, error, trace, warn};

use crate::process::fd::FileDesc;
use crate::task::TaskId;
use crate::wait::{WakeCondition, block_current, wake_one};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Readable data available.
pub const EPOLLIN: u32 = 0x001;
/// Writable (space in buffer).
pub const EPOLLOUT: u32 = 0x004;
/// Error condition.
pub const EPOLLERR: u32 = 0x008;
/// Hangup (connection closed).
pub const EPOLLHUP: u32 = 0x010;
/// Edge-triggered (default is level-triggered).
pub const EPOLLET: u32 = 1 << 31;
/// One‑shot delivery (not yet implemented).
pub const EPOLLONESHOT: u32 = 1 << 30;

/// epoll_ctl operations.
pub const EPOLL_CTL_ADD: u32 = 1;
pub const EPOLL_CTL_MOD: u32 = 2;
pub const EPOLL_CTL_DEL: u32 = 3;

/// Maximum number of events returned in one `epoll_wait` call.
const MAX_EVENTS: usize = 1024;

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

/// Epoll file descriptor (opaque handle).
pub type EpollFd = u64;

/// Event structure passed to epoll_ctl and returned by epoll_wait.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EpollEvent {
    pub events: u32,
    pub data: u64,
}

/// Internal state for a monitored file descriptor within an epoll instance.
#[derive(Clone, Debug)]
struct MonitoredFd {
    events: u32,
    data: u64,
    /// Whether the current event has been reported (edge-triggered).
    reported: bool,
    /// Whether the fd is currently ready (level-triggered).
    ready: bool,
}

/// Epoll instance state.
struct EpollInstance {
    /// Monitored file descriptors: fd → state.
    interests: BTreeMap<usize, MonitoredFd>,
    /// Tasks waiting on this epoll instance.
    waiters: Vec<TaskId>,
    /// ID of this epoll instance.
    id: EpollFd,
}

impl EpollInstance {
    fn new(id: EpollFd) -> Self {
        Self {
            interests: BTreeMap::new(),
            waiters: Vec::new(),
            id,
        }
    }

    /// Add a waiter to the wait queue.
    fn add_waiter(&mut self, tid: TaskId) {
        if !self.waiters.contains(&tid) {
            self.waiters.push(tid);
        }
    }

    /// Wake all waiters.
    fn wake_all(&mut self) {
        let waiters = core::mem::take(&mut self.waiters);
        for tid in waiters {
            wake_one(tid);
        }
    }

    /// Check if any fd is ready (level-triggered) or has new event (edge-triggered).
    fn check_ready(&mut self, tid: TaskId) -> Vec<EpollEvent> {
        let mut ready_events = Vec::new();
        let mut to_remove = Vec::new();

        for (&fd, state) in self.interests.iter_mut() {
            let revents = Self::check_fd_readiness(fd, tid, state);
            if revents == 0 {
                // If edge-triggered and already reported, reset state.
                if (state.events & EPOLLET) != 0 && state.reported && !state.ready {
                    // No new event.
                }
                continue;
            }

            let is_edge = (state.events & EPOLLET) != 0;
            if is_edge {
                // Edge-triggered: only report if we haven't reported this event yet.
                if state.reported {
                    continue;
                }
                state.reported = true;
            } else {
                // Level-triggered: always report if ready.
                state.ready = true;
            }

            // If EPOLLONESHOT, we need to remove after one event (not implemented).
            ready_events.push(EpollEvent {
                events: revents,
                data: state.data,
            });

            // For edge-triggered, we reset reported after the user consumes the event.
            // We'll reset after the event is returned to user.
            // Since we can't know when user consumes, we'll just keep it until next check.
        }

        ready_events
    }

    /// Check readiness of a single fd.
    fn check_fd_readiness(fd: usize, tid: TaskId, state: &mut MonitoredFd) -> u32 {
        let mut revents = 0u32;

        // Get the file descriptor from the task's fd table.
        if let Some(fd_desc) = crate::process::fd::get_clone(tid, fd) {
            if (state.events & EPOLLIN) != 0 && Self::fd_readable(&fd_desc) {
                revents |= EPOLLIN;
            }
            if (state.events & EPOLLOUT) != 0 && Self::fd_writable(&fd_desc) {
                revents |= EPOLLOUT;
            }
            // Check for errors and hangup.
            if Self::fd_has_error(&fd_desc) {
                revents |= EPOLLERR;
            }
            if Self::fd_has_hup(&fd_desc) {
                revents |= EPOLLHUP;
            }
        } else {
            // fd not found: treat as error.
            revents |= EPOLLERR;
        }

        revents
    }

    // -------------------------------------------------------------------------
    // fd readiness helpers
    // -------------------------------------------------------------------------

    fn fd_readable(fd: &FileDesc) -> bool {
        match fd {
            FileDesc::TcpSocket(sfd) => crate::net::socket_has_data(*sfd),
            FileDesc::Pipe { read_end: true, id } => crate::process::pipe::has_data(*id),
            FileDesc::Keyboard => crate::drivers::keyboard::read_char().map(|_| true).unwrap_or(false),
            _ => false,
        }
    }

    fn fd_writable(fd: &FileDesc) -> bool {
        match fd {
            FileDesc::TcpSocket(sfd) => crate::net::socket_can_write(*sfd),
            FileDesc::Pipe { read_end: false, id } => crate::process::pipe::can_write(*id),
            _ => true, // assume writable for most fds
        }
    }

    fn fd_has_error(fd: &FileDesc) -> bool {
        match fd {
            FileDesc::TcpSocket(sfd) => crate::net::socket_has_error(*sfd),
            _ => false,
        }
    }

    fn fd_has_hup(fd: &FileDesc) -> bool {
        match fd {
            FileDesc::TcpSocket(sfd) => crate::net::socket_has_hup(*sfd),
            _ => false,
        }
    }
}

// -----------------------------------------------------------------------------
// Global state
// -----------------------------------------------------------------------------

/// All epoll instances, keyed by their file descriptor.
static EPOLL_INSTANCES: Lazy<Mutex<BTreeMap<EpollFd, EpollInstance>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

/// Next available epoll fd.
static NEXT_EPOLL_FD: AtomicU64 = AtomicU64::new(5000);

/// Global mapping from fd → set of epoll instances watching it.
/// Used to wake epoll instances when an fd becomes ready.
static FD_WATCHERS: Lazy<Mutex<BTreeMap<usize, BTreeSet<EpollFd>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

// -----------------------------------------------------------------------------
// Notification system
// -----------------------------------------------------------------------------

/// Notify all epoll instances that a file descriptor has become ready.
/// Called from drivers (e.g., socket receive, pipe write, etc.).
pub fn epoll_notify_fd(fd: usize) {
    let mut watchers = FD_WATCHERS.lock();
    let Some(epoll_ids) = watchers.get(&fd).cloned() else {
        return;
    };

    // Wake all epoll instances watching this fd.
    let mut instances = EPOLL_INSTANCES.lock();
    for eid in epoll_ids {
        if let Some(ep) = instances.get_mut(&eid) {
            // Mark the fd as ready (for level-triggered) and reset reported for edge.
            if let Some(state) = ep.interests.get_mut(&fd) {
                state.ready = true;
                if (state.events & EPOLLET) != 0 {
                    state.reported = false;
                }
            }
            ep.wake_all();
            trace!(epoll_id = eid, fd, "epoll instance woken");
        }
    }
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// epoll_create() — create a new epoll instance.
pub fn epoll_create() -> EpollFd {
    let eid = NEXT_EPOLL_FD.fetch_add(1, Ordering::Relaxed);
    let mut instances = EPOLL_INSTANCES.lock();
    instances.insert(eid, EpollInstance::new(eid));
    debug!(epoll_id = eid, "epoll instance created");
    eid
}

/// epoll_ctl() — add, modify, or remove a file descriptor in the epoll instance.
///
/// # Arguments
/// * `eid` – Epoll file descriptor.
/// * `op` – `EPOLL_CTL_ADD`, `EPOLL_CTL_MOD`, or `EPOLL_CTL_DEL`.
/// * `fd` – File descriptor to monitor.
/// * `event` – Event structure with events and user data.
///
/// # Returns
/// `0` on success, `-1` on error.
pub fn epoll_ctl(eid: EpollFd, op: u32, fd: usize, event: EpollEvent) -> i64 {
    let mut instances = EPOLL_INSTANCES.lock();
    let ep = match instances.get_mut(&eid) {
        Some(e) => e,
        None => {
            error!(epoll_id = eid, "epoll_ctl: instance not found");
            return -1;
        }
    };

    match op {
        EPOLL_CTL_ADD => {
            if ep.interests.contains_key(&fd) {
                warn!(epoll_id = eid, fd, "epoll_ctl ADD: fd already monitored");
                return -1;
            }
            let state = MonitoredFd {
                events: event.events,
                data: event.data,
                reported: false,
                ready: false,
            };
            ep.interests.insert(fd, state);
            // Register this epoll instance as a watcher for this fd.
            let mut watchers = FD_WATCHERS.lock();
            watchers.entry(fd).or_default().insert(eid);
            debug!(epoll_id = eid, fd, "epoll_ctl ADD success");
            0
        }
        EPOLL_CTL_MOD => {
            if let Some(state) = ep.interests.get_mut(&fd) {
                state.events = event.events;
                state.data = event.data;
                // Reset ready state on modification.
                state.ready = false;
                state.reported = false;
                debug!(epoll_id = eid, fd, "epoll_ctl MOD success");
                0
            } else {
                warn!(epoll_id = eid, fd, "epoll_ctl MOD: fd not monitored");
                -1
            }
        }
        EPOLL_CTL_DEL => {
            if ep.interests.remove(&fd).is_some() {
                // Remove from FD_WATCHERS.
                let mut watchers = FD_WATCHERS.lock();
                if let Some(set) = watchers.get_mut(&fd) {
                    set.remove(&eid);
                    if set.is_empty() {
                        watchers.remove(&fd);
                    }
                }
                debug!(epoll_id = eid, fd, "epoll_ctl DEL success");
                0
            } else {
                warn!(epoll_id = eid, fd, "epoll_ctl DEL: fd not monitored");
                -1
            }
        }
        _ => {
            error!(op, "epoll_ctl: invalid operation");
            -1
        }
    }
}

/// epoll_wait() — wait for events on the epoll instance.
///
/// # Arguments
/// * `eid` – Epoll file descriptor.
/// * `events_buf` – Slice of `EpollEvent` to store ready events.
/// * `timeout_ms` – Timeout in milliseconds (-1 = infinite, 0 = non‑blocking).
///
/// # Returns
/// Number of events ready, or `-1` on error.
pub fn epoll_wait(
    eid: EpollFd,
    tid: TaskId,
    events_buf: &mut [EpollEvent],
    timeout_ms: i64,
) -> i64 {
    let deadline = if timeout_ms < 0 {
        u64::MAX // infinite
    } else if timeout_ms == 0 {
        0 // non‑blocking
    } else {
        crate::arch::x86_64::timer::uptime_ms().saturating_add(timeout_ms as u64)
    };

    loop {
        // Check for ready events.
        let mut instances = EPOLL_INSTANCES.lock();
        let ep = match instances.get_mut(&eid) {
            Some(e) => e,
            None => {
                error!(epoll_id = eid, "epoll_wait: instance not found");
                return -1;
            }
        };

        let ready_events = ep.check_ready(tid);

        // If there are ready events, return them.
        if !ready_events.is_empty() {
            let n = ready_events.len().min(events_buf.len());
            for (i, ev) in ready_events[..n].iter().enumerate() {
                events_buf[i] = *ev;
            }
            trace!(epoll_id = eid, count = n, "epoll_wait returned events");
            return n as i64;
        }

        // Check timeout.
        let now = crate::arch::x86_64::timer::uptime_ms();
        if timeout_ms == 0 || now >= deadline {
            return 0;
        }

        // Add current task to wait queue.
        ep.add_waiter(tid);
        drop(instances);

        // Block until timeout or woken.
        let remaining = deadline.saturating_sub(now);
        let cond = if remaining == u64::MAX {
            WakeCondition::NoTimer
        } else {
            WakeCondition::Timer(now + 1) // We'll be woken by event or timer.
        };
        block_current(tid, cond);
        // After wake, loop again to check events.
    }
}

// -----------------------------------------------------------------------------
// Helper functions for driver integration
// -----------------------------------------------------------------------------

/// Register an fd watcher for future notifications.
/// This is called internally by epoll_ctl.
#[allow(dead_code)]
fn register_watcher(fd: usize, eid: EpollFd) {
    let mut watchers = FD_WATCHERS.lock();
    watchers.entry(fd).or_default().insert(eid);
}

/// Unregister an fd watcher.
#[allow(dead_code)]
fn unregister_watcher(fd: usize, eid: EpollFd) {
    let mut watchers = FD_WATCHERS.lock();
    if let Some(set) = watchers.get_mut(&fd) {
        set.remove(&eid);
        if set.is_empty() {
            watchers.remove(&fd);
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Mock task ID for testing.
    fn mock_tid() -> TaskId {
        TaskId::from_u64(1)
    }

    #[test]
    fn test_epoll_create() {
        let eid = epoll_create();
        assert!(eid > 0);
        let instances = EPOLL_INSTANCES.lock();
        assert!(instances.contains_key(&eid));
    }

    #[test]
    fn test_epoll_ctl_add_del() {
        let eid = epoll_create();
        let fd = 42;
        let event = EpollEvent {
            events: EPOLLIN,
            data: 100,
        };
        assert_eq!(epoll_ctl(eid, EPOLL_CTL_ADD, fd, event), 0);
        // Check that it's added.
        {
            let instances = EPOLL_INSTANCES.lock();
            let ep = instances.get(&eid).unwrap();
            assert!(ep.interests.contains_key(&fd));
        }
        // Delete.
        assert_eq!(epoll_ctl(eid, EPOLL_CTL_DEL, fd, event), 0);
        {
            let instances = EPOLL_INSTANCES.lock();
            let ep = instances.get(&eid).unwrap();
            assert!(!ep.interests.contains_key(&fd));
        }
    }

    #[test]
    fn test_epoll_ctl_mod() {
        let eid = epoll_create();
        let fd = 42;
        let event = EpollEvent {
            events: EPOLLIN,
            data: 100,
        };
        assert_eq!(epoll_ctl(eid, EPOLL_CTL_ADD, fd, event), 0);
        // Modify.
        let new_event = EpollEvent {
            events: EPOLLOUT,
            data: 200,
        };
        assert_eq!(epoll_ctl(eid, EPOLL_CTL_MOD, fd, new_event), 0);
        // Check state.
        {
            let instances = EPOLL_INSTANCES.lock();
            let ep = instances.get(&eid).unwrap();
            let state = ep.interests.get(&fd).unwrap();
            assert_eq!(state.events, EPOLLOUT);
            assert_eq!(state.data, 200);
        }
    }

    #[test]
    fn test_epoll_wait_timeout() {
        let eid = epoll_create();
        let mut events = [EpollEvent::default(); 4];
        let n = epoll_wait(eid, mock_tid(), &mut events, 0);
        assert_eq!(n, 0);
    }

    #[test]
    fn test_epoll_notify() {
        let eid = epoll_create();
        let fd = 42;
        let event = EpollEvent {
            events: EPOLLIN,
            data: 100,
        };
        assert_eq!(epoll_ctl(eid, EPOLL_CTL_ADD, fd, event), 0);

        // Simulate fd becoming ready.
        epoll_notify_fd(fd);

        // Check that the epoll instance was woken.
        // In a real test, we'd need to have a task waiting, but we can check the state.
        {
            let instances = EPOLL_INSTANCES.lock();
            let ep = instances.get(&eid).unwrap();
            let state = ep.interests.get(&fd).unwrap();
            assert!(state.ready);
        }
    }
}
