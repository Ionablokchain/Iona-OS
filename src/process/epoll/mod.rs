//! epoll — I/O event notification
//!
//! Permite un task să aștepte simultan pe multiple file descriptors.
//! epoll_wait() blochează task-ul până cel puțin un fd e ready.
//!
//! Events:
//!   EPOLLIN  (0x001) = readable data available
//!   EPOLLOUT (0x004) = writable (space in buffer)
//!   EPOLLERR (0x008) = error condition
//!   EPOLLHUP (0x010) = hangup (connection closed)

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::{Lazy, Mutex};
use crate::task::TaskId;
use crate::process::fd::FileDesc;

pub const EPOLLIN:  u32 = 0x001;
pub const EPOLLOUT: u32 = 0x004;
pub const EPOLLERR: u32 = 0x008;
pub const EPOLLHUP: u32 = 0x010;
pub const EPOLLET:  u32 = 1 << 31; // edge-triggered

pub type EpollFd = u64;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EpollEvent {
    pub events: u32,
    pub data:   u64, // user data (fd usually)
}

pub struct EpollInstance {
    /// fd → (events of interest, user data)
    pub interests: BTreeMap<usize, (u32, u64)>,
}

static EPOLLS: Lazy<Mutex<BTreeMap<EpollFd, EpollInstance>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

static NEXT_EPOLL: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(5000);

/// epoll_create() — create new epoll instance
pub fn epoll_create() -> EpollFd {
    let eid = NEXT_EPOLL.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    EPOLLS.lock().insert(eid, EpollInstance { interests: BTreeMap::new() });
    eid
}

/// epoll_ctl() — add/modify/remove fd in epoll instance
pub fn epoll_ctl(eid: EpollFd, op: u32, fd: usize, event: EpollEvent) -> i64 {
    const CTL_ADD: u32 = 1;
    const CTL_DEL: u32 = 2;
    const CTL_MOD: u32 = 3;
    let mut epolls = EPOLLS.lock();
    let ep = match epolls.get_mut(&eid) { Some(e) => e, None => return -1 };
    match op {
        CTL_ADD | CTL_MOD => { ep.interests.insert(fd, (event.events, event.data)); 0 }
        CTL_DEL            => { ep.interests.remove(&fd); 0 }
        _                  => -1,
    }
}

/// epoll_wait() — wait for events, block until at least one fd is ready
/// Returns number of ready events, or -1 on error
pub fn epoll_wait(eid: EpollFd, tid: TaskId, events_buf: &mut [EpollEvent], timeout_ms: i64) -> i64 {
    let deadline = if timeout_ms < 0 {
        u64::MAX // block indefinitely
    } else if timeout_ms == 0 {
        0 // non-blocking
    } else {
        crate::arch::x86_64::timer::uptime_ms() + timeout_ms as u64
    };

    loop {
        // Check which fds are ready
        let ready = check_ready_fds(eid, tid);

        if !ready.is_empty() {
            let n = ready.len().min(events_buf.len());
            for (i, ev) in ready[..n].iter().enumerate() {
                events_buf[i] = *ev;
            }
            return n as i64;
        }

        let now = crate::arch::x86_64::timer::uptime_ms();
        if timeout_ms == 0 || now >= deadline { return 0; }

        // Block until timeout or wake
        let cond = crate::wait::WakeCondition::Timer(
            now.min(deadline).saturating_add(1)
        );
        crate::wait::block_current(tid, cond);
    }
}

/// Check which fds in an epoll instance have pending events
fn check_ready_fds(eid: EpollFd, tid: TaskId) -> Vec<EpollEvent> {
    let epolls  = EPOLLS.lock();
    let ep      = match epolls.get(&eid) { Some(e) => e, None => return Vec::new() };
    let mut ready = Vec::new();

    for (&fd, &(events, data)) in &ep.interests {
        let fd_desc = crate::process::fd::get_clone(tid, fd);
        let mut revents = 0u32;

        if events & EPOLLIN != 0 {
            let readable = match &fd_desc {
                Some(FileDesc::TcpSocket(sfd)) => crate::net::socket_has_data(*sfd),
                Some(FileDesc::Pipe { read_end: true, id }) =>
                    crate::process::pipe::has_data(*id),
                Some(FileDesc::Keyboard) =>
                    crate::drivers::keyboard::read_char().map(|_| true).unwrap_or(false),
                _ => false,
            };
            if readable { revents |= EPOLLIN; }
        }

        if revents != 0 {
            ready.push(EpollEvent { events: revents, data });
        }
    }
    ready
}
