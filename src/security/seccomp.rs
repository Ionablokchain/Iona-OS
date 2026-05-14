//! Seccomp — per-process syscall filtering
//!
//! Each process has a SeccompPolicy: a whitelist/blacklist of allowed syscalls.
//! Applied at every syscall_dispatch() entry.
//!
//! Actions:
//!   Allow  — syscall proceeds normally
//!   Errno  — syscall returns -errno immediately
//!   Kill   — process receives SIGKILL
//!   Trap   — delivers SIGSYS (for ptrace-based sandboxing)
//!
//! Filter programs are simple: a sorted list of allowed syscall numbers.
//! Full implementation would support BPF-style filters (seccomp-bpf).

use alloc::collections::BTreeMap;
use spin::{Lazy, Mutex};
use crate::task::TaskId;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SeccompAction {
    Allow,
    Errno(u64),   // return -errno
    Kill,         // SIGKILL
    Trap,         // SIGSYS
}

#[derive(Clone)]
pub struct SeccompPolicy {
    pub default_action: SeccompAction,
    /// Syscalls that override the default action
    pub rules: BTreeMap<u64, SeccompAction>,
    pub enabled: bool,
}

impl SeccompPolicy {
    /// Allow all syscalls (permissive — for privileged processes)
    pub fn allow_all() -> Self {
        Self {
            default_action: SeccompAction::Allow,
            rules:   BTreeMap::new(),
            enabled: false,
        }
    }

    /// Strict policy: only the listed syscall numbers are allowed
    pub fn strict(allowed: &[u64]) -> Self {
        let mut rules = BTreeMap::new();
        for &nr in allowed {
            rules.insert(nr, SeccompAction::Allow);
        }
        Self {
            default_action: SeccompAction::Errno(38), // ENOSYS
            rules,
            enabled: true,
        }
    }

    /// WASM sandbox policy — minimal set for wasmi modules
    pub fn wasm_sandbox() -> Self {
        Self::strict(&[
            0,   // read
            1,   // write
            60,  // exit
            304, // get_uptime
            305, // log
            300, // wasm_spawn
            301, // ipc_send
            307, // ipc_recv
            302, // fs_read
            303, // fs_write
        ])
    }

    /// iona-node policy — network + fs + process ops
    pub fn iona_node() -> Self {
        let mut allowed = alloc::vec::Vec::new();
        allowed.extend_from_slice(&[0,1,2,3,4,5]);       // read/write/open/close/stat
        allowed.extend_from_slice(&[9,11]);              // mmap/munmap
        allowed.extend_from_slice(&[13,22]);             // sigaction/pipe
        allowed.extend_from_slice(&[24,35]);             // yield/sleep
        allowed.extend_from_slice(&[56,57,59,60,61]);    // clone/fork/exec/exit/wait
        allowed.extend_from_slice(&[62]);                // kill
        allowed.extend_from_slice(&[202]);               // futex
        allowed.extend_from_slice(&[213,232,233]);       // epoll
        for i in 300..=322 { allowed.push(i); }         // IONA syscalls
        for i in 310..=319 { allowed.push(i); }         // net syscalls
        Self::strict(&allowed)
    }

    pub fn check(&self, syscall_nr: u64) -> SeccompAction {
        if !self.enabled { return SeccompAction::Allow; }
        match self.rules.get(&syscall_nr) {
            Some(&action) => action,
            None          => self.default_action,
        }
    }
}


static POLICIES: Lazy<Mutex<BTreeMap<TaskId, SeccompPolicy>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

/// Set policy for a process (called at fork/exec)
pub fn set_policy(tid: TaskId, policy: SeccompPolicy) {
    POLICIES.lock().insert(tid, policy);
    crate::serial_println!("  [SECCOMP] tid={} policy enabled", tid);
}

/// Remove policy (process exit)
pub fn remove_policy(tid: TaskId) {
    POLICIES.lock().remove(&tid);
}

/// Check syscall — returns the action to take
/// Called from every syscall_dispatch()
#[inline]
pub fn check_syscall(tid: TaskId, syscall_nr: u64) -> SeccompAction {
    if tid == 0 { return SeccompAction::Allow; } // kernel tasks exempt
    let policies = POLICIES.lock();
    match policies.get(&tid) {
        Some(p) => p.check(syscall_nr),
        None    => SeccompAction::Allow, // no policy = allow
    }
}

/// Apply seccomp action — called when action != Allow
pub fn apply_action(tid: TaskId, syscall_nr: u64, action: SeccompAction) -> u64 {
    match action {
        SeccompAction::Allow      => 0, // shouldn't reach here
        SeccompAction::Errno(e)   => {
            crate::serial_println!("[SECCOMP] tid={} nr={} blocked (errno {})", tid, syscall_nr, e);
            (-(e as i64)) as u64
        }
        SeccompAction::Kill => {
            crate::serial_println!("[SECCOMP] tid={} nr={} → SIGKILL", tid, syscall_nr);
            crate::signal::send(tid, crate::signal::Signal::SIGKILL);
            (-(9i64)) as u64
        }
        SeccompAction::Trap => {
            crate::serial_println!("[SECCOMP] tid={} nr={} → SIGSYS", tid, syscall_nr);
            // SIGSYS — would need crate::signal::Signal::SIGSYS
            (-(31i64)) as u64
        }
    }
}

// ── Audit log ─────────────────────────────────────────────────────────────────

use alloc::collections::VecDeque;

const AUDIT_CAPACITY: usize = 1024;

#[derive(Clone, Debug)]
pub struct AuditEvent {
    pub ms:         u64,
    pub tid:        TaskId,
    pub syscall_nr: u64,
    pub action:     SeccompAction,
}

static AUDIT_LOG: spin::Lazy<spin::Mutex<VecDeque<AuditEvent>>> =
    spin::Lazy::new(|| spin::Mutex::new(VecDeque::new()));

fn audit(tid: TaskId, syscall_nr: u64, action: SeccompAction) {
    let ev = AuditEvent {
        ms: crate::arch::x86_64::timer::uptime_ms(),
        tid, syscall_nr, action,
    };
    let mut log = AUDIT_LOG.lock();
    if log.len() >= AUDIT_CAPACITY { log.pop_front(); }
    log.push_back(ev);
}

pub fn dump_audit_log() -> alloc::vec::Vec<AuditEvent> {
    AUDIT_LOG.lock().iter().cloned().collect()
}

/// Apply WASM module policy and register with supervisor
pub fn set_wasm_policy(tid: TaskId) {
    set_policy(tid, SeccompPolicy::wasm_sandbox());
}

/// Apply iona-node policy
pub fn set_iona_node_policy(tid: TaskId) {
    set_policy(tid, SeccompPolicy::iona_node());
}

/// WasmPolicy — seccomp policy pentru module WASM (alias)
pub type WasmPolicy = Policy;

/// Apply WASM-specific seccomp policy to a task
pub fn apply_wasm_policy(tid: crate::task::TaskId) {
    set_wasm_policy(tid);
}
