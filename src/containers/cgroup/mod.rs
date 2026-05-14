//! cgroups — resource limiting per grup de procese
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::{Lazy, Mutex};
use crate::task::TaskId;

pub type CgroupId = u64;

#[derive(Clone, Debug)]
pub struct CgroupLimits {
    pub cpu_quota_pct:  u8,   // 0-100: max % of CPU time
    pub mem_limit_kb:   u64,  // max memory in KB (0 = unlimited)
    pub io_weight:      u8,   // 1-100 (default 50)
    pub pids_max:       u32,  // max processes (0 = unlimited)
    pub blkio_bps:      u64,  // max block I/O bytes/sec (0 = unlimited)
}

impl Default for CgroupLimits {
    fn default() -> Self {
        CgroupLimits { cpu_quota_pct: 100, mem_limit_kb: 0, io_weight: 50,
                       pids_max: 0, blkio_bps: 0 }
    }
}

#[derive(Clone)]
pub struct Cgroup {
    pub id:      CgroupId,
    pub name:    String,
    pub limits:  CgroupLimits,
    pub tasks:   Vec<TaskId>,
    // Accounting
    pub cpu_ticks_used:  u64,
    pub mem_used_kb:     u64,
    pub pids_current:    u32,
    // Token bucket for CPU bandwidth control
    pub cpu_tokens:      i64,   // available tokens (microseconds of CPU time)
    pub cpu_period_us:   u64,   // replenishment period (default: 100ms = 100_000us)
    pub cpu_last_refill: u64,   // last refill timestamp (ms)
}

impl Cgroup {
    pub fn new(id: CgroupId, name: &str, limits: CgroupLimits) -> Self {
        let quota = limits.cpu_quota_pct as u64;
        let period_us = 100_000u64; // 100ms period
        let initial_tokens = (period_us * quota / 100) as i64;
        Cgroup { id, name: name.into(), limits, tasks: Vec::new(),
                 cpu_ticks_used: 0, mem_used_kb: 0, pids_current: 0,
                 cpu_tokens: initial_tokens, cpu_period_us: period_us, cpu_last_refill: 0 }
    }

    pub fn add_task(&mut self, tid: TaskId) -> bool {
        if self.limits.pids_max > 0 && self.pids_current >= self.limits.pids_max {
            return false; // over limit
        }
        if !self.tasks.contains(&tid) {
            self.tasks.push(tid);
            self.pids_current += 1;
        }
        true
    }

    pub fn remove_task(&mut self, tid: TaskId) {
        self.tasks.retain(|&t| t != tid);
        self.pids_current = self.pids_current.saturating_sub(1);
    }

    pub fn check_mem_limit(&self, alloc_kb: u64) -> bool {
        self.limits.mem_limit_kb == 0 ||
        self.mem_used_kb + alloc_kb <= self.limits.mem_limit_kb
    }

    pub fn record_cpu_tick(&mut self, ticks: u64) {
        self.cpu_ticks_used += ticks;
    }
}

static CGROUPS: Lazy<Mutex<BTreeMap<CgroupId, Cgroup>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

/// Task → cgroup mapping
static TASK_CGROUP: Lazy<Mutex<BTreeMap<TaskId, CgroupId>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

static NEXT_CGID: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(1);

/// Create a new cgroup
pub fn create(name: &str, limits: CgroupLimits) -> CgroupId {
    let id = NEXT_CGID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    CGROUPS.lock().insert(id, Cgroup::new(id, name, limits));
    crate::serial_println!("[CGROUP] created '{}' id={}", name, id);
    id
}

/// Add a task to a cgroup
pub fn add_task(cgroup_id: CgroupId, tid: TaskId) -> bool {
    let mut cgroups = CGROUPS.lock();
    let ok = cgroups.get_mut(&cgroup_id).map(|cg| cg.add_task(tid)).unwrap_or(false);
    if ok { TASK_CGROUP.lock().insert(tid, cgroup_id); }
    ok
}

/// Remove a task from its cgroup
pub fn remove_task(tid: TaskId) {
    let cgroup_id = TASK_CGROUP.lock().remove(&tid);
    if let Some(cgid) = cgroup_id {
        if let Some(cg) = CGROUPS.lock().get_mut(&cgid) {
            cg.remove_task(tid);
        }
    }
}

/// Check if a memory allocation is allowed for a task's cgroup
pub fn check_mem_alloc(tid: TaskId, kb: u64) -> bool {
    let task_cg = TASK_CGROUP.lock();
    match task_cg.get(&tid) {
        None      => true, // no cgroup = unlimited
        Some(&cgid) => {
            CGROUPS.lock().get(&cgid).map(|cg| cg.check_mem_limit(kb)).unwrap_or(true)
        }
    }
}

/// Check CPU throttling using token bucket algorithm (called by scheduler per tick)
pub fn should_throttle(tid: TaskId) -> bool {
    let task_cg = TASK_CGROUP.lock();
    match task_cg.get(&tid) {
        None => false,
        Some(&cgid) => {
            let mut cgroups = CGROUPS.lock();
            let cg = match cgroups.get_mut(&cgid) { Some(c) => c, None => return false };
            if cg.limits.cpu_quota_pct >= 100 { return false; } // unlimited

            // Token bucket: refill tokens based on elapsed time
            let now_ms = crate::arch::x86_64::timer::uptime_ms();
            let elapsed_ms = now_ms.saturating_sub(cg.cpu_last_refill);
            let period_ms = cg.cpu_period_us / 1000;
            if period_ms > 0 && elapsed_ms >= period_ms {
                // Refill tokens: quota_pct% of period
                let refill = (cg.cpu_period_us as i64 * cg.limits.cpu_quota_pct as i64) / 100;
                let max_tokens = refill * 2; // allow burst up to 2x
                cg.cpu_tokens = (cg.cpu_tokens + refill).min(max_tokens);
                cg.cpu_last_refill = now_ms;
            }

            // Consume one tick worth of tokens (~1ms = 1000us)
            let tick_cost = 1000i64;
            if cg.cpu_tokens >= tick_cost {
                cg.cpu_tokens -= tick_cost;
                false // allowed to run
            } else {
                true // throttled — no tokens available
            }
        }
    }
}

/// Get stats for a cgroup (for /sys/fs/cgroup/ equivalent)
pub fn stats(cgroup_id: CgroupId) -> Option<(u64, u64, u32)> {
    CGROUPS.lock().get(&cgroup_id).map(|cg| {
        (cg.cpu_ticks_used, cg.mem_used_kb, cg.pids_current)
    })
}

pub fn init() {
    // Create root cgroup
    create("root", CgroupLimits::default());
    crate::serial_println!("  [CGROUPS] resource limiting ready");
}
