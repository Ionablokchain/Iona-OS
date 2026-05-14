//! cgroups — resource limiting per group of processes
//!
//! Subsystems: cpu, memory, io
//! Hierarchy: /sys/fs/cgroup/{subsystem}/{group}/

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use spin::{Lazy, Mutex};
use crate::task::TaskId;

pub type CgroupId = u32;

#[derive(Clone, Debug)]
pub struct CpuConfig {
    pub shares:    u32,   // relative CPU weight (default 1024)
    pub quota_us:  i64,   // CPU time quota per period (-1 = unlimited)
    pub period_us: u64,   // period in microseconds (default 100_000)
}

impl Default for CpuConfig {
    fn default() -> Self { Self { shares: 1024, quota_us: -1, period_us: 100_000 } }
}

#[derive(Clone, Debug)]
pub struct MemConfig {
    pub limit_bytes:      i64,   // -1 = unlimited
    pub soft_limit_bytes: i64,
    pub swap_limit_bytes: i64,
    pub oom_kill_disable: bool,
}

impl Default for MemConfig {
    fn default() -> Self { Self { limit_bytes: -1, soft_limit_bytes: -1, swap_limit_bytes: -1, oom_kill_disable: false } }
}

#[derive(Clone, Debug, Default)]
pub struct IoConfig {
    pub read_bps_limit:  u64,  // bytes/sec, 0 = unlimited
    pub write_bps_limit: u64,
    pub read_iops_limit: u64,
    pub write_iops_limit: u64,
}

#[derive(Clone, Debug)]
pub struct Cgroup {
    pub id:      CgroupId,
    pub name:    String,
    pub parent:  Option<CgroupId>,
    pub tasks:   Vec<TaskId>,
    pub cpu:     CpuConfig,
    pub mem:     MemConfig,
    pub io:      IoConfig,
    // Accounting
    pub cpu_usage_us:    u64,
    pub mem_usage_bytes: u64,
}

impl Cgroup {
    pub fn new(id: CgroupId, name: &str, parent: Option<CgroupId>) -> Self {
        Self {
            id, name: name.into(), parent, tasks: Vec::new(),
            cpu: CpuConfig::default(), mem: MemConfig::default(), io: IoConfig::default(),
            cpu_usage_us: 0, mem_usage_bytes: 0,
        }
    }
}

static CGROUPS:    Lazy<Mutex<BTreeMap<CgroupId, Cgroup>>> = Lazy::new(|| {
    let mut m = BTreeMap::new();
    // Root cgroup (no limits)
    m.insert(0, Cgroup::new(0, "/", None));
    Mutex::new(m)
});
static TASK_CGROUP: Lazy<Mutex<BTreeMap<TaskId, CgroupId>>> = Lazy::new(|| Mutex::new(BTreeMap::new()));
static NEXT_ID:     spin::Mutex<CgroupId> = spin::Mutex::new(1);

/// Create a new cgroup
pub fn create(name: &str, parent: Option<CgroupId>) -> CgroupId {
    let id = { let mut n = NEXT_ID.lock(); let v = *n; *n += 1; v };
    CGROUPS.lock().insert(id, Cgroup::new(id, name, parent.or(Some(0))));
    crate::serial_println!("  [CGROUP] created '{}' id={}", name, id);
    id
}

/// Assign a task to a cgroup
pub fn attach(tid: TaskId, cgroup_id: CgroupId) {
    let mut cgs = CGROUPS.lock();
    // Remove from old cgroup
    if let Some(&old_id) = TASK_CGROUP.lock().get(&tid) {
        if let Some(old) = cgs.get_mut(&old_id) { old.tasks.retain(|&t| t != tid); }
    }
    // Add to new cgroup
    if let Some(cg) = cgs.get_mut(&cgroup_id) { cg.tasks.push(tid); }
    TASK_CGROUP.lock().insert(tid, cgroup_id);
}

pub fn get_cgroup(tid: TaskId) -> CgroupId {
    *TASK_CGROUP.lock().get(&tid).unwrap_or(&0)
}

/// Check memory limit — called when allocating memory for a process
pub fn check_mem_limit(tid: TaskId, alloc_bytes: usize) -> bool {
    let cgroup_id = get_cgroup(tid);
    let cgs = CGROUPS.lock();
    let cg  = match cgs.get(&cgroup_id) { Some(c) => c, None => return true };
    if cg.mem.limit_bytes < 0 { return true; } // unlimited
    (cg.mem_usage_bytes as i64 + alloc_bytes as i64) <= cg.mem.limit_bytes
}

/// Charge memory usage to cgroup
pub fn charge_mem(tid: TaskId, bytes: usize) {
    let cgroup_id = get_cgroup(tid);
    if let Some(cg) = CGROUPS.lock().get_mut(&cgroup_id) {
        cg.mem_usage_bytes += bytes as u64;
    }
}

/// Release memory from cgroup
pub fn release_mem(tid: TaskId, bytes: usize) {
    let cgroup_id = get_cgroup(tid);
    if let Some(cg) = CGROUPS.lock().get_mut(&cgroup_id) {
        cg.mem_usage_bytes = cg.mem_usage_bytes.saturating_sub(bytes as u64);
    }
}

/// Set CPU shares for a cgroup (influences scheduler weight)
pub fn set_cpu_shares(cgroup_id: CgroupId, shares: u32) {
    if let Some(cg) = CGROUPS.lock().get_mut(&cgroup_id) {
        cg.cpu.shares = shares;
        crate::serial_println!("  [CGROUP] '{}' cpu.shares={}", cg.name, shares);
    }
}

/// Set memory limit
pub fn set_mem_limit(cgroup_id: CgroupId, limit_bytes: i64) {
    if let Some(cg) = CGROUPS.lock().get_mut(&cgroup_id) {
        cg.mem.limit_bytes = limit_bytes;
        crate::serial_println!("  [CGROUP] '{}' memory.limit={}MB",
            cg.name, limit_bytes / 1_048_576);
    }
}

/// Get scheduler weight for a task (from its cgroup cpu.shares)
pub fn task_weight(tid: TaskId) -> u32 {
    let cgroup_id = get_cgroup(tid);
    CGROUPS.lock().get(&cgroup_id).map(|c| c.cpu.shares).unwrap_or(1024)
}

pub fn remove_task(tid: TaskId) {
    let cgroup_id = match TASK_CGROUP.lock().remove(&tid) { Some(c) => c, None => return };
    if let Some(cg) = CGROUPS.lock().get_mut(&cgroup_id) { cg.tasks.retain(|&t| t != tid); }
}

pub fn init() { crate::serial_println!("  [CGROUP] initialized: cpu + memory + io subsystems"); }
