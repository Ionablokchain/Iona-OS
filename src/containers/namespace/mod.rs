//! Namespaces — process isolation (PID, Mount, Network)
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use spin::{Lazy, Mutex};
use crate::task::TaskId;

pub type NsId = u64;

/// Namespace types (bitflags for clone())
pub const NS_PID:   u64 = 0x2000_0000;
pub const NS_NET:   u64 = 0x4000_0000;
pub const NS_MOUNT: u64 = 0x0002_0000;
pub const NS_IPC:   u64 = 0x0800_0000;
pub const NS_UTS:   u64 = 0x0400_0000; // hostname/domainname
pub const NS_USER:  u64 = 0x1000_0000;

#[derive(Clone, Debug)]
pub struct PidNamespace {
    pub id:         NsId,
    pub parent:     Option<NsId>,
    pub tasks:      BTreeSet<TaskId>,
    /// PID mapping: global TID → namespace-local PID
    pub pid_map:    BTreeMap<TaskId, u32>,
    pub next_pid:   u32,
}

impl PidNamespace {
    pub fn new(id: NsId, parent: Option<NsId>) -> Self {
        PidNamespace { id, parent, tasks: BTreeSet::new(),
                       pid_map: BTreeMap::new(), next_pid: 1 }
    }

    pub fn alloc_pid(&mut self, tid: TaskId) -> u32 {
        let pid = self.next_pid;
        self.next_pid += 1;
        self.pid_map.insert(tid, pid);
        self.tasks.insert(tid);
        pid
    }

    pub fn local_pid(&self, tid: TaskId) -> Option<u32> {
        self.pid_map.get(&tid).copied()
    }

    pub fn can_see(&self, tid: TaskId) -> bool {
        self.tasks.contains(&tid)
    }
}

#[derive(Clone, Debug)]
pub struct MountNamespace {
    pub id:     NsId,
    pub parent: Option<NsId>,
    /// Mounts: path → filesystem type
    pub mounts: BTreeMap<String, String>,
}

impl MountNamespace {
    pub fn new(id: NsId, parent: Option<NsId>) -> Self {
        let mut mounts = BTreeMap::new();
        mounts.insert("/".into(), "ionafs".into());
        mounts.insert("/proc".into(), "procfs".into());
        mounts.insert("/dev".into(), "devfs".into());
        MountNamespace { id, parent, mounts }
    }

    pub fn bind_mount(&mut self, src: &str, dst: &str, fs_type: &str) {
        self.mounts.insert(dst.into(), alloc::format!("{}:{}", fs_type, src));
    }

    pub fn is_mounted(&self, path: &str) -> bool {
        self.mounts.keys().any(|m| path.starts_with(m.as_str()))
    }
}

/// Container: a set of namespaces + cgroup
pub struct Container {
    pub id:         u64,
    pub name:       String,
    pub pid_ns:     NsId,
    pub mount_ns:   NsId,
    pub cgroup_id:  crate::containers::cgroup::CgroupId,
    pub root_task:  TaskId,
    pub hostname:   String,
}

static PID_NAMESPACES:   Lazy<Mutex<BTreeMap<NsId, PidNamespace>>>   = Lazy::new(|| Mutex::new(BTreeMap::new()));
static MOUNT_NAMESPACES: Lazy<Mutex<BTreeMap<NsId, MountNamespace>>> = Lazy::new(|| Mutex::new(BTreeMap::new()));
static TASK_PID_NS:      Lazy<Mutex<BTreeMap<TaskId, NsId>>>         = Lazy::new(|| Mutex::new(BTreeMap::new()));
static CONTAINERS:       Lazy<Mutex<BTreeMap<u64, Container>>>        = Lazy::new(|| Mutex::new(BTreeMap::new()));

static NEXT_NS_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
static NEXT_CTR_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

/// Create initial (root) namespaces
pub fn init() {
    // Root PID namespace (ID=1)
    PID_NAMESPACES.lock().insert(1, PidNamespace::new(1, None));
    // Root mount namespace (ID=1)
    MOUNT_NAMESPACES.lock().insert(1, MountNamespace::new(1, None));
    crate::serial_println!("  [NS] root PID + mount namespaces created");
}

/// Create a new container with isolated namespaces
pub fn create_container(name: &str, mem_limit_kb: u64, cpu_quota: u8) -> u64 {
    let ns_id  = NEXT_NS_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let ctr_id = NEXT_CTR_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    // New PID namespace (child of root)
    PID_NAMESPACES.lock().insert(ns_id, PidNamespace::new(ns_id, Some(1)));

    // New mount namespace (clone of root)
    let mut mnt_ns = MountNamespace::new(ns_id, Some(1));
    // Container root can be a chroot-like path
    mnt_ns.mounts.insert("/".into(), alloc::format!("ionafs:/containers/{}", name));
    MOUNT_NAMESPACES.lock().insert(ns_id, mnt_ns);

    // Create cgroup for resource limiting
    let limits = crate::containers::cgroup::CgroupLimits {
        cpu_quota_pct: cpu_quota,
        mem_limit_kb,
        io_weight: 50,
        pids_max: 100,
        blkio_bps: 0,
    };
    let cgid = crate::containers::cgroup::create(name, limits);

    CONTAINERS.lock().insert(ctr_id, Container {
        id: ctr_id, name: name.into(),
        pid_ns: ns_id, mount_ns: ns_id,
        cgroup_id: cgid, root_task: 0,
        hostname: name.into(),
    });

    crate::serial_println!("[NS] container '{}' created id={} mem={}KB cpu={}%",
        name, ctr_id, mem_limit_kb, cpu_quota);
    ctr_id
}

/// Add a task to a container (sets its namespaces + cgroup)
pub fn container_add_task(container_id: u64, tid: TaskId) -> u32 {
    let ns_id = {
        let ctrs = CONTAINERS.lock();
        let ctr  = match ctrs.get(&container_id) { Some(c) => c, None => return 0 };
        crate::containers::cgroup::add_task(ctr.cgroup_id, tid);
        ctr.pid_ns
    };

    let pid = PID_NAMESPACES.lock()
        .get_mut(&ns_id).map(|ns| ns.alloc_pid(tid)).unwrap_or(0);
    TASK_PID_NS.lock().insert(tid, ns_id);

    crate::serial_println!("[NS] task {} added to container {} as PID {}", tid, container_id, pid);
    pid
}

/// Get local PID of a task within its namespace
pub fn local_pid(tid: TaskId) -> u32 {
    let ns_id = match TASK_PID_NS.lock().get(&tid).copied() { Some(n) => n, None => return tid as u32 };
    PID_NAMESPACES.lock().get(&ns_id).and_then(|ns| ns.local_pid(tid)).unwrap_or(tid as u32)
}

/// Check if a task can see another task (PID namespace isolation)
pub fn can_see(observer: TaskId, target: TaskId) -> bool {
    let obs_ns = TASK_PID_NS.lock().get(&observer).copied().unwrap_or(1);
    let tgt_ns = TASK_PID_NS.lock().get(&target).copied().unwrap_or(1);
    // Same namespace = can see each other
    // Observer in root ns (1) = can see everyone
    obs_ns == tgt_ns || obs_ns == 1
}
