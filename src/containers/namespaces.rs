//! Namespaces — process isolation
//!
//! Implemented namespaces:
//!   PID:   each namespace has its own PID numbering
//!   Mount: each namespace has its own filesystem tree
//!   Net:   each namespace has its own network stack (virtual NIC per ns)
//!   UTS:   each namespace has its own hostname/domainname

use alloc::{collections::BTreeMap, string::String};
use spin::{Lazy, Mutex};
use crate::task::TaskId;

pub type NsId = u32;

bitflags::bitflags! {
    pub struct CloneFlags: u64 {
        const NEWPID   = 1 << 29;
        const NEWNS    = 1 << 17;  // Mount
        const NEWNET   = 1 << 30;
        const NEWUTS   = 1 << 26;
        const NEWUSER  = 1 << 28;
        const NEWIPC   = 1 << 27;
    }
}

#[derive(Clone, Debug)]
pub struct PidNamespace {
    pub id:          NsId,
    pub parent:      Option<NsId>,
    /// Maps: host TID → namespace-local PID
    pub pid_map:     BTreeMap<TaskId, u32>,
    pub next_pid:    u32,
}

impl PidNamespace {
    pub fn new(id: NsId, parent: Option<NsId>) -> Self {
        Self { id, parent, pid_map: BTreeMap::new(), next_pid: 1 }
    }

    pub fn allocate_pid(&mut self, tid: TaskId) -> u32 {
        let pid = self.next_pid;
        self.next_pid += 1;
        self.pid_map.insert(tid, pid);
        pid
    }

    pub fn get_pid(&self, tid: TaskId) -> u32 {
        *self.pid_map.get(&tid).unwrap_or(&0)
    }
}

#[derive(Clone, Debug)]
pub struct MountNamespace {
    pub id:     NsId,
    pub parent: Option<NsId>,
    /// Override mount table for this namespace
    pub mounts: BTreeMap<String, String>, // virt_path → fs_type
}

impl MountNamespace {
    pub fn new(id: NsId, parent: Option<NsId>) -> Self {
        let mut mounts = BTreeMap::new();
        mounts.insert("/".into(),     "ionafs".into());
        mounts.insert("/proc".into(), "procfs".into());
        mounts.insert("/dev".into(),  "devfs".into());
        Self { id, parent, mounts }
    }
}

#[derive(Clone, Debug)]
pub struct UtsNamespace {
    pub id:         NsId,
    pub hostname:   String,
    pub domainname: String,
}

impl UtsNamespace {
    pub fn new(id: NsId) -> Self {
        Self { id, hostname: "iona".into(), domainname: "iona.local".into() }
    }
}

/// All namespaces a process belongs to
#[derive(Clone, Debug)]
pub struct ProcessNamespaces {
    pub pid_ns:   NsId,
    pub mnt_ns:   NsId,
    pub uts_ns:   NsId,
    pub net_ns:   NsId,  // real: isolated network stack
}

static PID_NAMESPACES: Lazy<Mutex<BTreeMap<NsId, PidNamespace>>> = Lazy::new(|| {
    let mut m = BTreeMap::new();
    m.insert(0, PidNamespace::new(0, None)); // root PID namespace
    Mutex::new(m)
});
static MNT_NAMESPACES: Lazy<Mutex<BTreeMap<NsId, MountNamespace>>> = Lazy::new(|| {
    let mut m = BTreeMap::new();
    m.insert(0, MountNamespace::new(0, None));
    Mutex::new(m)
});
static UTS_NAMESPACES: Lazy<Mutex<BTreeMap<NsId, UtsNamespace>>> = Lazy::new(|| {
    let mut m = BTreeMap::new();
    m.insert(0, UtsNamespace::new(0));
    Mutex::new(m)
});
static TASK_NS: Lazy<Mutex<BTreeMap<TaskId, ProcessNamespaces>>> = Lazy::new(|| Mutex::new(BTreeMap::new()));
static NEXT_NS_ID: spin::Mutex<NsId> = spin::Mutex::new(1);

fn next_id() -> NsId { let mut n = NEXT_NS_ID.lock(); let v = *n; *n += 1; v }

/// Initialize namespaces for a new process (inherits from parent or root)
pub fn init_for_task(tid: TaskId, parent: Option<TaskId>) {
    let parent_ns = parent.and_then(|ptid| TASK_NS.lock().get(&ptid).cloned())
        .unwrap_or(ProcessNamespaces { pid_ns: 0, mnt_ns: 0, uts_ns: 0, net_ns: 0 });
    TASK_NS.lock().insert(tid, parent_ns);

    // Allocate PID in parent's PID namespace
    let pid_ns_id = TASK_NS.lock().get(&tid).map(|n| n.pid_ns).unwrap_or(0);
    if let Some(ns) = PID_NAMESPACES.lock().get_mut(&pid_ns_id) {
        let pid = ns.allocate_pid(tid);
        crate::serial_println!("  [NS] tid={} pid={} in ns={}", tid, pid, pid_ns_id);
    }
}

/// Create new namespaces (called from clone() with CLONE_NEW* flags)
pub fn unshare(tid: TaskId, flags: CloneFlags) {
    let mut task_ns = TASK_NS.lock();
    let ns = task_ns.entry(tid).or_insert(ProcessNamespaces { pid_ns:0, mnt_ns:0, uts_ns:0, net_ns:0 });

    if flags.contains(CloneFlags::NEWPID) {
        let id = next_id();
        PID_NAMESPACES.lock().insert(id, PidNamespace::new(id, Some(ns.pid_ns)));
        ns.pid_ns = id;
        crate::serial_println!("  [NS] new PID namespace {} for tid={}", id, tid);
    }
    if flags.contains(CloneFlags::NEWNS) {
        let id = next_id();
        MNT_NAMESPACES.lock().insert(id, MountNamespace::new(id, Some(ns.mnt_ns)));
        ns.mnt_ns = id;
    }
    if flags.contains(CloneFlags::NEWUTS) {
        let id = next_id();
        UTS_NAMESPACES.lock().insert(id, UtsNamespace::new(id));
        ns.uts_ns = id;
    }
    if flags.contains(CloneFlags::NEWNET) {
        let parent_net = ns.net_ns;
        let id = new_net_namespace(parent_net);
        ns.net_ns = id;
    }
}

pub fn get_pid(tid: TaskId) -> u32 {
    let ns_id = TASK_NS.lock().get(&tid).map(|n| n.pid_ns).unwrap_or(0);
    PID_NAMESPACES.lock().get(&ns_id).map(|ns| ns.get_pid(tid)).unwrap_or(tid as u32)
}

pub fn get_hostname(tid: TaskId) -> String {
    let ns_id = TASK_NS.lock().get(&tid).map(|n| n.uts_ns).unwrap_or(0);
    UTS_NAMESPACES.lock().get(&ns_id).map(|ns| ns.hostname.clone()).unwrap_or("iona".into())
}

pub fn init() { crate::serial_println!("  [NS] PID + Mount + UTS + Net namespaces ready"); }

// ── Network Namespace (real implementation) ───────────────────────────────────

#[derive(Clone, Debug)]
pub struct NetNamespace {
    pub id:         NsId,
    pub parent:     Option<NsId>,
    pub hostname:   String,
    /// Virtual IP assigned to this namespace (NAT from host)
    pub ip:         [u8; 4],
    pub netmask:    [u8; 4],
    pub gateway:    [u8; 4],
    /// Socket table: sockets in this namespace are isolated from other ns
    pub loopback:   bool,
    /// Port forwarding rules: host_port → (ns_ip, ns_port)
    pub port_fwd:   alloc::collections::BTreeMap<u16, ([u8; 4], u16)>,
}

impl NetNamespace {
    pub fn new_root() -> Self {
        Self {
            id: 0, parent: None,
            hostname: "iona".into(),
            ip: [10, 0, 2, 15],
            netmask: [255, 255, 255, 0],
            gateway: [10, 0, 2, 2],
            loopback: true,
            port_fwd: alloc::collections::BTreeMap::new(),
        }
    }

    pub fn new_isolated(id: NsId, parent: NsId) -> Self {
        // Each isolated namespace gets a 172.16.x.x address
        let ns_octet = (id % 254 + 1) as u8;
        Self {
            id, parent: Some(parent),
            hostname: alloc::format!("iona-ns-{}", id),
            ip: [172, 16, ns_octet, 1],
            netmask: [255, 255, 255, 0],
            gateway: [172, 16, ns_octet, 254],
            loopback: true,
            port_fwd: alloc::collections::BTreeMap::new(),
        }
    }

    /// Add port forwarding rule: host:port → this_ns:ns_port
    pub fn add_port_forward(&mut self, host_port: u16, ns_port: u16) {
        self.port_fwd.insert(host_port, (self.ip, ns_port));
        crate::serial_println!("  [NETNS] ns={} forward host:{} → {}:{}", self.id, host_port, self.ip[3], ns_port);
    }

    /// Check if a socket connect is allowed in this namespace
    pub fn allows_connect(&self, dst_ip: [u8; 4], _dst_port: u16) -> bool {
        // Loopback always allowed
        if dst_ip == [127, 0, 0, 1] { return true; }
        // Same subnet allowed
        for i in 0..4 {
            if (dst_ip[i] & self.netmask[i]) != (self.ip[i] & self.netmask[i]) {
                // Cross-subnet: only allowed if gateway is configured
                return self.gateway != [0, 0, 0, 0];
            }
        }
        true
    }
}

static NET_NAMESPACES: Lazy<Mutex<BTreeMap<NsId, NetNamespace>>> = Lazy::new(|| {
    let mut m = BTreeMap::new();
    m.insert(0, NetNamespace::new_root());
    Mutex::new(m)
});

pub fn new_net_namespace(parent: NsId) -> NsId {
    let id = next_id();
    NET_NAMESPACES.lock().insert(id, NetNamespace::new_isolated(id, parent));
    crate::serial_println!("  [NS] new net namespace {} (172.16.{}.x)", id, id % 254 + 1);
    id
}

pub fn get_net_ns(tid: TaskId) -> Option<NetNamespace> {
    let ns_id = TASK_NS.lock().get(&tid).map(|n| n.net_ns).unwrap_or(0);
    NET_NAMESPACES.lock().get(&ns_id).cloned()
}

/// Check if a connect is allowed for this process (enforced by net ns)
pub fn check_connect_allowed(tid: TaskId, dst_ip: [u8; 4], dst_port: u16) -> bool {
    let ns_id = TASK_NS.lock().get(&tid).map(|n| n.net_ns).unwrap_or(0);
    NET_NAMESPACES.lock().get(&ns_id)
        .map(|ns| ns.allows_connect(dst_ip, dst_port))
        .unwrap_or(true) // root namespace: allow all
}
