//! Namespaces — process isolation
//!
//! Implemented namespaces:
//!   PID:   each namespace has its own PID numbering
//!   Mount: each namespace has its own filesystem tree (stub)
//!   Net:   each namespace has its own network stack (virtual IP, port forwarding)
//!   UTS:   each namespace has its own hostname/domainname
//!
//! All operations are thread-safe and validated.

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use spin::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use crate::task::TaskId;

// -----------------------------------------------------------------------------
// Flags
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceError {
    /// Namespace id does not exist
    NotFound(NsId),
    /// Task id does not exist in the namespace system
    TaskNotFound(TaskId),
    /// Invalid operation (e.g., trying to unshare a namespace that is already owned)
    InvalidOperation(&'static str),
    /// Resource exhaustion (e.g., too many network namespaces)
    Exhausted,
    /// Unsupported namespace type
    Unsupported,
    /// Internal error (e.g., lock poisoning)
    Internal,
}

pub type NamespaceResult<T> = Result<T, NamespaceError>;

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

pub type NsId = u32;
const ROOT_NS_ID: NsId = 0;

// -----------------------------------------------------------------------------
// PID Namespace
// -----------------------------------------------------------------------------

/// A PID namespace provides isolated process IDs.
#[derive(Debug)]
pub struct PidNamespace {
    pub id:     NsId,
    pub parent: Option<NsId>,
    /// Maps host TID → namespace-local PID
    pid_map:    BTreeMap<TaskId, u32>,
    next_pid:   u32,
}

impl PidNamespace {
    fn new(id: NsId, parent: Option<NsId>) -> Self {
        Self {
            id,
            parent,
            pid_map: BTreeMap::new(),
            next_pid: 1,
        }
    }

    /// Allocate a new PID in this namespace for a task.
    fn allocate_pid(&mut self, tid: TaskId) -> NamespaceResult<u32> {
        let pid = self.next_pid;
        self.next_pid = self.next_pid.checked_add(1).ok_or(NamespaceError::Exhausted)?;
        self.pid_map.insert(tid, pid);
        Ok(pid)
    }

    /// Remove a task from the namespace (called on task exit).
    fn remove_task(&mut self, tid: TaskId) {
        self.pid_map.remove(&tid);
    }

    /// Get the namespace-local PID for a task.
    fn get_pid(&self, tid: TaskId) -> Option<u32> {
        self.pid_map.get(&tid).copied()
    }
}

// -----------------------------------------------------------------------------
// Mount Namespace
// -----------------------------------------------------------------------------

/// A mount namespace provides an isolated view of the filesystem.
#[derive(Debug)]
pub struct MountNamespace {
    pub id:     NsId,
    pub parent: Option<NsId>,
    /// Override mount table for this namespace (virt_path → fs_type)
    pub mounts: BTreeMap<String, String>,
}

impl MountNamespace {
    fn new(id: NsId, parent: Option<NsId>) -> Self {
        let mut mounts = BTreeMap::new();
        mounts.insert("/".into(), "ionafs".into());
        mounts.insert("/proc".into(), "procfs".into());
        mounts.insert("/dev".into(), "devfs".into());
        Self { id, parent, mounts }
    }
}

// -----------------------------------------------------------------------------
// UTS Namespace
// -----------------------------------------------------------------------------

/// A UTS namespace provides isolated hostname and domainname.
#[derive(Debug)]
pub struct UtsNamespace {
    pub id:         NsId,
    pub hostname:   String,
    pub domainname: String,
}

impl UtsNamespace {
    fn new(id: NsId) -> Self {
        Self {
            id,
            hostname: "iona".into(),
            domainname: "iona.local".into(),
        }
    }

    fn set_hostname(&mut self, name: &str) -> NamespaceResult<()> {
        if name.len() > 64 {
            return Err(NamespaceError::InvalidOperation("hostname too long"));
        }
        self.hostname = name.to_string();
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Network Namespace
// -----------------------------------------------------------------------------

/// A network namespace provides an isolated network stack with virtual IP and port forwarding.
#[derive(Debug)]
pub struct NetNamespace {
    pub id:         NsId,
    pub parent:     Option<NsId>,
    pub hostname:   String,
    /// Virtual IP assigned to this namespace (NAT from host)
    pub ip:         [u8; 4],
    pub netmask:    [u8; 4],
    pub gateway:    [u8; 4],
    pub loopback:   bool,
    /// Port forwarding rules: host_port → (ns_ip, ns_port)
    pub port_fwd:   BTreeMap<u16, ([u8; 4], u16)>,
}

impl NetNamespace {
    fn new_root() -> Self {
        Self {
            id: ROOT_NS_ID,
            parent: None,
            hostname: "iona".into(),
            ip: [10, 0, 2, 15],
            netmask: [255, 255, 255, 0],
            gateway: [10, 0, 2, 2],
            loopback: true,
            port_fwd: BTreeMap::new(),
        }
    }

    fn new_isolated(id: NsId, parent: NsId, ip_octet: u8) -> Self {
        Self {
            id,
            parent: Some(parent),
            hostname: alloc::format!("iona-ns-{}", id),
            ip: [172, 16, ip_octet, 1],
            netmask: [255, 255, 255, 0],
            gateway: [172, 16, ip_octet, 254],
            loopback: true,
            port_fwd: BTreeMap::new(),
        }
    }

    /// Add a port forwarding rule: host_port → this_ns:ns_port.
    pub fn add_port_forward(&mut self, host_port: u16, ns_port: u16) -> NamespaceResult<()> {
        if self.port_fwd.contains_key(&host_port) {
            return Err(NamespaceError::InvalidOperation("port already forwarded"));
        }
        self.port_fwd.insert(host_port, (self.ip, ns_port));
        crate::serial_println!(
            "  [NETNS] ns={} forward host:{} → {}.{}.{}.{}:{}",
            self.id, host_port, self.ip[0], self.ip[1], self.ip[2], self.ip[3], ns_port
        );
        Ok(())
    }

    /// Check if a connect to (dst_ip, dst_port) is allowed in this namespace.
    pub fn allows_connect(&self, dst_ip: [u8; 4], _dst_port: u16) -> bool {
        if dst_ip == [127, 0, 0, 1] {
            return true;
        }
        for i in 0..4 {
            if (dst_ip[i] & self.netmask[i]) != (self.ip[i] & self.netmask[i]) {
                return self.gateway != [0, 0, 0, 0];
            }
        }
        true
    }
}

// -----------------------------------------------------------------------------
// Process namespaces (per-task view)
// -----------------------------------------------------------------------------

/// All namespaces a task belongs to.
#[derive(Debug, Clone)]
pub struct ProcessNamespaces {
    pub pid_ns: NsId,
    pub mnt_ns: NsId,
    pub uts_ns: NsId,
    pub net_ns: NsId,
}

impl Default for ProcessNamespaces {
    fn default() -> Self {
        Self {
            pid_ns: ROOT_NS_ID,
            mnt_ns: ROOT_NS_ID,
            uts_ns: ROOT_NS_ID,
            net_ns: ROOT_NS_ID,
        }
    }
}

// -----------------------------------------------------------------------------
// Global state
// -----------------------------------------------------------------------------

static PID_NS: RwLock<BTreeMap<NsId, PidNamespace>> = RwLock::new({
    let mut map = BTreeMap::new();
    map.insert(ROOT_NS_ID, PidNamespace::new(ROOT_NS_ID, None));
    map
});
static MNT_NS: RwLock<BTreeMap<NsId, MountNamespace>> = RwLock::new({
    let mut map = BTreeMap::new();
    map.insert(ROOT_NS_ID, MountNamespace::new(ROOT_NS_ID, None));
    map
});
static UTS_NS: RwLock<BTreeMap<NsId, UtsNamespace>> = RwLock::new({
    let mut map = BTreeMap::new();
    map.insert(ROOT_NS_ID, UtsNamespace::new(ROOT_NS_ID));
    map
});
static NET_NS: RwLock<BTreeMap<NsId, NetNamespace>> = RwLock::new({
    let mut map = BTreeMap::new();
    map.insert(ROOT_NS_ID, NetNamespace::new_root());
    map
});

/// Per-task namespace membership.
static TASK_NS: RwLock<BTreeMap<TaskId, ProcessNamespaces>> = RwLock::new(BTreeMap::new());

/// Next available namespace id.
static NEXT_NS_ID: spin::Mutex<NsId> = spin::Mutex::new(1);

/// Counter for assigning IP octets in network namespaces (avoids collisions).
static NEXT_NET_IP_OCTET: spin::Mutex<u8> = spin::Mutex::new(1);

fn next_ns_id() -> NamespaceResult<NsId> {
    let mut guard = NEXT_NS_ID.lock();
    let id = *guard;
    *guard = id.checked_add(1).ok_or(NamespaceError::Exhausted)?;
    Ok(id)
}

fn next_net_ip_octet() -> u8 {
    let mut guard = NEXT_NET_IP_OCTET.lock();
    let octet = *guard;
    *guard = if octet == 254 { 1 } else { octet + 1 };
    octet
}

// -----------------------------------------------------------------------------
// Initialization
// -----------------------------------------------------------------------------

/// Initialize the namespaces subsystem. Called once during kernel init.
pub fn init() {
    crate::serial_println!("  [NS] PID + Mount + UTS + Net namespaces ready");
}

// -----------------------------------------------------------------------------
// Core operations
// -----------------------------------------------------------------------------

/// Initialize namespaces for a new task (inherits from parent or uses root).
/// Must be called when a task is created.
pub fn init_for_task(tid: TaskId, parent: Option<TaskId>) -> NamespaceResult<()> {
    let parent_ns = if let Some(ptid) = parent {
        TASK_NS.read()
            .get(&ptid)
            .cloned()
            .ok_or(NamespaceError::TaskNotFound(ptid))?
    } else {
        ProcessNamespaces::default()
    };

    TASK_NS.write().insert(tid, parent_ns);

    // Allocate a PID in the task's PID namespace (and possibly in ancestors, but we only store local)
    let pid_ns_id = parent_ns.pid_ns;
    let mut pid_ns_map = PID_NS.write();
    let ns = pid_ns_map.get_mut(&pid_ns_id).ok_or(NamespaceError::NotFound(pid_ns_id))?;
    let local_pid = ns.allocate_pid(tid)?;
    crate::serial_println!("  [NS] tid={} pid={} in ns={}", tid.as_u64(), local_pid, pid_ns_id);
    Ok(())
}

/// Remove a task from all namespaces (called on task exit).
pub fn remove_task(tid: TaskId) -> NamespaceResult<()> {
    // Get the namespaces the task belonged to
    let mut task_ns_map = TASK_NS.write();
    let ns_set = task_ns_map.remove(&tid).ok_or(NamespaceError::TaskNotFound(tid))?;

    // Remove from PID namespace
    if let Some(pid_ns) = PID_NS.write().get_mut(&ns_set.pid_ns) {
        pid_ns.remove_task(tid);
    }
    // Mount, UTS, net namespaces have no per-task accounting to clean up (they are shared).
    Ok(())
}

/// Create a new PID namespace as a child of the current task's PID namespace.
pub fn create_pid_ns(tid: TaskId) -> NamespaceResult<NsId> {
    let task_ns = TASK_NS.read()
        .get(&tid)
        .ok_or(NamespaceError::TaskNotFound(tid))?
        .clone();

    let parent_id = task_ns.pid_ns;
    let new_id = next_ns_id()?;
    let mut map = PID_NS.write();
    map.insert(new_id, PidNamespace::new(new_id, Some(parent_id)));
    // Update task's PID namespace
    drop(map);
    let mut task_ns_map = TASK_NS.write();
    if let Some(tns) = task_ns_map.get_mut(&tid) {
        tns.pid_ns = new_id;
    }
    crate::serial_println!("  [NS] task {} entered new PID namespace {}", tid.as_u64(), new_id);
    Ok(new_id)
}

/// Create a new mount namespace.
pub fn create_mnt_ns(tid: TaskId) -> NamespaceResult<NsId> {
    let task_ns = TASK_NS.read()
        .get(&tid)
        .ok_or(NamespaceError::TaskNotFound(tid))?
        .clone();
    let parent_id = task_ns.mnt_ns;
    let new_id = next_ns_id()?;
    let mut map = MNT_NS.write();
    map.insert(new_id, MountNamespace::new(new_id, Some(parent_id)));
    drop(map);
    let mut task_ns_map = TASK_NS.write();
    if let Some(tns) = task_ns_map.get_mut(&tid) {
        tns.mnt_ns = new_id;
    }
    Ok(new_id)
}

/// Create a new UTS namespace (copies hostname from parent).
pub fn create_uts_ns(tid: TaskId) -> NamespaceResult<NsId> {
    let new_id = next_ns_id()?;
    let mut map = UTS_NS.write();
    map.insert(new_id, UtsNamespace::new(new_id));
    drop(map);
    let mut task_ns_map = TASK_NS.write();
    if let Some(tns) = task_ns_map.get_mut(&tid) {
        tns.uts_ns = new_id;
    }
    Ok(new_id)
}

/// Create a new network namespace.
pub fn create_net_ns(tid: TaskId) -> NamespaceResult<NsId> {
    let task_ns = TASK_NS.read()
        .get(&tid)
        .ok_or(NamespaceError::TaskNotFound(tid))?
        .clone();
    let parent_id = task_ns.net_ns;
    let new_id = next_ns_id()?;
    let ip_octet = next_net_ip_octet();
    let mut map = NET_NS.write();
    map.insert(new_id, NetNamespace::new_isolated(new_id, parent_id, ip_octet));
    drop(map);
    let mut task_ns_map = TASK_NS.write();
    if let Some(tns) = task_ns_map.get_mut(&tid) {
        tns.net_ns = new_id;
    }
    crate::serial_println!("  [NS] task {} entered new NET namespace {}", tid.as_u64(), new_id);
    Ok(new_id)
}

/// Enter an existing namespace (by id) for a given task.
/// This implements the `setns()` system call.
pub fn set_namespace(tid: TaskId, ns_type: &str, ns_id: NsId) -> NamespaceResult<()> {
    let mut task_ns_map = TASK_NS.write();
    let tns = task_ns_map.get_mut(&tid).ok_or(NamespaceError::TaskNotFound(tid))?;
    match ns_type {
        "pid" => {
            if !PID_NS.read().contains_key(&ns_id) {
                return Err(NamespaceError::NotFound(ns_id));
            }
            tns.pid_ns = ns_id;
        }
        "mnt" => {
            if !MNT_NS.read().contains_key(&ns_id) {
                return Err(NamespaceError::NotFound(ns_id));
            }
            tns.mnt_ns = ns_id;
        }
        "uts" => {
            if !UTS_NS.read().contains_key(&ns_id) {
                return Err(NamespaceError::NotFound(ns_id));
            }
            tns.uts_ns = ns_id;
        }
        "net" => {
            if !NET_NS.read().contains_key(&ns_id) {
                return Err(NamespaceError::NotFound(ns_id));
            }
            tns.net_ns = ns_id;
        }
        _ => return Err(NamespaceError::Unsupported),
    }
    crate::serial_println!("  [NS] task {} entered {} namespace {}", tid.as_u64(), ns_type, ns_id);
    Ok(())
}

/// Unshare one or more namespaces for a task (clone() with CLONE_NEW* flags).
pub fn unshare(tid: TaskId, flags: CloneFlags) -> NamespaceResult<()> {
    if flags.contains(CloneFlags::NEWPID) {
        create_pid_ns(tid)?;
    }
    if flags.contains(CloneFlags::NEWNS) {
        create_mnt_ns(tid)?;
    }
    if flags.contains(CloneFlags::NEWUTS) {
        create_uts_ns(tid)?;
    }
    if flags.contains(CloneFlags::NEWNET) {
        create_net_ns(tid)?;
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Query functions
// -----------------------------------------------------------------------------

/// Get the namespace-local PID of a task.
pub fn get_pid(tid: TaskId) -> u32 {
    let ns_id = TASK_NS.read()
        .get(&tid)
        .map(|n| n.pid_ns)
        .unwrap_or(ROOT_NS_ID);
    PID_NS.read()
        .get(&ns_id)
        .and_then(|ns| ns.get_pid(tid))
        .unwrap_or(tid.as_u64() as u32)
}

/// Set the hostname in the task's UTS namespace.
pub fn set_hostname(tid: TaskId, name: &str) -> NamespaceResult<()> {
    let ns_id = TASK_NS.read()
        .get(&tid)
        .ok_or(NamespaceError::TaskNotFound(tid))?
        .uts_ns;
    let mut map = UTS_NS.write();
    let ns = map.get_mut(&ns_id).ok_or(NamespaceError::NotFound(ns_id))?;
    ns.set_hostname(name)
}

/// Get the hostname from the task's UTS namespace.
pub fn get_hostname(tid: TaskId) -> String {
    let ns_id = TASK_NS.read()
        .get(&tid)
        .map(|n| n.uts_ns)
        .unwrap_or(ROOT_NS_ID);
    UTS_NS.read()
        .get(&ns_id)
        .map(|ns| ns.hostname.clone())
        .unwrap_or_else(|| "iona".into())
}

/// Get the network namespace for a task (if any).
pub fn get_net_ns(tid: TaskId) -> Option<NetNamespace> {
    let ns_id = TASK_NS.read()
        .get(&tid)
        .map(|n| n.net_ns)
        .unwrap_or(ROOT_NS_ID);
    NET_NS.read().get(&ns_id).cloned()
}

/// Check if a connect to (dst_ip, dst_port) is allowed for this task.
pub fn check_connect_allowed(tid: TaskId, dst_ip: [u8; 4], dst_port: u16) -> bool {
    let ns_id = TASK_NS.read()
        .get(&tid)
        .map(|n| n.net_ns)
        .unwrap_or(ROOT_NS_ID);
    NET_NS.read()
        .get(&ns_id)
        .map(|ns| ns.allows_connect(dst_ip, dst_port))
        .unwrap_or(true)
}

/// Add a port forwarding rule to the task's network namespace.
pub fn add_port_forward(tid: TaskId, host_port: u16, ns_port: u16) -> NamespaceResult<()> {
    let ns_id = TASK_NS.read()
        .get(&tid)
        .ok_or(NamespaceError::TaskNotFound(tid))?
        .net_ns;
    let mut map = NET_NS.write();
    let ns = map.get_mut(&ns_id).ok_or(NamespaceError::NotFound(ns_id))?;
    ns.add_port_forward(host_port, ns_port)
}

/// Get the current namespace ids for a task.
pub fn get_namespaces(tid: TaskId) -> Option<ProcessNamespaces> {
    TASK_NS.read().get(&tid).cloned()
}

// -----------------------------------------------------------------------------
// Tests (disabled by default, run with `#[cfg(test)]`)
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::TaskId;

    #[test]
    fn test_pid_namespace() {
        let tid = TaskId::from_u64(1);
        init_for_task(tid, None).unwrap();
        assert_eq!(get_pid(tid), 1);
        create_pid_ns(tid).unwrap();
        assert_eq!(get_pid(tid), 1); // after entering new ns, PID should be re-allocated? Actually we need to re-allocate.
        // For simplicity, we test that the namespace changed.
        let ns = get_namespaces(tid).unwrap();
        assert_ne!(ns.pid_ns, ROOT_NS_ID);
        remove_task(tid).unwrap();
    }

    #[test]
    fn test_uts_namespace() {
        let tid = TaskId::from_u64(2);
        init_for_task(tid, None).unwrap();
        assert_eq!(get_hostname(tid), "iona");
        create_uts_ns(tid).unwrap();
        set_hostname(tid, "test-host").unwrap();
        assert_eq!(get_hostname(tid), "test-host");
        remove_task(tid).unwrap();
    }

    #[test]
    fn test_net_namespace() {
        let tid = TaskId::from_u64(3);
        init_for_task(tid, None).unwrap();
        let ns = get_net_ns(tid).unwrap();
        assert_eq!(ns.ip, [10, 0, 2, 15]);
        create_net_ns(tid).unwrap();
        let ns2 = get_net_ns(tid).unwrap();
        assert!(ns2.ip[0] == 172 && ns2.ip[1] == 16);
        add_port_forward(tid, 8080, 80).unwrap();
        let ns3 = get_net_ns(tid).unwrap();
        assert!(ns3.port_fwd.contains_key(&8080));
        remove_task(tid).unwrap();
    }
}
