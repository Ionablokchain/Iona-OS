//! Container subsystem — cgroups + namespaces integration
//!
//! Each container is backed by a cgroup (for resource limits) and optionally
//! by a network namespace for network isolation.
//!
//! Containers provide process isolation with resource control, similar to
//! Linux containers (LXC/Docker) but at the kernel level.

pub mod cgroups;
pub mod namespaces;

use alloc::{string::String, collections::BTreeMap, vec::Vec};
use spin::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use crate::task::TaskId;

// Re-export important types
pub use cgroups::{CgroupId, CpuConfig, MemConfig, IoConfig};
pub use namespaces::{NetNsId, NamespaceError};

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during container operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerError {
    /// Container with this id already exists (should not happen with auto-increment)
    AlreadyExists(u64),
    /// Container not found
    NotFound(u64),
    /// Failed to create or access cgroup
    CgroupError(&'static str),
    /// Failed to create or access namespace
    NamespaceError(&'static str),
    /// Task already belongs to a different container (move is allowed, but if you want to avoid)
    TaskAlreadyInContainer,
    /// Cannot destroy a container that still has tasks (unless force flag)
    ContainerHasTasks,
    /// Invalid container name (empty)
    InvalidName,
    /// Invalid filesystem root path
    InvalidFsRoot,
    /// Internal error (e.g., lock poisoning)
    Internal,
}

pub type ContainerResult<T> = Result<T, ContainerError>;

// -----------------------------------------------------------------------------
// Container definition
// -----------------------------------------------------------------------------

/// A container groups tasks with resource limits (cgroup) and isolation (namespaces).
#[derive(Debug)]
pub struct Container {
    pub id:        u64,
    pub name:      String,
    pub cgroup_id: CgroupId,        // associated cgroup
    pub net_ns_id: Option<NetNsId>,  // network namespace (if isolated)
    pub fs_root:   String,           // chroot path in IONAFS
    tasks:         Vec<TaskId>,      // tasks currently in this container
}

impl Container {
    fn new(
        id: u64,
        name: String,
        cgroup_id: CgroupId,
        net_ns_id: Option<NetNsId>,
        fs_root: String,
    ) -> Self {
        Self {
            id,
            name,
            cgroup_id,
            net_ns_id,
            fs_root,
            tasks: Vec::new(),
        }
    }

    /// Add a task to the container. This does not attach the task to the cgroup
    /// or namespaces; that is done by the container manager.
    fn add_task(&mut self, tid: TaskId) {
        if !self.tasks.contains(&tid) {
            self.tasks.push(tid);
        }
    }

    /// Remove a task from the container's task list.
    fn remove_task(&mut self, tid: TaskId) {
        self.tasks.retain(|&t| t != tid);
    }
}

// -----------------------------------------------------------------------------
// Global container registry
// -----------------------------------------------------------------------------

static CONTAINERS: RwLock<BTreeMap<u64, Container>> = RwLock::new(BTreeMap::new());
static NEXT_CID: spin::Mutex<u64> = spin::Mutex::new(1);

/// Initialize the container subsystem.
/// Must be called once during kernel init (after cgroups and namespaces).
pub fn init() {
    cgroups::init();
    namespaces::init();
    crate::serial_println!("[CONTAINER] subsystem initialized");
}

// -----------------------------------------------------------------------------
// Container lifecycle
// -----------------------------------------------------------------------------

/// Create a new container.
/// - `name`: human-readable name (must not be empty)
/// - `fs_root`: chroot path inside IONAFS (must not be empty)
/// - `net_isolate`: if true, create a new network namespace for the container
/// - `cpu_config`, `mem_config`, `io_config`: initial resource limits (None = use defaults)
///
/// Returns the new container id on success.
pub fn create_container(
    name: &str,
    fs_root: &str,
    net_isolate: bool,
    cpu_config: Option<CpuConfig>,
    mem_config: Option<MemConfig>,
    io_config: Option<IoConfig>,
) -> ContainerResult<u64> {
    if name.is_empty() {
        return Err(ContainerError::InvalidName);
    }
    if fs_root.is_empty() {
        return Err(ContainerError::InvalidFsRoot);
    }

    // 1. Create a new cgroup for the container
    let cgroup_name = alloc::format!("container_{}", name);
    let cgroup_id = cgroups::create(&cgroup_name, Some(cgroups::root_cgroup_id()))
        .ok_or(ContainerError::CgroupError("failed to create cgroup"))?;

    // Apply resource limits if provided
    if let Some(cpu) = cpu_config {
        let _ = cgroups::set_cpu_shares(cgroup_id, cpu.shares);
        let _ = cgroups::set_cpu_quota(cgroup_id, cpu.quota_us, cpu.period_us);
    }
    if let Some(mem) = mem_config {
        let _ = cgroups::set_mem_limit(cgroup_id, mem.limit_bytes);
        let _ = cgroups::set_mem_soft_limit(cgroup_id, mem.soft_limit_bytes);
        // swap and oom not implemented in cgroups stub, ignore
    }
    if let Some(io) = io_config {
        let _ = cgroups::set_io_limits(cgroup_id, io.read_bps_limit, io.write_bps_limit,
                                        io.read_iops_limit, io.write_iops_limit);
    }

    // 2. Create network namespace if requested
    let net_ns_id = if net_isolate {
        Some(namespaces::create_net_ns().map_err(|_| ContainerError::NamespaceError("net namespace creation failed"))?)
    } else {
        None
    };

    // 3. Allocate container id
    let cid = {
        let mut n = NEXT_CID.lock();
        let id = *n;
        *n = id.checked_add(1).ok_or(ContainerError::Internal)?;
        id
    };

    let container = Container::new(cid, name.to_string(), cgroup_id, net_ns_id, fs_root.to_string());

    // 4. Insert into registry
    {
        let mut map = CONTAINERS.write();
        if map.contains_key(&cid) {
            // Should never happen with auto-increment, but guard
            return Err(ContainerError::AlreadyExists(cid));
        }
        map.insert(cid, container);
    }

    crate::serial_println!(
        "[CONTAINER] created: id={} name='{}' cgroup={} net_ns={:?} root='{}'",
        cid, name, cgroup_id, net_ns_id, fs_root
    );
    Ok(cid)
}

/// Destroy a container and all its resources.
/// If `force` is true, all tasks are moved to the root container.
/// If `force` is false and the container still has tasks, returns `ContainerHasTasks`.
pub fn destroy_container(cid: u64, force: bool) -> ContainerResult<()> {
    let mut map = CONTAINERS.write();
    let container = map.remove(&cid).ok_or(ContainerError::NotFound(cid))?;

    if !force && !container.tasks.is_empty() {
        // Put it back
        map.insert(cid, container);
        return Err(ContainerError::ContainerHasTasks);
    }

    // Move all tasks to root container (or just detach from cgroup)
    for &tid in &container.tasks {
        // Move to root cgroup (id 0) and reset namespace
        let _ = cgroups::attach(tid, cgroups::root_cgroup_id());
        if let Some(ns_id) = container.net_ns_id {
            // Reset network namespace to default (root)
            let _ = namespaces::enter_net_ns(tid, namespaces::root_net_ns_id());
        }
        // Remove from container's task list (we are destroying anyway)
        cgroups::remove_task(tid); // also removes from cgroup task list
    }

    // Destroy the cgroup (must be empty now)
    if !cgroups::remove(container.cgroup_id) {
        crate::serial_println!(
            "[CONTAINER] warning: cgroup {} could not be destroyed (maybe still has children)",
            container.cgroup_id
        );
    }

    // Destroy network namespace if any
    if let Some(ns_id) = container.net_ns_id {
        let _ = namespaces::destroy_net_ns(ns_id);
    }

    crate::serial_println!("[CONTAINER] destroyed: id={} name='{}'", cid, container.name);
    Ok(())
}

/// Add a task to a container.
/// The task will be:
///   - Attached to the container's cgroup
///   - Moved into the container's network namespace (if any)
///   - Its filesystem root will be set to the container's fs_root (implementation dependent)
pub fn container_add_task(cid: u64, tid: TaskId) -> ContainerResult<()> {
    let mut map = CONTAINERS.write();
    let container = map.get_mut(&cid).ok_or(ContainerError::NotFound(cid))?;

    // Attach to cgroup
    if !cgroups::attach(tid, container.cgroup_id) {
        return Err(ContainerError::CgroupError("failed to attach to cgroup"));
    }

    // Enter network namespace if present
    if let Some(ns_id) = container.net_ns_id {
        namespaces::enter_net_ns(tid, ns_id).map_err(|_| ContainerError::NamespaceError("failed to enter net namespace"))?;
    }

    // TODO: set fs root for the task (chroot equivalent) – depends on IONAFS implementation
    // For now, we just store the root path in the container.

    container.add_task(tid);
    crate::serial_println!("[CONTAINER] task {} added to container {}", tid.as_u64(), cid);
    Ok(())
}

/// Remove a task from a container (without destroying the container).
/// The task is moved back to the root cgroup and default namespace.
pub fn container_remove_task(tid: TaskId) -> ContainerResult<()> {
    // Find which container contains this task
    let cid = {
        let map = CONTAINERS.read();
        map.iter().find_map(|(id, c)| if c.tasks.contains(&tid) { Some(*id) } else { None })
    };
    let cid = match cid {
        Some(id) => id,
        None => return Ok(()), // not in any container
    };

    let mut map = CONTAINERS.write();
    let container = map.get_mut(&cid).ok_or(ContainerError::NotFound(cid))?;

    // Move task to root cgroup
    let _ = cgroups::attach(tid, cgroups::root_cgroup_id());
    // Reset namespace
    if container.net_ns_id.is_some() {
        let _ = namespaces::enter_net_ns(tid, namespaces::root_net_ns_id());
    }
    container.remove_task(tid);
    crate::serial_println!("[CONTAINER] task {} removed from container {}", tid.as_u64(), cid);
    Ok(())
}

/// Get the container id that a task belongs to, if any.
pub fn task_container(tid: TaskId) -> Option<u64> {
    let map = CONTAINERS.read();
    map.iter().find_map(|(id, c)| if c.tasks.contains(&tid) { Some(*id) } else { None })
}

/// Get the filesystem root path for a task (if in a container).
pub fn get_container_root(tid: TaskId) -> Option<String> {
    let cid = task_container(tid)?;
    let map = CONTAINERS.read();
    map.get(&cid).map(|c| c.fs_root.clone())
}

// -----------------------------------------------------------------------------
// Query functions
// -----------------------------------------------------------------------------

/// List all container ids.
pub fn list_containers() -> Vec<u64> {
    CONTAINERS.read().keys().copied().collect()
}

/// Get a reference to a container by id (read-only).
pub fn get_container(cid: u64) -> Option<Container> {
    CONTAINERS.read().get(&cid).cloned()
}

/// Get statistics for a container (CPU, memory, I/O) via its cgroup.
pub fn container_stats(cid: u64) -> Option<cgroups::CgroupStats> {
    let container = CONTAINERS.read().get(&cid)?;
    Some(cgroups::CgroupStats {
        cpu_usage_us: cgroups::cpu_usage(container.cgroup_id)?,
        mem_usage_bytes: cgroups::mem_usage(container.cgroup_id)?,
        io_read_bytes: 0,   // not yet implemented in cgroups stub
        io_write_bytes: 0,
        io_read_ops: 0,
        io_write_ops: 0,
    })
}

/// Set CPU shares for a container (proportional weight).
pub fn container_set_cpu_shares(cid: u64, shares: u32) -> ContainerResult<()> {
    let map = CONTAINERS.read();
    let container = map.get(&cid).ok_or(ContainerError::NotFound(cid))?;
    if cgroups::set_cpu_shares(container.cgroup_id, shares) {
        Ok(())
    } else {
        Err(ContainerError::CgroupError("failed to set cpu shares"))
    }
}

/// Set memory limit for a container.
pub fn container_set_mem_limit(cid: u64, limit_bytes: i64) -> ContainerResult<()> {
    let map = CONTAINERS.read();
    let container = map.get(&cid).ok_or(ContainerError::NotFound(cid))?;
    if cgroups::set_mem_limit(container.cgroup_id, limit_bytes) {
        Ok(())
    } else {
        Err(ContainerError::CgroupError("failed to set memory limit"))
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::TaskId;

    // Note: tests require cgroups and namespaces to be initialized.
    // In a real kernel environment, these are called after init().

    #[test]
    fn test_create_and_destroy() {
        init();
        let cid = create_container("test", "/test/root", false, None, None, None).unwrap();
        assert!(get_container(cid).is_some());
        assert!(list_containers().contains(&cid));
        destroy_container(cid, false).unwrap();
        assert!(get_container(cid).is_none());
    }

    #[test]
    fn test_add_task() {
        init();
        let cid = create_container("test2", "/test2", false, None, None, None).unwrap();
        let tid = TaskId::from_u64(100);
        container_add_task(cid, tid).unwrap();
        assert_eq!(task_container(tid), Some(cid));
        assert_eq!(get_container_root(tid), Some("/test2".to_string()));
        container_remove_task(tid).unwrap();
        assert_eq!(task_container(tid), None);
        destroy_container(cid, false).unwrap();
    }

    #[test]
    fn test_destroy_with_tasks_not_force() {
        init();
        let cid = create_container("test3", "/test3", false, None, None, None).unwrap();
        let tid = TaskId::from_u64(200);
        container_add_task(cid, tid).unwrap();
        let err = destroy_container(cid, false).unwrap_err();
        assert!(matches!(err, ContainerError::ContainerHasTasks));
        // Force destroy
        destroy_container(cid, true).unwrap();
        // Task should now be in root cgroup
        assert_eq!(task_container(tid), None);
    }
}
