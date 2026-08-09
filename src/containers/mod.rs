//! Container subsystem — cgroups + namespaces integration
//!
//! Each container is backed by a cgroup (for resource limits) and optionally
//! by a network namespace for network isolation.
//!
//! Containers provide process isolation with resource control, similar to
//! Linux containers (LXC/Docker) but at the kernel level.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                        Container Module                                │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   config    │    error     │     types     │        metrics           │
//! │ (ContainerCfg)│ (ContainerErr)│ (Container,  │ (ContainerMetrics)      │
//! │             │              │  ContainerId) │                          │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   manager   │    legacy    │               │                          │
//! │ (ContainerMgr)│ (global fns)│               │                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::container::{ContainerManager, ContainerConfig};
//!
//! let config = ContainerConfig::default();
//! let manager = ContainerManager::new(config);
//! let cid = manager.create_container("web", "/var/www", false, None, None, None).unwrap();
//! manager.container_add_task(cid, task_id).unwrap();
//! let stats = manager.container_stats(cid).unwrap();
//! ```

#![allow(dead_code)]

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use crate::task::TaskId;
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for the container subsystem.
    use serde::{Deserialize, Serialize};
    use super::cgroups::{CpuConfig, MemConfig, IoConfig};

    /// Configuration for a container.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct ContainerConfig {
        pub max_containers: usize,
        pub collect_metrics: bool,
        pub log_operations: bool,
        pub default_cpu_shares: u32,
        pub default_mem_limit_bytes: i64,
        pub default_fs_root: String,
    }

    impl Default for ContainerConfig {
        fn default() -> Self {
            Self {
                max_containers: 1024,
                collect_metrics: true,
                log_operations: true,
                default_cpu_shares: 1024,
                default_mem_limit_bytes: -1,
                default_fs_root: "/".to_string(),
            }
        }
    }

    /// Container creation options.
    #[derive(Clone, Debug)]
    pub struct ContainerOptions {
        pub name: String,
        pub fs_root: String,
        pub net_isolate: bool,
        pub cpu_config: Option<CpuConfig>,
        pub mem_config: Option<MemConfig>,
        pub io_config: Option<IoConfig>,
    }

    impl ContainerOptions {
        pub fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                fs_root: "/".to_string(),
                net_isolate: false,
                cpu_config: None,
                mem_config: None,
                io_config: None,
            }
        }

        pub fn with_fs_root(mut self, path: &str) -> Self {
            self.fs_root = path.to_string();
            self
        }

        pub fn with_net_isolate(mut self) -> Self {
            self.net_isolate = true;
            self
        }

        pub fn with_cpu(mut self, config: CpuConfig) -> Self {
            self.cpu_config = Some(config);
            self
        }

        pub fn with_mem(mut self, config: MemConfig) -> Self {
            self.mem_config = Some(config);
            self
        }

        pub fn with_io(mut self, config: IoConfig) -> Self {
            self.io_config = Some(config);
            self
        }
    }
}

pub mod error {
    //! Error types for container operations.
    use super::types::ContainerId;
    use crate::task::TaskId;
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum ContainerError {
        #[error("container not found: id={0}")]
        NotFound(ContainerId),

        #[error("container with id {0} already exists")]
        AlreadyExists(ContainerId),

        #[error("container name cannot be empty")]
        EmptyName,

        #[error("filesystem root path cannot be empty")]
        EmptyFsRoot,

        #[error("task {0} not found in container")]
        TaskNotFound(TaskId),

        #[error("task {0} already in a container")]
        TaskAlreadyInContainer,

        #[error("container has tasks, cannot destroy (use force)")]
        ContainerHasTasks,

        #[error("cgroup error: {0}")]
        CgroupError(String),

        #[error("namespace error: {0}")]
        NamespaceError(String),

        #[error("too many containers (max {0})")]
        TooManyContainers(usize),

        #[error("configuration error: {0}")]
        Config(String),

        #[error("internal error: {0}")]
        Internal(String),
    }

    pub type ContainerResult<T> = Result<T, ContainerError>;
}

pub mod types {
    //! Core types for containers.
    use super::cgroups::{CgroupId, CpuConfig, MemConfig, IoConfig};
    use super::namespaces::NetNsId;
    use crate::task::TaskId;
    use alloc::{
        string::String,
        vec::Vec,
    };
    use core::fmt;

    /// Container identifier.
    pub type ContainerId = u64;

    /// Statistics for a container (aggregated from its cgroup).
    #[derive(Debug, Clone, Default)]
    pub struct ContainerStats {
        pub cpu_usage_us: u64,
        pub mem_usage_bytes: u64,
        pub io_read_bytes: u64,
        pub io_write_bytes: u64,
        pub io_read_ops: u64,
        pub io_write_ops: u64,
        pub task_count: usize,
    }

    /// Internal representation of a container.
    #[derive(Clone)]
    pub struct Container {
        pub id: ContainerId,
        pub name: String,
        pub cgroup_id: CgroupId,
        pub net_ns_id: Option<NetNsId>,
        pub fs_root: String,
        pub tasks: Vec<TaskId>,
    }

    impl Container {
        pub fn new(
            id: ContainerId,
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

        pub fn add_task(&mut self, tid: TaskId) {
            if !self.tasks.contains(&tid) {
                self.tasks.push(tid);
            }
        }

        pub fn remove_task(&mut self, tid: TaskId) {
            self.tasks.retain(|&t| t != tid);
        }

        pub fn task_count(&self) -> usize {
            self.tasks.len()
        }
    }

    impl fmt::Debug for Container {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Container")
                .field("id", &self.id)
                .field("name", &self.name)
                .field("cgroup_id", &self.cgroup_id)
                .field("net_ns_id", &self.net_ns_id)
                .field("fs_root", &self.fs_root)
                .field("task_count", &self.tasks.len())
                .finish()
        }
    }
}

pub mod metrics {
    //! Metrics for container operations.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct ContainerMetrics {
        pub containers_created: AtomicU64,
        pub containers_destroyed: AtomicU64,
        pub tasks_added: AtomicU64,
        pub tasks_removed: AtomicU64,
        pub failed_creations: AtomicU64,
        pub failed_destroys: AtomicU64,
        pub failed_adds: AtomicU64,
        pub failed_removes: AtomicU64,
    }

    impl ContainerMetrics {
        pub fn inc_created(&self) {
            self.containers_created.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_destroyed(&self) {
            self.containers_destroyed.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_task_added(&self) {
            self.tasks_added.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_task_removed(&self) {
            self.tasks_removed.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_failed_creation(&self) {
            self.failed_creations.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_failed_destroy(&self) {
            self.failed_destroys.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_failed_add(&self) {
            self.failed_adds.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_failed_remove(&self) {
            self.failed_removes.fetch_add(1, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> ContainerMetricsSnapshot {
            ContainerMetricsSnapshot {
                containers_created: self.containers_created.load(Ordering::Relaxed),
                containers_destroyed: self.containers_destroyed.load(Ordering::Relaxed),
                tasks_added: self.tasks_added.load(Ordering::Relaxed),
                tasks_removed: self.tasks_removed.load(Ordering::Relaxed),
                failed_creations: self.failed_creations.load(Ordering::Relaxed),
                failed_destroys: self.failed_destroys.load(Ordering::Relaxed),
                failed_adds: self.failed_adds.load(Ordering::Relaxed),
                failed_removes: self.failed_removes.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ContainerMetricsSnapshot {
        pub containers_created: u64,
        pub containers_destroyed: u64,
        pub tasks_added: u64,
        pub tasks_removed: u64,
        pub failed_creations: u64,
        pub failed_destroys: u64,
        pub failed_adds: u64,
        pub failed_removes: u64,
    }
}

pub mod manager {
    //! Centralised manager for containers.
    use super::{
        config::{ContainerConfig, ContainerOptions},
        error::{ContainerError, ContainerResult},
        types::{Container, ContainerId, ContainerStats},
        metrics::ContainerMetrics,
        cgroups,
        namespaces,
    };
    use crate::task::TaskId;
    use alloc::{
        collections::BTreeMap,
        string::{String, ToString},
        vec::Vec,
    };
    use core::sync::atomic::{AtomicU64, Ordering};
    use spin::RwLock;
    use tracing::{debug, error, info, warn};

    /// Centralised manager for containers.
    pub struct ContainerManager {
        containers: RwLock<BTreeMap<ContainerId, Container>>,
        next_id: AtomicU64,
        config: ContainerConfig,
        metrics: ContainerMetrics,
    }

    impl ContainerManager {
        /// Create a new container manager with the given configuration.
        pub fn new(config: ContainerConfig) -> Self {
            // Initialize sub‑systems.
            cgroups::init();
            namespaces::init();
            Self {
                containers: RwLock::new(BTreeMap::new()),
                next_id: AtomicU64::new(1),
                config,
                metrics: ContainerMetrics::default(),
            }
        }

        /// Create a manager with default configuration.
        pub fn default() -> Self {
            Self::new(ContainerConfig::default())
        }

        /// Get a reference to the metrics.
        pub fn metrics(&self) -> &ContainerMetrics {
            &self.metrics
        }

        /// Get the configuration.
        pub fn config(&self) -> &ContainerConfig {
            &self.config
        }

        /// Create a new container with the given options.
        pub fn create_container(&self, opts: ContainerOptions) -> ContainerResult<ContainerId> {
            if opts.name.is_empty() {
                return Err(ContainerError::EmptyName);
            }
            if opts.fs_root.is_empty() {
                return Err(ContainerError::EmptyFsRoot);
            }

            // Check max containers.
            {
                let containers = self.containers.read();
                if containers.len() >= self.config.max_containers {
                    self.metrics.inc_failed_creation();
                    return Err(ContainerError::TooManyContainers(self.config.max_containers));
                }
            }

            // 1. Create cgroup.
            let cgroup_name = alloc::format!("container_{}", opts.name);
            let cgroup_id = cgroups::create(&cgroup_name, Some(cgroups::root_cgroup_id()))
                .ok_or_else(|| {
                    self.metrics.inc_failed_creation();
                    ContainerError::CgroupError("failed to create cgroup".into())
                })?;

            // Apply resource limits if provided.
            if let Some(cpu) = opts.cpu_config {
                let _ = cgroups::set_cpu_shares(cgroup_id, cpu.shares);
                let _ = cgroups::set_cpu_quota(cgroup_id, cpu.quota_us, cpu.period_us);
            }
            if let Some(mem) = opts.mem_config {
                let _ = cgroups::set_mem_limit(cgroup_id, mem.limit_bytes);
                let _ = cgroups::set_mem_soft_limit(cgroup_id, mem.soft_limit_bytes);
            }
            if let Some(io) = opts.io_config {
                let _ = cgroups::set_io_limits(cgroup_id, io.read_bps_limit, io.write_bps_limit,
                                                io.read_iops_limit, io.write_iops_limit);
            }

            // 2. Create network namespace if requested.
            let net_ns_id = if opts.net_isolate {
                Some(namespaces::create_net_ns().map_err(|e| {
                    self.metrics.inc_failed_creation();
                    ContainerError::NamespaceError(format!("net ns creation failed: {}", e))
                })?)
            } else {
                None
            };

            // 3. Allocate container id.
            let cid = self.next_id.fetch_add(1, Ordering::Relaxed);

            let container = Container::new(
                cid,
                opts.name.clone(),
                cgroup_id,
                net_ns_id,
                opts.fs_root.clone(),
            );

            // 4. Insert into registry.
            {
                let mut map = self.containers.write();
                if map.contains_key(&cid) {
                    self.metrics.inc_failed_creation();
                    return Err(ContainerError::AlreadyExists(cid));
                }
                map.insert(cid, container);
            }

            self.metrics.inc_created();
            if self.config.log_operations {
                info!(
                    container_id = cid,
                    name = opts.name,
                    cgroup_id,
                    net_ns = ?net_ns_id,
                    fs_root = opts.fs_root,
                    "container created"
                );
            }
            Ok(cid)
        }

        /// Destroy a container and all its resources.
        pub fn destroy_container(&self, cid: ContainerId, force: bool) -> ContainerResult<()> {
            let mut map = self.containers.write();
            let container = map.remove(&cid).ok_or_else(|| {
                self.metrics.inc_failed_destroy();
                ContainerError::NotFound(cid)
            })?;

            if !force && !container.tasks.is_empty() {
                // Put it back.
                map.insert(cid, container);
                return Err(ContainerError::ContainerHasTasks);
            }

            // Move all tasks to root cgroup and default namespace.
            for &tid in &container.tasks {
                let _ = cgroups::attach(tid, cgroups::root_cgroup_id());
                if container.net_ns_id.is_some() {
                    let _ = namespaces::enter_net_ns(tid, namespaces::root_net_ns_id());
                }
                cgroups::remove_task(tid);
            }

            // Destroy the cgroup.
            if !cgroups::remove(container.cgroup_id) {
                warn!(
                    container_id = cid,
                    cgroup_id = container.cgroup_id,
                    "failed to destroy cgroup (maybe still has children)"
                );
            }

            // Destroy network namespace if any.
            if let Some(ns_id) = container.net_ns_id {
                let _ = namespaces::destroy_net_ns(ns_id);
            }

            self.metrics.inc_destroyed();
            if self.config.log_operations {
                info!(container_id = cid, name = container.name, "container destroyed");
            }
            Ok(())
        }

        /// Add a task to a container.
        pub fn container_add_task(&self, cid: ContainerId, tid: TaskId) -> ContainerResult<()> {
            let mut map = self.containers.write();
            let container = map.get_mut(&cid).ok_or_else(|| {
                self.metrics.inc_failed_add();
                ContainerError::NotFound(cid)
            })?;

            // Attach to cgroup.
            if !cgroups::attach(tid, container.cgroup_id) {
                self.metrics.inc_failed_add();
                return Err(ContainerError::CgroupError("failed to attach to cgroup".into()));
            }

            // Enter network namespace if present.
            if let Some(ns_id) = container.net_ns_id {
                if let Err(e) = namespaces::enter_net_ns(tid, ns_id) {
                    self.metrics.inc_failed_add();
                    return Err(ContainerError::NamespaceError(format!("failed to enter net ns: {}", e)));
                }
            }

            container.add_task(tid);
            self.metrics.inc_task_added();
            if self.config.log_operations {
                debug!(container_id = cid, task_id = tid.as_u64(), "task added to container");
            }
            Ok(())
        }

        /// Remove a task from its container (moves to root cgroup and default ns).
        pub fn container_remove_task(&self, tid: TaskId) -> ContainerResult<()> {
            // Find which container contains this task.
            let cid = {
                let map = self.containers.read();
                map.iter().find_map(|(id, c)| {
                    if c.tasks.contains(&tid) { Some(*id) } else { None }
                })
            };
            let cid = match cid {
                Some(id) => id,
                None => return Ok(()), // not in any container
            };

            let mut map = self.containers.write();
            let container = map.get_mut(&cid).ok_or_else(|| {
                self.metrics.inc_failed_remove();
                ContainerError::NotFound(cid)
            })?;

            // Move task to root cgroup.
            let _ = cgroups::attach(tid, cgroups::root_cgroup_id());
            // Reset namespace.
            if container.net_ns_id.is_some() {
                let _ = namespaces::enter_net_ns(tid, namespaces::root_net_ns_id());
            }
            container.remove_task(tid);
            self.metrics.inc_task_removed();
            if self.config.log_operations {
                debug!(container_id = cid, task_id = tid.as_u64(), "task removed from container");
            }
            Ok(())
        }

        /// Get the container id that a task belongs to, if any.
        pub fn task_container(&self, tid: TaskId) -> Option<ContainerId> {
            let map = self.containers.read();
            map.iter().find_map(|(id, c)| {
                if c.tasks.contains(&tid) { Some(*id) } else { None }
            })
        }

        /// Get the filesystem root path for a task (if in a container).
        pub fn get_container_root(&self, tid: TaskId) -> Option<String> {
            let cid = self.task_container(tid)?;
            let map = self.containers.read();
            map.get(&cid).map(|c| c.fs_root.clone())
        }

        /// List all container ids.
        pub fn list_containers(&self) -> Vec<ContainerId> {
            self.containers.read().keys().copied().collect()
        }

        /// Get a copy of a container by id.
        pub fn get_container(&self, cid: ContainerId) -> Option<Container> {
            self.containers.read().get(&cid).cloned()
        }

        /// Get statistics for a container (CPU, memory, I/O) via its cgroup.
        pub fn container_stats(&self, cid: ContainerId) -> Option<ContainerStats> {
            let container = self.containers.read().get(&cid)?;
            let cpu_usage = cgroups::cpu_usage(container.cgroup_id);
            let mem_usage = cgroups::mem_usage(container.cgroup_id);
            Some(ContainerStats {
                cpu_usage_us: cpu_usage.unwrap_or(0),
                mem_usage_bytes: mem_usage.unwrap_or(0),
                io_read_bytes: 0,   // not yet implemented in cgroups stub
                io_write_bytes: 0,
                io_read_ops: 0,
                io_write_ops: 0,
                task_count: container.task_count(),
            })
        }

        /// Set CPU shares for a container (proportional weight).
        pub fn container_set_cpu_shares(&self, cid: ContainerId, shares: u32) -> ContainerResult<()> {
            let map = self.containers.read();
            let container = map.get(&cid).ok_or(ContainerError::NotFound(cid))?;
            if cgroups::set_cpu_shares(container.cgroup_id, shares) {
                Ok(())
            } else {
                Err(ContainerError::CgroupError("failed to set cpu shares".into()))
            }
        }

        /// Set memory limit for a container.
        pub fn container_set_mem_limit(&self, cid: ContainerId, limit_bytes: i64) -> ContainerResult<()> {
            let map = self.containers.read();
            let container = map.get(&cid).ok_or(ContainerError::NotFound(cid))?;
            if cgroups::set_mem_limit(container.cgroup_id, limit_bytes) {
                Ok(())
            } else {
                Err(ContainerError::CgroupError("failed to set memory limit".into()))
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::{ContainerConfig, ContainerOptions};
pub use error::{ContainerError, ContainerResult};
pub use types::{Container, ContainerId, ContainerStats};
pub use manager::ContainerManager;
pub use metrics::{ContainerMetrics, ContainerMetricsSnapshot};

// Re-export cgroups and namespaces types for convenience.
pub use cgroups::{CgroupId, CpuConfig, MemConfig, IoConfig};
pub use namespaces::{NetNsId, NamespaceError};

// -----------------------------------------------------------------------------
// Legacy global API (wrappers around a global singleton)
// -----------------------------------------------------------------------------

static GLOBAL_MANAGER: spin::Once<ContainerManager> = spin::Once::new();

/// Initialize the container subsystem.
/// Must be called once during kernel init (after cgroups and namespaces).
pub fn init() {
    GLOBAL_MANAGER.call_once(|| ContainerManager::default());
    crate::serial_println!("[CONTAINER] subsystem initialized");
}

/// Get a reference to the global manager.
fn global_manager() -> &'static ContainerManager {
    GLOBAL_MANAGER.get().expect("container manager not initialized")
}

/// Create a new container with the given options.
pub fn create_container(
    name: &str,
    fs_root: &str,
    net_isolate: bool,
    cpu_config: Option<CpuConfig>,
    mem_config: Option<MemConfig>,
    io_config: Option<IoConfig>,
) -> ContainerResult<ContainerId> {
    let opts = ContainerOptions::new(name)
        .with_fs_root(fs_root)
        .with_net_isolate();
    let opts = if let Some(c) = cpu_config { opts.with_cpu(c) } else { opts };
    let opts = if let Some(m) = mem_config { opts.with_mem(m) } else { opts };
    let opts = if let Some(i) = io_config { opts.with_io(i) } else { opts };
    global_manager().create_container(opts)
}

/// Destroy a container.
pub fn destroy_container(cid: ContainerId, force: bool) -> ContainerResult<()> {
    global_manager().destroy_container(cid, force)
}

/// Add a task to a container.
pub fn container_add_task(cid: ContainerId, tid: TaskId) -> ContainerResult<()> {
    global_manager().container_add_task(cid, tid)
}

/// Remove a task from its container.
pub fn container_remove_task(tid: TaskId) -> ContainerResult<()> {
    global_manager().container_remove_task(tid)
}

/// Get the container id that a task belongs to.
pub fn task_container(tid: TaskId) -> Option<ContainerId> {
    global_manager().task_container(tid)
}

/// Get the filesystem root path for a task.
pub fn get_container_root(tid: TaskId) -> Option<String> {
    global_manager().get_container_root(tid)
}

/// List all container ids.
pub fn list_containers() -> Vec<ContainerId> {
    global_manager().list_containers()
}

/// Get a copy of a container.
pub fn get_container(cid: ContainerId) -> Option<Container> {
    global_manager().get_container(cid)
}

/// Get statistics for a container.
pub fn container_stats(cid: ContainerId) -> Option<ContainerStats> {
    global_manager().container_stats(cid)
}

/// Set CPU shares for a container.
pub fn container_set_cpu_shares(cid: ContainerId, shares: u32) -> ContainerResult<()> {
    global_manager().container_set_cpu_shares(cid, shares)
}

/// Set memory limit for a container.
pub fn container_set_mem_limit(cid: ContainerId, limit_bytes: i64) -> ContainerResult<()> {
    global_manager().container_set_mem_limit(cid, limit_bytes)
}

/// Get metrics snapshot.
pub fn metrics() -> ContainerMetricsSnapshot {
    global_manager().metrics().snapshot()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::TaskId;

    fn init_test() {
        // Ensure we have a fresh manager for each test.
        GLOBAL_MANAGER.call_once(|| ContainerManager::default());
        // Clear any leftover containers.
        let mgr = GLOBAL_MANAGER.get().unwrap();
        let containers = mgr.list_containers();
        for cid in containers {
            let _ = mgr.destroy_container(cid, true);
        }
    }

    #[test]
    fn test_create_and_destroy() {
        init_test();
        let cid = create_container("test", "/test/root", false, None, None, None).unwrap();
        assert!(get_container(cid).is_some());
        assert!(list_containers().contains(&cid));
        destroy_container(cid, false).unwrap();
        assert!(get_container(cid).is_none());
    }

    #[test]
    fn test_add_task() {
        init_test();
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
        init_test();
        let cid = create_container("test3", "/test3", false, None, None, None).unwrap();
        let tid = TaskId::from_u64(200);
        container_add_task(cid, tid).unwrap();
        let err = destroy_container(cid, false).unwrap_err();
        assert!(matches!(err, ContainerError::ContainerHasTasks));
        // Force destroy.
        destroy_container(cid, true).unwrap();
        // Task should now be in root cgroup.
        assert_eq!(task_container(tid), None);
    }
}
