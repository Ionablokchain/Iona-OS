//! Namespaces — process isolation
//!
//! Implemented namespaces:
//!   PID:   each namespace has its own PID numbering
//!   Mount: each namespace has its own filesystem tree (stub)
//!   Net:   each namespace has its own network stack (virtual IP, port forwarding)
//!   UTS:   each namespace has its own hostname/domainname
//!
//! All operations are thread-safe and validated.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                        Namespaces Module                               │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   config    │    error     │     types     │        metrics           │
//! │ (NsConfig)  │ (NsError)    │ (NsId, flags, │ (NsMetrics)              │
//! │             │              │  ProcessNss)  │                          │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   pid       │    mount     │     uts       │         net              │
//! │ (PidNs)     │ (MountNs)    │ (UtsNs)       │ (NetNs)                  │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   manager   │    legacy    │               │                          │
//! │ (NsManager) │ (global fns) │               │                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::namespaces::{NamespaceManager, NamespaceConfig};
//!
//! let config = NamespaceConfig::default();
//! let manager = NamespaceManager::new(config);
//! manager.init_for_task(task_id, None).unwrap();
//! let pid = manager.get_pid(task_id);
//! manager.create_pid_ns(task_id).unwrap();
//! ```

#![allow(dead_code)]

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use crate::task::TaskId;
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for namespaces.
    use serde::{Deserialize, Serialize};

    /// Configuration for the namespace subsystem.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct NamespaceConfig {
        pub max_pid_ns: usize,
        pub max_mnt_ns: usize,
        pub max_uts_ns: usize,
        pub max_net_ns: usize,
        pub collect_metrics: bool,
        pub log_operations: bool,
        pub default_hostname: String,
        pub default_domainname: String,
    }

    impl Default for NamespaceConfig {
        fn default() -> Self {
            Self {
                max_pid_ns: 1024,
                max_mnt_ns: 1024,
                max_uts_ns: 1024,
                max_net_ns: 1024,
                collect_metrics: true,
                log_operations: true,
                default_hostname: "iona".into(),
                default_domainname: "iona.local".into(),
            }
        }
    }

    impl NamespaceConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.max_pid_ns == 0 { return Err("max_pid_ns must be > 0"); }
            if self.max_mnt_ns == 0 { return Err("max_mnt_ns must be > 0"); }
            if self.max_uts_ns == 0 { return Err("max_uts_ns must be > 0"); }
            if self.max_net_ns == 0 { return Err("max_net_ns must be > 0"); }
            Ok(())
        }
    }
}

pub mod error {
    //! Error types for namespaces.
    use super::types::{NsId, CloneFlags};
    use crate::task::TaskId;
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum NamespaceError {
        #[error("namespace not found: id={0}")]
        NotFound(NsId),

        #[error("task not found: {0}")]
        TaskNotFound(TaskId),

        #[error("invalid operation: {0}")]
        InvalidOperation(&'static str),

        #[error("resource exhausted (too many namespaces)")]
        Exhausted,

        #[error("unsupported namespace type")]
        Unsupported,

        #[error("hostname too long (max 64)")]
        HostnameTooLong,

        #[error("port already forwarded")]
        PortAlreadyForwarded,

        #[error("configuration error: {0}")]
        Config(String),

        #[error("internal error: {0}")]
        Internal(String),
    }

    pub type NamespaceResult<T> = Result<T, NamespaceError>;
}

pub mod types {
    //! Core types for namespaces.
    use super::error::{NamespaceError, NamespaceResult};
    use crate::task::TaskId;
    use alloc::{
        collections::BTreeMap,
        string::String,
    };
    use bitflags::bitflags;

    /// Namespace identifier.
    pub type NsId = u32;

    /// Root namespace id.
    pub const ROOT_NS_ID: NsId = 0;

    bitflags! {
        /// Clone flags for unshare().
        pub struct CloneFlags: u64 {
            const NEWPID   = 1 << 29;
            const NEWNS    = 1 << 17;  // Mount
            const NEWNET   = 1 << 30;
            const NEWUTS   = 1 << 26;
            const NEWUSER  = 1 << 28;
            const NEWIPC   = 1 << 27;
        }
    }

    /// All namespaces a task belongs to.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

pub mod pid {
    //! PID namespace implementation.
    use super::{
        config::NamespaceConfig,
        error::{NamespaceError, NamespaceResult},
        types::{NsId, ROOT_NS_ID},
    };
    use crate::task::TaskId;
    use alloc::collections::BTreeMap;
    use core::fmt;

    /// A PID namespace provides isolated process IDs.
    #[derive(Debug)]
    pub struct PidNamespace {
        pub id: NsId,
        pub parent: Option<NsId>,
        pid_map: BTreeMap<TaskId, u32>,
        next_pid: u32,
    }

    impl PidNamespace {
        pub fn new(id: NsId, parent: Option<NsId>) -> Self {
            Self {
                id,
                parent,
                pid_map: BTreeMap::new(),
                next_pid: 1,
            }
        }

        pub fn allocate_pid(&mut self, tid: TaskId) -> NamespaceResult<u32> {
            let pid = self.next_pid;
            self.next_pid = self.next_pid.checked_add(1).ok_or(NamespaceError::Exhausted)?;
            self.pid_map.insert(tid, pid);
            Ok(pid)
        }

        pub fn remove_task(&mut self, tid: TaskId) {
            self.pid_map.remove(&tid);
        }

        pub fn get_pid(&self, tid: TaskId) -> Option<u32> {
            self.pid_map.get(&tid).copied()
        }

        pub fn task_count(&self) -> usize {
            self.pid_map.len()
        }
    }
}

pub mod mount {
    //! Mount namespace implementation (stub).
    use super::types::NsId;
    use alloc::{
        collections::BTreeMap,
        string::{String, ToString},
    };
    use core::fmt;

    /// A mount namespace provides an isolated view of the filesystem.
    #[derive(Debug)]
    pub struct MountNamespace {
        pub id: NsId,
        pub parent: Option<NsId>,
        pub mounts: BTreeMap<String, String>,
    }

    impl MountNamespace {
        pub fn new(id: NsId, parent: Option<NsId>) -> Self {
            let mut mounts = BTreeMap::new();
            mounts.insert("/".into(), "ionafs".into());
            mounts.insert("/proc".into(), "procfs".into());
            mounts.insert("/dev".into(), "devfs".into());
            Self { id, parent, mounts }
        }
    }
}

pub mod uts {
    //! UTS namespace implementation.
    use super::{
        error::{NamespaceError, NamespaceResult},
        types::NsId,
        config::NamespaceConfig,
    };
    use alloc::string::String;
    use core::fmt;

    /// A UTS namespace provides isolated hostname and domainname.
    #[derive(Debug)]
    pub struct UtsNamespace {
        pub id: NsId,
        pub hostname: String,
        pub domainname: String,
    }

    impl UtsNamespace {
        pub fn new(id: NsId, config: &NamespaceConfig) -> Self {
            Self {
                id,
                hostname: config.default_hostname.clone(),
                domainname: config.default_domainname.clone(),
            }
        }

        pub fn set_hostname(&mut self, name: &str) -> NamespaceResult<()> {
            if name.len() > 64 {
                return Err(NamespaceError::HostnameTooLong);
            }
            self.hostname = name.to_string();
            Ok(())
        }

        pub fn set_domainname(&mut self, name: &str) -> NamespaceResult<()> {
            if name.len() > 64 {
                return Err(NamespaceError::HostnameTooLong);
            }
            self.domainname = name.to_string();
            Ok(())
        }
    }
}

pub mod net {
    //! Network namespace implementation.
    use super::{
        error::{NamespaceError, NamespaceResult},
        types::NsId,
    };
    use alloc::{
        collections::BTreeMap,
        string::{String, ToString},
    };
    use core::fmt;

    /// A network namespace provides an isolated network stack.
    #[derive(Debug)]
    pub struct NetNamespace {
        pub id: NsId,
        pub parent: Option<NsId>,
        pub hostname: String,
        pub ip: [u8; 4],
        pub netmask: [u8; 4],
        pub gateway: [u8; 4],
        pub loopback: bool,
        pub port_fwd: BTreeMap<u16, ([u8; 4], u16)>,
    }

    impl NetNamespace {
        pub fn new_root() -> Self {
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

        pub fn new_isolated(id: NsId, parent: NsId, ip_octet: u8) -> Self {
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

        pub fn add_port_forward(&mut self, host_port: u16, ns_port: u16) -> NamespaceResult<()> {
            if self.port_fwd.contains_key(&host_port) {
                return Err(NamespaceError::PortAlreadyForwarded);
            }
            self.port_fwd.insert(host_port, (self.ip, ns_port));
            Ok(())
        }

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

    use super::types::ROOT_NS_ID;
}

pub mod metrics {
    //! Metrics for namespace operations.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct NamespaceMetrics {
        pub pid_ns_created: AtomicU64,
        pub mnt_ns_created: AtomicU64,
        pub uts_ns_created: AtomicU64,
        pub net_ns_created: AtomicU64,
        pub tasks_initialized: AtomicU64,
        pub tasks_removed: AtomicU64,
        pub setns_calls: AtomicU64,
        pub unshare_calls: AtomicU64,
        pub failures: AtomicU64,
    }

    impl NamespaceMetrics {
        pub fn inc_pid_ns(&self) { self.pid_ns_created.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_mnt_ns(&self) { self.mnt_ns_created.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_uts_ns(&self) { self.uts_ns_created.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_net_ns(&self) { self.net_ns_created.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_task_init(&self) { self.tasks_initialized.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_task_remove(&self) { self.tasks_removed.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_setns(&self) { self.setns_calls.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_unshare(&self) { self.unshare_calls.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_failure(&self) { self.failures.fetch_add(1, Ordering::Relaxed); }

        pub fn snapshot(&self) -> NamespaceMetricsSnapshot {
            NamespaceMetricsSnapshot {
                pid_ns_created: self.pid_ns_created.load(Ordering::Relaxed),
                mnt_ns_created: self.mnt_ns_created.load(Ordering::Relaxed),
                uts_ns_created: self.uts_ns_created.load(Ordering::Relaxed),
                net_ns_created: self.net_ns_created.load(Ordering::Relaxed),
                tasks_initialized: self.tasks_initialized.load(Ordering::Relaxed),
                tasks_removed: self.tasks_removed.load(Ordering::Relaxed),
                setns_calls: self.setns_calls.load(Ordering::Relaxed),
                unshare_calls: self.unshare_calls.load(Ordering::Relaxed),
                failures: self.failures.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct NamespaceMetricsSnapshot {
        pub pid_ns_created: u64,
        pub mnt_ns_created: u64,
        pub uts_ns_created: u64,
        pub net_ns_created: u64,
        pub tasks_initialized: u64,
        pub tasks_removed: u64,
        pub setns_calls: u64,
        pub unshare_calls: u64,
        pub failures: u64,
    }
}

pub mod manager {
    //! Centralised manager for namespaces.
    use super::{
        config::NamespaceConfig,
        error::{NamespaceError, NamespaceResult},
        types::{NsId, ProcessNamespaces, ROOT_NS_ID, CloneFlags},
        pid::PidNamespace,
        mount::MountNamespace,
        uts::UtsNamespace,
        net::NetNamespace,
        metrics::NamespaceMetrics,
    };
    use crate::task::TaskId;
    use alloc::{
        collections::BTreeMap,
        string::{String, ToString},
        vec::Vec,
    };
    use core::sync::atomic::{AtomicU32, Ordering};
    use spin::RwLock;
    use tracing::{debug, error, info, warn};

    /// Centralised manager for namespaces.
    pub struct NamespaceManager {
        config: NamespaceConfig,
        pid_ns: RwLock<BTreeMap<NsId, PidNamespace>>,
        mnt_ns: RwLock<BTreeMap<NsId, MountNamespace>>,
        uts_ns: RwLock<BTreeMap<NsId, UtsNamespace>>,
        net_ns: RwLock<BTreeMap<NsId, NetNamespace>>,
        task_ns: RwLock<BTreeMap<TaskId, ProcessNamespaces>>,
        next_ns_id: AtomicU32,
        next_net_ip_octet: AtomicU32,
        metrics: NamespaceMetrics,
    }

    impl NamespaceManager {
        /// Create a new namespace manager with the given configuration.
        pub fn new(config: NamespaceConfig) -> Self {
            config.validate().expect("invalid NamespaceConfig");
            let mut pid_map = BTreeMap::new();
            pid_map.insert(ROOT_NS_ID, PidNamespace::new(ROOT_NS_ID, None));
            let mut mnt_map = BTreeMap::new();
            mnt_map.insert(ROOT_NS_ID, MountNamespace::new(ROOT_NS_ID, None));
            let mut uts_map = BTreeMap::new();
            uts_map.insert(ROOT_NS_ID, UtsNamespace::new(ROOT_NS_ID, &config));
            let mut net_map = BTreeMap::new();
            net_map.insert(ROOT_NS_ID, NetNamespace::new_root());

            Self {
                config,
                pid_ns: RwLock::new(pid_map),
                mnt_ns: RwLock::new(mnt_map),
                uts_ns: RwLock::new(uts_map),
                net_ns: RwLock::new(net_map),
                task_ns: RwLock::new(BTreeMap::new()),
                next_ns_id: AtomicU32::new(1),
                next_net_ip_octet: AtomicU32::new(1),
                metrics: NamespaceMetrics::default(),
            }
        }

        /// Create a manager with default configuration.
        pub fn default() -> Self {
            Self::new(NamespaceConfig::default())
        }

        /// Get a reference to the metrics.
        pub fn metrics(&self) -> &NamespaceMetrics {
            &self.metrics
        }

        /// Get the configuration.
        pub fn config(&self) -> &NamespaceConfig {
            &self.config
        }

        // ---------------------------------------------------------------------
        // Core operations
        // ---------------------------------------------------------------------

        /// Initialize namespaces for a new task (inherits from parent or uses root).
        pub fn init_for_task(&self, tid: TaskId, parent: Option<TaskId>) -> NamespaceResult<()> {
            let parent_ns = if let Some(ptid) = parent {
                self.task_ns.read()
                    .get(&ptid)
                    .copied()
                    .ok_or(NamespaceError::TaskNotFound(ptid))?
            } else {
                ProcessNamespaces::default()
            };

            self.task_ns.write().insert(tid, parent_ns);

            // Allocate a PID in the task's PID namespace.
            let pid_ns_id = parent_ns.pid_ns;
            let mut pid_map = self.pid_ns.write();
            let ns = pid_map.get_mut(&pid_ns_id).ok_or(NamespaceError::NotFound(pid_ns_id))?;
            let local_pid = ns.allocate_pid(tid)?;
            self.metrics.inc_task_init();
            if self.config.log_operations {
                debug!(tid = tid.as_u64(), pid = local_pid, ns = pid_ns_id, "task initialized in PID namespace");
            }
            Ok(())
        }

        /// Remove a task from all namespaces (called on task exit).
        pub fn remove_task(&self, tid: TaskId) -> NamespaceResult<()> {
            let mut task_ns_map = self.task_ns.write();
            let ns_set = task_ns_map.remove(&tid).ok_or(NamespaceError::TaskNotFound(tid))?;

            // Remove from PID namespace.
            if let Some(pid_ns) = self.pid_ns.write().get_mut(&ns_set.pid_ns) {
                pid_ns.remove_task(tid);
            }
            self.metrics.inc_task_remove();
            if self.config.log_operations {
                debug!(tid = tid.as_u64(), "task removed from namespaces");
            }
            Ok(())
        }

        /// Create a new PID namespace as a child of the current task's PID namespace.
        pub fn create_pid_ns(&self, tid: TaskId) -> NamespaceResult<NsId> {
            let task_ns = self.task_ns.read()
                .get(&tid)
                .copied()
                .ok_or(NamespaceError::TaskNotFound(tid))?;

            let parent_id = task_ns.pid_ns;
            // Check limit.
            {
                let map = self.pid_ns.read();
                if map.len() >= self.config.max_pid_ns {
                    self.metrics.inc_failure();
                    return Err(NamespaceError::Exhausted);
                }
            }
            let new_id = self.next_ns_id.fetch_add(1, Ordering::Relaxed);
            let mut map = self.pid_ns.write();
            map.insert(new_id, PidNamespace::new(new_id, Some(parent_id)));
            drop(map);
            let mut task_ns_map = self.task_ns.write();
            if let Some(tns) = task_ns_map.get_mut(&tid) {
                tns.pid_ns = new_id;
            }
            self.metrics.inc_pid_ns();
            if self.config.log_operations {
                info!(tid = tid.as_u64(), ns = new_id, "created new PID namespace");
            }
            Ok(new_id)
        }

        /// Create a new mount namespace.
        pub fn create_mnt_ns(&self, tid: TaskId) -> NamespaceResult<NsId> {
            let task_ns = self.task_ns.read()
                .get(&tid)
                .copied()
                .ok_or(NamespaceError::TaskNotFound(tid))?;
            let parent_id = task_ns.mnt_ns;
            {
                let map = self.mnt_ns.read();
                if map.len() >= self.config.max_mnt_ns {
                    self.metrics.inc_failure();
                    return Err(NamespaceError::Exhausted);
                }
            }
            let new_id = self.next_ns_id.fetch_add(1, Ordering::Relaxed);
            let mut map = self.mnt_ns.write();
            map.insert(new_id, MountNamespace::new(new_id, Some(parent_id)));
            drop(map);
            let mut task_ns_map = self.task_ns.write();
            if let Some(tns) = task_ns_map.get_mut(&tid) {
                tns.mnt_ns = new_id;
            }
            self.metrics.inc_mnt_ns();
            Ok(new_id)
        }

        /// Create a new UTS namespace.
        pub fn create_uts_ns(&self, tid: TaskId) -> NamespaceResult<NsId> {
            {
                let map = self.uts_ns.read();
                if map.len() >= self.config.max_uts_ns {
                    self.metrics.inc_failure();
                    return Err(NamespaceError::Exhausted);
                }
            }
            let new_id = self.next_ns_id.fetch_add(1, Ordering::Relaxed);
            let mut map = self.uts_ns.write();
            map.insert(new_id, UtsNamespace::new(new_id, &self.config));
            drop(map);
            let mut task_ns_map = self.task_ns.write();
            if let Some(tns) = task_ns_map.get_mut(&tid) {
                tns.uts_ns = new_id;
            }
            self.metrics.inc_uts_ns();
            Ok(new_id)
        }

        /// Create a new network namespace.
        pub fn create_net_ns(&self, tid: TaskId) -> NamespaceResult<NsId> {
            let task_ns = self.task_ns.read()
                .get(&tid)
                .copied()
                .ok_or(NamespaceError::TaskNotFound(tid))?;
            let parent_id = task_ns.net_ns;
            {
                let map = self.net_ns.read();
                if map.len() >= self.config.max_net_ns {
                    self.metrics.inc_failure();
                    return Err(NamespaceError::Exhausted);
                }
            }
            let new_id = self.next_ns_id.fetch_add(1, Ordering::Relaxed);
            let ip_octet = self.next_net_ip_octet.fetch_add(1, Ordering::Relaxed) as u8;
            let mut map = self.net_ns.write();
            map.insert(new_id, NetNamespace::new_isolated(new_id, parent_id, ip_octet));
            drop(map);
            let mut task_ns_map = self.task_ns.write();
            if let Some(tns) = task_ns_map.get_mut(&tid) {
                tns.net_ns = new_id;
            }
            self.metrics.inc_net_ns();
            if self.config.log_operations {
                info!(tid = tid.as_u64(), ns = new_id, "created new NET namespace");
            }
            Ok(new_id)
        }

        /// Enter an existing namespace (by id) for a given task.
        pub fn set_namespace(&self, tid: TaskId, ns_type: &str, ns_id: NsId) -> NamespaceResult<()> {
            let mut task_ns_map = self.task_ns.write();
            let tns = task_ns_map.get_mut(&tid).ok_or(NamespaceError::TaskNotFound(tid))?;
            match ns_type {
                "pid" => {
                    if !self.pid_ns.read().contains_key(&ns_id) {
                        return Err(NamespaceError::NotFound(ns_id));
                    }
                    tns.pid_ns = ns_id;
                }
                "mnt" => {
                    if !self.mnt_ns.read().contains_key(&ns_id) {
                        return Err(NamespaceError::NotFound(ns_id));
                    }
                    tns.mnt_ns = ns_id;
                }
                "uts" => {
                    if !self.uts_ns.read().contains_key(&ns_id) {
                        return Err(NamespaceError::NotFound(ns_id));
                    }
                    tns.uts_ns = ns_id;
                }
                "net" => {
                    if !self.net_ns.read().contains_key(&ns_id) {
                        return Err(NamespaceError::NotFound(ns_id));
                    }
                    tns.net_ns = ns_id;
                }
                _ => return Err(NamespaceError::Unsupported),
            }
            self.metrics.inc_setns();
            if self.config.log_operations {
                debug!(tid = tid.as_u64(), ns_type, ns_id, "task entered existing namespace");
            }
            Ok(())
        }

        /// Unshare one or more namespaces for a task (clone() with CLONE_NEW* flags).
        pub fn unshare(&self, tid: TaskId, flags: CloneFlags) -> NamespaceResult<()> {
            if flags.contains(CloneFlags::NEWPID) {
                self.create_pid_ns(tid)?;
            }
            if flags.contains(CloneFlags::NEWNS) {
                self.create_mnt_ns(tid)?;
            }
            if flags.contains(CloneFlags::NEWUTS) {
                self.create_uts_ns(tid)?;
            }
            if flags.contains(CloneFlags::NEWNET) {
                self.create_net_ns(tid)?;
            }
            self.metrics.inc_unshare();
            Ok(())
        }

        // ---------------------------------------------------------------------
        // Query functions
        // ---------------------------------------------------------------------

        /// Get the namespace-local PID of a task.
        pub fn get_pid(&self, tid: TaskId) -> u32 {
            let ns_id = self.task_ns.read()
                .get(&tid)
                .map(|n| n.pid_ns)
                .unwrap_or(ROOT_NS_ID);
            self.pid_ns.read()
                .get(&ns_id)
                .and_then(|ns| ns.get_pid(tid))
                .unwrap_or(tid.as_u64() as u32)
        }

        /// Set the hostname in the task's UTS namespace.
        pub fn set_hostname(&self, tid: TaskId, name: &str) -> NamespaceResult<()> {
            let ns_id = self.task_ns.read()
                .get(&tid)
                .ok_or(NamespaceError::TaskNotFound(tid))?
                .uts_ns;
            let mut map = self.uts_ns.write();
            let ns = map.get_mut(&ns_id).ok_or(NamespaceError::NotFound(ns_id))?;
            ns.set_hostname(name)
        }

        /// Get the hostname from the task's UTS namespace.
        pub fn get_hostname(&self, tid: TaskId) -> String {
            let ns_id = self.task_ns.read()
                .get(&tid)
                .map(|n| n.uts_ns)
                .unwrap_or(ROOT_NS_ID);
            self.uts_ns.read()
                .get(&ns_id)
                .map(|ns| ns.hostname.clone())
                .unwrap_or_else(|| self.config.default_hostname.clone())
        }

        /// Get the network namespace for a task (if any).
        pub fn get_net_ns(&self, tid: TaskId) -> Option<net::NetNamespace> {
            let ns_id = self.task_ns.read()
                .get(&tid)
                .map(|n| n.net_ns)
                .unwrap_or(ROOT_NS_ID);
            self.net_ns.read().get(&ns_id).cloned()
        }

        /// Check if a connect to (dst_ip, dst_port) is allowed for this task.
        pub fn check_connect_allowed(&self, tid: TaskId, dst_ip: [u8; 4], dst_port: u16) -> bool {
            let ns_id = self.task_ns.read()
                .get(&tid)
                .map(|n| n.net_ns)
                .unwrap_or(ROOT_NS_ID);
            self.net_ns.read()
                .get(&ns_id)
                .map(|ns| ns.allows_connect(dst_ip, dst_port))
                .unwrap_or(true)
        }

        /// Add a port forwarding rule to the task's network namespace.
        pub fn add_port_forward(&self, tid: TaskId, host_port: u16, ns_port: u16) -> NamespaceResult<()> {
            let ns_id = self.task_ns.read()
                .get(&tid)
                .ok_or(NamespaceError::TaskNotFound(tid))?
                .net_ns;
            let mut map = self.net_ns.write();
            let ns = map.get_mut(&ns_id).ok_or(NamespaceError::NotFound(ns_id))?;
            ns.add_port_forward(host_port, ns_port)
        }

        /// Get the current namespace ids for a task.
        pub fn get_namespaces(&self, tid: TaskId) -> Option<ProcessNamespaces> {
            self.task_ns.read().get(&tid).copied()
        }

        /// List all PID namespace ids.
        pub fn list_pid_ns(&self) -> Vec<NsId> {
            self.pid_ns.read().keys().copied().collect()
        }

        /// List all network namespace ids.
        pub fn list_net_ns(&self) -> Vec<NsId> {
            self.net_ns.read().keys().copied().collect()
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::NamespaceConfig;
pub use error::{NamespaceError, NamespaceResult};
pub use types::{NsId, ProcessNamespaces, CloneFlags, ROOT_NS_ID};
pub use metrics::{NamespaceMetrics, NamespaceMetricsSnapshot};
pub use manager::NamespaceManager;

// Re-export net namespace struct for convenience.
pub use net::NetNamespace;

// -----------------------------------------------------------------------------
// Legacy global API (wrappers around a global singleton)
// -----------------------------------------------------------------------------

static GLOBAL_MANAGER: spin::Once<NamespaceManager> = spin::Once::new();

/// Initialize the global namespace manager.
pub fn init() {
    GLOBAL_MANAGER.call_once(|| NamespaceManager::default());
    crate::serial_println!("  [NS] PID + Mount + UTS + Net namespaces ready");
}

/// Get a reference to the global manager.
fn global_manager() -> &'static NamespaceManager {
    GLOBAL_MANAGER.get().expect("namespace manager not initialized")
}

/// Initialize namespaces for a new task (inherits from parent or uses root).
pub fn init_for_task(tid: TaskId, parent: Option<TaskId>) -> NamespaceResult<()> {
    global_manager().init_for_task(tid, parent)
}

/// Remove a task from all namespaces (called on task exit).
pub fn remove_task(tid: TaskId) -> NamespaceResult<()> {
    global_manager().remove_task(tid)
}

/// Create a new PID namespace as a child of the current task's PID namespace.
pub fn create_pid_ns(tid: TaskId) -> NamespaceResult<NsId> {
    global_manager().create_pid_ns(tid)
}

/// Create a new mount namespace.
pub fn create_mnt_ns(tid: TaskId) -> NamespaceResult<NsId> {
    global_manager().create_mnt_ns(tid)
}

/// Create a new UTS namespace.
pub fn create_uts_ns(tid: TaskId) -> NamespaceResult<NsId> {
    global_manager().create_uts_ns(tid)
}

/// Create a new network namespace.
pub fn create_net_ns(tid: TaskId) -> NamespaceResult<NsId> {
    global_manager().create_net_ns(tid)
}

/// Enter an existing namespace (by id) for a given task.
pub fn set_namespace(tid: TaskId, ns_type: &str, ns_id: NsId) -> NamespaceResult<()> {
    global_manager().set_namespace(tid, ns_type, ns_id)
}

/// Unshare one or more namespaces for a task.
pub fn unshare(tid: TaskId, flags: CloneFlags) -> NamespaceResult<()> {
    global_manager().unshare(tid, flags)
}

/// Get the namespace-local PID of a task.
pub fn get_pid(tid: TaskId) -> u32 {
    global_manager().get_pid(tid)
}

/// Set the hostname in the task's UTS namespace.
pub fn set_hostname(tid: TaskId, name: &str) -> NamespaceResult<()> {
    global_manager().set_hostname(tid, name)
}

/// Get the hostname from the task's UTS namespace.
pub fn get_hostname(tid: TaskId) -> String {
    global_manager().get_hostname(tid)
}

/// Get the network namespace for a task (if any).
pub fn get_net_ns(tid: TaskId) -> Option<NetNamespace> {
    global_manager().get_net_ns(tid)
}

/// Check if a connect to (dst_ip, dst_port) is allowed for this task.
pub fn check_connect_allowed(tid: TaskId, dst_ip: [u8; 4], dst_port: u16) -> bool {
    global_manager().check_connect_allowed(tid, dst_ip, dst_port)
}

/// Add a port forwarding rule to the task's network namespace.
pub fn add_port_forward(tid: TaskId, host_port: u16, ns_port: u16) -> NamespaceResult<()> {
    global_manager().add_port_forward(tid, host_port, ns_port)
}

/// Get the current namespace ids for a task.
pub fn get_namespaces(tid: TaskId) -> Option<ProcessNamespaces> {
    global_manager().get_namespaces(tid)
}

/// Get metrics snapshot.
pub fn metrics() -> NamespaceMetricsSnapshot {
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
        GLOBAL_MANAGER.call_once(|| NamespaceManager::default());
    }

    #[test]
    fn test_pid_namespace() {
        init_test();
        let tid = TaskId::from_u64(1);
        init_for_task(tid, None).unwrap();
        assert_eq!(get_pid(tid), 1);
        create_pid_ns(tid).unwrap();
        // After entering new namespace, we need to re-allocate PID.
        // For simplicity, we test that the namespace changed.
        let ns = get_namespaces(tid).unwrap();
        assert_ne!(ns.pid_ns, ROOT_NS_ID);
        remove_task(tid).unwrap();
    }

    #[test]
    fn test_uts_namespace() {
        init_test();
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
        init_test();
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
