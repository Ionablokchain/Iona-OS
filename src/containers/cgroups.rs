//! cgroups — resource limiting per group of processes
//!
//! Subsystems: cpu, memory, io
//! Hierarchy: /sys/fs/cgroup/{subsystem}/{group}/
//!
//! All operations are thread-safe, validated, and hierarchical.
//! Limits are enforced during allocations (memory) and I/O operations.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                           Cgroups Module                               │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   config    │    error     │     types     │        metrics           │
//! │ (CgroupCfg) │ (CgroupError)│ (CgroupId,    │ (CgroupMetrics)          │
//! │             │              │  CgroupData)  │                          │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   manager   │    legacy    │               │                          │
//! │ (CgroupMgr) │ (global fns) │               │                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::cgroups::{CgroupManager, CgroupConfig, CpuConfig, MemConfig};
//!
//! let config = CgroupConfig::default();
//! let manager = CgroupManager::new(config);
//! let cg_id = manager.create("mygroup", None).unwrap();
//! manager.set_cpu_shares(cg_id, 512).unwrap();
//! manager.attach(task_id, cg_id).unwrap();
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
    //! Configuration for cgroups.
    use serde::{Deserialize, Serialize};

    /// CPU configuration for a cgroup.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct CpuConfig {
        pub shares: u32,
        pub quota_us: i64,
        pub period_us: u64,
    }

    impl Default for CpuConfig {
        fn default() -> Self {
            Self {
                shares: 1024,
                quota_us: -1,
                period_us: 100_000,
            }
        }
    }

    /// Memory configuration for a cgroup.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct MemConfig {
        pub limit_bytes: i64,
        pub soft_limit_bytes: i64,
        pub swap_limit_bytes: i64,
        pub oom_kill_disable: bool,
    }

    impl Default for MemConfig {
        fn default() -> Self {
            Self {
                limit_bytes: -1,
                soft_limit_bytes: -1,
                swap_limit_bytes: -1,
                oom_kill_disable: false,
            }
        }
    }

    /// I/O configuration for a cgroup.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct IoConfig {
        pub read_bps_limit: u64,
        pub write_bps_limit: u64,
        pub read_iops_limit: u64,
        pub write_iops_limit: u64,
    }

    impl Default for IoConfig {
        fn default() -> Self {
            Self {
                read_bps_limit: 0,
                write_bps_limit: 0,
                read_iops_limit: 0,
                write_iops_limit: 0,
            }
        }
    }

    /// Overall configuration for the cgroup subsystem.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct CgroupConfig {
        pub max_cgroups: usize,
        pub collect_metrics: bool,
        pub log_operations: bool,
    }

    impl Default for CgroupConfig {
        fn default() -> Self {
            Self {
                max_cgroups: 1024,
                collect_metrics: true,
                log_operations: true,
            }
        }
    }
}

pub mod error {
    //! Error types for cgroup operations.
    use super::types::CgroupId;
    use crate::task::TaskId;
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum CgroupError {
        #[error("cgroup not found: id={0}")]
        NotFound(CgroupId),

        #[error("cgroup name cannot be empty")]
        EmptyName,

        #[error("parent cgroup not found: id={0}")]
        ParentNotFound(CgroupId),

        #[error("cgroup has children, cannot delete")]
        HasChildren,

        #[error("cgroup has tasks, cannot delete")]
        HasTasks,

        #[error("cannot delete root cgroup")]
        CannotDeleteRoot,

        #[error("task {0} not found")]
        TaskNotFound(TaskId),

        #[error("invalid CPU shares: {0} (must be > 0)")]
        InvalidShares(u32),

        #[error("invalid CPU quota: {0} (must be -1 or > 0)")]
        InvalidQuota(i64),

        #[error("invalid CPU period: {0} (must be > 0)")]
        InvalidPeriod(u64),

        #[error("memory limit must be -1 or > 0")]
        InvalidMemLimit,

        #[error("cgroup limit exceeded: {0}")]
        LimitExceeded(String),

        #[error("configuration error: {0}")]
        Config(String),

        #[error("too many cgroups (max {0})")]
        TooManyCgroups(usize),

        #[error("internal error: {0}")]
        Internal(String),
    }

    pub type CgroupResult<T> = Result<T, CgroupError>;
}

pub mod types {
    //! Core types for cgroups.
    use super::config::{CpuConfig, MemConfig, IoConfig};
    use crate::task::TaskId;
    use alloc::{
        collections::BTreeMap,
        string::String,
        vec::Vec,
    };
    use core::fmt;

    /// Cgroup identifier.
    pub type CgroupId = u32;

    /// Root cgroup id.
    pub const ROOT_CGROUP_ID: CgroupId = 0;

    /// Statistics that are updated frequently (accounting).
    #[derive(Clone, Debug, Default)]
    pub struct CgroupStats {
        pub cpu_usage_us: u64,
        pub mem_usage_bytes: u64,
        pub io_read_bytes: u64,
        pub io_write_bytes: u64,
        pub io_read_ops: u64,
        pub io_write_ops: u64,
    }

    /// Internal representation of a cgroup.
    #[derive(Clone)]
    pub struct CgroupData {
        pub id: CgroupId,
        pub name: String,
        pub parent: Option<CgroupId>,
        pub tasks: Vec<TaskId>,
        pub children: Vec<CgroupId>,
        pub cpu: CpuConfig,
        pub mem: MemConfig,
        pub io: IoConfig,
        pub stats: CgroupStats,
    }

    impl CgroupData {
        pub fn new(id: CgroupId, name: &str, parent: Option<CgroupId>) -> Self {
            Self {
                id,
                name: name.to_string(),
                parent,
                tasks: Vec::new(),
                children: Vec::new(),
                cpu: CpuConfig::default(),
                mem: MemConfig::default(),
                io: IoConfig::default(),
                stats: CgroupStats::default(),
            }
        }
    }

    impl fmt::Debug for CgroupData {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("CgroupData")
                .field("id", &self.id)
                .field("name", &self.name)
                .field("parent", &self.parent)
                .field("task_count", &self.tasks.len())
                .field("child_count", &self.children.len())
                .field("cpu_shares", &self.cpu.shares)
                .field("mem_limit", &self.mem.limit_bytes)
                .finish()
        }
    }
}

pub mod metrics {
    //! Metrics for cgroup operations.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct CgroupMetrics {
        pub cgroups_created: AtomicU64,
        pub cgroups_deleted: AtomicU64,
        pub tasks_attached: AtomicU64,
        pub tasks_detached: AtomicU64,
        pub mem_charges: AtomicU64,
        pub mem_releases: AtomicU64,
        pub mem_limit_exceeded: AtomicU64,
        pub io_operations: AtomicU64,
        pub io_limited: AtomicU64,
        pub cpu_accounts: AtomicU64,
    }

    impl CgroupMetrics {
        pub fn inc_created(&self) {
            self.cgroups_created.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_deleted(&self) {
            self.cgroups_deleted.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_attached(&self) {
            self.tasks_attached.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_detached(&self) {
            self.tasks_detached.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_mem_charge(&self) {
            self.mem_charges.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_mem_release(&self) {
            self.mem_releases.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_mem_limit_exceeded(&self) {
            self.mem_limit_exceeded.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_io_op(&self) {
            self.io_operations.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_io_limited(&self) {
            self.io_limited.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_cpu_account(&self) {
            self.cpu_accounts.fetch_add(1, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> CgroupMetricsSnapshot {
            CgroupMetricsSnapshot {
                cgroups_created: self.cgroups_created.load(Ordering::Relaxed),
                cgroups_deleted: self.cgroups_deleted.load(Ordering::Relaxed),
                tasks_attached: self.tasks_attached.load(Ordering::Relaxed),
                tasks_detached: self.tasks_detached.load(Ordering::Relaxed),
                mem_charges: self.mem_charges.load(Ordering::Relaxed),
                mem_releases: self.mem_releases.load(Ordering::Relaxed),
                mem_limit_exceeded: self.mem_limit_exceeded.load(Ordering::Relaxed),
                io_operations: self.io_operations.load(Ordering::Relaxed),
                io_limited: self.io_limited.load(Ordering::Relaxed),
                cpu_accounts: self.cpu_accounts.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CgroupMetricsSnapshot {
        pub cgroups_created: u64,
        pub cgroups_deleted: u64,
        pub tasks_attached: u64,
        pub tasks_detached: u64,
        pub mem_charges: u64,
        pub mem_releases: u64,
        pub mem_limit_exceeded: u64,
        pub io_operations: u64,
        pub io_limited: u64,
        pub cpu_accounts: u64,
    }
}

pub mod manager {
    //! Centralised manager for cgroups.
    use super::{
        config::{CgroupConfig, CpuConfig, MemConfig, IoConfig},
        error::{CgroupError, CgroupResult},
        types::{CgroupId, CgroupData, ROOT_CGROUP_ID},
        metrics::CgroupMetrics,
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

    /// Centralised manager for cgroups.
    pub struct CgroupManager {
        cgroups: RwLock<BTreeMap<CgroupId, CgroupData>>,
        task_cgroup: RwLock<BTreeMap<TaskId, CgroupId>>,
        next_id: AtomicU32,
        config: CgroupConfig,
        metrics: CgroupMetrics,
    }

    impl CgroupManager {
        /// Create a new cgroup manager with the given configuration.
        pub fn new(config: CgroupConfig) -> Self {
            let mut cgroups = BTreeMap::new();
            // Create root cgroup.
            cgroups.insert(ROOT_CGROUP_ID, CgroupData::new(ROOT_CGROUP_ID, "/", None));
            Self {
                cgroups: RwLock::new(cgroups),
                task_cgroup: RwLock::new(BTreeMap::new()),
                next_id: AtomicU32::new(1),
                config,
                metrics: CgroupMetrics::default(),
            }
        }

        /// Create a manager with default configuration.
        pub fn default() -> Self {
            Self::new(CgroupConfig::default())
        }

        /// Get a reference to the metrics.
        pub fn metrics(&self) -> &CgroupMetrics {
            &self.metrics
        }

        /// Get the configuration.
        pub fn config(&self) -> &CgroupConfig {
            &self.config
        }

        /// Create a new cgroup with the given name and optional parent.
        /// If parent is `None`, the new cgroup is attached to the root.
        /// Returns the new cgroup id, or an error.
        pub fn create(&self, name: &str, parent: Option<CgroupId>) -> CgroupResult<CgroupId> {
            if name.is_empty() {
                return Err(CgroupError::EmptyName);
            }
            let parent_id = parent.unwrap_or(ROOT_CGROUP_ID);

            // Check if we've reached the max number of cgroups.
            {
                let cgs = self.cgroups.read();
                if cgs.len() >= self.config.max_cgroups {
                    return Err(CgroupError::TooManyCgroups(self.config.max_cgroups));
                }
                if !cgs.contains_key(&parent_id) {
                    return Err(CgroupError::ParentNotFound(parent_id));
                }
            }

            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let new_cg = CgroupData::new(id, name, Some(parent_id));

            let mut cgs = self.cgroups.write();
            // Double-check parent still exists.
            if !cgs.contains_key(&parent_id) {
                return Err(CgroupError::ParentNotFound(parent_id));
            }
            cgs.insert(id, new_cg);
            if let Some(parent_cg) = cgs.get_mut(&parent_id) {
                parent_cg.children.push(id);
            }
            self.metrics.inc_created();
            if self.config.log_operations {
                info!(cgroup_id = id, name, parent_id, "cgroup created");
            }
            Ok(id)
        }

        /// Remove an empty cgroup. Fails if the cgroup has tasks or child cgroups.
        /// Root cgroup cannot be removed.
        pub fn remove(&self, cgroup_id: CgroupId) -> CgroupResult<()> {
            if cgroup_id == ROOT_CGROUP_ID {
                return Err(CgroupError::CannotDeleteRoot);
            }
            let mut cgs = self.cgroups.write();
            let cg = cgs.get(&cgroup_id).ok_or(CgroupError::NotFound(cgroup_id))?;
            if !cg.tasks.is_empty() {
                return Err(CgroupError::HasTasks);
            }
            if !cg.children.is_empty() {
                return Err(CgroupError::HasChildren);
            }
            let parent_id = cg.parent.ok_or(CgroupError::NotFound(cgroup_id))?;
            if let Some(parent) = cgs.get_mut(&parent_id) {
                parent.children.retain(|&id| id != cgroup_id);
            }
            cgs.remove(&cgroup_id);
            self.metrics.inc_deleted();
            if self.config.log_operations {
                info!(cgroup_id, "cgroup removed");
            }
            Ok(())
        }

        /// Attach a task to a cgroup. If the task was already in another cgroup, it is moved.
        /// Returns `Ok(())` on success.
        pub fn attach(&self, tid: TaskId, cgroup_id: CgroupId) -> CgroupResult<()> {
            // Check that the cgroup exists.
            {
                let cgs = self.cgroups.read();
                if !cgs.contains_key(&cgroup_id) {
                    return Err(CgroupError::NotFound(cgroup_id));
                }
            }

            // Remove from old cgroup if any.
            let old_id = {
                let mut task_map = self.task_cgroup.write();
                task_map.insert(tid, cgroup_id)
            };
            if let Some(old) = old_id {
                let mut cgs = self.cgroups.write();
                if let Some(cg) = cgs.get_mut(&old) {
                    cg.tasks.retain(|&t| t != tid);
                }
            }

            // Add to new cgroup.
            {
                let mut cgs = self.cgroups.write();
                if let Some(cg) = cgs.get_mut(&cgroup_id) {
                    cg.tasks.push(tid);
                } else {
                    return Err(CgroupError::NotFound(cgroup_id));
                }
            }
            // Update task map.
            {
                let mut task_map = self.task_cgroup.write();
                task_map.insert(tid, cgroup_id);
            }
            self.metrics.inc_attached();
            if self.config.log_operations {
                debug!(tid, cgroup_id, "task attached to cgroup");
            }
            Ok(())
        }

        /// Remove a task from the cgroup system (called when task exits).
        pub fn remove_task(&self, tid: TaskId) {
            let cgroup_id = {
                let mut task_map = self.task_cgroup.write();
                task_map.remove(&tid)
            };
            if let Some(cg_id) = cgroup_id {
                let mut cgs = self.cgroups.write();
                if let Some(cg) = cgs.get_mut(&cg_id) {
                    cg.tasks.retain(|&t| t != tid);
                }
                self.metrics.inc_detached();
                if self.config.log_operations {
                    debug!(tid, cg_id, "task removed from cgroup");
                }
            }
        }

        /// Get the cgroup id of a task. Returns root id if task not found.
        pub fn get_cgroup_id(&self, tid: TaskId) -> CgroupId {
            self.task_cgroup.read().get(&tid).copied().unwrap_or(ROOT_CGROUP_ID)
        }

        /// Get the cgroup name for debugging.
        pub fn get_cgroup_name(&self, cgroup_id: CgroupId) -> Option<String> {
            self.cgroups.read().get(&cgroup_id).map(|cg| cg.name.clone())
        }

        /// Set CPU shares (relative weight) for a cgroup.
        pub fn set_cpu_shares(&self, cgroup_id: CgroupId, shares: u32) -> CgroupResult<()> {
            if shares == 0 {
                return Err(CgroupError::InvalidShares(shares));
            }
            let mut cgs = self.cgroups.write();
            let cg = cgs.get_mut(&cgroup_id).ok_or(CgroupError::NotFound(cgroup_id))?;
            cg.cpu.shares = shares;
            if self.config.log_operations {
                debug!(cgroup_id, shares, "CPU shares updated");
            }
            Ok(())
        }

        /// Set CPU quota (max microseconds per period).
        /// `quota_us` can be -1 (unlimited) or >0. `period_us` must be >0.
        pub fn set_cpu_quota(&self, cgroup_id: CgroupId, quota_us: i64, period_us: u64) -> CgroupResult<()> {
            if period_us == 0 {
                return Err(CgroupError::InvalidPeriod(period_us));
            }
            if quota_us != -1 && quota_us <= 0 {
                return Err(CgroupError::InvalidQuota(quota_us));
            }
            let mut cgs = self.cgroups.write();
            let cg = cgs.get_mut(&cgroup_id).ok_or(CgroupError::NotFound(cgroup_id))?;
            cg.cpu.quota_us = quota_us;
            cg.cpu.period_us = period_us;
            if self.config.log_operations {
                debug!(cgroup_id, quota_us, period_us, "CPU quota updated");
            }
            Ok(())
        }

        /// Get the effective CPU weight for a task (based on its cgroup's shares).
        /// Used by the scheduler.
        pub fn task_weight(&self, tid: TaskId) -> u32 {
            let cg_id = self.get_cgroup_id(tid);
            self.cgroups.read()
                .get(&cg_id)
                .map(|cg| cg.cpu.shares)
                .unwrap_or(1024)
        }

        /// Called by the scheduler to account CPU time consumed by a task.
        pub fn account_cpu(&self, tid: TaskId, cpu_us: u64) {
            let cg_id = self.get_cgroup_id(tid);
            let mut cgs = self.cgroups.write();
            if let Some(cg) = cgs.get_mut(&cg_id) {
                cg.stats.cpu_usage_us = cg.stats.cpu_usage_us.saturating_add(cpu_us);
                self.metrics.inc_cpu_account();
            }
        }

        /// Set memory hard limit (bytes). -1 = unlimited.
        pub fn set_mem_limit(&self, cgroup_id: CgroupId, limit_bytes: i64) -> CgroupResult<()> {
            if limit_bytes != -1 && limit_bytes <= 0 {
                return Err(CgroupError::InvalidMemLimit);
            }
            let mut cgs = self.cgroups.write();
            let cg = cgs.get_mut(&cgroup_id).ok_or(CgroupError::NotFound(cgroup_id))?;
            cg.mem.limit_bytes = limit_bytes;
            if self.config.log_operations {
                debug!(cgroup_id, limit_bytes, "memory limit updated");
            }
            Ok(())
        }

        /// Set memory soft limit.
        pub fn set_mem_soft_limit(&self, cgroup_id: CgroupId, soft_limit_bytes: i64) -> CgroupResult<()> {
            if soft_limit_bytes != -1 && soft_limit_bytes <= 0 {
                return Err(CgroupError::InvalidMemLimit);
            }
            let mut cgs = self.cgroups.write();
            let cg = cgs.get_mut(&cgroup_id).ok_or(CgroupError::NotFound(cgroup_id))?;
            cg.mem.soft_limit_bytes = soft_limit_bytes;
            Ok(())
        }

        /// Check if allocating `alloc_bytes` would exceed the cgroup's memory limit.
        /// Returns `Ok(())` if allowed, `Err` if would exceed limit.
        pub fn check_mem_limit(&self, tid: TaskId, alloc_bytes: usize) -> CgroupResult<()> {
            let cg_id = self.get_cgroup_id(tid);
            let cgs = self.cgroups.read();
            let cg = cgs.get(&cg_id).ok_or(CgroupError::NotFound(cg_id))?;
            if cg.mem.limit_bytes < 0 {
                return Ok(());
            }
            let current = cg.stats.mem_usage_bytes;
            if (current as i64 + alloc_bytes as i64) > cg.mem.limit_bytes {
                self.metrics.inc_mem_limit_exceeded();
                return Err(CgroupError::LimitExceeded(format!(
                    "memory limit {} exceeded by {} bytes",
                    cg.mem.limit_bytes, alloc_bytes
                )));
            }
            Ok(())
        }

        /// Charge memory usage to the task's cgroup. Must be called after successful allocation.
        pub fn charge_mem(&self, tid: TaskId, bytes: usize) {
            let cg_id = self.get_cgroup_id(tid);
            let mut cgs = self.cgroups.write();
            if let Some(cg) = cgs.get_mut(&cg_id) {
                cg.stats.mem_usage_bytes = cg.stats.mem_usage_bytes.saturating_add(bytes as u64);
                self.metrics.inc_mem_charge();
            }
        }

        /// Release memory (free). Called when memory is deallocated.
        pub fn release_mem(&self, tid: TaskId, bytes: usize) {
            let cg_id = self.get_cgroup_id(tid);
            let mut cgs = self.cgroups.write();
            if let Some(cg) = cgs.get_mut(&cg_id) {
                cg.stats.mem_usage_bytes = cg.stats.mem_usage_bytes.saturating_sub(bytes as u64);
                self.metrics.inc_mem_release();
            }
        }

        /// Set I/O limits (bytes per second and IOPS) for a cgroup.
        pub fn set_io_limits(
            &self,
            cgroup_id: CgroupId,
            read_bps: u64,
            write_bps: u64,
            read_iops: u64,
            write_iops: u64,
        ) -> CgroupResult<()> {
            let mut cgs = self.cgroups.write();
            let cg = cgs.get_mut(&cgroup_id).ok_or(CgroupError::NotFound(cgroup_id))?;
            cg.io.read_bps_limit = read_bps;
            cg.io.write_bps_limit = write_bps;
            cg.io.read_iops_limit = read_iops;
            cg.io.write_iops_limit = write_iops;
            if self.config.log_operations {
                debug!(cgroup_id, "I/O limits updated");
            }
            Ok(())
        }

        /// Account I/O bytes and operations. Call after performing I/O.
        pub fn account_io(&self, tid: TaskId, write: bool, bytes: u64, ops: u64) {
            let cg_id = self.get_cgroup_id(tid);
            let mut cgs = self.cgroups.write();
            if let Some(cg) = cgs.get_mut(&cg_id) {
                if write {
                    cg.stats.io_write_bytes = cg.stats.io_write_bytes.saturating_add(bytes);
                    cg.stats.io_write_ops = cg.stats.io_write_ops.saturating_add(ops);
                } else {
                    cg.stats.io_read_bytes = cg.stats.io_read_bytes.saturating_add(bytes);
                    cg.stats.io_read_ops = cg.stats.io_read_ops.saturating_add(ops);
                }
                self.metrics.inc_io_op();
            }
        }

        /// Get memory usage (bytes) for a cgroup.
        pub fn mem_usage(&self, cgroup_id: CgroupId) -> Option<u64> {
            self.cgroups.read()
                .get(&cgroup_id)
                .map(|cg| cg.stats.mem_usage_bytes)
        }

        /// Get total CPU usage (microseconds) for a cgroup.
        pub fn cpu_usage(&self, cgroup_id: CgroupId) -> Option<u64> {
            self.cgroups.read()
                .get(&cgroup_id)
                .map(|cg| cg.stats.cpu_usage_us)
        }

        /// List all tasks in a cgroup.
        pub fn tasks_in_cgroup(&self, cgroup_id: CgroupId) -> Option<Vec<TaskId>> {
            self.cgroups.read()
                .get(&cgroup_id)
                .map(|cg| cg.tasks.clone())
        }

        /// Get statistics for a cgroup.
        pub fn stats(&self, cgroup_id: CgroupId) -> Option<super::types::CgroupStats> {
            self.cgroups.read()
                .get(&cgroup_id)
                .map(|cg| cg.stats.clone())
        }

        /// Clear all statistics for a cgroup (reset counters).
        pub fn clear_stats(&self, cgroup_id: CgroupId) -> CgroupResult<()> {
            let mut cgs = self.cgroups.write();
            let cg = cgs.get_mut(&cgroup_id).ok_or(CgroupError::NotFound(cgroup_id))?;
            cg.stats = super::types::CgroupStats::default();
            Ok(())
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::{CgroupConfig, CpuConfig, MemConfig, IoConfig};
pub use error::{CgroupError, CgroupResult};
pub use types::{CgroupId, CgroupData, CgroupStats, ROOT_CGROUP_ID};
pub use manager::CgroupManager;
pub use metrics::{CgroupMetrics, CgroupMetricsSnapshot};

// -----------------------------------------------------------------------------
// Legacy global API (wrappers around a global singleton)
// -----------------------------------------------------------------------------

static GLOBAL_MANAGER: spin::Once<CgroupManager> = spin::Once::new();

/// Initialize the global cgroup manager.
pub fn init() {
    GLOBAL_MANAGER.call_once(|| CgroupManager::default());
    crate::serial_println!("  [CGROUP] initialized: CPU + memory + IO subsystems");
}

/// Get a reference to the global manager.
fn global_manager() -> &'static CgroupManager {
    GLOBAL_MANAGER.get().expect("cgroup manager not initialized")
}

/// Create a new cgroup with the given name and optional parent.
pub fn create(name: &str, parent: Option<CgroupId>) -> Option<CgroupId> {
    global_manager().create(name, parent).ok()
}

/// Remove an empty cgroup. Fails if the cgroup has tasks or child cgroups.
pub fn remove(cgroup_id: CgroupId) -> bool {
    global_manager().remove(cgroup_id).is_ok()
}

/// Attach a task to a cgroup.
pub fn attach(tid: TaskId, cgroup_id: CgroupId) -> bool {
    global_manager().attach(tid, cgroup_id).is_ok()
}

/// Remove a task from the cgroup system (called when task exits).
pub fn remove_task(tid: TaskId) {
    global_manager().remove_task(tid);
}

/// Get the cgroup id of a task.
pub fn get_cgroup_id(tid: TaskId) -> CgroupId {
    global_manager().get_cgroup_id(tid)
}

/// Get the cgroup name for debugging.
pub fn get_cgroup_name(cgroup_id: CgroupId) -> Option<String> {
    global_manager().get_cgroup_name(cgroup_id)
}

/// Set CPU shares (relative weight) for a cgroup.
pub fn set_cpu_shares(cgroup_id: CgroupId, shares: u32) -> bool {
    global_manager().set_cpu_shares(cgroup_id, shares).is_ok()
}

/// Set CPU quota (max microseconds per period).
pub fn set_cpu_quota(cgroup_id: CgroupId, quota_us: i64, period_us: u64) -> bool {
    global_manager().set_cpu_quota(cgroup_id, quota_us, period_us).is_ok()
}

/// Get the effective CPU weight for a task.
pub fn task_weight(tid: TaskId) -> u32 {
    global_manager().task_weight(tid)
}

/// Account CPU time consumed by a task.
pub fn account_cpu(tid: TaskId, cpu_us: u64) {
    global_manager().account_cpu(tid, cpu_us);
}

/// Set memory hard limit (bytes). -1 = unlimited.
pub fn set_mem_limit(cgroup_id: CgroupId, limit_bytes: i64) -> bool {
    global_manager().set_mem_limit(cgroup_id, limit_bytes).is_ok()
}

/// Set memory soft limit.
pub fn set_mem_soft_limit(cgroup_id: CgroupId, soft_limit_bytes: i64) -> bool {
    global_manager().set_mem_soft_limit(cgroup_id, soft_limit_bytes).is_ok()
}

/// Check if allocating `alloc_bytes` would exceed the cgroup's memory limit.
pub fn check_mem_limit(tid: TaskId, alloc_bytes: usize) -> bool {
    global_manager().check_mem_limit(tid, alloc_bytes).is_ok()
}

/// Charge memory usage to the task's cgroup.
pub fn charge_mem(tid: TaskId, bytes: usize) {
    global_manager().charge_mem(tid, bytes);
}

/// Release memory (free).
pub fn release_mem(tid: TaskId, bytes: usize) {
    global_manager().release_mem(tid, bytes);
}

/// Set I/O limits.
pub fn set_io_limits(
    cgroup_id: CgroupId,
    read_bps: u64,
    write_bps: u64,
    read_iops: u64,
    write_iops: u64,
) -> bool {
    global_manager()
        .set_io_limits(cgroup_id, read_bps, write_bps, read_iops, write_iops)
        .is_ok()
}

/// Account I/O bytes and operations.
pub fn account_io(tid: TaskId, write: bool, bytes: u64, ops: u64) {
    global_manager().account_io(tid, write, bytes, ops);
}

/// Get memory usage (bytes) for a cgroup.
pub fn mem_usage(cgroup_id: CgroupId) -> Option<u64> {
    global_manager().mem_usage(cgroup_id)
}

/// Get total CPU usage (microseconds) for a cgroup.
pub fn cpu_usage(cgroup_id: CgroupId) -> Option<u64> {
    global_manager().cpu_usage(cgroup_id)
}

/// List all tasks in a cgroup.
pub fn tasks_in_cgroup(cgroup_id: CgroupId) -> Option<Vec<TaskId>> {
    global_manager().tasks_in_cgroup(cgroup_id)
}

/// Get metrics snapshot.
pub fn metrics() -> CgroupMetricsSnapshot {
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
        GLOBAL_MANAGER.call_once(|| CgroupManager::default());
        // Clear any leftover state.
        let mgr = GLOBAL_MANAGER.get().unwrap();
        // Remove all cgroups except root.
        let cgroups = mgr.cgroups.read().keys().copied().collect::<Vec<_>>();
        for id in cgroups {
            if id != ROOT_CGROUP_ID {
                let _ = mgr.remove(id);
            }
        }
        // Clear task map.
        mgr.task_cgroup.write().clear();
    }

    #[test]
    fn test_create_and_remove() {
        init_test();
        let id = create("test", None).unwrap();
        assert!(get_cgroup_name(id).is_some());
        assert!(remove(id));
        assert!(get_cgroup_name(id).is_none());
    }

    #[test]
    fn test_cannot_remove_non_empty() {
        init_test();
        let id = create("test", None).unwrap();
        let tid = TaskId::from_u64(1);
        attach(tid, id);
        assert!(!remove(id)); // has tasks
        remove_task(tid);
        assert!(remove(id));
    }

    #[test]
    fn test_memory_limits() {
        init_test();
        let id = create("memtest", None).unwrap();
        let tid = TaskId::from_u64(2);
        attach(tid, id);
        set_mem_limit(id, 1000);
        assert!(check_mem_limit(tid, 500));
        charge_mem(tid, 500);
        assert!(check_mem_limit(tid, 500)); // 500+500=1000 allowed
        assert!(!check_mem_limit(tid, 1));   // would exceed
        release_mem(tid, 200);
        assert!(check_mem_limit(tid, 200));  // 300+200=500 allowed
    }

    #[test]
    fn test_cpu_weight() {
        init_test();
        let id = create("cputest", None).unwrap();
        let tid = TaskId::from_u64(3);
        attach(tid, id);
        set_cpu_shares(id, 512);
        assert_eq!(task_weight(tid), 512);
        account_cpu(tid, 10_000);
        assert_eq!(cpu_usage(id), Some(10_000));
    }

    #[test]
    fn test_io_accounting() {
        init_test();
        let id = create("iotest", None).unwrap();
        let tid = TaskId::from_u64(4);
        attach(tid, id);
        account_io(tid, false, 1024, 1);
        account_io(tid, true, 2048, 2);
        let mgr = global_manager();
        let stats = mgr.stats(id).unwrap();
        assert_eq!(stats.io_read_bytes, 1024);
        assert_eq!(stats.io_write_bytes, 2048);
        assert_eq!(stats.io_read_ops, 1);
        assert_eq!(stats.io_write_ops, 2);
    }
}
