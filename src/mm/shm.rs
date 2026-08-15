//! Shared Memory — IPC via physical pages shared between processes.
//!
//! This module implements System V shared memory (shmget, shmat, shmdt, shmctl)
//! for inter‑process communication. The same physical pages are mapped into
//! multiple address spaces.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                         Shared Memory Module                           │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   config    │    error     │    metrics    │         types            │
//! │ (ShmCfg)    │ (ShmError)   │ (ShmMetrics)  │ (Segment, Perm, Stats)   │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │    table    │   manager    │    legacy     │                          │
//! │ (registry)  │ (ShmManager) │ (global fns)  │                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::ipc::shm::{ShmManager, ShmConfig};
//!
//! let config = ShmConfig::default();
//! let manager = ShmManager::new(config);
//! let key = manager.shmget(0x1234, 4096, IPC_CREAT | SHM_R | SHM_W, pid)?;
//! let addr = manager.shmat(key, 0, 0, pid)?;
//! // write to shared memory
//! manager.shmdt(addr, pid)?;
//! ```

#![allow(dead_code)]

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::{Mutex, RwLock};
use x86_64::PhysAddr;
use tracing::{debug, info, trace, warn};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod constants {
    //! Constants for System V shared memory.

    /// Create a new segment if it does not already exist.
    pub const IPC_CREAT: u32 = 0o1000;

    /// Exclusive create (fails if segment already exists).
    pub const IPC_EXCL: u32 = 0o2000;

    /// Private segment (key is ignored, kernel allocates a unique key).
    pub const IPC_PRIVATE: u64 = 0;

    /// Remove the segment (used with shmctl).
    pub const IPC_RMID: u32 = 0;

    /// Get statistics (used with shmctl).
    pub const IPC_STAT: u32 = 1;

    /// Set permissions (used with shmctl).
    pub const IPC_SET: u32 = 2;

    /// Read permission.
    pub const SHM_R: u32 = 0o400;

    /// Write permission.
    pub const SHM_W: u32 = 0o200;

    /// Lock segment in memory (no swap).
    pub const SHM_LOCK: u32 = 3;

    /// Unlock segment (allow swap).
    pub const SHM_UNLOCK: u32 = 4;

    /// Map read‑only.
    pub const SHM_RDONLY: u32 = 0o10000;

    /// Map as remote (NUMA hint).
    pub const SHM_REMAP: u32 = 0o20000;

    /// Default maximum segment size (64 MiB).
    pub const SHMMAX: usize = 64 * 1024 * 1024;

    /// Default maximum segments per process.
    pub const SHMSEG_MAX: usize = 32;
}

pub mod config {
    //! Configuration for the shared memory subsystem.
    use serde::{Deserialize, Serialize};
    use super::constants::{SHMMAX, SHMSEG_MAX};

    /// Configuration for shared memory.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ShmConfig {
        pub max_segment_size: usize,
        pub max_segments_per_process: usize,
        pub collect_metrics: bool,
        pub log_operations: bool,
        pub default_perm_mode: u32,
    }

    impl Default for ShmConfig {
        fn default() -> Self {
            Self {
                max_segment_size: SHMMAX,
                max_segments_per_process: SHMSEG_MAX,
                collect_metrics: true,
                log_operations: false,
                default_perm_mode: super::constants::SHM_R | super::constants::SHM_W,
            }
        }
    }

    impl ShmConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.max_segment_size == 0 {
                return Err("max_segment_size must be > 0");
            }
            if self.max_segments_per_process == 0 {
                return Err("max_segments_per_process must be > 0");
            }
            Ok(())
        }

        pub fn with_metrics(mut self) -> Self {
            self.collect_metrics = true;
            self
        }
    }
}

pub mod error {
    //! Error types for shared memory operations.
    use super::types::{Key, Address};
    use crate::task::Pid;
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum ShmError {
        #[error("segment not found for key {key}")]
        NotFound { key: Key },

        #[error("segment already exists for key {key} (IPC_EXCL)")]
        AlreadyExists { key: Key },

        #[error("segment size {size} exceeds maximum {max}")]
        SizeTooLarge { size: usize, max: usize },

        #[error("zero size segment not allowed")]
        ZeroSize,

        #[error("out of memory: failed to allocate physical frames")]
        OutOfMemory,

        #[error("permission denied: insufficient access rights")]
        PermissionDenied,

        #[error("too many segments attached to process {pid} (max {max})")]
        TooManyAttachments { pid: Pid, max: usize },

        #[error("invalid address 0x{addr:x}")]
        InvalidAddress { addr: Address },

        #[error("invalid command {cmd}")]
        InvalidCommand { cmd: u32 },

        #[error("configuration error: {0}")]
        Config(String),
    }

    pub type ShmResult<T> = Result<T, ShmError>;
}

pub mod types {
    //! Core types for shared memory.
    use super::constants::{SHM_R, SHM_W};
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU32, Ordering};
    use core::fmt;

    /// Shared memory key.
    pub type Key = u64;

    /// Virtual address.
    pub type Address = u64;

    /// Permission flags for a shared memory segment.
    #[derive(Debug, Clone, Copy)]
    pub struct ShmPerm {
        pub uid: u32,
        pub gid: u32,
        pub cuid: u32,
        pub cgid: u32,
        pub mode: u32,
    }

    impl Default for ShmPerm {
        fn default() -> Self {
            Self {
                uid: 0,
                gid: 0,
                cuid: 0,
                cgid: 0,
                mode: SHM_R | SHM_W,
            }
        }
    }

    /// A shared memory segment.
    #[derive(Debug)]
    pub struct ShmSegment {
        pub key: Key,
        pub size: usize,
        pub phys_frames: Vec<u64>,
        pub ref_count: AtomicU32,
        pub perm: ShmPerm,
        pub flags: u32,
        pub creator_pid: u32,
        pub last_attach_pid: u32,
        pub last_detach_pid: u32,
        pub attach_time: u64,
        pub detach_time: u64,
        pub mod_time: u64,
        pub locked: bool,
    }

    impl ShmSegment {
        pub fn is_attached(&self) -> bool {
            self.ref_count.load(Ordering::Relaxed) > 0
        }

        pub fn attach_count(&self) -> u32 {
            self.ref_count.load(Ordering::Relaxed)
        }

        pub fn page_count(&self) -> usize {
            self.phys_frames.len()
        }
    }

    impl Clone for ShmSegment {
        fn clone(&self) -> Self {
            Self {
                key: self.key,
                size: self.size,
                phys_frames: self.phys_frames.clone(),
                ref_count: AtomicU32::new(self.ref_count.load(Ordering::Relaxed)),
                perm: self.perm,
                flags: self.flags,
                creator_pid: self.creator_pid,
                last_attach_pid: self.last_attach_pid,
                last_detach_pid: self.last_detach_pid,
                attach_time: self.attach_time,
                detach_time: self.detach_time,
                mod_time: self.mod_time,
                locked: self.locked,
            }
        }
    }

    /// Per‑process attachment record.
    #[derive(Debug, Clone)]
    pub struct ProcessAttachment {
        pub key: Key,
        pub virt_addr: Address,
        pub flags: u32,
    }

    /// Shared memory statistics.
    #[derive(Debug, Default)]
    pub struct ShmStats {
        pub active_segments: usize,
        pub total_bytes: usize,
        pub used_bytes: usize,
        pub attached_processes: usize,
    }

    impl ShmStats {
        pub fn summary(&self) -> alloc::string::String {
            alloc::format!(
                "SHM: {} segments, {:.2} MiB total, {:.2} MiB used, {} processes attached",
                self.active_segments,
                self.total_bytes as f64 / 1024.0 / 1024.0,
                self.used_bytes as f64 / 1024.0 / 1024.0,
                self.attached_processes
            )
        }
    }
}

pub mod metrics {
    //! Metrics for shared memory operations.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct ShmMetrics {
        pub segments_created: AtomicU64,
        pub segments_removed: AtomicU64,
        pub attaches: AtomicU64,
        pub detaches: AtomicU64,
        pub oom_events: AtomicU64,
        pub permission_denied: AtomicU64,
        pub not_found: AtomicU64,
        pub total_bytes_allocated: AtomicU64,
    }

    impl ShmMetrics {
        pub fn inc_created(&self, bytes: usize) {
            self.segments_created.fetch_add(1, Ordering::Relaxed);
            self.total_bytes_allocated.fetch_add(bytes as u64, Ordering::Relaxed);
        }
        pub fn inc_removed(&self) {
            self.segments_removed.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_attach(&self) {
            self.attaches.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_detach(&self) {
            self.detaches.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_oom(&self) {
            self.oom_events.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_permission_denied(&self) {
            self.permission_denied.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_not_found(&self) {
            self.not_found.fetch_add(1, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> ShmMetricsSnapshot {
            ShmMetricsSnapshot {
                segments_created: self.segments_created.load(Ordering::Relaxed),
                segments_removed: self.segments_removed.load(Ordering::Relaxed),
                attaches: self.attaches.load(Ordering::Relaxed),
                detaches: self.detaches.load(Ordering::Relaxed),
                oom_events: self.oom_events.load(Ordering::Relaxed),
                permission_denied: self.permission_denied.load(Ordering::Relaxed),
                not_found: self.not_found.load(Ordering::Relaxed),
                total_bytes_allocated: self.total_bytes_allocated.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ShmMetricsSnapshot {
        pub segments_created: u64,
        pub segments_removed: u64,
        pub attaches: u64,
        pub detaches: u64,
        pub oom_events: u64,
        pub permission_denied: u64,
        pub not_found: u64,
        pub total_bytes_allocated: u64,
    }
}

pub mod table {
    //! Global shared memory segment registry.
    use super::{
        config::ShmConfig,
        error::{ShmError, ShmResult},
        types::{Key, ShmSegment, ProcessAttachment},
        metrics::ShmMetrics,
    };
    use crate::task::Pid;
    use alloc::collections::BTreeMap;
    use spin::RwLock;
    use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

    /// Global segment table.
    static SEGMENT_TABLE: RwLock<BTreeMap<Key, ShmSegment>> = RwLock::new(BTreeMap::new());

    /// Per‑process attachment table.
    static ATTACHMENT_TABLE: RwLock<BTreeMap<Pid, Vec<ProcessAttachment>>> = RwLock::new(BTreeMap::new());

    /// Insert a segment.
    pub fn insert_segment(seg: ShmSegment) -> ShmResult<()> {
        let mut table = SEGMENT_TABLE.write();
        if table.contains_key(&seg.key) {
            return Err(ShmError::AlreadyExists { key: seg.key });
        }
        table.insert(seg.key, seg);
        Ok(())
    }

    /// Get a segment by key (read-only).
    pub fn get_segment(key: Key) -> Option<ShmSegment> {
        SEGMENT_TABLE.read().get(&key).cloned()
    }

    /// Get a segment mutably.
    pub fn get_segment_mut(key: Key) -> Option<ShmSegment> {
        SEGMENT_TABLE.write().get(&key).cloned()
    }

    /// Remove a segment.
    pub fn remove_segment(key: Key) -> Option<ShmSegment> {
        SEGMENT_TABLE.write().remove(&key)
    }

    /// Check if a segment exists.
    pub fn exists(key: Key) -> bool {
        SEGMENT_TABLE.read().contains_key(&key)
    }

    /// Iterate over all segments.
    pub fn iter_segments<F>(f: F) where F: FnMut(&ShmSegment) {
        let table = SEGMENT_TABLE.read();
        for seg in table.values() {
            f(seg);
        }
    }

    /// Add an attachment for a process.
    pub fn add_attachment(pid: Pid, attachment: ProcessAttachment, config: &ShmConfig) -> ShmResult<()> {
        let mut table = ATTACHMENT_TABLE.write();
        let entries = table.entry(pid).or_default();
        if entries.len() >= config.max_segments_per_process {
            return Err(ShmError::TooManyAttachments {
                pid,
                max: config.max_segments_per_process,
            });
        }
        entries.push(attachment);
        Ok(())
    }

    /// Remove an attachment for a process by virtual address.
    pub fn remove_attachment(pid: Pid, addr: u64) -> Option<ProcessAttachment> {
        let mut table = ATTACHMENT_TABLE.write();
        let entries = table.get_mut(&pid)?;
        let pos = entries.iter().position(|a| a.virt_addr == addr)?;
        Some(entries.remove(pos))
    }

    /// Get all attachments for a process.
    pub fn get_attachments(pid: Pid) -> Vec<ProcessAttachment> {
        ATTACHMENT_TABLE.read().get(&pid).cloned().unwrap_or_default()
    }

    /// Clear all attachments for a process.
    pub fn clear_attachments(pid: Pid) -> Vec<ProcessAttachment> {
        ATTACHMENT_TABLE.write().remove(&pid).unwrap_or_default()
    }

    /// Get number of active segments.
    pub fn segment_count() -> usize {
        SEGMENT_TABLE.read().len()
    }

    /// Get total bytes used.
    pub fn total_bytes() -> usize {
        let table = SEGMENT_TABLE.read();
        table.values().map(|s| s.size).sum()
    }

    /// Get used bytes (attached segments).
    pub fn used_bytes() -> usize {
        let table = SEGMENT_TABLE.read();
        table.values().filter(|s| s.is_attached()).map(|s| s.size).sum()
    }

    /// Get attached process count.
    pub fn attached_process_count() -> usize {
        let table = SEGMENT_TABLE.read();
        table.values().map(|s| s.attach_count() as usize).sum()
    }

    /// Stats snapshot.
    pub fn stats() -> super::types::ShmStats {
        super::types::ShmStats {
            active_segments: segment_count(),
            total_bytes: total_bytes(),
            used_bytes: used_bytes(),
            attached_processes: attached_process_count(),
        }
    }
}

pub mod manager {
    //! Centralised manager for shared memory.
    use super::{
        config::ShmConfig,
        constants::{IPC_CREAT, IPC_EXCL, IPC_PRIVATE, IPC_RMID, IPC_STAT, IPC_SET, SHM_LOCK, SHM_UNLOCK, SHM_R, SHM_W, SHM_RDONLY},
        error::{ShmError, ShmResult},
        metrics::ShmMetrics,
        types::{Key, Address, ShmPerm, ShmSegment, ProcessAttachment, ShmStats},
        table,
    };
    use crate::task::Pid;
    use crate::memory::frame_alloc::{allocate_one, deallocate, FRAME_SIZE};
    use x86_64::structures::paging::PhysFrame;
    use x86_64::PhysAddr;
    use core::sync::atomic::Ordering;
    use tracing::{debug, info, trace, warn};

    /// Centralised manager for shared memory.
    pub struct ShmManager {
        config: ShmConfig,
        metrics: ShmMetrics,
        private_key_base: AtomicU64,
    }

    impl ShmManager {
        pub fn new(config: ShmConfig) -> Self {
            config.validate().expect("invalid ShmConfig");
            Self {
                config,
                metrics: ShmMetrics::default(),
                private_key_base: AtomicU64::new(0x8000_0000_0000_0000),
            }
        }

        pub fn default() -> Self {
            Self::new(ShmConfig::default())
        }

        pub fn config(&self) -> &ShmConfig {
            &self.config
        }

        pub fn metrics(&self) -> &ShmMetrics {
            &self.metrics
        }

        // ---------------------------------------------------------------------
        // Public API
        // ---------------------------------------------------------------------

        /// Create or access a shared memory segment (shmget).
        pub fn shmget(&self, key: Key, size: usize, flags: u32, pid: Pid) -> ShmResult<Key> {
            if size == 0 {
                return Err(ShmError::ZeroSize);
            }
            if size > self.config.max_segment_size {
                return Err(ShmError::SizeTooLarge {
                    size,
                    max: self.config.max_segment_size,
                });
            }

            let page_size = FRAME_SIZE;
            let aligned_size = (size + page_size - 1) & !(page_size - 1);
            let page_count = aligned_size / page_size;

            // Check if segment already exists
            if let Some(seg) = table::get_segment(key) {
                if flags & IPC_EXCL != 0 {
                    self.metrics.inc_permission_denied();
                    return Err(ShmError::AlreadyExists { key });
                }
                if seg.size < aligned_size {
                    return Err(ShmError::SizeTooLarge {
                        size: aligned_size,
                        max: seg.size,
                    });
                }
                if self.config.log_operations {
                    debug!(key, size, "shmget: existing segment found");
                }
                return Ok(key);
            }

            // Create new segment
            if flags & IPC_CREAT == 0 && key != IPC_PRIVATE {
                self.metrics.inc_not_found();
                return Err(ShmError::NotFound { key });
            }

            // Allocate physical frames
            let mut phys_frames = Vec::with_capacity(page_count);
            for _ in 0..page_count {
                match allocate_one() {
                    Some(frame) => {
                        let frame_phys = frame.start_address().as_u64();
                        phys_frames.push(frame_phys);
                    }
                    None => {
                        // Free already allocated frames
                        for &p in &phys_frames {
                            let frame = PhysFrame::from_start_address(PhysAddr::new(p)).unwrap();
                            deallocate(frame);
                        }
                        self.metrics.inc_oom();
                        return Err(ShmError::OutOfMemory);
                    }
                }
            }

            let segment_key = if key == IPC_PRIVATE {
                self.private_key_base.fetch_add(1, Ordering::Relaxed)
            } else {
                key
            };

            let perm = ShmPerm {
                mode: flags & (SHM_R | SHM_W),
                ..Default::default()
            };

            let seg = ShmSegment {
                key: segment_key,
                size: aligned_size,
                phys_frames,
                ref_count: core::sync::atomic::AtomicU32::new(0),
                perm,
                flags,
                creator_pid: pid,
                last_attach_pid: 0,
                last_detach_pid: 0,
                attach_time: 0,
                detach_time: 0,
                mod_time: crate::arch::x86_64::timer::uptime_ms(),
                locked: false,
            };

            table::insert_segment(seg)?;
            self.metrics.inc_created(aligned_size);

            if self.config.log_operations {
                info!(
                    key = segment_key,
                    size = aligned_size,
                    pages = page_count,
                    "shmget: created new segment"
                );
            }
            Ok(segment_key)
        }

        /// Attach a shared memory segment (shmat).
        pub fn shmat(&self, key: Key, virt_addr: Address, flags: u32, pid: Pid) -> ShmResult<Address> {
            let mut seg = table::get_segment(key).ok_or(ShmError::NotFound { key })?;

            // Check permissions
            let need_read = true;
            let need_write = (flags & SHM_RDONLY) == 0;
            if need_read && (seg.perm.mode & SHM_R) == 0 {
                self.metrics.inc_permission_denied();
                return Err(ShmError::PermissionDenied);
            }
            if need_write && (seg.perm.mode & SHM_W) == 0 {
                self.metrics.inc_permission_denied();
                return Err(ShmError::PermissionDenied);
            }

            // Check process attachment limit
            let attachments = table::get_attachments(pid);
            if attachments.len() >= self.config.max_segments_per_process {
                return Err(ShmError::TooManyAttachments {
                    pid,
                    max: self.config.max_segments_per_process,
                });
            }

            // Choose virtual address
            let addr = if virt_addr != 0 {
                virt_addr
            } else {
                // Find a free area (simplified – use high address space)
                0x0000_8000_0000_0000 + (key as u64 * 0x10_0000)
            };

            // Map physical pages into the process page table (simplified)
            let page_size = FRAME_SIZE;
            for (i, &phys) in seg.phys_frames.iter().enumerate() {
                let virt = addr + (i * page_size) as u64;
                // In a full implementation: call VMM to map the physical frame
                if self.config.log_operations {
                    trace!(
                        phys = phys,
                        virt = virt,
                        frame = i,
                        "shmat: mapping physical frame"
                    );
                }
            }

            // Update segment metadata
            seg.ref_count.fetch_add(1, Ordering::Relaxed);
            seg.last_attach_pid = pid;
            seg.attach_time = crate::arch::x86_64::timer::uptime_ms();

            // Update the segment in the table
            // We need to replace it (we have a clone)
            let _ = table::insert_segment(seg); // Should not fail.

            // Record attachment
            let attachment = ProcessAttachment {
                key,
                virt_addr: addr,
                flags,
            };
            table::add_attachment(pid, attachment, &self.config)?;

            self.metrics.inc_attach();
            if self.config.log_operations {
                info!(
                    key,
                    virt_addr = addr,
                    pid,
                    "shmat: attached segment"
                );
            }
            Ok(addr)
        }

        /// Detach a shared memory segment (shmdt).
        pub fn shmdt(&self, addr: Address, pid: Pid) -> ShmResult<()> {
            let attachment = table::remove_attachment(pid, addr)
                .ok_or(ShmError::InvalidAddress { addr })?;

            // Find the segment and decrement refcount
            let mut seg = table::get_segment(attachment.key)
                .ok_or(ShmError::NotFound { key: attachment.key })?;

            let old_count = seg.ref_count.load(Ordering::Relaxed);
            if old_count > 0 {
                seg.ref_count.fetch_sub(1, Ordering::Relaxed);
                seg.last_detach_pid = pid;
                seg.detach_time = crate::arch::x86_64::timer::uptime_ms();
            }

            // Update the segment
            let _ = table::insert_segment(seg);

            self.metrics.inc_detach();
            if self.config.log_operations {
                info!(
                    key = attachment.key,
                    addr,
                    pid,
                    "shmdt: detached segment"
                );
            }

            // If segment was marked for removal and no longer attached, actually remove it.
            let seg_after = table::get_segment(attachment.key);
            if let Some(s) = seg_after {
                if (s.flags & super::constants::IPC_RMID) != 0 && !s.is_attached() {
                    self.remove_segment_internal(attachment.key)?;
                }
            }
            Ok(())
        }

        /// Control operations on a shared memory segment (shmctl).
        pub fn shmctl(&self, key: Key, cmd: u32, buf: Option<&mut ShmPerm>) -> ShmResult<()> {
            let mut seg = table::get_segment(key).ok_or(ShmError::NotFound { key })?;

            match cmd {
                super::constants::IPC_RMID => {
                    if !seg.is_attached() {
                        // Remove immediately
                        self.remove_segment_internal(key)?;
                    } else {
                        // Mark for removal
                        seg.flags |= super::constants::IPC_RMID;
                        let _ = table::insert_segment(seg);
                        if self.config.log_operations {
                            info!(key, "shmctl: segment marked for removal (still attached)");
                        }
                    }
                    Ok(())
                }
                super::constants::IPC_STAT => {
                    if let Some(perms) = buf {
                        *perms = seg.perm;
                    }
                    Ok(())
                }
                super::constants::IPC_SET => {
                    if let Some(perms) = buf {
                        seg.perm = *perms;
                        seg.mod_time = crate::arch::x86_64::timer::uptime_ms();
                        let _ = table::insert_segment(seg);
                    }
                    Ok(())
                }
                super::constants::SHM_LOCK => {
                    seg.locked = true;
                    let _ = table::insert_segment(seg);
                    Ok(())
                }
                super::constants::SHM_UNLOCK => {
                    seg.locked = false;
                    let _ = table::insert_segment(seg);
                    Ok(())
                }
                _ => Err(ShmError::InvalidCommand { cmd }),
            }
        }

        /// Clean up a terminated process.
        pub fn cleanup_process(&self, pid: Pid) {
            let attachments = table::clear_attachments(pid);
            for a in attachments {
                let _ = self.shmdt(a.virt_addr, pid);
            }
            if self.config.log_operations {
                info!(pid, "shm: cleaned up process attachments");
            }
        }

        /// Get statistics.
        pub fn stats(&self) -> ShmStats {
            table::stats()
        }

        /// Get metrics snapshot.
        pub fn metrics_snapshot(&self) -> super::metrics::ShmMetricsSnapshot {
            self.metrics.snapshot()
        }

        /// Reset metrics.
        pub fn reset_metrics(&self) {
            *self.metrics = ShmMetrics::default();
        }

        // ---------------------------------------------------------------------
        // Internal helpers
        // ---------------------------------------------------------------------

        fn remove_segment_internal(&self, key: Key) -> ShmResult<()> {
            let seg = table::remove_segment(key).ok_or(ShmError::NotFound { key })?;
            // Free physical frames
            for &phys in &seg.phys_frames {
                let frame = PhysFrame::from_start_address(PhysAddr::new(phys)).unwrap();
                deallocate(frame);
            }
            self.metrics.inc_removed();
            if self.config.log_operations {
                info!(key, "shmctl: segment removed");
            }
            Ok(())
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use constants::{
    IPC_CREAT, IPC_EXCL, IPC_PRIVATE, IPC_RMID, IPC_STAT, IPC_SET,
    SHM_R, SHM_W, SHM_LOCK, SHM_UNLOCK, SHM_RDONLY, SHM_REMAP,
    SHMMAX, SHMSEG_MAX,
};
pub use config::ShmConfig;
pub use error::{ShmError, ShmResult};
pub use metrics::{ShmMetrics, ShmMetricsSnapshot};
pub use types::{Key, Address, ShmPerm, ShmSegment, ProcessAttachment, ShmStats};
pub use manager::ShmManager;

// -----------------------------------------------------------------------------
// Legacy global API (backward compatibility)
// -----------------------------------------------------------------------------

static GLOBAL_MANAGER: spin::Once<ShmManager> = spin::Once::new();

/// Get the global manager instance.
fn global_manager() -> &'static ShmManager {
    GLOBAL_MANAGER.get().expect("shm manager not initialised")
}

/// Initialise the shared memory subsystem.
pub fn init() {
    GLOBAL_MANAGER.call_once(|| ShmManager::default());
    crate::serial_println!("  [SHM] System V shared memory initialised");
    crate::serial_println!("    SHMMAX = {} KiB", SHMMAX / 1024);
    crate::serial_println!("    SHMSEG_MAX = {}", SHMSEG_MAX);
}

/// shmget (legacy).
pub fn shmget(key: u64, size: usize, flags: u32, current_pid: u32) -> Result<u64, &'static str> {
    global_manager().shmget(key, size, flags, current_pid)
        .map_err(|e| match e {
            ShmError::NotFound { .. } => "SHM key not found",
            ShmError::AlreadyExists { .. } => "SHM segment already exists",
            ShmError::SizeTooLarge { .. } => "SHM size too large",
            ShmError::ZeroSize => "SHM size must be > 0",
            ShmError::OutOfMemory => "OOM for SHM segment",
            ShmError::PermissionDenied => "SHM permission denied",
            ShmError::TooManyAttachments { .. } => "too many SHM segments attached",
            _ => "SHM error",
        })
}

/// shmat (legacy).
pub fn shmat(key: u64, virt_addr: u64, flags: u32, pid: u32) -> Result<u64, &'static str> {
    global_manager().shmat(key, virt_addr, flags, pid)
        .map_err(|e| match e {
            ShmError::NotFound { .. } => "SHM key not found",
            ShmError::PermissionDenied => "SHM permission denied",
            ShmError::TooManyAttachments { .. } => "too many SHM segments attached",
            ShmError::InvalidAddress { .. } => "invalid address",
            _ => "SHM error",
        })
}

/// shmdt (legacy).
pub fn shmdt(addr: u64, pid: u32) -> bool {
    global_manager().shmdt(addr, pid).is_ok()
}

/// shmctl (legacy).
pub fn shmctl(key: u64, cmd: u32, buf: Option<&mut ShmPerm>) -> Result<(), &'static str> {
    global_manager().shmctl(key, cmd, buf)
        .map_err(|e| match e {
            ShmError::NotFound { .. } => "SHM key not found",
            ShmError::InvalidCommand { .. } => "invalid SHM command",
            _ => "SHM error",
        })
}

/// Clean up a process (legacy).
pub fn cleanup_process(pid: u32) {
    global_manager().cleanup_process(pid);
}

/// Get statistics (legacy).
pub fn shm_stats() -> ShmStats {
    global_manager().stats()
}

/// Check if a segment exists (legacy).
pub fn shm_exists(key: u64) -> bool {
    table::exists(key)
}

/// Get segment info (legacy).
pub fn shm_info(key: u64) -> Option<ShmSegment> {
    table::get_segment(key)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::Pid;

    #[test]
    fn test_config_validation() {
        let config = ShmConfig::default();
        assert!(config.validate().is_ok());

        let mut bad = config.clone();
        bad.max_segment_size = 0;
        assert!(bad.validate().is_err());

        let mut bad2 = config;
        bad2.max_segments_per_process = 0;
        assert!(bad2.validate().is_err());
    }

    #[test]
    fn test_shmget_create() {
        let manager = ShmManager::default();
        let key = manager.shmget(0x1234, 4096, IPC_CREAT | SHM_R | SHM_W, 1).unwrap();
        assert_eq!(key, 0x1234);
        assert!(table::exists(key));
        let stats = manager.stats();
        assert_eq!(stats.active_segments, 1);
        assert!(stats.total_bytes >= 4096);
    }

    #[test]
    fn test_shmget_private() {
        let manager = ShmManager::default();
        let key = manager.shmget(IPC_PRIVATE, 4096, IPC_CREAT | SHM_R | SHM_W, 1).unwrap();
        assert!(key != IPC_PRIVATE);
        assert!(table::exists(key));
    }

    #[test]
    fn test_shmget_excl() {
        let manager = ShmManager::default();
        manager.shmget(0x5678, 4096, IPC_CREAT | SHM_R | SHM_W, 1).unwrap();
        let err = manager.shmget(0x5678, 4096, IPC_EXCL | IPC_CREAT, 1).unwrap_err();
        assert!(matches!(err, ShmError::AlreadyExists { .. }));
    }

    #[test]
    fn test_shmat_shmdt() {
        let manager = ShmManager::default();
        let key = manager.shmget(0x9999, 4096, IPC_CREAT | SHM_R | SHM_W, 1).unwrap();
        let addr = manager.shmat(key, 0, 0, 1).unwrap();
        assert!(addr != 0);
        let stats = manager.stats();
        assert_eq!(stats.used_bytes, 4096);
        assert!(stats.attached_processes >= 1);
        manager.shmdt(addr, 1).unwrap();
        let stats2 = manager.stats();
        assert_eq!(stats2.used_bytes, 0);
    }

    #[test]
    fn test_shmctl_rmid() {
        let manager = ShmManager::default();
        let key = manager.shmget(0xAAAA, 4096, IPC_CREAT | SHM_R | SHM_W, 1).unwrap();
        // Attach so it stays alive
        let addr = manager.shmat(key, 0, 0, 1).unwrap();
        manager.shmctl(key, IPC_RMID, None).unwrap();
        // Should still exist because attached
        assert!(table::exists(key));
        // Detach should free it
        manager.shmdt(addr, 1).unwrap();
        // Now it should be gone
        assert!(!table::exists(key));
    }

    #[test]
    fn test_cleanup_process() {
        let manager = ShmManager::default();
        let key = manager.shmget(0xBBBB, 4096, IPC_CREAT | SHM_R | SHM_W, 2).unwrap();
        manager.shmat(key, 0, 0, 2).unwrap();
        manager.cleanup_process(2);
        // Segment should be detached
        let stats = manager.stats();
        assert_eq!(stats.attached_processes, 0);
    }

    #[test]
    fn test_metrics() {
        let manager = ShmManager::default();
        let key = manager.shmget(0xCCCC, 4096, IPC_CREAT | SHM_R | SHM_W, 1).unwrap();
        manager.shmat(key, 0, 0, 1).unwrap();
        let snap = manager.metrics_snapshot();
        assert_eq!(snap.segments_created, 1);
        assert_eq!(snap.attaches, 1);
        assert!(snap.total_bytes_allocated >= 4096);
    }
}
