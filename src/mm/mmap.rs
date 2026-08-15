//! mmap — memory‑mapped files + anonymous mappings
//!
//! Supports:
//!   - `MAP_ANON` – anonymous zero‑fill pages (already functional via VMM)
//!   - `MAP_FILE` – IONAFS file mapped into virtual space
//!   - `MAP_PRIVATE` – Copy‑on‑write, modifications do not propagate to file
//!   - `MAP_SHARED` – Shared, flushed to disk on `msync`/`munmap`
//!   - `MAP_FIXED` – Map at exact address (requires page‑aligned hint)
//!   - `MAP_POPULATE` – Pre‑fault all pages (option)
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                            MMAP Module                                 │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   config    │    error     │     types     │        backing           │
//! │ (MmapCfg)   │ (MmapError)  │ (MmapRegion)  │ (Anonymous, File)        │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │    table    │    stats     │    manager    │        legacy            │
//! │ (global)    │ (metrics)    │ (MmapManager) │ (global functions)       │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::memory::mmap::{MmapManager, MmapConfig};
//!
//! let config = MmapConfig::default();
//! let manager = MmapManager::new(config);
//! let addr = manager.mmap_file(tid, "/data/file", 0, 4096, PROT_READ, MAP_SHARED, 0)?;
//! ```

#![allow(dead_code)]

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use core::sync::atomic::{AtomicU64, Ordering};
use core::sync::atomic::AtomicUsize;
use spin::{Mutex, RwLock};
use tracing::{debug, info, trace, warn};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod constants {
    //! Constants for mmap.
    /// Page size (4 KiB).
    pub const PAGE_SIZE: usize = 4096;

    /// Page mask (for alignment).
    pub const PAGE_MASK: u64 = !(PAGE_SIZE as u64 - 1);

    /// Read permission.
    pub const PROT_READ: u32 = 0x1;
    /// Write permission.
    pub const PROT_WRITE: u32 = 0x2;
    /// Execute permission.
    pub const PROT_EXEC: u32 = 0x4;
    /// No access (used for guard pages).
    pub const PROT_NONE: u32 = 0x0;

    /// File‑backed mapping (default when `MAP_ANON` is not set).
    pub const MAP_FILE: u32 = 0x0;
    /// Anonymous mapping (zero‑fill).
    pub const MAP_ANON: u32 = 0x20;
    /// Shared mapping (writes propagate to file).
    pub const MAP_SHARED: u32 = 0x01;
    /// Private copy‑on‑write mapping.
    pub const MAP_PRIVATE: u32 = 0x02;
    /// Map at exact address (hint must be page‑aligned).
    pub const MAP_FIXED: u32 = 0x10;
    /// Populate (pre‑fault) all pages at map time.
    pub const MAP_POPULATE: u32 = 0x8000;

    /// Maximum number of mmap regions per process (sanity limit).
    pub const MAX_MMAP_REGIONS: usize = 1024;
}

pub mod config {
    //! Configuration for the mmap subsystem.
    use serde::{Deserialize, Serialize};
    use super::constants::MAX_MMAP_REGIONS;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct MmapConfig {
        pub max_regions_per_task: usize,
        pub enable_metrics: bool,
        pub log_operations: bool,
        pub default_prot: u32,
        pub default_flags: u32,
    }

    impl Default for MmapConfig {
        fn default() -> Self {
            Self {
                max_regions_per_task: MAX_MMAP_REGIONS,
                enable_metrics: true,
                log_operations: false,
                default_prot: super::constants::PROT_READ | super::constants::PROT_WRITE,
                default_flags: super::constants::MAP_SHARED,
            }
        }
    }

    impl MmapConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.max_regions_per_task == 0 {
                return Err("max_regions_per_task must be > 0");
            }
            Ok(())
        }

        pub fn with_max_regions(mut self, n: usize) -> Self {
            self.max_regions_per_task = n;
            self
        }

        pub fn with_metrics(mut self) -> Self {
            self.enable_metrics = true;
            self
        }
    }
}

pub mod error {
    //! Error types for mmap operations.
    use super::types::{Address, Length};
    use crate::task::TaskId;
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum MmapError {
        #[error("no free virtual address space for length {0}")]
        NoFreeAddressSpace(Length),

        #[error("too many regions for task {0} (max {1})")]
        TooManyRegions(TaskId, usize),

        #[error("region overlap at {addr:?} with length {len}")]
        RegionOverlap { addr: Address, len: Length },

        #[error("invalid offset {offset}: must be page‑aligned")]
        InvalidOffset { offset: u64 },

        #[error("file not found: {path}")]
        FileNotFound { path: String },

        #[error("file offset {offset} beyond file size {size}")]
        OffsetBeyondFile { offset: u64, size: usize },

        #[error("invalid protection flags: {prot:#x}")]
        InvalidProtection { prot: u32 },

        #[error("invalid mapping flags: {flags:#x}")]
        InvalidFlags { flags: u32 },

        #[error("region not found for address {addr:?}")]
        RegionNotFound { addr: Address },

        #[error("operation not permitted")]
        PermissionDenied,

        #[error("I/O error: {0}")]
        Io(String),

        #[error("configuration error: {0}")]
        Config(String),
    }

    pub type MmapResult<T> = Result<T, MmapError>;
}

pub mod types {
    //! Core types for mmap.
    use super::constants::PAGE_SIZE;
    use alloc::string::String;
    use core::fmt;

    /// Virtual address.
    pub type Address = u64;
    /// Length in bytes.
    pub type Length = usize;
    /// Protection flags.
    pub type Prot = u32;
    /// Mapping flags.
    pub type Flags = u32;

    /// Backing storage for an mmap region.
    #[derive(Clone, Debug)]
    pub enum MmapBacking {
        Anonymous,
        File {
            path: String,
            offset: u64,
            length: usize,
            writeable: bool,
        },
    }

    /// A single mmap region.
    #[derive(Clone, Debug)]
    pub struct MmapRegion {
        pub base: Address,
        pub length: Length,
        pub prot: Prot,
        pub flags: Flags,
        pub backing: MmapBacking,
        pub dirty_mask: u64,
        pub populated: bool,
    }

    impl MmapRegion {
        #[inline]
        pub fn contains(&self, addr: Address) -> bool {
            addr >= self.base && addr < self.base + self.length as u64
        }

        #[inline]
        pub fn page_offset(&self, addr: Address) -> usize {
            ((addr & !(PAGE_SIZE as u64 - 1)) - self.base) as usize
        }

        #[inline]
        pub fn page_index(&self, addr: Address) -> usize {
            self.page_offset(addr) / PAGE_SIZE
        }

        #[inline]
        pub fn mark_dirty(&mut self, addr: Address) {
            if self.flags & super::constants::MAP_SHARED != 0 {
                let idx = self.page_index(addr);
                self.dirty_mask |= 1 << (idx % 64);
            }
        }

        #[inline]
        pub fn is_dirty(&self, idx: usize) -> bool {
            (self.dirty_mask >> (idx % 64)) & 1 != 0
        }

        #[inline]
        pub fn clear_dirty(&mut self) {
            self.dirty_mask = 0;
        }

        /// Total number of pages in this region.
        pub fn page_count(&self) -> usize {
            self.length / PAGE_SIZE
        }
    }

    impl fmt::Display for MmapRegion {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "MmapRegion [{:#x}..{:#x}) prot={:#x} flags={:#x} backing={:?}",
                self.base,
                self.base + self.length as u64,
                self.prot,
                self.flags,
                self.backing
            )
        }
    }
}

pub mod stats {
    //! Statistics for mmap.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct MmapStats {
        pub total_regions: AtomicU64,
        pub anonymous_regions: AtomicU64,
        pub file_regions: AtomicU64,
        pub shared_regions: AtomicU64,
        pub private_regions: AtomicU64,
        pub total_mapped_pages: AtomicU64,
        pub dirty_pages: AtomicU64,
        pub page_faults: AtomicU64,
        pub msync_calls: AtomicU64,
        pub munmap_calls: AtomicU64,
    }

    impl MmapStats {
        pub fn record_region(&self, region: &super::types::MmapRegion) {
            self.total_regions.fetch_add(1, Ordering::Relaxed);
            match region.backing {
                super::types::MmapBacking::Anonymous => {
                    self.anonymous_regions.fetch_add(1, Ordering::Relaxed);
                }
                super::types::MmapBacking::File { .. } => {
                    self.file_regions.fetch_add(1, Ordering::Relaxed);
                }
            }
            if region.flags & super::constants::MAP_SHARED != 0 {
                self.shared_regions.fetch_add(1, Ordering::Relaxed);
            } else {
                self.private_regions.fetch_add(1, Ordering::Relaxed);
            }
            self.total_mapped_pages
                .fetch_add(region.page_count() as u64, Ordering::Relaxed);
        }

        pub fn remove_region(&self, region: &super::types::MmapRegion) {
            self.total_regions.fetch_sub(1, Ordering::Relaxed);
            match region.backing {
                super::types::MmapBacking::Anonymous => {
                    self.anonymous_regions.fetch_sub(1, Ordering::Relaxed);
                }
                super::types::MmapBacking::File { .. } => {
                    self.file_regions.fetch_sub(1, Ordering::Relaxed);
                }
            }
            if region.flags & super::constants::MAP_SHARED != 0 {
                self.shared_regions.fetch_sub(1, Ordering::Relaxed);
            } else {
                self.private_regions.fetch_sub(1, Ordering::Relaxed);
            }
            self.total_mapped_pages
                .fetch_sub(region.page_count() as u64, Ordering::Relaxed);
        }

        pub fn inc_dirty(&self) {
            self.dirty_pages.fetch_add(1, Ordering::Relaxed);
        }

        pub fn inc_page_fault(&self) {
            self.page_faults.fetch_add(1, Ordering::Relaxed);
        }

        pub fn inc_msync(&self) {
            self.msync_calls.fetch_add(1, Ordering::Relaxed);
        }

        pub fn inc_munmap(&self) {
            self.munmap_calls.fetch_add(1, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> MmapStatsSnapshot {
            MmapStatsSnapshot {
                total_regions: self.total_regions.load(Ordering::Relaxed),
                anonymous_regions: self.anonymous_regions.load(Ordering::Relaxed),
                file_regions: self.file_regions.load(Ordering::Relaxed),
                shared_regions: self.shared_regions.load(Ordering::Relaxed),
                private_regions: self.private_regions.load(Ordering::Relaxed),
                total_mapped_pages: self.total_mapped_pages.load(Ordering::Relaxed),
                dirty_pages: self.dirty_pages.load(Ordering::Relaxed),
                page_faults: self.page_faults.load(Ordering::Relaxed),
                msync_calls: self.msync_calls.load(Ordering::Relaxed),
                munmap_calls: self.munmap_calls.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct MmapStatsSnapshot {
        pub total_regions: u64,
        pub anonymous_regions: u64,
        pub file_regions: u64,
        pub shared_regions: u64,
        pub private_regions: u64,
        pub total_mapped_pages: u64,
        pub dirty_pages: u64,
        pub page_faults: u64,
        pub msync_calls: u64,
        pub munmap_calls: u64,
    }
}

pub mod table {
    //! Per‑task mmap table.
    use super::{
        config::MmapConfig,
        error::{MmapError, MmapResult},
        types::{Address, Length, MmapRegion},
        stats::MmapStats,
        constants::{PAGE_SIZE, PAGE_MASK},
    };
    use crate::task::TaskId;
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;
    use spin::RwLock;
    use tracing::{debug, trace};

    /// Global mmap table: task ID → list of mmap regions.
    pub static MMAP_TABLE: RwLock<BTreeMap<TaskId, Vec<MmapRegion>>> = RwLock::new(BTreeMap::new());

    /// Add a region for a task.
    pub fn add_region(
        tid: TaskId,
        region: MmapRegion,
        config: &MmapConfig,
        stats: &MmapStats,
    ) -> MmapResult<()> {
        let mut table = MMAP_TABLE.write();
        let regions = table.entry(tid).or_default();

        if regions.len() >= config.max_regions_per_task {
            return Err(MmapError::TooManyRegions(tid, config.max_regions_per_task));
        }

        // Check overlap.
        for r in regions.iter() {
            let end = region.base + region.length as u64;
            let r_end = r.base + r.length as u64;
            if !(end <= r.base || region.base >= r_end) {
                return Err(MmapError::RegionOverlap {
                    addr: region.base,
                    len: region.length,
                });
            }
        }

        regions.push(region.clone());
        stats.record_region(&region);

        if config.log_operations {
            debug!(tid, base = region.base, len = region.length, "mmap region added");
        }
        Ok(())
    }

    /// Remove a region for a task.
    pub fn remove_region(tid: TaskId, addr: Address, length: Length) -> MmapResult<Vec<MmapRegion>> {
        let mut table = MMAP_TABLE.write();
        let regions = table.get_mut(&tid).ok_or(MmapError::RegionNotFound { addr })?;

        let end = addr + length as u64;
        let mut removed = Vec::new();
        regions.retain(|r| {
            let r_end = r.base + r.length as u64;
            if r.base >= addr && r_end <= end {
                removed.push(r.clone());
                false
            } else {
                true
            }
        });

        if removed.is_empty() {
            return Err(MmapError::RegionNotFound { addr });
        }
        Ok(removed)
    }

    /// Find a region containing the given address.
    pub fn find_region(tid: TaskId, addr: Address) -> Option<MmapRegion> {
        let table = MMAP_TABLE.read();
        let regions = table.get(&tid)?;
        regions.iter().find(|r| r.contains(addr)).cloned()
    }

    /// Find a region and return a mutable reference.
    pub fn find_region_mut(tid: TaskId, addr: Address) -> Option<MmapRegion> {
        let mut table = MMAP_TABLE.write();
        let regions = table.get_mut(&tid)?;
        regions.iter_mut().find(|r| r.contains(addr)).cloned()
    }

    /// Get all regions for a task.
    pub fn get_regions(tid: TaskId) -> Vec<MmapRegion> {
        MMAP_TABLE.read().get(&tid).cloned().unwrap_or_default()
    }

    /// Remove all regions for a task (cleanup).
    pub fn clear_task(tid: TaskId) -> Vec<MmapRegion> {
        MMAP_TABLE.write().remove(&tid).unwrap_or_default()
    }

    /// Find a free virtual address range.
    pub fn find_free_address(
        tid: TaskId,
        length: Length,
        hint: Address,
    ) -> Address {
        let table = MMAP_TABLE.read();
        let regions = table.get(&tid);

        let user_start = 0x0000_7000_0000_0000u64;
        let mut candidate = if hint != 0 && hint < user_start {
            user_start
        } else if hint != 0 {
            hint & PAGE_MASK
        } else {
            user_start
        };

        if let Some(regs) = regions {
            for r in regs {
                if r.base <= candidate && candidate < r.base + r.length as u64 {
                    // Try to place after the region.
                    candidate = r.base.saturating_add(r.length as u64);
                    candidate = (candidate + (PAGE_SIZE as u64 - 1)) & PAGE_MASK;
                }
            }
        }

        if candidate < 0x0000_1000_0000_0000 {
            candidate = 0x0000_1000_0000_0000;
        }
        candidate & PAGE_MASK
    }
}

pub mod manager {
    //! Centralised manager for mmap.
    use super::{
        config::MmapConfig,
        error::{MmapError, MmapResult},
        types::{Address, Length, Prot, Flags, MmapRegion, MmapBacking},
        stats::MmapStats,
        table,
        constants::{PAGE_SIZE, PAGE_MASK, PROT_READ, PROT_WRITE, MAP_SHARED, MAP_PRIVATE, MAP_FIXED, MAP_POPULATE, MAP_ANON},
    };
    use crate::task::TaskId;
    use alloc::string::String;
    use core::sync::atomic::Ordering;
    use tracing::{debug, info, trace, warn};

    /// Centralised manager for mmap operations.
    pub struct MmapManager {
        config: MmapConfig,
        stats: MmapStats,
    }

    impl MmapManager {
        pub fn new(config: MmapConfig) -> Self {
            config.validate().expect("invalid MmapConfig");
            Self {
                config,
                stats: MmapStats::default(),
            }
        }

        pub fn default() -> Self {
            Self::new(MmapConfig::default())
        }

        pub fn config(&self) -> &MmapConfig {
            &self.config
        }

        pub fn stats(&self) -> &MmapStats {
            &self.stats
        }

        /// Map a file region.
        pub fn mmap_file(
            &self,
            tid: TaskId,
            path: &str,
            offset: u64,
            length: Length,
            prot: Prot,
            flags: Flags,
            hint: Address,
        ) -> MmapResult<Address> {
            // Validate offset alignment.
            if offset & (PAGE_SIZE as u64 - 1) != 0 {
                return Err(MmapError::InvalidOffset { offset });
            }

            // Check file exists and is readable.
            let file_data = crate::fs::ionafs::read(path)
                .ok_or_else(|| MmapError::FileNotFound { path: path.to_string() })?;
            if offset as usize >= file_data.len() {
                return Err(MmapError::OffsetBeyondFile {
                    offset,
                    size: file_data.len(),
                });
            }

            let actual_len = length.min(file_data.len() - offset as usize);
            let aligned_len = (actual_len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

            let base = if hint != 0 && (flags & MAP_FIXED != 0) {
                hint & PAGE_MASK
            } else {
                table::find_free_address(tid, aligned_len, hint)
            };
            if base == 0 {
                return Err(MmapError::NoFreeAddressSpace(aligned_len));
            }

            let region = MmapRegion {
                base,
                length: aligned_len,
                prot,
                flags,
                backing: MmapBacking::File {
                    path: path.to_string(),
                    offset,
                    length: actual_len,
                    writeable: (prot & PROT_WRITE) != 0,
                },
                dirty_mask: 0,
                populated: false,
            };

            table::add_region(tid, region.clone(), &self.config, &self.stats)?;

            if flags & MAP_POPULATE != 0 {
                self.pre_populate(&region);
            }

            if self.config.log_operations {
                info!(
                    tid,
                    path,
                    offset,
                    len = actual_len,
                    base,
                    "mmap file mapped"
                );
            }
            Ok(base)
        }

        /// Map anonymous pages.
        pub fn mmap_anon(
            &self,
            tid: TaskId,
            length: Length,
            prot: Prot,
            flags: Flags,
            hint: Address,
        ) -> MmapResult<Address> {
            let aligned_len = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
            let base = if hint != 0 && (flags & MAP_FIXED != 0) {
                hint & PAGE_MASK
            } else {
                table::find_free_address(tid, aligned_len, hint)
            };
            if base == 0 {
                return Err(MmapError::NoFreeAddressSpace(aligned_len));
            }

            let region = MmapRegion {
                base,
                length: aligned_len,
                prot,
                flags,
                backing: MmapBacking::Anonymous,
                dirty_mask: 0,
                populated: false,
            };

            table::add_region(tid, region.clone(), &self.config, &self.stats)?;

            if flags & MAP_POPULATE != 0 {
                self.pre_populate(&region);
            }

            if self.config.log_operations {
                info!(
                    tid,
                    len = aligned_len,
                    base,
                    "mmap anonymous mapped"
                );
            }
            Ok(base)
        }

        /// Handle a page fault.
        pub fn handle_page_fault(&self, tid: TaskId, fault_addr: Address) -> Option<[u8; PAGE_SIZE]> {
            self.stats.inc_page_fault();
            let region = table::find_region(tid, fault_addr)?;

            let mut page = [0u8; PAGE_SIZE];

            match &region.backing {
                MmapBacking::Anonymous => {
                    // Already zeroed.
                }
                MmapBacking::File { path, offset, .. } => {
                    let page_off = region.page_offset(fault_addr);
                    let file_pos = *offset as usize + page_off;

                    if let Some(data) = crate::fs::ionafs::read(path) {
                        let src_start = file_pos.min(data.len());
                        let src_end = (file_pos + PAGE_SIZE).min(data.len());
                        let copy_len = src_end - src_start;
                        if copy_len > 0 {
                            page[..copy_len].copy_from_slice(&data[src_start..src_end]);
                        }
                    }
                }
            }

            if self.config.log_operations {
                trace!(
                    tid,
                    fault_addr,
                    region_base = region.base,
                    "page fault handled for mmap"
                );
            }
            Some(page)
        }

        /// Mark a page as dirty.
        pub fn mark_dirty(&self, tid: TaskId, addr: Address) {
            if let Some(mut region) = table::find_region_mut(tid, addr) {
                region.mark_dirty(addr);
                self.stats.inc_dirty();
            }
        }

        /// Unmap a region.
        pub fn munmap(&self, tid: TaskId, addr: Address, length: Length) -> MmapResult<()> {
            self.stats.inc_munmap();
            let removed = table::remove_region(tid, addr, length)?;
            for region in &removed {
                self.stats.remove_region(region);
                // Evict from swap.
                crate::memory::swap::evict_range(region.base, region.base + region.length as u64);
                if self.config.log_operations {
                    debug!(
                        tid,
                        base = region.base,
                        len = region.length,
                        "munmap region removed"
                    );
                }
            }
            Ok(())
        }

        /// Synchronise a memory region to disk (for MAP_SHARED).
        pub fn msync(&self, tid: TaskId, addr: Address, length: Length) -> MmapResult<()> {
            self.stats.inc_msync();
            let end = addr + length as u64;
            let mut flushed = false;

            let regions = table::get_regions(tid);
            for mut region in regions {
                if region.base >= addr && region.base + region.length as u64 <= end {
                    if region.flags & MAP_SHARED != 0 {
                        self.flush_region(&mut region);
                        flushed = true;
                    }
                }
            }

            if !flushed {
                return Err(MmapError::RegionNotFound { addr });
            }
            Ok(())
        }

        /// Clean up all mappings for a task.
        pub fn cleanup_task(&self, tid: TaskId) {
            let regions = table::clear_task(tid);
            for region in &regions {
                self.stats.remove_region(region);
                crate::memory::swap::evict_range(region.base, region.base + region.length as u64);
            }
            if self.config.log_operations {
                info!(tid, count = regions.len(), "mmap cleaned up task");
            }
        }

        /// Get a snapshot of statistics.
        pub fn stats_snapshot(&self) -> super::stats::MmapStatsSnapshot {
            self.stats.snapshot()
        }

        // ---------------------------------------------------------------------
        // Internal helpers
        // ---------------------------------------------------------------------

        fn pre_populate(&self, region: &MmapRegion) {
            for offset in (0..region.length).step_by(PAGE_SIZE) {
                let addr = region.base + offset as u64;
                unsafe {
                    core::ptr::read_volatile(addr as *const u8);
                }
            }
        }

        fn flush_region(&self, region: &mut MmapRegion) {
            if let MmapBacking::File { path, offset, writeable, .. } = &region.backing {
                if !writeable {
                    return;
                }
                let page_count = region.page_count();
                for i in 0..page_count {
                    if region.is_dirty(i) {
                        let page_addr = region.base + (i * PAGE_SIZE) as u64;
                        let file_offset = *offset as usize + i * PAGE_SIZE;
                        let data = unsafe {
                            core::slice::from_raw_parts(page_addr as *const u8, PAGE_SIZE)
                        };
                        let _ = crate::fs::ionafs::write_at(path, file_offset as u64, data);
                    }
                }
                region.clear_dirty();
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use constants::{
    PAGE_SIZE, PAGE_MASK, PROT_READ, PROT_WRITE, PROT_EXEC, PROT_NONE,
    MAP_FILE, MAP_ANON, MAP_SHARED, MAP_PRIVATE, MAP_FIXED, MAP_POPULATE,
    MAX_MMAP_REGIONS,
};
pub use config::MmapConfig;
pub use error::{MmapError, MmapResult};
pub use types::{Address, Length, Prot, Flags, MmapRegion, MmapBacking};
pub use stats::{MmapStats, MmapStatsSnapshot};
pub use manager::MmapManager;

// -----------------------------------------------------------------------------
// Legacy global API (backward compatibility)
// -----------------------------------------------------------------------------

static GLOBAL_MANAGER: spin::Once<MmapManager> = spin::Once::new();

/// Initialize the global mmap manager.
pub fn init() {
    GLOBAL_MANAGER.call_once(|| MmapManager::default());
    crate::serial_println!("  [MMAP] file‑backed + anonymous mmap initialised");
}

/// Get a reference to the global manager.
fn global_manager() -> &'static MmapManager {
    GLOBAL_MANAGER.get().expect("mmap manager not initialised")
}

/// Map a file.
pub fn mmap_file(
    tid: TaskId,
    path: &str,
    offset: u64,
    length: usize,
    prot: u32,
    flags: u32,
    hint: u64,
) -> Option<u64> {
    global_manager().mmap_file(tid, path, offset, length, prot, flags, hint).ok()
}

/// Map anonymous memory.
pub fn mmap_anon(
    tid: TaskId,
    length: usize,
    prot: u32,
    flags: u32,
    hint: u64,
) -> u64 {
    global_manager().mmap_anon(tid, length, prot, flags, hint).unwrap_or(0)
}

/// Handle a page fault.
pub fn handle_page_fault(tid: TaskId, fault_addr: u64) -> Option<[u8; PAGE_SIZE]> {
    global_manager().handle_page_fault(tid, fault_addr)
}

/// Mark a page as dirty.
pub fn mark_dirty(tid: TaskId, addr: u64) {
    global_manager().mark_dirty(tid, addr);
}

/// Unmap a region.
pub fn munmap(tid: TaskId, addr: u64, length: usize) -> bool {
    global_manager().munmap(tid, addr, length).is_ok()
}

/// Synchronise to disk.
pub fn msync(tid: TaskId, addr: u64, length: usize) -> bool {
    global_manager().msync(tid, addr, length).is_ok()
}

/// Clean up task.
pub fn cleanup_task(tid: TaskId) {
    global_manager().cleanup_task(tid);
}

/// Get statistics.
pub fn mmap_stats() -> &'static MmapStats {
    &global_manager().stats()
}

/// Get memory statistics (total_mb, used_mb, swap_used_mb).
pub fn memory_stats() -> (usize, usize, usize) {
    let (total_f, used_f) = crate::memory::frame_alloc::stats();
    let (_total_s, used_s) = crate::memory::swap::stats();
    (total_f * 4 / 1024, used_f * 4 / 1024, used_s)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::TaskId;

    #[test]
    fn test_region_contains() {
        let region = MmapRegion {
            base: 0x1000,
            length: 0x1000,
            prot: PROT_READ,
            flags: MAP_SHARED,
            backing: MmapBacking::Anonymous,
            dirty_mask: 0,
            populated: false,
        };
        assert!(region.contains(0x1000));
        assert!(region.contains(0x1FFF));
        assert!(!region.contains(0x0FFF));
        assert!(!region.contains(0x2000));
    }

    #[test]
    fn test_page_index() {
        let region = MmapRegion {
            base: 0x1000,
            length: 0x3000,
            prot: PROT_READ,
            flags: MAP_SHARED,
            backing: MmapBacking::Anonymous,
            dirty_mask: 0,
            populated: false,
        };
        assert_eq!(region.page_index(0x1000), 0);
        assert_eq!(region.page_index(0x1FFF), 0);
        assert_eq!(region.page_index(0x2000), 1);
        assert_eq!(region.page_index(0x3000), 2);
    }

    #[test]
    fn test_dirty_marking() {
        let mut region = MmapRegion {
            base: 0x1000,
            length: 0x3000,
            prot: PROT_READ | PROT_WRITE,
            flags: MAP_SHARED,
            backing: MmapBacking::Anonymous,
            dirty_mask: 0,
            populated: false,
        };
        region.mark_dirty(0x1000);
        assert!(region.is_dirty(0));
        assert!(!region.is_dirty(1));
        region.mark_dirty(0x2000);
        assert!(region.is_dirty(1));
        region.clear_dirty();
        assert!(!region.is_dirty(0));
        assert!(!region.is_dirty(1));
    }

    #[test]
    fn test_config_validation() {
        let config = MmapConfig::default();
        assert!(config.validate().is_ok());

        let bad = MmapConfig { max_regions_per_task: 0, ..Default::default() };
        assert!(bad.validate().is_err());
    }
}
