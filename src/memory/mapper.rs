//! Memory mapper utilities — OffsetPageTable wrapper for IONA OS.
//!
//! Provides safe abstractions over `x86_64` page table operations using
//! the physical memory offset mapping established by the bootloader.
//!
//! The bootloader maps ALL physical memory at a fixed virtual offset
//! (`PHYS_OFFSET = 0xFFFF_8000_0000_0000`), so any physical address `p`
//! is accessible at virtual address `PHYS_OFFSET + p`.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                          Mapper Module                                 │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   config    │    error     │    metrics    │         types            │
//! │ (MapperCfg) │ (MapperError)│ (MapperMetrics)│ (Page, Frame, Flags)    │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   mapper    │ translation  │   manager     │        legacy            │
//! │ (map/unmap) │ (phys/virt)  │ (MapperMgr)   │ (global functions)       │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::memory::mapper::{MapperManager, MapperConfig};
//!
//! let config = MapperConfig::default();
//! let manager = MapperManager::new(config);
//! let mut mapper = manager.init_offset_page_table().unwrap();
//! let page = Page::containing_address(VirtAddr::new(0x1000));
//! let frame = PhysFrame::containing_address(PhysAddr::new(0x2000));
//! manager.map_page(&mut mapper, page, frame, flags)?;
//! ```

#![allow(dead_code)]

use x86_64::{
    structures::paging::{
        OffsetPageTable, PageTable, PageTableFlags, PhysFrame, Size4KiB,
        Page, Mapper, FrameAllocator, Translate,
    },
    VirtAddr, PhysAddr,
};
use tracing::{debug, info, trace, warn};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod constants {
    //! Constants for the memory mapper.
    /// Physical memory offset used by the bootloader's identity mapping.
    pub const PHYS_OFFSET: u64 = 0xFFFF_8000_0000_0000;

    /// Default flags for kernel mappings (present, writable, no-execute).
    pub const KERNEL_FLAGS: u64 = 0x3 | 0x10; // PRESENT | WRITABLE | NO_EXECUTE

    /// Default flags for user mappings (present, writable, user-accessible, no-execute).
    pub const USER_FLAGS: u64 = 0x7 | 0x10; // PRESENT | WRITABLE | USER_ACCESSIBLE | NO_EXECUTE
}

pub mod config {
    //! Configuration for the memory mapper.
    use serde::{Deserialize, Serialize};
    use x86_64::structures::paging::PageTableFlags;
    use super::constants;

    /// Configuration for the memory mapper.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct MapperConfig {
        pub physical_offset: u64,
        pub default_kernel_flags: PageTableFlags,
        pub default_user_flags: PageTableFlags,
        pub enforce_wx: bool,
        pub collect_metrics: bool,
        pub log_mappings: bool,
    }

    impl Default for MapperConfig {
        fn default() -> Self {
            Self {
                physical_offset: constants::PHYS_OFFSET,
                default_kernel_flags: PageTableFlags::from_bits_truncate(constants::KERNEL_FLAGS),
                default_user_flags: PageTableFlags::from_bits_truncate(constants::USER_FLAGS),
                enforce_wx: true,
                collect_metrics: true,
                log_mappings: false,
            }
        }
    }

    impl MapperConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.physical_offset == 0 {
                return Err("physical_offset cannot be zero");
            }
            Ok(())
        }

        pub fn with_offset(mut self, offset: u64) -> Self {
            self.physical_offset = offset;
            self
        }

        pub fn with_metrics(mut self) -> Self {
            self.collect_metrics = true;
            self
        }

        pub fn with_logging(mut self) -> Self {
            self.log_mappings = true;
            self
        }
    }
}

pub mod error {
    //! Error types for memory mapping operations.
    use x86_64::structures::paging::PageTableFlags;
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum MapperError {
        #[error("W^X violation: page cannot be both writable and executable")]
        WxViolation,

        #[error("failed to map page {page:#x}: {reason}")]
        MapFailed { page: u64, reason: &'static str },

        #[error("failed to unmap page {page:#x}: {reason}")]
        UnmapFailed { page: u64, reason: &'static str },

        #[error("page already mapped: {page:#x}")]
        AlreadyMapped { page: u64 },

        #[error("physical frame allocation failed")]
        FrameAllocationFailed,

        #[error("invalid page table: {0}")]
        InvalidPageTable(&'static str),

        #[error("address translation failed for {addr:#x}")]
        TranslationFailed { addr: u64 },

        #[error("configuration error: {0}")]
        Config(String),
    }

    pub type MapperResult<T> = Result<T, MapperError>;
}

pub mod types {
    //! Core types for memory mapping.
    pub use x86_64::{
        structures::paging::{Page, PhysFrame, PageTableFlags, Size4KiB},
        VirtAddr, PhysAddr,
    };
    use super::constants::PHYS_OFFSET;

    /// Convert a physical address to a virtual address via the offset mapping.
    #[inline]
    pub const fn phys_to_virt(phys: u64) -> u64 {
        PHYS_OFFSET + phys
    }

    /// Convert a virtual address (within the offset-mapped region) back to a
    /// physical address. Returns `None` if the virtual address is outside the
    /// physical mapping window.
    #[inline]
    pub fn virt_to_phys(virt: u64) -> Option<u64> {
        if virt >= PHYS_OFFSET {
            Some(virt - PHYS_OFFSET)
        } else {
            None
        }
    }

    /// Statistics about page mappings.
    #[derive(Debug, Clone, Default)]
    pub struct MappingStats {
        pub total_pages_mapped: u64,
        pub total_pages_unmapped: u64,
        pub total_allocations: u64,
        pub total_failures: u64,
        pub current_mappings: u64,
    }
}

pub mod metrics {
    //! Metrics for the memory mapper.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct MapperMetrics {
        pub pages_mapped: AtomicU64,
        pub pages_unmapped: AtomicU64,
        pub failed_maps: AtomicU64,
        pub failed_unmaps: AtomicU64,
        pub wx_violations: AtomicU64,
        pub frame_allocation_failures: AtomicU64,
        pub translations: AtomicU64,
    }

    impl MapperMetrics {
        pub fn inc_mapped(&self) {
            self.pages_mapped.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_unmapped(&self) {
            self.pages_unmapped.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_failed_map(&self) {
            self.failed_maps.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_failed_unmap(&self) {
            self.failed_unmaps.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_wx_violation(&self) {
            self.wx_violations.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_frame_allocation_failure(&self) {
            self.frame_allocation_failures.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_translation(&self) {
            self.translations.fetch_add(1, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> MapperMetricsSnapshot {
            MapperMetricsSnapshot {
                pages_mapped: self.pages_mapped.load(Ordering::Relaxed),
                pages_unmapped: self.pages_unmapped.load(Ordering::Relaxed),
                failed_maps: self.failed_maps.load(Ordering::Relaxed),
                failed_unmaps: self.failed_unmaps.load(Ordering::Relaxed),
                wx_violations: self.wx_violations.load(Ordering::Relaxed),
                frame_allocation_failures: self.frame_allocation_failures.load(Ordering::Relaxed),
                translations: self.translations.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct MapperMetricsSnapshot {
        pub pages_mapped: u64,
        pub pages_unmapped: u64,
        pub failed_maps: u64,
        pub failed_unmaps: u64,
        pub wx_violations: u64,
        pub frame_allocation_failures: u64,
        pub translations: u64,
    }
}

pub mod mapper {
    //! Core page mapping operations.
    use super::{
        config::MapperConfig,
        error::{MapperError, MapperResult},
        metrics::MapperMetrics,
        types::Page,
        constants,
    };
    use x86_64::{
        structures::paging::{
            OffsetPageTable, PageTable, PageTableFlags, PhysFrame, Size4KiB,
            Mapper, FrameAllocator, Translate,
        },
        VirtAddr, PhysAddr,
    };
    use tracing::{debug, trace, warn};

    /// Frame allocator wrapper for the kernel.
    struct KernelFrameAllocator;

    unsafe impl FrameAllocator<Size4KiB> for KernelFrameAllocator {
        fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
            crate::memory::frame_alloc::allocate_one()
        }
    }

    /// Checks W^X compliance.
    pub fn check_wx(flags: PageTableFlags, config: &MapperConfig) -> MapperResult<()> {
        if config.enforce_wx && flags.contains(PageTableFlags::WRITABLE) && !flags.contains(PageTableFlags::NO_EXECUTE) {
            return Err(MapperError::WxViolation);
        }
        Ok(())
    }

    /// Maps a virtual page to a physical frame with the given flags.
    pub fn map_page(
        mapper: &mut OffsetPageTable,
        page: Page<Size4KiB>,
        frame: PhysFrame<Size4KiB>,
        flags: PageTableFlags,
        config: &MapperConfig,
        metrics: &MapperMetrics,
    ) -> MapperResult<()> {
        check_wx(flags, config)?;

        let mut allocator = KernelFrameAllocator;
        unsafe {
            match mapper.map_to(page, frame, flags, &mut allocator) {
                Ok(flush) => {
                    flush.flush();
                    metrics.inc_mapped();
                    if config.log_mappings {
                        trace!(
                            page = page.start_address().as_u64(),
                            frame = frame.start_address().as_u64(),
                            flags = flags.bits(),
                            "page mapped"
                        );
                    }
                    Ok(())
                }
                Err(e) => {
                    metrics.inc_failed_map();
                    Err(MapperError::MapFailed {
                        page: page.start_address().as_u64(),
                        reason: "map_to failed",
                    })
                }
            }
        }
    }

    /// Unmaps a virtual page and returns the previously mapped frame.
    pub fn unmap_page(
        mapper: &mut OffsetPageTable,
        page: Page<Size4KiB>,
        config: &MapperConfig,
        metrics: &MapperMetrics,
    ) -> MapperResult<PhysFrame<Size4KiB>> {
        unsafe {
            match mapper.unmap(page) {
                Ok((frame, flush)) => {
                    flush.flush();
                    metrics.inc_unmapped();
                    if config.log_mappings {
                        trace!(
                            page = page.start_address().as_u64(),
                            frame = frame.start_address().as_u64(),
                            "page unmapped"
                        );
                    }
                    Ok(frame)
                }
                Err(e) => {
                    metrics.inc_failed_unmap();
                    Err(MapperError::UnmapFailed {
                        page: page.start_address().as_u64(),
                        reason: "unmap failed",
                    })
                }
            }
        }
    }

    /// Maps a consecutive range of pages to contiguous physical frames.
    pub fn map_range(
        mapper: &mut OffsetPageTable,
        start_page: Page<Size4KiB>,
        start_frame: PhysFrame<Size4KiB>,
        count: u64,
        flags: PageTableFlags,
        config: &MapperConfig,
        metrics: &MapperMetrics,
    ) -> MapperResult<()> {
        check_wx(flags, config)?;

        for i in 0..count {
            let page = Page::containing_address(start_page.start_address() + i * 4096);
            let frame = PhysFrame::containing_address(start_frame.start_address() + i * 4096);
            map_page(mapper, page, frame, flags, config, metrics)?;
        }
        Ok(())
    }

    /// Translates a virtual address to its physical address.
    pub fn translate_addr(
        mapper: &OffsetPageTable,
        virt: VirtAddr,
        metrics: &MapperMetrics,
    ) -> Option<PhysAddr> {
        metrics.inc_translation();
        mapper.translate_addr(virt)
    }

    /// Creates an `OffsetPageTable` from the current CR3 register.
    ///
    /// # Safety
    /// - Must be called after the bootloader has established the physical memory
    ///   mapping and the current page table is valid.
    /// - `PHYS_OFFSET` must match the bootloader's mapping.
    pub unsafe fn init_offset_page_table(config: &MapperConfig) -> OffsetPageTable<'static> {
        let (l4_frame, _) = x86_64::registers::control::Cr3::read();
        let l4_phys = l4_frame.start_address().as_u64();
        let l4_table = &mut *((config.physical_offset + l4_phys) as *mut PageTable);
        OffsetPageTable::new(l4_table, VirtAddr::new(config.physical_offset))
    }

    /// Creates an `OffsetPageTable` from a specific L4 physical frame.
    ///
    /// # Safety
    /// - `l4_frame` must contain a valid L4 page table.
    pub unsafe fn from_l4_frame(
        l4_frame: PhysFrame<Size4KiB>,
        config: &MapperConfig,
    ) -> OffsetPageTable<'static> {
        let l4_phys = l4_frame.start_address().as_u64();
        let l4_table = &mut *((config.physical_offset + l4_phys) as *mut PageTable);
        OffsetPageTable::new(l4_table, VirtAddr::new(config.physical_offset))
    }
}

pub mod manager {
    //! Centralised manager for the memory mapper.
    use super::{
        config::MapperConfig,
        error::{MapperError, MapperResult},
        metrics::MapperMetrics,
        types::{Page, VirtAddr, PhysAddr},
        mapper,
    };
    use x86_64::{
        structures::paging::{OffsetPageTable, PhysFrame, PageTableFlags, Size4KiB},
        VirtAddr as XVirtAddr, PhysAddr as XPhysAddr,
    };
    use core::sync::atomic::Ordering;

    /// Manager for the memory mapper.
    pub struct MapperManager {
        config: MapperConfig,
        metrics: MapperMetrics,
    }

    impl MapperManager {
        pub fn new(config: MapperConfig) -> Self {
            config.validate().expect("invalid MapperConfig");
            Self {
                config,
                metrics: MapperMetrics::default(),
            }
        }

        pub fn default() -> Self {
            Self::new(MapperConfig::default())
        }

        pub fn config(&self) -> &MapperConfig {
            &self.config
        }

        pub fn metrics(&self) -> &MapperMetrics {
            &self.metrics
        }

        /// Create an `OffsetPageTable` from the current CR3.
        pub fn init_offset_page_table(&self) -> OffsetPageTable<'static> {
            unsafe { mapper::init_offset_page_table(&self.config) }
        }

        /// Create an `OffsetPageTable` from a given L4 frame.
        pub fn from_l4_frame(&self, l4_frame: PhysFrame<Size4KiB>) -> OffsetPageTable<'static> {
            unsafe { mapper::from_l4_frame(l4_frame, &self.config) }
        }

        /// Map a single page.
        pub fn map_page(
            &self,
            mapper: &mut OffsetPageTable,
            page: Page<Size4KiB>,
            frame: PhysFrame<Size4KiB>,
            flags: PageTableFlags,
        ) -> MapperResult<()> {
            mapper::map_page(mapper, page, frame, flags, &self.config, &self.metrics)
        }

        /// Unmap a single page.
        pub fn unmap_page(
            &self,
            mapper: &mut OffsetPageTable,
            page: Page<Size4KiB>,
        ) -> MapperResult<PhysFrame<Size4KiB>> {
            mapper::unmap_page(mapper, page, &self.config, &self.metrics)
        }

        /// Map a range.
        pub fn map_range(
            &self,
            mapper: &mut OffsetPageTable,
            start_page: Page<Size4KiB>,
            start_frame: PhysFrame<Size4KiB>,
            count: u64,
            flags: PageTableFlags,
        ) -> MapperResult<()> {
            mapper::map_range(mapper, start_page, start_frame, count, flags, &self.config, &self.metrics)
        }

        /// Translate an address.
        pub fn translate_addr(
            &self,
            mapper: &OffsetPageTable,
            virt: VirtAddr,
        ) -> Option<PhysAddr> {
            mapper::translate_addr(mapper, virt, &self.metrics)
        }

        /// Check W^X.
        pub fn check_wx(&self, flags: PageTableFlags) -> MapperResult<()> {
            mapper::check_wx(flags, &self.config)
        }

        /// Get a metrics snapshot.
        pub fn metrics_snapshot(&self) -> super::metrics::MapperMetricsSnapshot {
            self.metrics.snapshot()
        }

        /// Reset metrics.
        pub fn reset_metrics(&self) {
            *self.metrics = MapperMetrics::default();
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use constants::PHYS_OFFSET;
pub use config::MapperConfig;
pub use error::{MapperError, MapperResult};
pub use metrics::{MapperMetrics, MapperMetricsSnapshot};
pub use types::{Page, PhysFrame, PageTableFlags, VirtAddr, PhysAddr, Size4KiB};
pub use mapper::{check_wx, map_page, unmap_page, map_range, translate_addr};
pub use manager::MapperManager;

// -----------------------------------------------------------------------------
// Legacy global API (backward compatibility)
// -----------------------------------------------------------------------------

static GLOBAL_MANAGER: spin::Once<MapperManager> = spin::Once::new();

/// Get the global manager instance.
fn global_manager() -> &'static MapperManager {
    GLOBAL_MANAGER.get().expect("mapper manager not initialised")
}

/// Initialise the global mapper manager (legacy).
pub fn init() {
    GLOBAL_MANAGER.call_once(|| MapperManager::default());
    crate::serial_println!("  [MAPPER] memory mapper utilities initialised");
}

/// Initialise an `OffsetPageTable` from the current CR3 (legacy).
pub unsafe fn init_offset_page_table() -> OffsetPageTable<'static> {
    global_manager().init_offset_page_table()
}

/// Create an `OffsetPageTable` from a given L4 frame (legacy).
pub unsafe fn from_l4_frame(l4_frame: PhysFrame<Size4KiB>) -> OffsetPageTable<'static> {
    global_manager().from_l4_frame(l4_frame)
}

/// Map a page (legacy).
pub fn map_page(
    mapper: &mut OffsetPageTable,
    page: Page<Size4KiB>,
    frame: PhysFrame<Size4KiB>,
    flags: PageTableFlags,
) -> Result<(), &'static str> {
    global_manager()
        .map_page(mapper, page, frame, flags)
        .map_err(|e| match e {
            MapperError::WxViolation => "W^X violation",
            MapperError::MapFailed { .. } => "map failed",
            _ => "unknown error",
        })
}

/// Unmap a page (legacy).
pub fn unmap_page(
    mapper: &mut OffsetPageTable,
    page: Page<Size4KiB>,
) -> Result<PhysFrame<Size4KiB>, &'static str> {
    global_manager()
        .unmap_page(mapper, page)
        .map_err(|_| "unmap failed")
}

/// Map a range (legacy).
pub fn map_range(
    mapper: &mut OffsetPageTable,
    start_page: Page<Size4KiB>,
    start_frame: PhysFrame<Size4KiB>,
    count: u64,
    flags: PageTableFlags,
) -> Result<(), &'static str> {
    global_manager()
        .map_range(mapper, start_page, start_frame, count, flags)
        .map_err(|_| "range map failed")
}

/// Translate an address (legacy).
pub fn translate_addr(mapper: &OffsetPageTable, virt: VirtAddr) -> Option<PhysAddr> {
    global_manager().translate_addr(mapper, virt)
}

/// Convert physical to virtual (legacy).
#[inline]
pub const fn phys_to_virt(phys: u64) -> u64 {
    PHYS_OFFSET + phys
}

/// Convert virtual to physical (legacy).
#[inline]
pub fn virt_to_phys(virt: u64) -> Option<u64> {
    if virt >= PHYS_OFFSET {
        Some(virt - PHYS_OFFSET)
    } else {
        None
    }
}

/// Check W^X (legacy).
pub fn check_wx_legacy(flags: PageTableFlags) -> Result<(), &'static str> {
    global_manager()
        .check_wx(flags)
        .map_err(|_| "W^X violation")
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use x86_64::structures::paging::PageTableFlags;

    #[test]
    fn test_phys_to_virt_conversion() {
        assert_eq!(phys_to_virt(0), PHYS_OFFSET);
        assert_eq!(phys_to_virt(4096), PHYS_OFFSET + 4096);
    }

    #[test]
    fn test_virt_to_phys_in_range() {
        assert_eq!(virt_to_phys(PHYS_OFFSET), Some(0));
        assert_eq!(virt_to_phys(PHYS_OFFSET + 0x1000), Some(0x1000));
    }

    #[test]
    fn test_virt_to_phys_out_of_range() {
        assert_eq!(virt_to_phys(0), None);
        assert_eq!(virt_to_phys(PHYS_OFFSET - 1), None);
    }

    #[test]
    fn test_check_wx_safe_flags() {
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
        assert!(check_wx(flags, &MapperConfig::default()).is_ok());

        let flags2 = PageTableFlags::PRESENT;
        assert!(check_wx(flags2, &MapperConfig::default()).is_ok());
    }

    #[test]
    fn test_check_wx_violation() {
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        assert!(check_wx(flags, &MapperConfig::default()).is_err());
    }

    #[test]
    fn test_config_validation() {
        let config = MapperConfig::default();
        assert!(config.validate().is_ok());

        let mut bad = config.clone();
        bad.physical_offset = 0;
        assert!(bad.validate().is_err());
    }

    #[test]
    fn test_metrics() {
        let metrics = MapperMetrics::default();
        metrics.inc_mapped();
        metrics.inc_unmapped();
        let snap = metrics.snapshot();
        assert_eq!(snap.pages_mapped, 1);
        assert_eq!(snap.pages_unmapped, 1);
    }
}
