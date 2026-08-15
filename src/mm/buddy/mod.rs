//! Buddy allocator — allocates 2^order pages, O(log n), no external fragmentation.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                         Buddy Allocator Module                         │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   config    │    error     │    metrics    │        types             │
//! │ (BuddyCfg)  │ (BuddyError) │ (BuddyMetrics)│ (Order, Address)         │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │  allocator  │   manager    │    legacy     │                          │
//! │ (BuddyAlloc)│ (BuddyMgr)   │ (global fns)  │                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::memory::buddy::{BuddyManager, BuddyConfig};
//!
//! let config = BuddyConfig::default();
//! let manager = BuddyManager::new(config);
//! manager.init(base, pages);
//! let addr = manager.alloc_pages(4)?;
//! manager.free_pages(addr, 4);
//! ```

#![allow(dead_code)]

use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Mutex, RwLock};
use tracing::{debug, info, trace, warn};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod constants {
    //! Constants for the buddy allocator.
    /// Default maximum order: 0..10 → 1..1024 pages (4MB max block).
    pub const DEFAULT_MAX_ORDER: usize = 11;

    /// Default page size in bytes.
    pub const DEFAULT_PAGE_SIZE: usize = 4096;

    /// Minimum order (0 = 1 page).
    pub const MIN_ORDER: usize = 0;
}

pub mod config {
    //! Configuration for the buddy allocator.
    use serde::{Deserialize, Serialize};
    use super::constants::{DEFAULT_MAX_ORDER, DEFAULT_PAGE_SIZE};

    /// Configuration for the buddy allocator.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct BuddyConfig {
        pub max_order: usize,
        pub page_size: usize,
        pub collect_metrics: bool,
        pub log_operations: bool,
    }

    impl Default for BuddyConfig {
        fn default() -> Self {
            Self {
                max_order: DEFAULT_MAX_ORDER,
                page_size: DEFAULT_PAGE_SIZE,
                collect_metrics: true,
                log_operations: false,
            }
        }
    }

    impl BuddyConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.max_order == 0 {
                return Err("max_order must be > 0");
            }
            if self.page_size == 0 {
                return Err("page_size must be > 0");
            }
            if self.page_size & (self.page_size - 1) != 0 {
                return Err("page_size must be a power of two");
            }
            Ok(())
        }

        pub fn with_max_order(mut self, order: usize) -> Self {
            self.max_order = order;
            self
        }

        pub fn with_page_size(mut self, size: usize) -> Self {
            self.page_size = size;
            self
        }

        pub fn with_metrics(mut self) -> Self {
            self.collect_metrics = true;
            self
        }
    }
}

pub mod error {
    //! Error types for the buddy allocator.
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum BuddyError {
        #[error("allocation failed: no free block of order {order} available")]
        AllocationFailed { order: usize },

        #[error("invalid order {order}: must be between 0 and {max_order}")]
        InvalidOrder { order: usize, max_order: usize },

        #[error("invalid address 0x{address:x}: not page-aligned")]
        InvalidAddress { address: u64 },

        #[error("double free detected for address 0x{address:x}")]
        DoubleFree { address: u64 },

        #[error("buddy not found for address 0x{address:x}")]
        BuddyNotFound { address: u64 },

        #[error("configuration error: {0}")]
        Config(String),
    }

    pub type BuddyResult<T> = Result<T, BuddyError>;
}

pub mod types {
    //! Core types for the buddy allocator.
    use super::error::BuddyError;
    use core::fmt;

    /// Page address (physical or virtual).
    pub type Address = u64;

    /// Allocation order (2^order pages).
    pub type Order = usize;

    /// Statistics about the allocator.
    #[derive(Debug, Clone, Default)]
    pub struct BuddyStats {
        pub total_pages: usize,
        pub free_pages: usize,
        pub allocated_pages: usize,
        pub largest_free_order: Option<usize>,
        pub fragmentation_count: usize,
    }

    impl fmt::Display for BuddyStats {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            writeln!(f, "Buddy Allocator Statistics:")?;
            writeln!(f, "  Total pages: {}", self.total_pages)?;
            writeln!(f, "  Free pages: {}", self.free_pages)?;
            writeln!(f, "  Allocated pages: {}", self.allocated_pages)?;
            writeln!(f, "  Largest free order: {:?}", self.largest_free_order)?;
            writeln!(f, "  Fragmentation count: {}", self.fragmentation_count)
        }
    }
}

pub mod allocator {
    //! Core buddy allocator implementation.
    use super::{
        config::BuddyConfig,
        error::{BuddyError, BuddyResult},
        types::{Address, Order, BuddyStats},
    };
    use alloc::vec::Vec;
    use tracing::{debug, info, trace};

    /// Buddy allocator core.
    pub struct BuddyAllocator {
        config: BuddyConfig,
        free: Vec<Vec<Address>>,
        total_pages: usize,
        free_pages: usize,
    }

    impl BuddyAllocator {
        /// Create a new buddy allocator with the given configuration.
        pub fn new(config: &BuddyConfig) -> Self {
            let mut free = Vec::with_capacity(config.max_order);
            for _ in 0..config.max_order {
                free.push(Vec::new());
            }
            Self {
                config: config.clone(),
                free,
                total_pages: 0,
                free_pages: 0,
            }
        }

        /// Add a contiguous region of memory to the allocator.
        pub fn add_region(&mut self, base: Address, pages: usize) {
            let mut addr = base;
            let mut rem = pages;
            self.total_pages += pages;
            self.free_pages += pages;

            while rem > 0 {
                let mut order = self.config.max_order - 1;
                loop {
                    let size = 1usize << order;
                    let aligned = addr % ((size * self.config.page_size) as u64) == 0;
                    if size <= rem && aligned {
                        break;
                    }
                    if order == 0 {
                        break;
                    }
                    order -= 1;
                }
                let size = 1usize << order;
                self.free[order].push(addr);
                addr += (size * self.config.page_size) as u64;
                rem -= size;
            }

            if self.config.log_operations {
                debug!(
                    base = base,
                    pages = pages,
                    total = self.total_pages,
                    free = self.free_pages,
                    "added memory region"
                );
            }
        }

        /// Allocate a block of 2^order pages.
        pub fn alloc(&mut self, order: Order) -> BuddyResult<Address> {
            if order >= self.config.max_order {
                return Err(BuddyError::InvalidOrder {
                    order,
                    max_order: self.config.max_order - 1,
                });
            }

            let mut fo = order;
            while fo < self.config.max_order && self.free[fo].is_empty() {
                fo += 1;
            }
            if fo >= self.config.max_order {
                return Err(BuddyError::AllocationFailed { order });
            }

            let addr = self.free[fo].pop().unwrap();
            let mut co = fo;
            while co > order {
                co -= 1;
                let buddy_addr = addr + ((1u64 << co) * self.config.page_size as u64);
                self.free[co].push(buddy_addr);
            }

            let allocated_pages = 1 << order;
            self.free_pages -= allocated_pages;

            if self.config.log_operations {
                trace!(
                    order,
                    addr,
                    pages = allocated_pages,
                    free_pages = self.free_pages,
                    "allocated pages"
                );
            }

            Ok(addr)
        }

        /// Free a previously allocated block.
        pub fn free(&mut self, addr: Address, order: Order) -> BuddyResult<()> {
            if order >= self.config.max_order {
                return Err(BuddyError::InvalidOrder {
                    order,
                    max_order: self.config.max_order - 1,
                });
            }

            if addr % self.config.page_size as u64 != 0 {
                return Err(BuddyError::InvalidAddress { address: addr });
            }

            let page_size = self.config.page_size as u64;
            let mut a = addr;
            let mut o = order;

            while o < self.config.max_order - 1 {
                let block_size = (1u64 << o) * page_size;
                let buddy = if a % (block_size * 2) == 0 {
                    a + block_size
                } else {
                    a - block_size
                };

                if let Some(pos) = self.free[o].iter().position(|&p| p == buddy) {
                    self.free[o].swap_remove(pos);
                    a = a.min(buddy);
                    o += 1;
                } else {
                    break;
                }
            }

            // Check for double free.
            if self.free[o].contains(&a) {
                return Err(BuddyError::DoubleFree { address: a });
            }

            self.free[o].push(a);
            self.free_pages += 1 << order;

            if self.config.log_operations {
                trace!(
                    order,
                    addr,
                    pages = 1 << order,
                    free_pages = self.free_pages,
                    "freed pages"
                );
            }

            Ok(())
        }

        /// Get the largest free order.
        pub fn largest_free_order(&self) -> Option<usize> {
            for o in (0..self.config.max_order).rev() {
                if !self.free[o].is_empty() {
                    return Some(o);
                }
            }
            None
        }

        /// Get statistics.
        pub fn stats(&self) -> BuddyStats {
            let allocated_pages = self.total_pages.saturating_sub(self.free_pages);
            BuddyStats {
                total_pages: self.total_pages,
                free_pages: self.free_pages,
                allocated_pages,
                largest_free_order: self.largest_free_order(),
                fragmentation_count: self.free.iter().filter(|v| !v.is_empty()).count(),
            }
        }

        /// Get total pages.
        pub fn total_pages(&self) -> usize {
            self.total_pages
        }

        /// Get free pages.
        pub fn free_pages(&self) -> usize {
            self.free_pages
        }

        /// Check if the allocator is empty (no regions added).
        pub fn is_empty(&self) -> bool {
            self.total_pages == 0
        }

        /// Reset the allocator (clear all regions).
        pub fn reset(&mut self) {
            for list in &mut self.free {
                list.clear();
            }
            self.total_pages = 0;
            self.free_pages = 0;
        }

        /// Get the number of free lists (non-empty).
        pub fn free_list_count(&self) -> usize {
            self.free.iter().filter(|v| !v.is_empty()).count()
        }
    }

    impl Default for BuddyAllocator {
        fn default() -> Self {
            let config = BuddyConfig::default();
            Self::new(&config)
        }
    }
}

pub mod metrics {
    //! Metrics for the buddy allocator.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct BuddyMetrics {
        pub allocations: AtomicU64,
        pub frees: AtomicU64,
        pub allocation_failures: AtomicU64,
        pub free_failures: AtomicU64,
        pub total_pages_allocated: AtomicU64,
        pub total_pages_freed: AtomicU64,
        pub coalesces: AtomicU64,
    }

    impl BuddyMetrics {
        pub fn inc_alloc(&self, pages: usize) {
            self.allocations.fetch_add(1, Ordering::Relaxed);
            self.total_pages_allocated.fetch_add(pages as u64, Ordering::Relaxed);
        }
        pub fn inc_free(&self, pages: usize) {
            self.frees.fetch_add(1, Ordering::Relaxed);
            self.total_pages_freed.fetch_add(pages as u64, Ordering::Relaxed);
        }
        pub fn inc_alloc_failure(&self) {
            self.allocation_failures.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_free_failure(&self) {
            self.free_failures.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_coalesce(&self) {
            self.coalesces.fetch_add(1, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> BuddyMetricsSnapshot {
            BuddyMetricsSnapshot {
                allocations: self.allocations.load(Ordering::Relaxed),
                frees: self.frees.load(Ordering::Relaxed),
                allocation_failures: self.allocation_failures.load(Ordering::Relaxed),
                free_failures: self.free_failures.load(Ordering::Relaxed),
                total_pages_allocated: self.total_pages_allocated.load(Ordering::Relaxed),
                total_pages_freed: self.total_pages_freed.load(Ordering::Relaxed),
                coalesces: self.coalesces.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct BuddyMetricsSnapshot {
        pub allocations: u64,
        pub frees: u64,
        pub allocation_failures: u64,
        pub free_failures: u64,
        pub total_pages_allocated: u64,
        pub total_pages_freed: u64,
        pub coalesces: u64,
    }
}

pub mod manager {
    //! Centralised manager for the buddy allocator.
    use super::{
        config::BuddyConfig,
        error::{BuddyError, BuddyResult},
        allocator::BuddyAllocator,
        metrics::BuddyMetrics,
        types::{Address, Order, BuddyStats},
    };
    use std::sync::Arc;
    use spin::Mutex;
    use tracing::{info, warn};

    /// Global manager for the buddy allocator.
    pub struct BuddyManager {
        config: BuddyConfig,
        allocator: Mutex<BuddyAllocator>,
        metrics: Arc<BuddyMetrics>,
        initialised: Mutex<bool>,
    }

    impl BuddyManager {
        /// Create a new manager with the given configuration.
        pub fn new(config: BuddyConfig) -> Self {
            config.validate().expect("invalid BuddyConfig");
            let allocator = BuddyAllocator::new(&config);
            Self {
                config,
                allocator: Mutex::new(allocator),
                metrics: Arc::new(BuddyMetrics::default()),
                initialised: Mutex::new(false),
            }
        }

        /// Create a manager with default configuration.
        pub fn default() -> Self {
            Self::new(BuddyConfig::default())
        }

        /// Get a reference to the metrics.
        pub fn metrics(&self) -> &BuddyMetrics {
            &self.metrics
        }

        /// Get the configuration.
        pub fn config(&self) -> &BuddyConfig {
            &self.config
        }

        /// Initialise the allocator with a memory region.
        pub fn init(&self, base: Address, pages: usize) {
            let mut alloc = self.allocator.lock();
            alloc.add_region(base, pages);
            *self.initialised.lock() = true;
            let stats = alloc.stats();
            info!(
                base = base,
                pages = pages,
                total = stats.total_pages,
                free = stats.free_pages,
                "buddy allocator initialized"
            );
        }

        /// Allocate a block of 2^order pages.
        pub fn alloc_pages(&self, order: Order) -> BuddyResult<Address> {
            if !*self.initialised.lock() {
                return Err(BuddyError::AllocationFailed { order });
            }
            let mut alloc = self.allocator.lock();
            let result = alloc.alloc(order);
            match result {
                Ok(addr) => {
                    self.metrics.inc_alloc(1 << order);
                    Ok(addr)
                }
                Err(e) => {
                    self.metrics.inc_alloc_failure();
                    Err(e)
                }
            }
        }

        /// Free a previously allocated block.
        pub fn free_pages(&self, addr: Address, order: Order) -> BuddyResult<()> {
            if !*self.initialised.lock() {
                return Err(BuddyError::BuddyNotFound { address: addr });
            }
            let mut alloc = self.allocator.lock();
            let result = alloc.free(addr, order);
            match result {
                Ok(()) => {
                    self.metrics.inc_free(1 << order);
                    Ok(())
                }
                Err(e) => {
                    self.metrics.inc_free_failure();
                    Err(e)
                }
            }
        }

        /// Allocate a single page (order 0).
        pub fn alloc_page(&self) -> BuddyResult<Address> {
            self.alloc_pages(0)
        }

        /// Free a single page (order 0).
        pub fn free_page(&self, addr: Address) -> BuddyResult<()> {
            self.free_pages(addr, 0)
        }

        /// Get statistics.
        pub fn stats(&self) -> BuddyStats {
            let alloc = self.allocator.lock();
            alloc.stats()
        }

        /// Get total pages.
        pub fn total_pages(&self) -> usize {
            let alloc = self.allocator.lock();
            alloc.total_pages()
        }

        /// Get free pages.
        pub fn free_pages(&self) -> usize {
            let alloc = self.allocator.lock();
            alloc.free_pages()
        }

        /// Check if the allocator is initialised.
        pub fn is_initialised(&self) -> bool {
            *self.initialised.lock()
        }

        /// Reset the allocator.
        pub fn reset(&self) {
            let mut alloc = self.allocator.lock();
            alloc.reset();
            *self.initialised.lock() = false;
            info!("buddy allocator reset");
        }

        /// Get metrics snapshot.
        pub fn metrics_snapshot(&self) -> super::metrics::BuddyMetricsSnapshot {
            self.metrics.snapshot()
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use constants::{DEFAULT_MAX_ORDER, DEFAULT_PAGE_SIZE, MIN_ORDER};
pub use config::BuddyConfig;
pub use error::{BuddyError, BuddyResult};
pub use types::{Address, Order, BuddyStats};
pub use allocator::BuddyAllocator;
pub use metrics::{BuddyMetrics, BuddyMetricsSnapshot};
pub use manager::BuddyManager;

// -----------------------------------------------------------------------------
// Legacy global API (backward compatibility)
// -----------------------------------------------------------------------------

/// Global manager instance (legacy).
static GLOBAL_MANAGER: spin::Once<BuddyManager> = spin::Once::new();

/// Initialise the global buddy allocator.
pub fn init(base: Address, pages: usize) {
    GLOBAL_MANAGER.call_once(|| BuddyManager::default());
    let manager = GLOBAL_MANAGER.get().expect("buddy manager not initialised");
    manager.init(base, pages);
    let stats = manager.stats();
    crate::serial_println!(
        "  [BUDDY] {} pages ({} MB) available",
        stats.free_pages,
        stats.free_pages * DEFAULT_PAGE_SIZE / 1_048_576
    );
    crate::serial_println!(
        "  [BUDDY] init done tp={} fp={}",
        stats.total_pages,
        stats.free_pages
    );
}

/// Get a reference to the global manager (legacy).
fn global_manager() -> &'static BuddyManager {
    GLOBAL_MANAGER.get().expect("buddy manager not initialised")
}

/// Allocate 2^order pages.
pub fn alloc_pages(order: Order) -> Option<Address> {
    global_manager().alloc_pages(order).ok()
}

/// Free 2^order pages.
pub fn free_pages(addr: Address, order: Order) {
    let _ = global_manager().free_pages(addr, order);
}

/// Allocate a single page.
pub fn alloc_page() -> Option<Address> {
    alloc_pages(0)
}

/// Free a single page.
pub fn free_page(addr: Address) {
    free_pages(addr, 0);
}

/// Get statistics (total pages, free pages).
pub fn stats() -> (usize, usize) {
    let manager = global_manager();
    (manager.total_pages(), manager.free_pages())
}

/// Get full statistics.
pub fn full_stats() -> BuddyStats {
    global_manager().stats()
}

/// Reset the global allocator.
pub fn reset() {
    global_manager().reset();
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_region() {
        let config = BuddyConfig::default();
        let mut alloc = BuddyAllocator::new(&config);
        alloc.add_region(0x1000, 1024);
        assert_eq!(alloc.total_pages(), 1024);
        assert_eq!(alloc.free_pages(), 1024);
    }

    #[test]
    fn test_alloc_and_free() -> BuddyResult<()> {
        let config = BuddyConfig::default();
        let mut alloc = BuddyAllocator::new(&config);
        alloc.add_region(0x1000, 1024);

        let addr = alloc.alloc(2)?;
        assert_eq!(alloc.free_pages(), 1024 - 4);

        alloc.free(addr, 2)?;
        assert_eq!(alloc.free_pages(), 1024);
        Ok(())
    }

    #[test]
    fn test_largest_free_order() {
        let config = BuddyConfig::default();
        let mut alloc = BuddyAllocator::new(&config);
        alloc.add_region(0x1000, 1024);

        assert_eq!(alloc.largest_free_order(), Some(10)); // 2^10 = 1024 pages
        let addr = alloc.alloc(10).unwrap();
        assert_eq!(alloc.largest_free_order(), None);
        alloc.free(addr, 10).unwrap();
        assert_eq!(alloc.largest_free_order(), Some(10));
    }

    #[test]
    fn test_alloc_failure() {
        let config = BuddyConfig::default();
        let mut alloc = BuddyAllocator::new(&config);
        alloc.add_region(0x1000, 1); // only 1 page

        assert!(alloc.alloc(0).is_ok());
        assert!(alloc.alloc(0).is_err()); // no more pages
    }

    #[test]
    fn test_double_free() {
        let config = BuddyConfig::default();
        let mut alloc = BuddyAllocator::new(&config);
        alloc.add_region(0x1000, 8);

        let addr = alloc.alloc(0).unwrap();
        alloc.free(addr, 0).unwrap();
        assert!(alloc.free(addr, 0).is_err());
    }

    #[test]
    fn test_coalescing() -> BuddyResult<()> {
        let config = BuddyConfig::default();
        let mut alloc = BuddyAllocator::new(&config);
        alloc.add_region(0x1000, 8);

        let a = alloc.alloc(0)?; // page 0
        let b = alloc.alloc(0)?; // page 1
        let c = alloc.alloc(0)?; // page 2
        let d = alloc.alloc(0)?; // page 3

        // Free in reverse order to test coalescing.
        alloc.free(d, 0)?;
        alloc.free(c, 0)?;
        // At this point, pages 2-3 should coalesce into order 1.
        alloc.free(b, 0)?;
        // Pages 0-3 should coalesce into order 2 (4 pages).
        alloc.free(a, 0)?;

        // Should have one free block of order 2 (4 pages).
        assert_eq!(alloc.free_pages(), 8);
        assert_eq!(alloc.largest_free_order(), Some(3));
        Ok(())
    }

    #[test]
    fn test_stats() {
        let config = BuddyConfig::default();
        let mut alloc = BuddyAllocator::new(&config);
        alloc.add_region(0x1000, 1024);

        let stats = alloc.stats();
        assert_eq!(stats.total_pages, 1024);
        assert_eq!(stats.free_pages, 1024);
        assert_eq!(stats.allocated_pages, 0);
        assert_eq!(stats.largest_free_order, Some(10));

        alloc.alloc(2).unwrap();
        let stats2 = alloc.stats();
        assert_eq!(stats2.allocated_pages, 4);
        assert_eq!(stats2.free_pages, 1020);
    }

    #[test]
    fn test_reset() {
        let config = BuddyConfig::default();
        let mut alloc = BuddyAllocator::new(&config);
        alloc.add_region(0x1000, 1024);
        alloc.reset();
        assert_eq!(alloc.total_pages(), 0);
        assert_eq!(alloc.free_pages(), 0);
    }

    #[test]
    fn test_manager() -> BuddyResult<()> {
        let config = BuddyConfig::default();
        let manager = BuddyManager::new(config);
        manager.init(0x1000, 1024);
        assert!(manager.is_initialised());

        let addr = manager.alloc_pages(2)?;
        assert_eq!(manager.free_pages(), 1024 - 4);
        manager.free_pages(addr, 2)?;
        assert_eq!(manager.free_pages(), 1024);

        let stats = manager.stats();
        assert_eq!(stats.total_pages, 1024);
        assert_eq!(stats.free_pages, 1024);
        Ok(())
    }

    #[test]
    fn test_manager_metrics() -> BuddyResult<()> {
        let config = BuddyConfig::default();
        let manager = BuddyManager::new(config);
        manager.init(0x1000, 1024);

        let addr = manager.alloc_pages(2)?;
        manager.free_pages(addr, 2)?;

        let snap = manager.metrics_snapshot();
        assert_eq!(snap.allocations, 1);
        assert_eq!(snap.frees, 1);
        assert_eq!(snap.total_pages_allocated, 4);
        assert_eq!(snap.total_pages_freed, 4);
        Ok(())
    }

    #[test]
    fn test_invalid_order() {
        let config = BuddyConfig { max_order: 3, ..Default::default() };
        let mut alloc = BuddyAllocator::new(&config);
        alloc.add_region(0x1000, 8);

        assert!(alloc.alloc(3).is_err());
        assert!(alloc.free(0x1000, 3).is_err());
    }

    #[test]
    fn test_full_stats() {
        let config = BuddyConfig::default();
        let manager = BuddyManager::new(config);
        manager.init(0x1000, 1024);

        let stats = full_stats();
        assert_eq!(stats.total_pages, 1024);
        assert_eq!(stats.free_pages, 1024);
    }

    #[test]
    fn test_free_list_count() {
        let config = BuddyConfig::default();
        let mut alloc = BuddyAllocator::new(&config);
        alloc.add_region(0x1000, 1024);
        // Initially only the top order list is non-empty.
        assert_eq!(alloc.free_list_count(), 1);

        alloc.alloc(10).unwrap(); // allocate 1024 pages, should leave no free blocks.
        assert_eq!(alloc.free_list_count(), 0);
    }
}
