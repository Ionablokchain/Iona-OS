//! Slab allocator — O(1) fixed-size object allocation.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                          Slab Allocator Module                         │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   config    │    error     │    metrics    │        cache             │
//! │ (SlabCfg)   │ (SlabError)  │ (SlabMetrics) │ (SlabCache)              │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   manager   │    legacy    │               │                          │
//! │ (SlabManager)│ (global fns)│               │                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::memory::slab::{SlabManager, SlabConfig};
//!
//! let config = SlabConfig::default();
//! let manager = SlabManager::new(config);
//! manager.create_cache("my_obj", 128);
//! let ptr = manager.alloc("my_obj")?;
//! manager.free("my_obj", ptr);
//! ```

#![allow(dead_code)]

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Mutex, RwLock};
use tracing::{debug, info, trace, warn};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Page size in bytes.
pub const PAGE_SIZE: usize = 4096;

/// Physical offset for virtual address mapping.
pub const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;

/// Default slab cache sizes for common kernel objects.
pub const DEFAULT_CACHES: &[(&str, usize)] = &[
    ("task", 256),
    ("socket", 512),
    ("file", 128),
    ("inode", 192),
    ("dentry", 96),
    ("pipe", 64),
    ("page", 64),
    ("buffer", 256),
];

/// Minimum object size (8 bytes, padded to 16).
pub const MIN_OBJECT_SIZE: usize = 8;

/// Alignment requirement (16 bytes).
pub const OBJECT_ALIGN: usize = 16;

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for the slab allocator.
    use serde::{Deserialize, Serialize};
    use super::{PAGE_SIZE, DEFAULT_CACHES};

    /// Configuration for the slab allocator.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SlabConfig {
        pub page_size: usize,
        pub min_object_size: usize,
        pub object_align: usize,
        pub default_caches: Vec<(String, usize)>,
        pub collect_metrics: bool,
        pub log_operations: bool,
    }

    impl Default for SlabConfig {
        fn default() -> Self {
            Self {
                page_size: PAGE_SIZE,
                min_object_size: 8,
                object_align: 16,
                default_caches: DEFAULT_CACHES.iter().map(|(k, v)| ((*k).to_string(), *v)).collect(),
                collect_metrics: true,
                log_operations: false,
            }
        }
    }

    impl SlabConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.page_size == 0 {
                return Err("page_size must be > 0");
            }
            if self.min_object_size == 0 {
                return Err("min_object_size must be > 0");
            }
            if self.object_align == 0 {
                return Err("object_align must be > 0");
            }
            if self.page_size & (self.page_size - 1) != 0 {
                return Err("page_size must be a power of two");
            }
            if self.object_align & (self.object_align - 1) != 0 {
                return Err("object_align must be a power of two");
            }
            Ok(())
        }

        pub fn with_page_size(mut self, size: usize) -> Self {
            self.page_size = size;
            self
        }

        pub fn with_metrics(mut self) -> Self {
            self.collect_metrics = true;
            self
        }

        pub fn with_logging(mut self) -> Self {
            self.log_operations = true;
            self
        }
    }
}

pub mod error {
    //! Error types for the slab allocator.
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum SlabError {
        #[error("slab cache '{name}' not found")]
        CacheNotFound { name: String },

        #[error("cache '{name}' already exists")]
        CacheAlreadyExists { name: String },

        #[error("invalid object size {size}: must be >= {min}")]
        InvalidObjectSize { size: usize, min: usize },

        #[error("allocation failed for cache '{name}'")]
        AllocationFailed { name: String },

        #[error("double free detected in cache '{name}'")]
        DoubleFree { name: String },

        #[error("configuration error: {0}")]
        Config(String),
    }

    pub type SlabResult<T> = Result<T, SlabError>;
}

pub mod cache {
    //! Slab cache implementation.
    use super::{
        config::SlabConfig,
        error::{SlabError, SlabResult},
        metrics::SlabMetrics,
    };
    use alloc::vec::Vec;
    use core::ptr;
    use tracing::{debug, trace};

    /// Slab cache for fixed-size objects.
    pub struct SlabCache {
        /// Object size (aligned).
        obj_size: usize,
        /// Free list of object pointers.
        free_list: Vec<*mut u8>,
        /// Total objects allocated from pages.
        pub total: usize,
        /// Currently free objects.
        pub free: usize,
        /// Number of pages allocated.
        pages: usize,
        /// Name of the cache.
        name: String,
        /// Reference to the config.
        config: SlabConfig,
    }

    impl SlabCache {
        /// Create a new slab cache for objects of `size` bytes.
        pub fn new(name: &str, size: usize, config: &SlabConfig) -> SlabResult<Self> {
            if size < config.min_object_size {
                return Err(SlabError::InvalidObjectSize {
                    size,
                    min: config.min_object_size,
                });
            }
            // Align object size to the configured alignment.
            let obj_size = (size + config.object_align - 1) & !(config.object_align - 1);
            if obj_size > config.page_size {
                return Err(SlabError::InvalidObjectSize {
                    size,
                    min: config.min_object_size,
                });
            }
            Ok(Self {
                obj_size,
                free_list: Vec::new(),
                total: 0,
                free: 0,
                pages: 0,
                name: name.to_string(),
                config: config.clone(),
            })
        }

        /// Allocate a new page and add its objects to the free list.
        pub fn grow(&mut self, alloc_page_fn: impl Fn() -> Option<u64>) -> bool {
            let p = match alloc_page_fn() {
                Some(p) => p,
                None => return false,
            };
            let v = (super::PHYS_OFF + p) as *mut u8;
            let n = self.config.page_size / self.obj_size;
            for i in 0..n {
                unsafe {
                    self.free_list.push(v.add(i * self.obj_size));
                }
            }
            self.total += n;
            self.free += n;
            self.pages += 1;

            if self.config.log_operations {
                trace!(
                    cache = %self.name,
                    objects = n,
                    pages = self.pages,
                    "slab cache grew"
                );
            }
            true
        }

        /// Allocate an object from the cache.
        pub fn alloc(&mut self, alloc_page_fn: impl Fn() -> Option<u64>) -> Option<*mut u8> {
            if self.free_list.is_empty() {
                if !self.grow(alloc_page_fn) {
                    return None;
                }
            }
            let p = self.free_list.pop()?;
            self.free -= 1;
            unsafe {
                ptr::write_bytes(p, 0, self.obj_size);
            }
            Some(p)
        }

        /// Free an object back to the cache.
        pub fn free(&mut self, p: *mut u8) -> SlabResult<()> {
            if p.is_null() {
                return Ok(());
            }
            // Check if this pointer is already in the free list (double free detection).
            if self.free_list.contains(&p) {
                return Err(SlabError::DoubleFree {
                    name: self.name.clone(),
                });
            }
            self.free_list.push(p);
            self.free += 1;
            Ok(())
        }

        /// Get the object size.
        pub fn obj_size(&self) -> usize {
            self.obj_size
        }

        /// Get the number of pages allocated.
        pub fn pages(&self) -> usize {
            self.pages
        }

        /// Get the usage ratio (used / total).
        pub fn usage_ratio(&self) -> f64 {
            if self.total == 0 {
                0.0
            } else {
                (self.total - self.free) as f64 / self.total as f64
            }
        }

        /// Get the name of the cache.
        pub fn name(&self) -> &str {
            &self.name
        }

        /// Clear the cache (free all pages).
        pub fn clear(&mut self, free_page_fn: impl Fn(u64)) {
            // We don't track page addresses, so we just clear the free list.
            // In a real implementation, we would free the pages back to the buddy allocator.
            self.free_list.clear();
            self.total = 0;
            self.free = 0;
            self.pages = 0;
        }

        /// Merge with another cache's stats (for metrics).
        pub fn merge_stats(&self, target: &mut SlabStats) {
            target.total += self.total;
            target.free += self.free;
            target.pages += self.pages;
            target.name = self.name.clone();
        }
    }

    /// Statistics for a slab cache.
    #[derive(Debug, Clone, Default)]
    pub struct SlabStats {
        pub name: String,
        pub total: usize,
        pub free: usize,
        pub pages: usize,
    }

    impl fmt::Display for SlabStats {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let used = self.total - self.free;
            let usage = if self.total > 0 {
                (used as f64 / self.total as f64) * 100.0
            } else {
                0.0
            };
            write!(
                f,
                "{:>12}: total={:>6}, used={:>6}, free={:>6}, pages={:>4} ({:.1}%)",
                self.name, self.total, used, self.free, self.pages, usage
            )
        }
    }
}

pub mod metrics {
    //! Metrics for the slab allocator.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct SlabMetrics {
        pub allocations: AtomicU64,
        pub frees: AtomicU64,
        pub allocation_failures: AtomicU64,
        pub free_failures: AtomicU64,
        pub grows: AtomicU64,
        pub cache_creations: AtomicU64,
        pub cache_deletions: AtomicU64,
    }

    impl SlabMetrics {
        pub fn inc_alloc(&self) {
            self.allocations.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_free(&self) {
            self.frees.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_alloc_failure(&self) {
            self.allocation_failures.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_free_failure(&self) {
            self.free_failures.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_grow(&self) {
            self.grows.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_cache_creation(&self) {
            self.cache_creations.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_cache_deletion(&self) {
            self.cache_deletions.fetch_add(1, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> SlabMetricsSnapshot {
            SlabMetricsSnapshot {
                allocations: self.allocations.load(Ordering::Relaxed),
                frees: self.frees.load(Ordering::Relaxed),
                allocation_failures: self.allocation_failures.load(Ordering::Relaxed),
                free_failures: self.free_failures.load(Ordering::Relaxed),
                grows: self.grows.load(Ordering::Relaxed),
                cache_creations: self.cache_creations.load(Ordering::Relaxed),
                cache_deletions: self.cache_deletions.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SlabMetricsSnapshot {
        pub allocations: u64,
        pub frees: u64,
        pub allocation_failures: u64,
        pub free_failures: u64,
        pub grows: u64,
        pub cache_creations: u64,
        pub cache_deletions: u64,
    }
}

pub mod manager {
    //! Centralised manager for slab caches.
    use super::{
        config::SlabConfig,
        error::{SlabError, SlabResult},
        cache::{SlabCache, SlabStats},
        metrics::SlabMetrics,
    };
    use alloc::{
        collections::BTreeMap,
        string::{String, ToString},
        vec::Vec,
    };
    use core::sync::atomic::Ordering;
    use spin::Mutex;
    use tracing::{debug, info, warn};

    /// Page allocation function type.
    pub type AllocPageFn = dyn Fn() -> Option<u64> + Send + Sync;
    /// Page free function type.
    pub type FreePageFn = dyn Fn(u64) + Send + Sync;

    /// Centralised manager for slab caches.
    pub struct SlabManager {
        config: SlabConfig,
        caches: Mutex<BTreeMap<String, SlabCache>>,
        metrics: SlabMetrics,
        alloc_page_fn: Box<AllocPageFn>,
        free_page_fn: Box<FreePageFn>,
    }

    impl SlabManager {
        /// Create a new slab manager with the given configuration.
        pub fn new(
            config: SlabConfig,
            alloc_page_fn: impl Fn() -> Option<u64> + Send + Sync + 'static,
            free_page_fn: impl Fn(u64) + Send + Sync + 'static,
        ) -> Self {
            config.validate().expect("invalid SlabConfig");
            let mut manager = Self {
                config,
                caches: Mutex::new(BTreeMap::new()),
                metrics: SlabMetrics::default(),
                alloc_page_fn: Box::new(alloc_page_fn),
                free_page_fn: Box::new(free_page_fn),
            };

            // Create default caches.
            for (name, size) in &manager.config.default_caches {
                let _ = manager.create_cache(name, *size);
            }

            info!(
                caches = manager.config.default_caches.len(),
                "slab manager initialized"
            );
            manager
        }

        /// Create a manager with default configuration and functions.
        pub fn default_with_functions() -> Self {
            #[cfg(feature = "buddy")]
            {
                Self::new(
                    SlabConfig::default(),
                    || crate::mm::buddy::alloc_page(),
                    |p| crate::mm::buddy::free_page(p),
                )
            }
            #[cfg(not(feature = "buddy"))]
            {
                // Stub implementation when buddy is not available.
                Self::new(
                    SlabConfig::default(),
                    || Some(0x1000),
                    |_| {},
                )
            }
        }

        /// Get a reference to the metrics.
        pub fn metrics(&self) -> &SlabMetrics {
            &self.metrics
        }

        /// Get the configuration.
        pub fn config(&self) -> &SlabConfig {
            &self.config
        }

        /// Create a new slab cache.
        pub fn create_cache(&self, name: &str, size: usize) -> SlabResult<()> {
            let mut caches = self.caches.lock();
            if caches.contains_key(name) {
                return Err(SlabError::CacheAlreadyExists {
                    name: name.to_string(),
                });
            }
            let cache = SlabCache::new(name, size, &self.config)?;
            caches.insert(name.to_string(), cache);
            self.metrics.inc_cache_creation();
            if self.config.log_operations {
                info!(name, size, "slab cache created");
            }
            Ok(())
        }

        /// Get a reference to a slab cache.
        fn get_cache(&self, name: &str) -> SlabResult<&SlabCache> {
            let caches = self.caches.lock();
            caches.get(name).ok_or_else(|| SlabError::CacheNotFound {
                name: name.to_string(),
            })
        }

        /// Get a mutable reference to a slab cache.
        fn get_cache_mut(&self, name: &str) -> SlabResult<&mut SlabCache> {
            let mut caches = self.caches.lock();
            caches.get_mut(name).ok_or_else(|| SlabError::CacheNotFound {
                name: name.to_string(),
            })
        }

        /// Allocate an object from the specified cache.
        pub fn alloc(&self, name: &str) -> SlabResult<*mut u8> {
            let cache = self.get_cache_mut(name)?;
            match cache.alloc(&self.alloc_page_fn) {
                Some(ptr) => {
                    self.metrics.inc_alloc();
                    if self.config.log_operations {
                        trace!(name, ptr = ptr as u64, "slab allocated");
                    }
                    Ok(ptr)
                }
                None => {
                    self.metrics.inc_alloc_failure();
                    Err(SlabError::AllocationFailed {
                        name: name.to_string(),
                    })
                }
            }
        }

        /// Free an object back to its cache.
        pub fn free(&self, name: &str, ptr: *mut u8) -> SlabResult<()> {
            let cache = self.get_cache_mut(name)?;
            match cache.free(ptr) {
                Ok(()) => {
                    self.metrics.inc_free();
                    if self.config.log_operations {
                        trace!(name, ptr = ptr as u64, "slab freed");
                    }
                    Ok(())
                }
                Err(e) => {
                    self.metrics.inc_free_failure();
                    Err(e)
                }
            }
        }

        /// Delete a slab cache.
        pub fn delete_cache(&self, name: &str) -> SlabResult<()> {
            let mut caches = self.caches.lock();
            if let Some(mut cache) = caches.remove(name) {
                cache.clear(&self.free_page_fn);
                self.metrics.inc_cache_deletion();
                if self.config.log_operations {
                    info!(name, "slab cache deleted");
                }
                Ok(())
            } else {
                Err(SlabError::CacheNotFound {
                    name: name.to_string(),
                })
            }
        }

        /// Get statistics for a specific cache.
        pub fn cache_stats(&self, name: &str) -> SlabResult<SlabStats> {
            let cache = self.get_cache(name)?;
            let mut stats = SlabStats::default();
            cache.merge_stats(&mut stats);
            Ok(stats)
        }

        /// Get statistics for all caches.
        pub fn all_stats(&self) -> Vec<SlabStats> {
            let caches = self.caches.lock();
            let mut stats = Vec::with_capacity(caches.len());
            for (_, cache) in caches.iter() {
                let mut s = SlabStats::default();
                cache.merge_stats(&mut s);
                stats.push(s);
            }
            stats
        }

        /// Get total memory used by all caches.
        pub fn total_memory_used(&self) -> usize {
            let caches = self.caches.lock();
            caches.values().map(|c| c.pages() * self.config.page_size).sum()
        }

        /// Get the number of caches.
        pub fn cache_count(&self) -> usize {
            self.caches.lock().len()
        }

        /// Check if a cache exists.
        pub fn cache_exists(&self, name: &str) -> bool {
            self.caches.lock().contains_key(name)
        }

        /// Reset all caches (for testing).
        pub fn reset(&self) {
            let mut caches = self.caches.lock();
            for (_, cache) in caches.iter_mut() {
                cache.clear(&self.free_page_fn);
            }
            caches.clear();
            // Re-create default caches.
            for (name, size) in &self.config.default_caches {
                let _ = self.create_cache(name, *size);
            }
        }

        /// Get metrics snapshot.
        pub fn metrics_snapshot(&self) -> super::metrics::SlabMetricsSnapshot {
            self.metrics.snapshot()
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::SlabConfig;
pub use error::{SlabError, SlabResult};
pub use cache::{SlabCache, SlabStats};
pub use metrics::{SlabMetrics, SlabMetricsSnapshot};
pub use manager::SlabManager;

// -----------------------------------------------------------------------------
// Legacy global API (backward compatibility)
// -----------------------------------------------------------------------------

/// Global manager instance.
static GLOBAL_MANAGER: spin::Once<SlabManager> = spin::Once::new();

/// Initialise the global slab allocator.
pub fn init() {
    GLOBAL_MANAGER.call_once(|| {
        #[cfg(feature = "buddy")]
        {
            SlabManager::default_with_functions()
        }
        #[cfg(not(feature = "buddy"))]
        {
            SlabManager::new(
                SlabConfig::default(),
                || Some(0x1000),
                |_| {},
            )
        }
    });
    let manager = GLOBAL_MANAGER.get().expect("slab manager not initialised");
    crate::serial_println!(
        "  [SLAB] caches: {}",
        manager.all_stats().iter().map(|s| s.name.clone()).collect::<Vec<_>>().join("/")
    );
}

/// Get a reference to the global manager.
fn global_manager() -> &'static SlabManager {
    GLOBAL_MANAGER.get().expect("slab manager not initialised")
}

/// Allocate an object from the specified cache.
pub fn alloc(name: &str) -> Option<*mut u8> {
    global_manager().alloc(name).ok()
}

/// Free an object back to its cache.
pub fn free(name: &str, ptr: *mut u8) {
    let _ = global_manager().free(name, ptr);
}

/// Create a new slab cache.
pub fn create_cache(name: &str, size: usize) {
    let _ = global_manager().create_cache(name, size);
}

/// Delete a slab cache.
pub fn delete_cache(name: &str) {
    let _ = global_manager().delete_cache(name);
}

/// Get statistics for all caches.
pub fn all_stats() -> Vec<SlabStats> {
    global_manager().all_stats()
}

/// Get statistics for a specific cache.
pub fn cache_stats(name: &str) -> Option<SlabStats> {
    global_manager().cache_stats(name).ok()
}

/// Get total memory used.
pub fn total_memory_used() -> usize {
    global_manager().total_memory_used()
}

/// Get metrics snapshot.
pub fn metrics() -> SlabMetricsSnapshot {
    global_manager().metrics_snapshot()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_alloc_page() -> Option<u64> {
        Some(0x1000)
    }

    fn test_free_page(_p: u64) {}

    #[test]
    fn test_slab_cache_new() -> SlabResult<()> {
        let config = SlabConfig::default();
        let cache = SlabCache::new("test", 64, &config)?;
        assert_eq!(cache.obj_size(), 64);
        assert_eq!(cache.total, 0);
        assert_eq!(cache.free, 0);
        Ok(())
    }

    #[test]
    fn test_slab_cache_grow() {
        let config = SlabConfig::default();
        let mut cache = SlabCache::new("test", 64, &config).unwrap();
        let result = cache.grow(test_alloc_page);
        assert!(result);
        assert_eq!(cache.total, config.page_size / 64);
        assert_eq!(cache.free, config.page_size / 64);
        assert_eq!(cache.pages(), 1);
    }

    #[test]
    fn test_slab_cache_alloc_and_free() -> SlabResult<()> {
        let config = SlabConfig::default();
        let mut cache = SlabCache::new("test", 64, &config).unwrap();
        cache.grow(test_alloc_page);

        let p = cache.alloc(test_alloc_page).unwrap();
        assert!(!p.is_null());
        assert_eq!(cache.free, (config.page_size / 64) - 1);

        cache.free(p)?;
        assert_eq!(cache.free, config.page_size / 64);
        Ok(())
    }

    #[test]
    fn test_double_free_detection() -> SlabResult<()> {
        let config = SlabConfig::default();
        let mut cache = SlabCache::new("test", 64, &config).unwrap();
        cache.grow(test_alloc_page);

        let p = cache.alloc(test_alloc_page).unwrap();
        cache.free(p)?;
        let result = cache.free(p);
        assert!(matches!(result, Err(SlabError::DoubleFree { .. })));
        Ok(())
    }

    #[test]
    fn test_slab_stats() -> SlabResult<()> {
        let config = SlabConfig::default();
        let mut cache = SlabCache::new("test", 64, &config).unwrap();
        cache.grow(test_alloc_page);

        let mut stats = SlabStats::default();
        cache.merge_stats(&mut stats);
        assert_eq!(stats.total, config.page_size / 64);
        assert_eq!(stats.free, config.page_size / 64);
        assert_eq!(stats.pages, 1);
        Ok(())
    }

    #[test]
    fn test_manager_create_cache() -> SlabResult<()> {
        let manager = SlabManager::new(SlabConfig::default(), test_alloc_page, test_free_page);
        manager.create_cache("test", 64)?;
        assert!(manager.cache_exists("test"));
        Ok(())
    }

    #[test]
    fn test_manager_duplicate_cache_fails() -> SlabResult<()> {
        let manager = SlabManager::new(SlabConfig::default(), test_alloc_page, test_free_page);
        manager.create_cache("test", 64)?;
        let result = manager.create_cache("test", 128);
        assert!(matches!(result, Err(SlabError::CacheAlreadyExists { .. })));
        Ok(())
    }

    #[test]
    fn test_manager_alloc_and_free() -> SlabResult<()> {
        let manager = SlabManager::new(SlabConfig::default(), test_alloc_page, test_free_page);
        manager.create_cache("test", 64)?;
        let p = manager.alloc("test")?;
        assert!(!p.is_null());
        manager.free("test", p)?;
        Ok(())
    }

    #[test]
    fn test_manager_cache_not_found() {
        let manager = SlabManager::new(SlabConfig::default(), test_alloc_page, test_free_page);
        let result = manager.alloc("nonexistent");
        assert!(matches!(result, Err(SlabError::CacheNotFound { .. })));
    }

    #[test]
    fn test_manager_delete_cache() -> SlabResult<()> {
        let manager = SlabManager::new(SlabConfig::default(), test_alloc_page, test_free_page);
        manager.create_cache("test", 64)?;
        manager.delete_cache("test")?;
        assert!(!manager.cache_exists("test"));
        Ok(())
    }

    #[test]
    fn test_manager_all_stats() -> SlabResult<()> {
        let manager = SlabManager::new(SlabConfig::default(), test_alloc_page, test_free_page);
        manager.create_cache("test1", 64)?;
        manager.create_cache("test2", 128)?;
        let stats = manager.all_stats();
        assert_eq!(stats.len(), 2 + manager.config.default_caches.len());
        Ok(())
    }

    #[test]
    fn test_manager_total_memory() -> SlabResult<()> {
        let manager = SlabManager::new(SlabConfig::default(), test_alloc_page, test_free_page);
        manager.create_cache("test", 64)?;
        manager.alloc("test")?;
        let mem = manager.total_memory_used();
        assert!(mem > 0);
        Ok(())
    }
}
