//! Redb → IONAFS storage backend — production implementation.
//!
//! This module provides a persistent storage backend for the Redb database
//! using IONA’s native file system (`IONAFS`). It maps Redb’s page‑based I/O
//! to individual files in the IONAFS directory.
//!
//! # Layout
//! ```text
//! /db/{name}/super       — database superblock (16 bytes: num_pages, page_size)
//! /db/{name}/p{N}        — page N (exactly `PAGE_SIZE` bytes, default 4 KiB)
//! ```
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                       Redb Adapter Module                              │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   config    │    error     │    metrics    │        cache             │
//! │ (AdapterCfg)│ (AdapterError)│ (metrics)    │ (LRU page cache)         │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │               db (IonafsDatabaseFile)                                 │
//! │              (page I/O, flushing, growth)                             │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │               manager (RedbManager)                                   │
//! │              (centralised database management)                        │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::blockchain::redb_adapter::{RedbManager, RedbAdapterConfig};
//!
//! let config = RedbAdapterConfig::default();
//! let manager = RedbManager::new(config);
//! let db = manager.open("my_database")?;
//! let data = db.read_at(0, 4096)?;
//! db.write_at(4096, b"hello")?;
//! db.flush()?;
//! ```

#![allow(dead_code)]

use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::cmp::min;
use core::sync::atomic::{AtomicU64, Ordering};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod constants {
    //! Constants for the Redb adapter.
    /// Page size used by Redb (must match the underlying storage).
    pub const PAGE_SIZE: usize = 4096;

    /// Default number of pages to keep in the LRU read cache.
    pub const DEFAULT_CACHE_SIZE: usize = 64;

    /// Superblock layout: [num_pages (8 bytes), page_size (8 bytes)]
    pub const SUPERBLOCK_SIZE: usize = 16;

    /// Default flush interval (milliseconds).
    pub const DEFAULT_FLUSH_INTERVAL_MS: u64 = 1000;

    /// Maximum number of dirty pages before forcing a flush.
    pub const DEFAULT_MAX_DIRTY_PAGES: usize = 1024;
}

pub mod config {
    //! Configuration for the Redb adapter.
    use serde::{Deserialize, Serialize};
    use super::constants::*;

    /// Configuration for the Redb adapter.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RedbAdapterConfig {
        pub cache_size: usize,
        pub flush_interval_ms: u64,
        pub max_dirty_pages: usize,
        pub sync_on_flush: bool,
        pub trace_operations: bool,
        pub collect_metrics: bool,
    }

    impl Default for RedbAdapterConfig {
        fn default() -> Self {
            Self {
                cache_size: DEFAULT_CACHE_SIZE,
                flush_interval_ms: DEFAULT_FLUSH_INTERVAL_MS,
                max_dirty_pages: DEFAULT_MAX_DIRTY_PAGES,
                sync_on_flush: true,
                trace_operations: false,
                collect_metrics: true,
            }
        }
    }

    impl RedbAdapterConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.cache_size == 0 {
                return Err("cache_size must be > 0");
            }
            if self.flush_interval_ms == 0 {
                return Err("flush_interval_ms must be > 0");
            }
            if self.max_dirty_pages == 0 {
                return Err("max_dirty_pages must be > 0");
            }
            Ok(())
        }

        pub fn with_trace(mut self) -> Self {
            self.trace_operations = true;
            self
        }

        pub fn with_metrics(mut self) -> Self {
            self.collect_metrics = true;
            self
        }

        pub fn with_cache_size(mut self, size: usize) -> Self {
            self.cache_size = size;
            self
        }
    }
}

pub mod error {
    //! Error types for the Redb adapter.
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum RedbAdapterError {
        #[error("I/O error: {0}")]
        Io(String),

        #[error("superblock corrupted: {0}")]
        CorruptedSuperblock(String),

        #[error("page {page} not found")]
        PageNotFound { page: u64 },

        #[error("offset {offset} out of bounds (file size {size})")]
        OutOfBounds { offset: u64, size: u64 },

        #[error("invalid page size: expected {expected}, got {actual}")]
        InvalidPageSize { expected: usize, actual: usize },

        #[error("cache capacity must be > 0")]
        InvalidCacheCapacity,

        #[error("flush interval must be > 0")]
        InvalidFlushInterval,

        #[error("database is closed")]
        Closed,

        #[error("database already exists")]
        AlreadyExists,

        #[error("database not found")]
        NotFound,

        #[error("internal error: {0}")]
        Internal(String),
    }

    pub type RedbAdapterResult<T> = Result<T, RedbAdapterError>;
}

pub mod metrics {
    //! Metrics for the Redb adapter.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct RedbAdapterMetrics {
        pub reads: AtomicU64,
        pub writes: AtomicU64,
        pub cache_hits: AtomicU64,
        pub cache_misses: AtomicU64,
        pub flushes: AtomicU64,
        pub pages_read: AtomicU64,
        pub pages_written: AtomicU64,
        pub grows: AtomicU64,
        pub opens: AtomicU64,
        pub closes: AtomicU64,
    }

    impl RedbAdapterMetrics {
        pub fn record_read(&self) {
            self.reads.fetch_add(1, Ordering::Relaxed);
        }
        pub fn record_write(&self) {
            self.writes.fetch_add(1, Ordering::Relaxed);
        }
        pub fn record_cache_hit(&self) {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
        }
        pub fn record_cache_miss(&self) {
            self.cache_misses.fetch_add(1, Ordering::Relaxed);
        }
        pub fn record_flush(&self) {
            self.flushes.fetch_add(1, Ordering::Relaxed);
        }
        pub fn record_page_read(&self) {
            self.pages_read.fetch_add(1, Ordering::Relaxed);
        }
        pub fn record_page_write(&self) {
            self.pages_written.fetch_add(1, Ordering::Relaxed);
        }
        pub fn record_grow(&self) {
            self.grows.fetch_add(1, Ordering::Relaxed);
        }
        pub fn record_open(&self) {
            self.opens.fetch_add(1, Ordering::Relaxed);
        }
        pub fn record_close(&self) {
            self.closes.fetch_add(1, Ordering::Relaxed);
        }

        pub fn hit_ratio(&self) -> f64 {
            let hits = self.cache_hits.load(Ordering::Relaxed);
            let misses = self.cache_misses.load(Ordering::Relaxed);
            let total = hits + misses;
            if total == 0 {
                1.0
            } else {
                hits as f64 / total as f64
            }
        }

        pub fn snapshot(&self) -> RedbAdapterMetricsSnapshot {
            RedbAdapterMetricsSnapshot {
                reads: self.reads.load(Ordering::Relaxed),
                writes: self.writes.load(Ordering::Relaxed),
                cache_hits: self.cache_hits.load(Ordering::Relaxed),
                cache_misses: self.cache_misses.load(Ordering::Relaxed),
                flushes: self.flushes.load(Ordering::Relaxed),
                pages_read: self.pages_read.load(Ordering::Relaxed),
                pages_written: self.pages_written.load(Ordering::Relaxed),
                grows: self.grows.load(Ordering::Relaxed),
                opens: self.opens.load(Ordering::Relaxed),
                closes: self.closes.load(Ordering::Relaxed),
                hit_ratio: self.hit_ratio(),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RedbAdapterMetricsSnapshot {
        pub reads: u64,
        pub writes: u64,
        pub cache_hits: u64,
        pub cache_misses: u64,
        pub flushes: u64,
        pub pages_read: u64,
        pub pages_written: u64,
        pub grows: u64,
        pub opens: u64,
        pub closes: u64,
        pub hit_ratio: f64,
    }
}

pub mod cache {
    //! LRU page cache for the Redb adapter.
    use super::constants::PAGE_SIZE;
    use alloc::{
        collections::BTreeMap,
        vec::Vec,
    };

    /// A simple LRU cache for database pages.
    #[derive(Debug, Default)]
    pub struct PageCache {
        pages: BTreeMap<u64, Vec<u8>>,
        order: Vec<u64>,
        capacity: usize,
    }

    impl PageCache {
        pub fn new(capacity: usize) -> Self {
            Self {
                pages: BTreeMap::new(),
                order: Vec::with_capacity(capacity),
                capacity,
            }
        }

        pub fn get(&self, page: u64) -> Option<&Vec<u8>> {
            self.pages.get(&page)
        }

        pub fn insert(&mut self, page: u64, data: Vec<u8>) -> Option<u64> {
            let mut evicted = None;

            if self.pages.contains_key(&page) {
                self.order.retain(|&p| p != page);
            } else if self.pages.len() >= self.capacity {
                if let Some(&lru) = self.order.first() {
                    self.order.remove(0);
                    self.pages.remove(&lru);
                    evicted = Some(lru);
                }
            }

            self.pages.insert(page, data);
            self.order.push(page);
            evicted
        }

        pub fn invalidate(&mut self, page: u64) {
            self.pages.remove(&page);
            self.order.retain(|&p| p != page);
        }

        pub fn clear(&mut self) {
            self.pages.clear();
            self.order.clear();
        }

        pub fn len(&self) -> usize {
            self.pages.len()
        }

        pub fn is_empty(&self) -> bool {
            self.pages.is_empty()
        }

        pub fn capacity(&self) -> usize {
            self.capacity
        }

        pub fn contains(&self, page: u64) -> bool {
            self.pages.contains_key(&page)
        }
    }
}

pub mod db {
    //! Database file handle for Redb in IONAFS.
    use super::{
        config::RedbAdapterConfig,
        error::{RedbAdapterError, RedbAdapterResult},
        metrics::RedbAdapterMetrics,
        cache::PageCache,
        constants::{PAGE_SIZE, SUPERBLOCK_SIZE},
    };
    use alloc::{
        collections::BTreeMap,
        format,
        string::{String, ToString},
        vec::Vec,
    };
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, RwLock};
    use tracing::{debug, info, trace, warn};

    /// A handle to a Redb database stored in IONAFS.
    #[derive(Clone)]
    pub struct IonafsDatabaseFile {
        db_name: String,
        num_pages: Arc<AtomicU64>,
        cache: Arc<RwLock<PageCache>>,
        dirty: Arc<RwLock<BTreeMap<u64, Vec<u8>>>>,
        config: RedbAdapterConfig,
        metrics: Arc<RedbAdapterMetrics>,
        closed: Arc<AtomicU64>,
    }

    impl IonafsDatabaseFile {
        /// Open an existing database. If the superblock is missing,
        /// assumes an empty database (zero pages).
        pub fn open(db_name: &str, config: RedbAdapterConfig) -> RedbAdapterResult<Self> {
            config.validate().map_err(|e| RedbAdapterError::Internal(e.to_string()))?;

            let super_path = format!("/db/{}/super", db_name);
            let num_pages = crate::fs::ionafs::read(&super_path)
                .and_then(|data| {
                    if data.len() >= SUPERBLOCK_SIZE {
                        let bytes = data[0..8].try_into().unwrap_or([0u8; 8]);
                        Some(u64::from_le_bytes(bytes))
                    } else {
                        None
                    }
                })
                .unwrap_or(0);

            info!(
                db_name,
                num_pages,
                cache_size = config.cache_size,
                "opened Redb database"
            );

            let metrics = Arc::new(RedbAdapterMetrics::default());
            metrics.record_open();

            Ok(Self {
                db_name: db_name.into(),
                num_pages: Arc::new(AtomicU64::new(num_pages)),
                cache: Arc::new(RwLock::new(PageCache::new(config.cache_size))),
                dirty: Arc::new(RwLock::new(BTreeMap::new())),
                config,
                metrics,
                closed: Arc::new(AtomicU64::new(0)),
            })
        }

        /// Create a new empty database.
        pub fn create(db_name: &str, config: RedbAdapterConfig) -> RedbAdapterResult<Self> {
            // Check if it already exists.
            if crate::fs::ionafs::exists(&format!("/db/{}/super", db_name)) {
                return Err(RedbAdapterError::AlreadyExists);
            }
            let mut db = Self::open(db_name, config)?;
            db.grow_to(2 * PAGE_SIZE as u64)?;
            info!(db_name, "created new Redb database");
            Ok(db)
        }

        /// Total database size in bytes.
        pub fn len(&self) -> u64 {
            self.num_pages.load(Ordering::Relaxed) * PAGE_SIZE as u64
        }

        pub fn is_empty(&self) -> bool {
            self.num_pages.load(Ordering::Relaxed) == 0
        }

        /// Read bytes from the database at a given offset.
        pub fn read_at(&self, offset: u64, len: usize) -> RedbAdapterResult<Vec<u8>> {
            if self.is_closed() {
                return Err(RedbAdapterError::Closed);
            }

            let file_size = self.len();
            if offset >= file_size {
                return Ok(vec![0u8; len]);
            }

            self.metrics.record_read();
            let mut result = Vec::with_capacity(len);
            let mut pos = offset;
            while result.len() < len {
                let page = pos / PAGE_SIZE as u64;
                let off_in = (pos % PAGE_SIZE as u64) as usize;
                let can_read = (PAGE_SIZE - off_in).min(len - result.len());

                let page_data = self.read_page(page)?;
                let end = (off_in + can_read).min(page_data.len());
                result.extend_from_slice(&page_data[off_in..end]);
                pos += can_read as u64;
            }
            Ok(result)
        }

        /// Write bytes to the database at a given offset.
        pub fn write_at(&self, offset: u64, data: &[u8]) -> RedbAdapterResult<()> {
            if self.is_closed() {
                return Err(RedbAdapterError::Closed);
            }

            self.metrics.record_write();
            let end_offset = offset + data.len() as u64;
            if end_offset > self.len() {
                self.grow_to(end_offset)?;
            }

            let mut pos = offset;
            let mut src = 0;
            while src < data.len() {
                let page = pos / PAGE_SIZE as u64;
                let off_in = (pos % PAGE_SIZE as u64) as usize;
                let can_write = (PAGE_SIZE - off_in).min(data.len() - src);

                let mut page_data = self.read_page(page)?;
                if page_data.len() < PAGE_SIZE {
                    page_data.resize(PAGE_SIZE, 0);
                }
                page_data[off_in..off_in + can_write].copy_from_slice(&data[src..src + can_write]);

                {
                    let mut cache = self.cache.write().unwrap();
                    cache.insert(page, page_data.clone());
                }
                {
                    let mut dirty = self.dirty.write().unwrap();
                    dirty.insert(page, page_data);
                    if dirty.len() >= self.config.max_dirty_pages {
                        drop(dirty);
                        self.flush()?;
                    }
                }

                pos += can_write as u64;
                src += can_write;
            }
            Ok(())
        }

        /// Flush all dirty pages to durable storage.
        pub fn flush(&self) -> RedbAdapterResult<()> {
            if self.is_closed() {
                return Err(RedbAdapterError::Closed);
            }

            let dirty_pages: Vec<(u64, Vec<u8>)> = {
                let dirty = self.dirty.read().unwrap();
                dirty.iter().map(|(k, v)| (*k, v.clone())).collect()
            };

            if dirty_pages.is_empty() {
                return Ok(());
            }

            let mut dirty_write = self.dirty.write().unwrap();
            for (page, data) in &dirty_pages {
                let path = format!("/db/{}/p{}", self.db_name, page);
                crate::fs::ionafs::write(&path, data);
                if self.config.sync_on_flush {
                    crate::fs::ionafs::sync_to_disk();
                }
                dirty_write.remove(page);
                self.metrics.record_page_write();
            }
            self.metrics.record_flush();
            self.write_superblock()?;

            if self.config.trace_operations {
                debug!(db = %self.db_name, pages = dirty_pages.len(), "flushed dirty pages");
            }
            Ok(())
        }

        /// Force a full sync of all data to disk.
        pub fn sync_all(&self) -> RedbAdapterResult<()> {
            self.flush()?;
            crate::fs::ionafs::sync_to_disk();
            Ok(())
        }

        /// Close the database, flushing all pending writes.
        pub fn close(&self) -> RedbAdapterResult<()> {
            if self.is_closed() {
                return Ok(());
            }
            self.flush()?;
            self.closed.store(1, Ordering::Release);
            self.metrics.record_close();
            info!(db = %self.db_name, "closed Redb database");
            Ok(())
        }

        pub fn is_closed(&self) -> bool {
            self.closed.load(Ordering::Acquire) == 1
        }

        /// Grow the database to at least `new_size` bytes.
        pub fn grow_to(&self, new_size: u64) -> RedbAdapterResult<()> {
            if self.is_closed() {
                return Err(RedbAdapterError::Closed);
            }

            let new_pages = (new_size + PAGE_SIZE as u64 - 1) / PAGE_SIZE as u64;
            let current_pages = self.num_pages.load(Ordering::Relaxed);
            if new_pages <= current_pages {
                return Ok(());
            }

            for page in current_pages..new_pages {
                let path = format!("/db/{}/p{}", self.db_name, page);
                let zero_page = vec![0u8; PAGE_SIZE];
                crate::fs::ionafs::write(&path, &zero_page);
                self.metrics.record_page_write();
            }
            self.num_pages.store(new_pages, Ordering::Release);
            self.metrics.record_grow();
            self.write_superblock()?;

            if self.config.trace_operations {
                debug!(
                    db = %self.db_name,
                    current_pages,
                    new_pages,
                    "grew database"
                );
            }
            Ok(())
        }

        /// Get a reference to the metrics.
        pub fn metrics(&self) -> &RedbAdapterMetrics {
            &self.metrics
        }

        /// Get the database name.
        pub fn name(&self) -> &str {
            &self.db_name
        }

        /// Get the current number of pages.
        pub fn num_pages(&self) -> u64 {
            self.num_pages.load(Ordering::Relaxed)
        }

        // ---------------------------------------------------------------------
        // Private helpers
        // ---------------------------------------------------------------------

        fn read_page(&self, page: u64) -> RedbAdapterResult<Vec<u8>> {
            {
                let dirty = self.dirty.read().unwrap();
                if let Some(data) = dirty.get(&page) {
                    return Ok(data.clone());
                }
            }

            {
                let cache = self.cache.read().unwrap();
                if let Some(data) = cache.get(page) {
                    self.metrics.record_cache_hit();
                    return Ok(data.clone());
                }
            }

            self.metrics.record_cache_miss();

            let path = format!("/db/{}/p{}", self.db_name, page);
            let data = crate::fs::ionafs::read(&path)
                .unwrap_or_else(|| vec![0u8; PAGE_SIZE]);
            self.metrics.record_page_read();

            {
                let mut cache = self.cache.write().unwrap();
                cache.insert(page, data.clone());
            }
            Ok(data)
        }

        fn write_superblock(&self) -> RedbAdapterResult<()> {
            let num_pages = self.num_pages.load(Ordering::Relaxed);
            let mut sb = [0u8; SUPERBLOCK_SIZE];
            sb[0..8].copy_from_slice(&num_pages.to_le_bytes());
            sb[8..16].copy_from_slice(&(PAGE_SIZE as u64).to_le_bytes());
            crate::fs::ionafs::write(&format!("/db/{}/super", self.db_name), &sb);
            if self.config.sync_on_flush {
                crate::fs::ionafs::sync_to_disk();
            }
            Ok(())
        }
    }

    impl Drop for IonafsDatabaseFile {
        fn drop(&mut self) {
            if !self.is_closed() {
                let _ = self.close();
            }
        }
    }
}

pub mod manager {
    //! Centralised manager for Redb databases.
    use super::{
        config::RedbAdapterConfig,
        error::{RedbAdapterError, RedbAdapterResult},
        db::IonafsDatabaseFile,
        metrics::RedbAdapterMetrics,
    };
    use alloc::{
        collections::BTreeMap,
        string::{String, ToString},
        sync::Arc,
    };
    use std::sync::RwLock;
    use tracing::{debug, info, warn};

    /// Centralised manager for Redb databases.
    #[derive(Clone)]
    pub struct RedbManager {
        config: RedbAdapterConfig,
        databases: Arc<RwLock<BTreeMap<String, IonafsDatabaseFile>>>,
        metrics: Arc<RedbAdapterMetrics>,
    }

    impl RedbManager {
        /// Create a new Redb manager with the given configuration.
        pub fn new(config: RedbAdapterConfig) -> RedbAdapterResult<Self> {
            config.validate().map_err(|e| RedbAdapterError::Internal(e.to_string()))?;
            info!(
                cache_size = config.cache_size,
                flush_interval_ms = config.flush_interval_ms,
                "Redb manager created"
            );
            Ok(Self {
                config,
                databases: Arc::new(RwLock::new(BTreeMap::new())),
                metrics: Arc::new(RedbAdapterMetrics::default()),
            })
        }

        /// Create a manager with default configuration.
        pub fn default() -> Self {
            Self::new(RedbAdapterConfig::default()).expect("default Redb manager")
        }

        /// Get the configuration.
        pub fn config(&self) -> &RedbAdapterConfig {
            &self.config
        }

        /// Update the configuration at runtime.
        pub fn set_config(&mut self, config: RedbAdapterConfig) -> RedbAdapterResult<()> {
            config.validate().map_err(|e| RedbAdapterError::Internal(e.to_string()))?;
            self.config = config;
            Ok(())
        }

        /// Open or create a database.
        pub fn open(&self, db_name: &str, create_if_missing: bool) -> RedbAdapterResult<IonafsDatabaseFile> {
            // Check if already open.
            {
                let dbs = self.databases.read().unwrap();
                if let Some(db) = dbs.get(db_name) {
                    if !db.is_closed() {
                        return Ok(db.clone());
                    }
                }
            }

            let exists = crate::fs::ionafs::exists(&format!("/db/{}/super", db_name));

            let db = if exists {
                IonafsDatabaseFile::open(db_name, self.config.clone())?
            } else if create_if_missing {
                IonafsDatabaseFile::create(db_name, self.config.clone())?
            } else {
                return Err(RedbAdapterError::NotFound);
            };

            {
                let mut dbs = self.databases.write().unwrap();
                dbs.insert(db_name.to_string(), db.clone());
            }

            self.metrics.record_open();
            debug!(db_name, "database opened");
            Ok(db)
        }

        /// Open an existing database (fails if not found).
        pub fn open_existing(&self, db_name: &str) -> RedbAdapterResult<IonafsDatabaseFile> {
            self.open(db_name, false)
        }

        /// Create a new database (fails if already exists).
        pub fn create(&self, db_name: &str) -> RedbAdapterResult<IonafsDatabaseFile> {
            self.open(db_name, true)
        }

        /// Close a database and remove it from the manager.
        pub fn close(&self, db_name: &str) -> RedbAdapterResult<()> {
            let mut dbs = self.databases.write().unwrap();
            if let Some(db) = dbs.remove(db_name) {
                db.close()?;
                self.metrics.record_close();
                debug!(db_name, "database closed and removed from manager");
            }
            Ok(())
        }

        /// Close all databases.
        pub fn close_all(&self) -> RedbAdapterResult<()> {
            let dbs = {
                let mut dbs = self.databases.write().unwrap();
                let dbs = dbs.clone();
                dbs
            };

            for (name, db) in &dbs {
                if let Err(e) = db.close() {
                    warn!(db_name = %name, error = %e, "failed to close database");
                }
            }

            self.databases.write().unwrap().clear();
            debug!("all databases closed");
            Ok(())
        }

        /// Flush all open databases.
        pub fn flush_all(&self) -> RedbAdapterResult<()> {
            let dbs = self.databases.read().unwrap();
            for (name, db) in dbs.iter() {
                if let Err(e) = db.flush() {
                    warn!(db_name = %name, error = %e, "failed to flush database");
                }
            }
            Ok(())
        }

        /// Check if a database is open.
        pub fn is_open(&self, db_name: &str) -> bool {
            let dbs = self.databases.read().unwrap();
            dbs.get(db_name).map(|db| !db.is_closed()).unwrap_or(false)
        }

        /// Get a list of open database names.
        pub fn list_databases(&self) -> Vec<String> {
            let dbs = self.databases.read().unwrap();
            dbs.keys().cloned().collect()
        }

        /// Get metrics snapshot.
        pub fn metrics_snapshot(&self) -> super::metrics::RedbAdapterMetricsSnapshot {
            self.metrics.snapshot()
        }
    }

    impl Drop for RedbManager {
        fn drop(&mut self) {
            let _ = self.close_all();
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::RedbAdapterConfig;
pub use error::{RedbAdapterError, RedbAdapterResult};
pub use metrics::{RedbAdapterMetrics, RedbAdapterMetricsSnapshot};
pub use cache::PageCache;
pub use db::IonafsDatabaseFile;
pub use manager::RedbManager;

// Re-export constants.
pub use constants::{PAGE_SIZE, SUPERBLOCK_SIZE};

// -----------------------------------------------------------------------------
// Tests (compile‑time only – real tests would need IONAFS)
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_are_correct() {
        assert_eq!(PAGE_SIZE, 4096);
        assert_eq!(SUPERBLOCK_SIZE, 16);
        assert_eq!(constants::DEFAULT_CACHE_SIZE, 64);
    }

    #[test]
    fn page_cache_eviction_works() {
        let mut cache = PageCache::new(2);
        cache.insert(1, vec![1u8; PAGE_SIZE]);
        cache.insert(2, vec![2u8; PAGE_SIZE]);
        let evicted = cache.insert(3, vec![3u8; PAGE_SIZE]);
        assert_eq!(evicted, Some(1));
        assert!(cache.get(1).is_none());
        assert!(cache.get(2).is_some());
        assert!(cache.get(3).is_some());
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn page_cache_invalidate_works() {
        let mut cache = PageCache::new(3);
        cache.insert(1, vec![1u8; PAGE_SIZE]);
        cache.insert(2, vec![2u8; PAGE_SIZE]);
        cache.invalidate(1);
        assert!(cache.get(1).is_none());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn config_validation() {
        let mut config = RedbAdapterConfig::default();
        assert!(config.validate().is_ok());

        config.cache_size = 0;
        assert!(config.validate().is_err());

        config.cache_size = 10;
        config.flush_interval_ms = 0;
        assert!(config.validate().is_err());

        config.flush_interval_ms = 100;
        config.max_dirty_pages = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn metrics_initial_state() {
        let metrics = RedbAdapterMetrics::default();
        assert_eq!(metrics.reads.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.cache_hits.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.hit_ratio(), 1.0);
        metrics.record_read();
        metrics.record_cache_hit();
        assert_eq!(metrics.hit_ratio(), 1.0);
        metrics.record_cache_miss();
        assert!((metrics.hit_ratio() - 0.5).abs() < 0.01);
    }

    #[test]
    fn metrics_snapshot() {
        let metrics = RedbAdapterMetrics::default();
        metrics.record_read();
        metrics.record_write();
        metrics.record_cache_hit();
        let snap = metrics.snapshot();
        assert_eq!(snap.reads, 1);
        assert_eq!(snap.writes, 1);
        assert_eq!(snap.cache_hits, 1);
        assert_eq!(snap.hit_ratio, 1.0);
    }

    #[test]
    fn config_builder_methods() {
        let config = RedbAdapterConfig::default()
            .with_trace()
            .with_metrics()
            .with_cache_size(128);
        assert!(config.trace_operations);
        assert!(config.collect_metrics);
        assert_eq!(config.cache_size, 128);
    }

    #[test]
    fn manager_creation() {
        let manager = RedbManager::default();
        assert_eq!(manager.list_databases().len(), 0);
        assert!(!manager.is_open("test"));
        let snap = manager.metrics_snapshot();
        assert_eq!(snap.opens, 0);
    }

    #[test]
    fn cache_capacity() {
        let cache = PageCache::new(42);
        assert_eq!(cache.capacity(), 42);
        assert!(cache.is_empty());
    }

    #[test]
    fn cache_contains() {
        let mut cache = PageCache::new(3);
        cache.insert(1, vec![1u8; PAGE_SIZE]);
        assert!(cache.contains(1));
        assert!(!cache.contains(2));
    }

    #[test]
    fn cache_clear() {
        let mut cache = PageCache::new(3);
        cache.insert(1, vec![1u8; PAGE_SIZE]);
        cache.insert(2, vec![2u8; PAGE_SIZE]);
        cache.clear();
        assert!(cache.is_empty());
    }
}
