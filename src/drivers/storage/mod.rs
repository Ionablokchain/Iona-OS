//! Storage abstraction — re‑exports virtio‑blk driver.
//!
//! This module provides a uniform interface for block storage access.
//! Currently, it re‑exports the VirtIO block driver functions and adds
//! disk usage metrics.
//!
//! # Functions
//! - `read_sectors(port, lba, count, buf)` – Read one or more sectors.
//! - `write_sectors(port, lba, buf)` – Write one or more sectors.
//! - `is_present()` – Check if a storage device is available.
//! - `storage_stats()` – Get total and used sector counts.
//! - `disk_metrics()` – Get detailed disk metrics.
//!
//! # Example
//! ```rust,ignore
//! use crate::drivers::storage::{read_sectors, write_sectors, is_present, storage_stats};
//!
//! if is_present() {
//!     let (total, used) = storage_stats();
//!     let mut buf = [0u8; 512];
//!     read_sectors(0, 0, 1, &mut buf);
//! }
//! ```

pub use crate::drivers::virtio::blk::{read_sectors, write_sectors, is_present};

/// Disk usage metrics: total and used sectors.
pub struct DiskMetrics {
    /// Total number of sectors on the disk.
    pub total_sectors: u64,
    /// Number of sectors currently used by the file system.
    pub used_sectors: u64,
    /// Number of I/O errors encountered (incremented by low‑level drivers).
    pub error_count: u64,
}

/// Get the total and used sector counts from the IONAFS superblock.
///
/// # Returns
/// A tuple `(total_sectors, used_sectors)`.
#[must_use]
pub fn storage_stats() -> (u64, u64) {
    let total = crate::fs::ionafs::total_sectors();
    let used = crate::fs::ionafs::used_sectors();
    (total, used)
}

/// Get a `DiskMetrics` struct with current storage statistics.
#[must_use]
pub fn disk_metrics() -> DiskMetrics {
    let (total, used) = storage_stats();
    DiskMetrics {
        total_sectors: total,
        used_sectors: used,
        error_count: 0,
    }
}
