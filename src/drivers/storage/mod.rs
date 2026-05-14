//! Storage abstraction — re-exports virtio-blk
pub use crate::drivers::virtio::blk::{read_sectors, write_sectors, is_present};

/// Disk usage metrics
pub fn storage_stats() -> (u64, u64) {
    // (total_sectors, used_sectors) — from IONAFS superblock
    let total = crate::fs::ionafs::total_sectors();
    let used  = crate::fs::ionafs::used_sectors();
    (total, used)
}

pub fn disk_metrics() -> DiskMetrics {
    let (total, used) = storage_stats();
    DiskMetrics { total_sectors: total, used_sectors: used, error_count: 0 }
}

pub struct DiskMetrics {
    pub total_sectors: u64,
    pub used_sectors:  u64,
    pub error_count:   u64,
}
