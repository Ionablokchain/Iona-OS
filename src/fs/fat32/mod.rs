//! FAT32 filesystem — read-only for Phase 3.
//!
//! Used to read kernel modules and data from the disk image at boot.
//! Supports:
//! - Parsing the BIOS Parameter Block (BPB) from the boot sector.
//! - Reading clusters (with caching for performance).
//! - Following the FAT chain for file traversal.
//! - Limited directory entry parsing.
//!
//! # TODO
//! - Add directory traversal (reading root directory and subdirectories).
//! - Add file open/read by path.
//! - Add caching for frequently used clusters and FAT sectors.
//! - Support long file names (LFN).

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use crate::drivers::virtio::blk::read_sectors;
use crate::sync::Mutex;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

const SECTOR_SIZE: usize = 512;
const BYTES_PER_SECTOR: usize = 512;
const MAX_CLUSTER_CACHE: usize = 32;

/// FAT32 special cluster values.
#[allow(dead_code)]
mod fat_clusters {
    pub const FREE: u32 = 0x0000_0000;
    pub const RESERVED: u32 = 0x0000_0001;
    pub const BAD: u32 = 0x0FFF_FFF7;
    pub const END_MIN: u32 = 0x0FFF_FFF8;
    pub const END_MAX: u32 = 0x0FFF_FFFF;
}

// -----------------------------------------------------------------------------
// Error handling
// -----------------------------------------------------------------------------

/// FAT32-specific errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatError {
    BadBootSector,
    UnsupportedSectorSize,
    ClusterOutOfRange,
    EndOfClusterChain,
    ReadError,
    NotFound,
}

impl core::fmt::Display for FatError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadBootSector => write!(f, "invalid boot sector (missing 0x55AA signature)"),
            Self::UnsupportedSectorSize => write!(f, "sector size != 512 (unsupported)"),
            Self::ClusterOutOfRange => write!(f, "cluster number out of range"),
            Self::EndOfClusterChain => write!(f, "end of cluster chain reached"),
            Self::ReadError => write!(f, "disk read error"),
            Self::NotFound => write!(f, "file or directory not found"),
        }
    }
}

pub type Result<T> = core::result::Result<T, FatError>;

// -----------------------------------------------------------------------------
// Cluster cache
// -----------------------------------------------------------------------------

/// A simple cache for recently read clusters.
#[derive(Debug)]
pub struct ClusterCache {
    entries: [Option<(u32, Vec<u8>)>; MAX_CLUSTER_CACHE],
    hits: u64,
    misses: u64,
}

impl ClusterCache {
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_CLUSTER_CACHE],
            hits: 0,
            misses: 0,
        }
    }

    /// Get a cluster from the cache.
    pub fn get(&mut self, cluster: u32) -> Option<&[u8]> {
        for entry in &self.entries {
            if let Some((c, data)) = entry {
                if *c == cluster {
                    self.hits += 1;
                    return Some(data.as_slice());
                }
            }
        }
        self.misses += 1;
        None
    }

    /// Insert a cluster into the cache (simple FIFO replacement).
    pub fn insert(&mut self, cluster: u32, data: Vec<u8>) {
        // Check if already present.
        for entry in &self.entries {
            if let Some((c, _)) = entry {
                if *c == cluster {
                    return;
                }
            }
        }
        // Shift entries left, drop the oldest.
        for i in 1..MAX_CLUSTER_CACHE {
            self.entries[i - 1] = self.entries[i].take();
        }
        self.entries[MAX_CLUSTER_CACHE - 1] = Some((cluster, data));
    }

    /// Get cache statistics.
    pub fn stats(&self) -> (u64, u64) {
        (self.hits, self.misses)
    }

    /// Clear the cache.
    pub fn clear(&mut self) {
        for entry in &mut self.entries {
            *entry = None;
        }
    }
}

// -----------------------------------------------------------------------------
// FAT32 filesystem structure
// -----------------------------------------------------------------------------

/// Main FAT32 filesystem handle.
pub struct Fat32 {
    /// Number of sectors per cluster (power of 2).
    pub sectors_per_cluster: u8,
    /// Number of reserved sectors (including boot sector).
    pub reserved_sectors: u16,
    /// Number of FAT copies.
    pub num_fats: u8,
    /// Size of each FAT in sectors.
    pub fat_size_sectors: u32,
    /// Root directory cluster number.
    pub root_cluster: u32,
    /// Total number of sectors on the volume.
    pub total_sectors: u32,
    /// Bytes per sector (should be 512).
    pub bytes_per_sector: u16,
    /// Number of sectors per FAT (calculated).
    pub sectors_per_fat: u32,
    /// Cluster cache.
    cache: Mutex<ClusterCache>,
}

impl Fat32 {
    /// Parse the BIOS Parameter Block (BPB) from the boot sector.
    pub fn from_boot_sector(sector: &[u8; SECTOR_SIZE]) -> Option<Self> {
        // Check boot signature.
        if sector[510] != 0x55 || sector[511] != 0xAA {
            return None;
        }

        let bytes_per_sector = u16::from_le_bytes([sector[11], sector[12]]);
        if bytes_per_sector != SECTOR_SIZE as u16 {
            return None; // only support 512-byte sectors for now
        }

        let sectors_per_cluster = sector[13];
        if sectors_per_cluster == 0 || !sectors_per_cluster.is_power_of_two() {
            return None; // invalid
        }

        let total_sectors = u32::from_le_bytes([sector[32], sector[33], sector[34], sector[35]]);
        if total_sectors == 0 {
            // Use total_sectors_32 from offset 0x20.
            let total_sectors_32 = u32::from_le_bytes([sector[32], sector[33], sector[34], sector[35]]);
            if total_sectors_32 == 0 {
                return None;
            }
        }

        Some(Self {
            sectors_per_cluster,
            reserved_sectors: u16::from_le_bytes([sector[14], sector[15]]),
            num_fats: sector[16],
            fat_size_sectors: u32::from_le_bytes([sector[36], sector[37], sector[38], sector[39]]),
            root_cluster: u32::from_le_bytes([sector[44], sector[45], sector[46], sector[47]]),
            total_sectors: u32::from_le_bytes([sector[32], sector[33], sector[34], sector[35]]),
            bytes_per_sector,
            sectors_per_fat: u32::from_le_bytes([sector[36], sector[37], sector[38], sector[39]]),
            cache: Mutex::new(ClusterCache::new()),
        })
    }

    /// Get the starting LBA of the FAT area.
    pub fn fat_start_lba(&self) -> u64 {
        self.reserved_sectors as u64
    }

    /// Get the starting LBA of the data area.
    pub fn data_start_lba(&self) -> u64 {
        self.fat_start_lba() + (self.num_fats as u64) * (self.fat_size_sectors as u64)
    }

    /// Get the LBA of a cluster.
    pub fn cluster_lba(&self, cluster: u32) -> u64 {
        self.data_start_lba() + (cluster as u64 - 2) * (self.sectors_per_cluster as u64)
    }

    /// Read a cluster from disk (with caching).
    pub fn read_cluster(&self, cluster: u32) -> Result<Vec<u8>> {
        if cluster < 2 {
            return Err(FatError::ClusterOutOfRange);
        }

        // Check cache.
        {
            let mut cache = self.cache.lock();
            if let Some(data) = cache.get(cluster) {
                return Ok(data.to_vec());
            }
        }

        let lba = self.cluster_lba(cluster);
        let sectors = self.sectors_per_cluster as usize;
        let size = sectors * SECTOR_SIZE;
        let mut buf = vec![0u8; size];

        for i in 0..sectors {
            let sector_lba = lba + i as u64;
            let offset = i * SECTOR_SIZE;
            // Safety: we trust the driver to read correctly.
            read_sectors(sector_lba, 1, &mut buf[offset..offset + SECTOR_SIZE]);
        }

        // Insert into cache.
        {
            let mut cache = self.cache.lock();
            cache.insert(cluster, buf.clone());
        }

        Ok(buf)
    }

    /// Read a cluster without caching (for internal use).
    pub fn read_cluster_raw(&self, cluster: u32) -> Vec<u8> {
        let lba = self.cluster_lba(cluster);
        let sectors = self.sectors_per_cluster as usize;
        let size = sectors * SECTOR_SIZE;
        let mut buf = vec![0u8; size];
        for i in 0..sectors {
            let sector_lba = lba + i as u64;
            let offset = i * SECTOR_SIZE;
            read_sectors(sector_lba, 1, &mut buf[offset..offset + SECTOR_SIZE]);
        }
        buf
    }

    /// Read the FAT entry for a cluster.
    /// Returns the next cluster in the chain, or None if it's the end.
    pub fn next_cluster(&self, cluster: u32) -> Result<Option<u32>> {
        if cluster < 2 {
            return Err(FatError::ClusterOutOfRange);
        }

        let fat_offset = (cluster * 4) as u64;
        let fat_sector = self.fat_start_lba() + (fat_offset / SECTOR_SIZE as u64);
        let offset_in_sector = (fat_offset % SECTOR_SIZE as u64) as usize;

        let mut buf = [0u8; SECTOR_SIZE];
        read_sectors(fat_sector, 1, &mut buf);

        let next = u32::from_le_bytes([
            buf[offset_in_sector],
            buf[offset_in_sector + 1],
            buf[offset_in_sector + 2],
            buf[offset_in_sector + 3],
        ]) & 0x0FFF_FFFF;

        if next >= 0x0FFF_FFF8 {
            Ok(None) // End of cluster chain
        } else if next == 0x0FFF_FFF7 {
            Err(FatError::ReadError) // Bad cluster
        } else {
            Ok(Some(next))
        }
    }

    /// Walk the cluster chain and collect all cluster numbers.
    pub fn walk_cluster_chain(&self, start_cluster: u32) -> Result<Vec<u32>> {
        let mut clusters = Vec::new();
        let mut current = start_cluster;

        while current >= 2 {
            clusters.push(current);
            match self.next_cluster(current)? {
                Some(next) => current = next,
                None => break,
            }
        }
        Ok(clusters)
    }

    /// Read the entire data from a cluster chain.
    pub fn read_chain(&self, start_cluster: u32) -> Result<Vec<u8>> {
        let clusters = self.walk_cluster_chain(start_cluster)?;
        let mut data = Vec::new();
        for cluster in clusters {
            let cluster_data = self.read_cluster(cluster)?;
            data.extend_from_slice(&cluster_data);
        }
        Ok(data)
    }

    /// Get cache statistics.
    pub fn cache_stats(&self) -> (u64, u64) {
        self.cache.lock().stats()
    }

    /// Clear the cluster cache.
    pub fn clear_cache(&self) {
        self.cache.lock().clear();
    }
}

// -----------------------------------------------------------------------------
// FAT32 Directory Entry (Short Name)
// -----------------------------------------------------------------------------

/// A FAT32 directory entry (short name, 8.3 format).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct DirEntry {
    pub name: [u8; 8],
    pub ext: [u8; 3],
    pub attr: u8,
    pub reserved: u8,
    pub create_time_tenth: u8,
    pub create_time: u16,
    pub create_date: u16,
    pub last_access_date: u16,
    pub first_cluster_high: u16,
    pub write_time: u16,
    pub write_date: u16,
    pub first_cluster_low: u16,
    pub file_size: u32,
}

// Constants for attribute bits.
pub const ATTR_READ_ONLY: u8 = 0x01;
pub const ATTR_HIDDEN: u8 = 0x02;
pub const ATTR_SYSTEM: u8 = 0x04;
pub const ATTR_VOLUME_ID: u8 = 0x08;
pub const ATTR_DIRECTORY: u8 = 0x10;
pub const ATTR_ARCHIVE: u8 = 0x20;
pub const ATTR_LONG_NAME: u8 = 0x0F;

impl DirEntry {
    /// Check if this entry is a long file name (LFN) entry.
    pub fn is_lfn(&self) -> bool {
        self.attr == ATTR_LONG_NAME
    }

    /// Check if this entry is a directory.
    pub fn is_directory(&self) -> bool {
        (self.attr & ATTR_DIRECTORY) != 0
    }

    /// Check if this entry is a volume label.
    pub fn is_volume_label(&self) -> bool {
        (self.attr & ATTR_VOLUME_ID) != 0
    }

    /// Check if this entry is a regular file.
    pub fn is_file(&self) -> bool {
        !self.is_directory() && !self.is_volume_label() && !self.is_lfn()
    }

    /// Check if this entry is empty (deleted).
    pub fn is_empty(&self) -> bool {
        self.name[0] == 0xE5
    }

    /// Check if this entry is the last entry in the directory.
    pub fn is_last(&self) -> bool {
        self.name[0] == 0x00
    }

    /// Get the cluster number of this entry (32-bit).
    pub fn cluster(&self) -> u32 {
        ((self.first_cluster_high as u32) << 16) | (self.first_cluster_low as u32)
    }

    /// Convert the 8.3 name to a string (without padding spaces).
    pub fn name_string(&self) -> alloc::string::String {
        use alloc::string::String;
        let mut name = String::new();
        for &c in &self.name {
            if c == 0x20 || c == 0x00 {
                break;
            }
            name.push(c as char);
        }
        // Add extension if present.
        let mut has_ext = false;
        for &c in &self.ext {
            if c != 0x20 && c != 0x00 {
                has_ext = true;
                break;
            }
        }
        if has_ext {
            name.push('.');
            for &c in &self.ext {
                if c == 0x20 || c == 0x00 {
                    break;
                }
                name.push(c as char);
            }
        }
        name
    }

    /// Get the file size (only valid for regular files).
    pub fn size(&self) -> u32 {
        self.file_size
    }
}

// -----------------------------------------------------------------------------
// Directory traversal
// -----------------------------------------------------------------------------

/// Iterator over directory entries.
pub struct DirIterator<'a> {
    fat: &'a Fat32,
    current_cluster: u32,
    offset: usize,
    buf: Vec<u8>,
}

impl<'a> DirIterator<'a> {
    pub fn new(fat: &'a Fat32, cluster: u32) -> Result<Self> {
        let buf = fat.read_cluster(cluster)?;
        Ok(Self {
            fat,
            current_cluster: cluster,
            offset: 0,
            buf,
        })
    }

    /// Read the next directory entry.
    pub fn next_entry(&mut self) -> Option<DirEntry> {
        while self.offset + 32 <= self.buf.len() {
            let entry_data = &self.buf[self.offset..self.offset + 32];
            let entry: DirEntry = unsafe { core::ptr::read(entry_data.as_ptr() as *const DirEntry) };
            self.offset += 32;

            if entry.is_last() {
                return None;
            }
            if entry.is_empty() {
                continue;
            }
            return Some(entry);
        }

        // Try the next cluster in the chain.
        match self.fat.next_cluster(self.current_cluster) {
            Ok(Some(next)) => {
                self.current_cluster = next;
                self.buf = self.fat.read_cluster(next).ok()?;
                self.offset = 0;
                self.next_entry()
            }
            _ => None,
        }
    }
}

impl<'a> Iterator for DirIterator<'a> {
    type Item = DirEntry;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_entry()
    }
}

// -----------------------------------------------------------------------------
// File open by path
// -----------------------------------------------------------------------------

/// Open a file in the FAT32 filesystem by path.
pub fn open_file(fat: &Fat32, path: &str) -> Result<DirEntry> {
    // Split path into components.
    let path = path.trim_matches('/');
    if path.is_empty() {
        return Err(FatError::NotFound);
    }

    let components: Vec<&str> = path.split('/').collect();
    let mut current_cluster = fat.root_cluster;

    for (i, component) in components.iter().enumerate() {
        let is_last = i == components.len() - 1;
        let iter = DirIterator::new(fat, current_cluster)?;
        let mut found = false;

        for entry in iter {
            if entry.is_lfn() {
                // We don't handle LFN yet; skip and continue.
                continue;
            }
            if entry.is_empty() || entry.is_volume_label() {
                continue;
            }

            let entry_name = entry.name_string();
            if entry_name == *component {
                if is_last {
                    // Last component: return the entry.
                    return Ok(entry);
                } else if entry.is_directory() {
                    // Continue traversal.
                    current_cluster = entry.cluster();
                    found = true;
                    break;
                } else {
                    // Not a directory but we need to traverse further.
                    return Err(FatError::NotFound);
                }
            }
        }

        if !found {
            return Err(FatError::NotFound);
        }
    }

    Err(FatError::NotFound)
}

/// Read a file's data by path.
pub fn read_file(fat: &Fat32, path: &str) -> Result<Vec<u8>> {
    let entry = open_file(fat, path)?;
    if entry.is_directory() {
        return Err(FatError::NotFound);
    }
    fat.read_chain(entry.cluster())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // These tests require a real disk image, so they are marked as ignored by default.
    // In a real environment, you'd provide a test disk image.

    #[test]
    #[ignore]
    fn test_fat32_parse() {
        // This test requires a boot sector from a real FAT32 volume.
        // We'll just test the structure creation.
        let sector = [0u8; 512];
        // Cannot test without a valid boot sector.
    }

    #[test]
    fn test_dir_entry() {
        let mut entry = DirEntry {
            name: *b"KERNEL  ",
            ext: *b"BIN",
            attr: 0,
            reserved: 0,
            create_time_tenth: 0,
            create_time: 0,
            create_date: 0,
            last_access_date: 0,
            first_cluster_high: 0x0001,
            write_time: 0,
            write_date: 0,
            first_cluster_low: 0x0002,
            file_size: 1024,
        };
        assert_eq!(entry.name_string(), "KERNEL.BIN");
        assert_eq!(entry.cluster(), 0x0001_0002);
        assert_eq!(entry.size(), 1024);

        entry.attr = ATTR_DIRECTORY;
        assert!(entry.is_directory());
        assert!(!entry.is_file());
    }

    #[test]
    fn test_cluster_cache() {
        let mut cache = ClusterCache::new();
        let data = vec![1, 2, 3];
        cache.insert(10, data.clone());
        let cached = cache.get(10);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap(), data.as_slice());
        let stats = cache.stats();
        assert_eq!(stats.0, 1); // hit
        assert_eq!(stats.1, 0); // miss
    }
}
