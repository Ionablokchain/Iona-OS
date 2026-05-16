//! Virtio Block Device Driver
//!
//! Reads and writes 512‑byte sectors via VirtQueue.
//! Implements retry logic and a small read cache.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::mem::ManuallyDrop;
use core::ptr;
use spin::Mutex;
use super::{VirtQueue, init_device};
use crate::pci::PciDevice;
use crate::arch::x86_64::timer::sleep_ms;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Sector size in bytes (standard for virtio‑blk).
pub const SECTOR_SIZE: usize = 512;

/// Number of retries for I/O operations.
const RETRY_COUNT: usize = 3;

/// Delay between retries in milliseconds.
const RETRY_DELAY_MS: u64 = 10;

/// Maximum number of cached sectors.
const CACHE_SIZE: usize = 16;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during virtio‑blk operations.
#[derive(Debug, Error)]
pub enum VirtioBlkError {
    #[error("virtio-blk device not initialized")]
    NotInitialized,
    #[error("I/O error: status = {status}")]
    IoError { status: u8 },
    #[error("buffer length mismatch: expected {expected}, got {actual}")]
    BufferLengthMismatch { expected: usize, actual: usize },
    #[error("DMA mapping failed")]
    DmaMappingFailed,
    #[error("queue operation failed: {0}")]
    QueueError(&'static str),
}

pub type VirtioBlkResult<T> = Result<T, VirtioBlkError>;

// -----------------------------------------------------------------------------
// Request structures
// -----------------------------------------------------------------------------

#[repr(C)]
struct BlkRequest {
    type_: u32,
    ioprio: u32,
    sector: u64,
}

#[repr(C)]
struct BlkStatus {
    status: u8,
}

// -----------------------------------------------------------------------------
// VirtioBlk driver
// -----------------------------------------------------------------------------

/// Virtio block device driver.
pub struct VirtioBlk {
    queue: VirtQueue,
    capacity: u64, // number of 512‑byte sectors
}

/// Global singleton (protected by Mutex).
static DISK: Mutex<Option<VirtioBlk>> = Mutex::new(None);

/// Block cache (LRU‑like, only for reads).
static BLOCK_CACHE: spin::Lazy<Mutex<BTreeMap<u64, Vec<u8>>>> =
    spin::Lazy::new(|| Mutex::new(BTreeMap::new()));

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

impl VirtioBlk {
    /// Initialize the device from PCI configuration.
    pub fn init(dev: &PciDevice) -> Option<Self> {
        let io_base = init_device(dev)?;
        // Read capacity from virtio config space (offset 0x14: low 32 bits, 0x18: high 32 bits)
        let cap_lo = crate::pci::config_read_u32(dev.addr.bus, dev.addr.device, dev.addr.function, 0x14);
        let cap_hi = crate::pci::config_read_u32(dev.addr.bus, dev.addr.device, dev.addr.function, 0x18);
        let capacity = (cap_hi as u64) << 32 | cap_lo as u64;

        let queue = VirtQueue::new(io_base, 0)?;
        crate::serial_println!("  [VIRTIO-BLK] capacity={} sectors ({} MB)",
            capacity, capacity * SECTOR_SIZE as u64 / 1_048_576);
        Some(VirtioBlk { queue, capacity })
    }

    /// Read `count` sectors starting at `lba` into `buf`.
    /// Buffer must be exactly `count * SECTOR_SIZE` bytes.
    pub fn read_sectors(&mut self, lba: u64, count: usize, buf: &mut [u8]) -> VirtioBlkResult<()> {
        let expected_len = count * SECTOR_SIZE;
        if buf.len() != expected_len {
            return Err(VirtioBlkError::BufferLengthMismatch {
                expected: expected_len,
                actual: buf.len(),
            });
        }
        if count == 0 {
            return Ok(());
        }

        // Prepare request and status buffers.
        let req = Box::new(BlkRequest {
            type_: VIRTIO_BLK_T_IN,
            ioprio: 0,
            sector: lba,
        });
        let status = Box::new(BlkStatus { status: 0xFF });

        // Get physical addresses.
        let req_phys = virt_to_phys(&*req);
        let buf_phys = virt_to_phys(buf.as_mut_ptr());
        let status_phys = virt_to_phys(&*status);

        // Build descriptor chain:
        // desc0: request header (device reads)
        // desc1: data buffer (device writes)
        // desc2: status (device writes)
        self.queue.send(req_phys, core::mem::size_of::<BlkRequest>() as u32, 1)?; // NEXT
        self.queue.send(buf_phys, buf.len() as u32, 1 | 2)?; // NEXT | WRITE
        self.queue.send(status_phys, 1, 2)?; // WRITE
        self.queue.wait_used();

        if status.status != 0 {
            return Err(VirtioBlkError::IoError { status: status.status });
        }

        // Prevent deallocation of buffers (they will be reused or dropped later).
        core::mem::forget(req);
        core::mem::forget(status);
        Ok(())
    }

    /// Write a single sector at `lba` (or multiple aligned sectors).
    /// Buffer must be a multiple of `SECTOR_SIZE`.
    pub fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> VirtioBlkResult<()> {
        if buf.len() % SECTOR_SIZE != 0 {
            return Err(VirtioBlkError::BufferLengthMismatch {
                expected: buf.len() / SECTOR_SIZE * SECTOR_SIZE,
                actual: buf.len(),
            });
        }
        if buf.is_empty() {
            return Ok(());
        }

        let req = Box::new(BlkRequest {
            type_: VIRTIO_BLK_T_OUT,
            ioprio: 0,
            sector: lba,
        });
        let status = Box::new(BlkStatus { status: 0xFF });

        let req_phys = virt_to_phys(&*req);
        let buf_phys = virt_to_phys(buf.as_ptr());
        let status_phys = virt_to_phys(&*status);

        self.queue.send(req_phys, core::mem::size_of::<BlkRequest>() as u32, 1)?;
        self.queue.send(buf_phys, buf.len() as u32, 1)?;
        self.queue.send(status_phys, 1, 2)?;
        self.queue.wait_used();

        if status.status != 0 {
            return Err(VirtioBlkError::IoError { status: status.status });
        }

        core::mem::forget(req);
        core::mem::forget(status);
        Ok(())
    }

    /// Invalidate cache for a specific sector.
    pub fn invalidate_cache(&self, lba: u64) {
        let mut cache = BLOCK_CACHE.lock();
        cache.remove(&lba);
    }
}

// -----------------------------------------------------------------------------
// Helper: convert virtual address to physical (placeholder – real kernel would use page tables)
// -----------------------------------------------------------------------------
#[inline(never)]
fn virt_to_phys<T>(ptr: *const T) -> u64 {
    // In a real kernel, this would translate the virtual address using the current page tables.
    // For simplicity, we assume identity mapping for DMA buffers or use proper DMA API.
    // This placeholder returns the value as if identity mapping.
    ptr as u64
}

// -----------------------------------------------------------------------------
// Public API (global singleton)
// -----------------------------------------------------------------------------

/// Check if the virtio‑blk device is present.
pub fn is_present() -> bool {
    DISK.lock().is_some()
}

/// Check if the device is available (alias for `is_present`).
pub fn is_available() -> bool {
    is_present()
}

/// Return disk capacity in megabytes.
pub fn capacity_mb() -> Option<u64> {
    DISK.lock().as_ref().map(|d| d.capacity * SECTOR_SIZE as u64 / 1_048_576)
}

/// Try to initialize the device from a PCI device.
pub fn try_init(dev: &PciDevice) -> bool {
    if let Some(disk) = VirtioBlk::init(dev) {
        *DISK.lock() = Some(disk);
        true
    } else {
        false
    }
}

/// Read sectors (no retry).
pub fn read_sectors(lba: u64, count: usize, buf: &mut [u8]) -> VirtioBlkResult<()> {
    let mut guard = DISK.lock();
    let disk = guard.as_mut().ok_or(VirtioBlkError::NotInitialized)?;
    disk.read_sectors(lba, count, buf)
}

/// Write sectors (no retry).
pub fn write_sectors(lba: u64, buf: &[u8]) -> VirtioBlkResult<()> {
    let mut guard = DISK.lock();
    let disk = guard.as_mut().ok_or(VirtioBlkError::NotInitialized)?;
    disk.write_sectors(lba, buf)
}

/// Read with retry – attempts up to `RETRY_COUNT` times.
pub fn read_sectors_retry(lba: u64, count: usize, buf: &mut [u8]) -> VirtioBlkResult<()> {
    let mut last_err = VirtioBlkError::NotInitialized;
    for attempt in 0..RETRY_COUNT {
        match read_sectors(lba, count, buf) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_err = e;
                crate::serial_println!("[VIRTIO-BLK] read retry {}/{} lba={}", attempt + 1, RETRY_COUNT, lba);
                sleep_ms(RETRY_DELAY_MS);
            }
        }
    }
    Err(last_err)
}

/// Write with retry.
pub fn write_sectors_retry(lba: u64, buf: &[u8]) -> VirtioBlkResult<()> {
    let mut last_err = VirtioBlkError::NotInitialized;
    for attempt in 0..RETRY_COUNT {
        match write_sectors(lba, buf) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_err = e;
                crate::serial_println!("[VIRTIO-BLK] write retry {}/{} lba={}", attempt + 1, RETRY_COUNT, lba);
                sleep_ms(RETRY_DELAY_MS);
            }
        }
    }
    Err(last_err)
}

/// Read a single sector with caching (simple LRU).
pub fn read_cached(lba: u64, buf: &mut [u8]) -> VirtioBlkResult<()> {
    if buf.len() < SECTOR_SIZE {
        return Err(VirtioBlkError::BufferLengthMismatch {
            expected: SECTOR_SIZE,
            actual: buf.len(),
        });
    }
    {
        let cache = BLOCK_CACHE.lock();
        if let Some(cached) = cache.get(&lba) {
            let copy_len = cached.len().min(buf.len());
            buf[..copy_len].copy_from_slice(&cached[..copy_len]);
            return Ok(());
        }
    }
    // Not in cache – read from disk.
    read_sectors_retry(lba, 1, &mut buf[..SECTOR_SIZE])?;
    // Store in cache (evict oldest if needed).
    let mut cache = BLOCK_CACHE.lock();
    if cache.len() >= CACHE_SIZE {
        if let Some(oldest) = cache.first_entry() {
            cache.remove(oldest.key());
        }
    }
    cache.insert(lba, buf[..SECTOR_SIZE].to_vec());
    Ok(())
}

/// Invalidate a specific cache entry.
pub fn invalidate_cache(lba: u64) {
    if let Some(disk) = DISK.lock().as_ref() {
        disk.invalidate_cache(lba);
    }
}

// -----------------------------------------------------------------------------
// Tests (compile‑time only)
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(SECTOR_SIZE, 512);
        assert_eq!(RETRY_COUNT, 3);
    }
}
