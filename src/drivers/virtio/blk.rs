//! Virtio Block Device Driver.
//!
//! Reads and writes 512-byte sectors via a legacy virtio-blk queue.
//! Submission is synchronous: each read/write blocks the caller until
//! the device reports completion.
//!
//! # Features
//!
//! * 512-byte sectors, any count up to `u32::MAX / 512`.
//! * Full input validation: buffer length, LBA bounds, overflow checks.
//! * DMA via identity-mapped physical memory at [`PHYS_OFFSET`].
//! * Read cache with explicit invalidation on write.
//! * Retry logic that only retries device-reported I/O errors, not
//!   programming errors.
//!
//! # Assumptions
//!
//! * Physical memory is identity-mapped at [`PHYS_OFFSET`]; the caller's
//!   buffers and the driver's internal request/status records are all
//!   DMA-mappable.
//! * `VirtQueue::send` will not partially submit a descriptor chain. If
//!   it can (e.g. on ENOSPC), the driver is left in a poisoned state and
//!   subsequent I/O returns `QueueError` until re-init.
//! * `VirtQueue::wait_used` returns when the device advances the used
//!   ring; if it hangs, the caller hangs. A future VirtQueue version
//!   should add a timeout.
//!
//! # Not supported
//!
//! * Non-512-byte sector sizes (4K-native virtio-blk).
//! * Multi-queue / virtio-blk 1.0 (VIRTIO_F_MQ).
//! * Scatter-gather beyond one contiguous buffer.
//! * Discard, write-zeroes, or flush commands.
//! * Encrypted or integrity-protected device modes.
//!
//! # Concurrency
//!
//! All I/O is serialized through a global `DISK` mutex. Do not call the
//! public I/O functions from IRQ context — they block. `is_present` and
//! `capacity_mb` are IRQ-safe (no locks).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use core::sync::atomic::{compiler_fence, AtomicBool, AtomicU64, Ordering};

use spin::Mutex;
use thiserror::Error;

use super::{VirtQueue, init_device};
use crate::arch::x86_64::timer::sleep_ms;
use crate::pci::PciDevice;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Sector size for virtio-blk (fixed by the spec for legacy devices).
pub const SECTOR_SIZE: usize = 512;

/// Number of retries for retriable I/O errors.
const RETRY_COUNT: usize = 3;

/// Delay between retries, milliseconds.
const RETRY_DELAY_MS: u64 = 10;

/// Maximum number of cached sectors. With 512-byte sectors, 16 entries
/// use 8 KiB.
const CACHE_SIZE: usize = 16;

/// virtio-blk request types (§5.2.6).
const VIRTIO_BLK_T_IN:  u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;

/// Virtqueue descriptor flags.
const VIRTQ_DESC_F_NEXT:  u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

/// Physical-to-virtual offset (identity map of physical memory).
const PHYS_OFFSET: usize = 0xFFFF_8000_0000_0000;

/// virtio-blk device ID (legacy). Also 0x1042 for modern; both use the
/// same PCI class 0x01 (mass storage).
const PCI_CLASS_MASS_STORAGE: u8 = 0x01;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum VirtioBlkError {
    #[error("virtio-blk device not initialized")]
    NotInitialized,

    #[error("I/O error: device status = {status}")]
    IoError { status: u8 },

    #[error("buffer length mismatch: expected {expected}, got {actual}")]
    BufferLengthMismatch { expected: usize, actual: usize },

    #[error("LBA out of range: lba={lba}, count={count}, capacity={capacity}")]
    OutOfRange { lba: u64, count: usize, capacity: u64 },

    #[error("DMA buffer outside identity-mapped range")]
    DmaMappingFailed,

    #[error("queue operation failed: {0}")]
    QueueError(&'static str),

    #[error("virtio-blk device is in a poisoned state; re-init required")]
    Poisoned,
}

impl VirtioBlkError {
    /// Returns true if the error is worth retrying. Programming errors
    /// (bad arguments, DMA mapping) are never retried; device-reported
    /// I/O errors are.
    fn is_retriable(&self) -> bool {
        matches!(
            self,
            VirtioBlkError::IoError { .. } | VirtioBlkError::QueueError(_)
        )
    }
}

pub type VirtioBlkResult<T> = Result<T, VirtioBlkError>;

// ---------------------------------------------------------------------------
// Wire structures (little-endian, 16-byte request header per §5.2.6)
// ---------------------------------------------------------------------------

#[repr(C)]
struct BlkRequest {
    type_:  u32,
    ioprio: u32,
    sector: u64,
}

#[repr(C)]
struct BlkStatus {
    status: u8,
}

const _: () = {
    assert!(core::mem::size_of::<BlkRequest>() == 16);
    assert!(core::mem::size_of::<BlkStatus>() == 1);
};

// Status byte codes from §5.2.6.
const STATUS_OK:       u8 = 0;
#[allow(dead_code)]
const STATUS_IOERR:    u8 = 1;
#[allow(dead_code)]
const STATUS_UNSUPP:   u8 = 2;
#[allow(dead_code)]
const STATUS_NEEDS_RESET: u8 = 3;

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

pub struct VirtioBlk {
    queue:    VirtQueue,
    capacity: u64, // sectors
    poisoned: bool,
}

/// Global singleton. All I/O is serialized through this lock.
static DISK: Mutex<Option<VirtioBlk>> = Mutex::new(None);

/// IRQ-safe mirror of "is a disk present". Kept in sync with `DISK`.
static PRESENT: AtomicBool = AtomicBool::new(false);

/// IRQ-safe mirror of capacity. Kept in sync with `VirtioBlk::capacity`.
static CAPACITY_SECTORS: AtomicU64 = AtomicU64::new(0);

/// Read cache. Bounded at [`CACHE_SIZE`] entries; evicts the lowest
/// LBA on overflow (not LRU — the name in the previous version was
/// misleading).
static BLOCK_CACHE: spin::Lazy<Mutex<BTreeMap<u64, Vec<u8>>>> =
    spin::Lazy::new(|| Mutex::new(BTreeMap::new()));

impl VirtioBlk {
    /// Initialise the device from a PCI configuration descriptor.
    pub fn init(dev: &PciDevice) -> Option<Self> {
        // Refuse anything that is not a mass-storage controller. This
        // catches accidental attachment of a virtio-net or virtio-gpu
        // PCI function, which would otherwise DMA the wrong way.
        if dev.class != PCI_CLASS_MASS_STORAGE {
            return None;
        }

        let io_base = init_device(dev)?;

        // Read capacity from the virtio device config space (§5.2.4).
        // For legacy virtio-blk over PCI, capacity is a u64 at offset
        // 0x14 of the virtio config area, split across two 32-bit MMIO
        // reads. `init_device` returns the physical base; we add
        // `PHYS_OFFSET` to reach the virtual mapping.
        let cfg_virt = io_base.checked_add(PHYS_OFFSET as u64)?;
        let cap_lo = unsafe { ((cfg_virt + 0x14) as *const u32).read_volatile() };
        let cap_hi = unsafe { ((cfg_virt + 0x18) as *const u32).read_volatile() };
        let capacity = ((cap_hi as u64) << 32) | cap_lo as u64;

        if capacity == 0 {
            return None;
        }

        let queue = VirtQueue::new(io_base, 0)?;

        crate::serial_println!(
            "  [VIRTIO-BLK] capacity={} sectors ({} MiB)",
            capacity,
            capacity.saturating_mul(SECTOR_SIZE as u64) / 1_048_576,
        );

        Some(VirtioBlk { queue, capacity, poisoned: false })
    }

    fn ensure_healthy(&self) -> VirtioBlkResult<()> {
        if self.poisoned {
            return Err(VirtioBlkError::Poisoned);
        }
        Ok(())
    }

    fn check_range(&self, lba: u64, count: usize) -> VirtioBlkResult<()> {
        let count_u64 = count as u64;
        let end = lba.checked_add(count_u64).ok_or(VirtioBlkError::OutOfRange {
            lba, count, capacity: self.capacity,
        })?;
        if end > self.capacity {
            return Err(VirtioBlkError::OutOfRange { lba, count, capacity: self.capacity });
        }
        Ok(())
    }

    /// Submit a request + data + status chain and block until completion.
    ///
    /// `req`, `status` must be stack-local and remain alive for the
    /// whole call. Their physical addresses are handed to the device.
    fn submit(
        &mut self,
        req:    &BlkRequest,
        buf_phys: u64,
        buf_len:  u32,
        buf_write: bool,
        status: &mut BlkStatus,
    ) -> VirtioBlkResult<()> {
        let req_phys    = virt_to_phys(req as *const BlkRequest as *const u8)?;
        let status_phys = virt_to_phys(status as *const BlkStatus as *const u8)?;

        // Descriptor 0: request header (device reads).
        if let Err(e) = self.queue.send(req_phys, core::mem::size_of::<BlkRequest>() as u32, VIRTQ_DESC_F_NEXT) {
            self.poisoned = true;
            return Err(VirtioBlkError::QueueError(e));
        }

        // Descriptor 1: data buffer.
        let data_flags = if buf_write {
            VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE
        } else {
            VIRTQ_DESC_F_NEXT
        };
        if let Err(e) = self.queue.send(buf_phys, buf_len, data_flags) {
            // The chain is broken. Mark the disk unusable until re-init.
            self.poisoned = true;
            return Err(VirtioBlkError::QueueError(e));
        }

        // Descriptor 2: status byte (device writes).
        if let Err(e) = self.queue.send(status_phys, core::mem::size_of::<BlkStatus>() as u32, VIRTQ_DESC_F_WRITE) {
            self.poisoned = true;
            return Err(VirtioBlkError::QueueError(e));
        }

        // Ensure the descriptor writes are visible before the doorbell.
        compiler_fence(Ordering::SeqCst);
        self.queue.wait_used();

        if status.status != STATUS_OK {
            return Err(VirtioBlkError::IoError { status: status.status });
        }
        Ok(())
    }

    /// Read `count` sectors starting at `lba` into `buf`.
    ///
    /// `buf.len()` must be exactly `count * 512`.
    pub fn read_sectors(&mut self, lba: u64, count: usize, buf: &mut [u8]) -> VirtioBlkResult<()> {
        self.ensure_healthy()?;
        let expected = count
            .checked_mul(SECTOR_SIZE)
            .ok_or(VirtioBlkError::BufferLengthMismatch {
                expected: usize::MAX,
                actual: buf.len(),
            })?;
        if buf.len() != expected {
            return Err(VirtioBlkError::BufferLengthMismatch {
                expected,
                actual: buf.len(),
            });
        }
        if count == 0 {
            return Ok(());
        }
        if expected > u32::MAX as usize {
            return Err(VirtioBlkError::BufferLengthMismatch {
                expected: u32::MAX as usize,
                actual: expected,
            });
        }
        self.check_range(lba, count)?;

        let req = BlkRequest { type_: VIRTIO_BLK_T_IN, ioprio: 0, sector: lba };
        let mut status = BlkStatus { status: 0xFF };
        let buf_phys = virt_to_phys(buf.as_mut_ptr())?;
        self.submit(&req, buf_phys, expected as u32, true, &mut status)
    }

    /// Write `buf` starting at `lba`. `buf.len()` must be a nonzero
    /// multiple of 512.
    pub fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> VirtioBlkResult<()> {
        self.ensure_healthy()?;
        if buf.is_empty() || buf.len() % SECTOR_SIZE != 0 {
            return Err(VirtioBlkError::BufferLengthMismatch {
                expected: (buf.len() / SECTOR_SIZE) * SECTOR_SIZE,
                actual: buf.len(),
            });
        }
        if buf.len() > u32::MAX as usize {
            return Err(VirtioBlkError::BufferLengthMismatch {
                expected: u32::MAX as usize,
                actual: buf.len(),
            });
        }
        let count = buf.len() / SECTOR_SIZE;
        self.check_range(lba, count)?;

        let req = BlkRequest { type_: VIRTIO_BLK_T_OUT, ioprio: 0, sector: lba };
        let mut status = BlkStatus { status: 0xFF };
        let buf_phys = virt_to_phys(buf.as_ptr())?;
        self.submit(&req, buf_phys, buf.len() as u32, false, &mut status)?;

        // Invalidate any cached sectors in the written range so a later
        // read returns the fresh data.
        let end = lba.saturating_add(count as u64);
        BLOCK_CACHE.lock().retain(|&k, _| k < lba || k >= end);
        Ok(())
    }

    /// Invalidate the cache entry for a single sector.
    pub fn invalidate_cache(&self, lba: u64) {
        BLOCK_CACHE.lock().remove(&lba);
    }
}

// ---------------------------------------------------------------------------
// Virtual → physical
// ---------------------------------------------------------------------------

/// Translate a virtual DMA address to physical. Returns `None` if the
/// pointer is outside the identity-mapped range (would silently produce
/// garbage otherwise).
#[inline]
fn virt_to_phys(ptr: *const u8) -> VirtioBlkResult<u64> {
    let addr = ptr as usize;
    if addr < PHYS_OFFSET {
        return Err(VirtioBlkError::DmaMappingFailed);
    }
    Ok((addr - PHYS_OFFSET) as u64)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Returns `true` if a virtio-blk device is present. IRQ-safe.
pub fn is_present() -> bool {
    PRESENT.load(Ordering::Acquire)
}

/// Alias for [`is_present`].
pub fn is_available() -> bool {
    is_present()
}

/// Disk capacity in MiB, or `None` if no disk is present. IRQ-safe.
pub fn capacity_mb() -> Option<u64> {
    let sectors = CAPACITY_SECTORS.load(Ordering::Acquire);
    if sectors == 0 { None } else {
        Some(sectors.saturating_mul(SECTOR_SIZE as u64) / 1_048_576)
    }
}

/// Disk capacity in sectors, or `None` if no disk is present.
pub fn capacity_sectors() -> Option<u64> {
    let s = CAPACITY_SECTORS.load(Ordering::Acquire);
    if s == 0 { None } else { Some(s) }
}

/// Attempt to bring up the virtio-blk device from a PCI descriptor.
///
/// Idempotent: a second call while a disk is installed returns `false`
/// and leaves the existing disk untouched.
pub fn try_init(dev: &PciDevice) -> bool {
    let mut guard = DISK.lock();
    if guard.is_some() {
        return false;
    }
    let Some(disk) = VirtioBlk::init(dev) else {
        return false;
    };

    // Clear any stale cache entries from a previous disk; they would
    // refer to sectors that no longer mean the same thing.
    BLOCK_CACHE.lock().clear();

    let sectors = disk.capacity;
    *guard = Some(disk);
    CAPACITY_SECTORS.store(sectors, Ordering::Release);
    PRESENT.store(true, Ordering::Release);
    true
}

/// Read sectors. Blocks until completion. Must not be called from IRQ.
pub fn read_sectors(lba: u64, count: usize, buf: &mut [u8]) -> VirtioBlkResult<()> {
    let mut guard = DISK.lock();
    let disk = guard.as_mut().ok_or(VirtioBlkError::NotInitialized)?;
    disk.read_sectors(lba, count, buf)
}

/// Write sectors. Blocks until completion. Must not be called from IRQ.
pub fn write_sectors(lba: u64, buf: &[u8]) -> VirtioBlkResult<()> {
    let mut guard = DISK.lock();
    let disk = guard.as_mut().ok_or(VirtioBlkError::NotInitialized)?;
    disk.write_sectors(lba, buf)
}

/// Read with up to `RETRY_COUNT` attempts on retriable errors.
pub fn read_sectors_retry(lba: u64, count: usize, buf: &mut [u8]) -> VirtioBlkResult<()> {
    let mut last_err = VirtioBlkError::NotInitialized;
    for attempt in 0..RETRY_COUNT {
        match read_sectors(lba, count, buf) {
            Ok(()) => return Ok(()),
            Err(e) if !e.is_retriable() => return Err(e),
            Err(e) => {
                crate::serial_println!(
                    "[VIRTIO-BLK] read retry {}/{} lba={} err={}",
                    attempt + 1, RETRY_COUNT, lba, e,
                );
                last_err = e;
                if attempt + 1 < RETRY_COUNT {
                    sleep_ms(RETRY_DELAY_MS);
                }
            }
        }
    }
    Err(last_err)
}

/// Write with up to `RETRY_COUNT` attempts on retriable errors.
pub fn write_sectors_retry(lba: u64, buf: &[u8]) -> VirtioBlkResult<()> {
    let mut last_err = VirtioBlkError::NotInitialized;
    for attempt in 0..RETRY_COUNT {
        match write_sectors(lba, buf) {
            Ok(()) => return Ok(()),
            Err(e) if !e.is_retriable() => return Err(e),
            Err(e) => {
                crate::serial_println!(
                    "[VIRTIO-BLK] write retry {}/{} lba={} err={}",
                    attempt + 1, RETRY_COUNT, lba, e,
                );
                last_err = e;
                if attempt + 1 < RETRY_COUNT {
                    sleep_ms(RETRY_DELAY_MS);
                }
            }
        }
    }
    Err(last_err)
}

/// Read a single sector through the cache.
///
/// `buf.len()` must be exactly [`SECTOR_SIZE`]. Cache misses fall back
/// to a retried disk read. Writes invalidate the corresponding cache
/// entries automatically, so a read after a write returns fresh data.
pub fn read_cached(lba: u64, buf: &mut [u8]) -> VirtioBlkResult<()> {
    if buf.len() != SECTOR_SIZE {
        return Err(VirtioBlkError::BufferLengthMismatch {
            expected: SECTOR_SIZE,
            actual: buf.len(),
        });
    }

    // Fast path: cache hit without the disk lock.
    if let Some(cached) = BLOCK_CACHE.lock().get(&lba) {
        buf.copy_from_slice(cached);
        return Ok(());
    }

    // Slow path: take the disk lock, re-check the cache (another thread
    // may have populated it in the meantime), and read on miss.
    let mut guard = DISK.lock();
    let disk = guard.as_mut().ok_or(VirtioBlkError::NotInitialized)?;

    if let Some(cached) = BLOCK_CACHE.lock().get(&lba) {
        buf.copy_from_slice(cached);
        return Ok(());
    }

    // Retry the physical read inline so we don't recurse into
    // `read_sectors_retry`, which would try to lock `DISK` again.
    let mut last_err = VirtioBlkError::NotInitialized;
    for attempt in 0..RETRY_COUNT {
        match disk.read_sectors(lba, 1, buf) {
            Ok(()) => { last_err = VirtioBlkError::IoError { status: 0 }; break; }
            Err(e) if !e.is_retriable() => return Err(e),
            Err(e) => {
                last_err = e;
                if attempt + 1 < RETRY_COUNT {
                    sleep_ms(RETRY_DELAY_MS);
                }
            }
        }
    }
    // `last_err` is either `IoError{status:0}` (success sentinel) or a real error.
    if !matches!(last_err, VirtioBlkError::IoError { status: 0 }) {
        return Err(last_err);
    }

    // Populate the cache.
    let mut cache = BLOCK_CACHE.lock();
    if cache.len() >= CACHE_SIZE {
        if let Some((&oldest, _)) = cache.iter().next() {
            cache.remove(&oldest);
        }
    }
    cache.insert(lba, buf.to_vec());
    Ok(())
}

/// Invalidate a single cached sector.
pub fn invalidate_cache(lba: u64) {
    BLOCK_CACHE.lock().remove(&lba);
}

/// Invalidate the entire cache.
pub fn invalidate_cache_all() {
    BLOCK_CACHE.lock().clear();
}

// ---------------------------------------------------------------------------
// Tests (compile-time only)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_are_sane() {
        assert_eq!(SECTOR_SIZE, 512);
        assert_eq!(RETRY_COUNT, 3);
        assert_eq!(core::mem::size_of::<BlkRequest>(), 16);
        assert_eq!(core::mem::size_of::<BlkStatus>(), 1);
    }

    #[test]
    fn programming_errors_are_not_retriable() {
        assert!(!VirtioBlkError::BufferLengthMismatch { expected: 512, actual: 0 }.is_retriable());
        assert!(!VirtioBlkError::NotInitialized.is_retriable());
        assert!(!VirtioBlkError::OutOfRange { lba: 0, count: 1, capacity: 0 }.is_retriable());
        assert!(!VirtioBlkError::DmaMappingFailed.is_retriable());
    }

    #[test]
    fn device_errors_are_retriable() {
        assert!(VirtioBlkError::IoError { status: 1 }.is_retriable());
        assert!(VirtioBlkError::QueueError("full").is_retriable());
    }
}
