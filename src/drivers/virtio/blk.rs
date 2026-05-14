//! Virtio Block Device Driver
//! Citim/scriem sectoare de 512 bytes via VirtQueue

use alloc::boxed::Box;
use spin::Mutex;
use super::{VirtQueue, init_device};
use crate::pci::PciDevice;

const VIRTIO_BLK_T_IN:  u32 = 0; // read
const VIRTIO_BLK_T_OUT: u32 = 1; // write

#[repr(C)]
struct BlkRequest {
    type_:   u32,
    ioprio:  u32,
    sector:  u64,
}

#[repr(C)]
struct BlkStatus { status: u8 }

pub struct VirtioBlk {
    queue:    VirtQueue,
    capacity: u64, // sectoare de 512 bytes
}

unsafe impl Send for VirtioBlk {}
static DISK: Mutex<Option<VirtioBlk>> = Mutex::new(None);

impl VirtioBlk {
    pub fn init(dev: &PciDevice) -> Option<()> {
        let io_base = init_device(dev)?;
        // Citim capacitatea (offset 0x14 în config space virtio)
        let cap_lo = crate::pci::config_read_u32(dev.addr.bus, dev.addr.device, dev.addr.function, 0x14);
        let cap_hi = crate::pci::config_read_u32(dev.addr.bus, dev.addr.device, dev.addr.function, 0x18);
        let capacity = (cap_hi as u64) << 32 | cap_lo as u64;

        let queue = VirtQueue::new(io_base, 0)?;
        crate::serial_println!("  [VIRTIO-BLK] capacity={} sectors ({} MB)",
            capacity, capacity * 512 / 1_048_576);

        *DISK.lock() = Some(VirtioBlk { queue, capacity });
        Some(())
    }

    pub fn read_sectors(&mut self, lba: u64, count: usize, buf: &mut [u8]) {
        assert_eq!(buf.len(), count * 512);
        let req = Box::new(BlkRequest { type_: VIRTIO_BLK_T_IN, ioprio: 0, sector: lba });
        let status = Box::new(BlkStatus { status: 0xFF });

        let req_phys   = (&*req as *const _) as u64;
        let buf_phys   = buf.as_ptr() as u64;
        let status_phys = (&*status as *const _) as u64;

        // 3 descriptori în lanț: request header | data buffer (device write) | status
        self.queue.send(req_phys, core::mem::size_of::<BlkRequest>() as u32, 1); // NEXT
        self.queue.send(buf_phys, buf.len() as u32, 1 | 2); // NEXT | WRITE
        self.queue.send(status_phys, 1, 2); // WRITE only
        self.queue.wait_used();

        assert_eq!((*status).status, 0, "virtio-blk read error");
        core::mem::forget(req);
        core::mem::forget(status);
    }

    pub fn write_sectors(&mut self, lba: u64, buf: &[u8]) {
        assert_eq!(buf.len() % 512, 0);
        let req = Box::new(BlkRequest { type_: VIRTIO_BLK_T_OUT, ioprio: 0, sector: lba });
        let status = Box::new(BlkStatus { status: 0xFF });
        self.queue.send((&*req as *const _) as u64, core::mem::size_of::<BlkRequest>() as u32, 1);
        self.queue.send(buf.as_ptr() as u64, buf.len() as u32, 1);
        self.queue.send((&*status as *const _) as u64, 1, 2);
        self.queue.wait_used();
        assert_eq!((*status).status, 0, "virtio-blk write error");
        core::mem::forget(req); core::mem::forget(status);
    }
}

/// API publică pentru filesystemuri
pub fn read_sectors(lba: u64, count: usize, buf: &mut [u8]) -> bool {
    match DISK.lock().as_mut() {
        Some(d) => { d.read_sectors(lba, count, buf); true }
        None    => false,
    }
}

pub fn write_sectors(lba: u64, buf: &[u8]) -> bool {
    match DISK.lock().as_mut() {
        Some(d) => { d.write_sectors(lba, buf); true }
        None    => false,
    }
}

pub fn is_present() -> bool { DISK.lock().is_some() }

/// Check if virtio-blk device is available
pub fn is_available() -> bool { DISK.lock().is_some() }

/// Return disk capacity in MB
pub fn capacity_mb() -> Option<u64> {
    DISK.lock().as_ref().map(|d| d.capacity * 512 / 1_048_576)
}

pub fn try_init(dev: &PciDevice) -> bool {
    VirtioBlk::init(dev).is_some()
}

/// Read with retry — attempts up to 3 times on failure
pub fn read_sectors_retry(lba: u64, count: usize, buf: &mut [u8]) -> bool {
    for attempt in 0..3 {
        if read_sectors(lba, count, buf) { return true; }
        crate::serial_println!("[VIRTIO-BLK] read retry {}/3 lba={}", attempt+1, lba);
        crate::arch::x86_64::timer::sleep_ms(10);
    }
    crate::serial_println!("[VIRTIO-BLK] read FAILED after 3 retries lba={}", lba);
    false
}

/// Write with retry + verify
pub fn write_sectors_retry(lba: u64, buf: &[u8]) -> bool {
    for attempt in 0..3 {
        if write_sectors(lba, buf) { return true; }
        crate::serial_println!("[VIRTIO-BLK] write retry {}/3 lba={}", attempt+1, lba);
        crate::arch::x86_64::timer::sleep_ms(10);
    }
    false
}

/// Block cache — 16 cached sectors to reduce I/O
static BLOCK_CACHE: spin::Lazy<spin::Mutex<alloc::collections::BTreeMap<u64, alloc::vec::Vec<u8>>>> =
    spin::Lazy::new(|| spin::Mutex::new(alloc::collections::BTreeMap::new()));

pub fn read_cached(lba: u64, buf: &mut [u8]) -> bool {
    {
        let cache = BLOCK_CACHE.lock();
        if let Some(cached) = cache.get(&lba) {
            let copy_len = cached.len().min(buf.len());
            buf[..copy_len].copy_from_slice(&cached[..copy_len]);
            return true;
        }
    }
    if read_sectors(lba, 1, buf) {
        let mut cache = BLOCK_CACHE.lock();
        if cache.len() >= 16 { cache.pop_first(); } // evict oldest
        cache.insert(lba, buf.to_vec());
        true
    } else { false }
}
