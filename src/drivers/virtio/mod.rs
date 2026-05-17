//! Virtio driver — common interface for all virtio devices
//!
//! Virtio is the standard for virtual devices in QEMU/KVM.
//! Advantages: simple, performant, well‑documented (virtio 1.1+ spec)
//!
//! Subsystems:
//!   - virtio-blk  → storage (read/write sectors)
//!   - virtio-net  → network (Ethernet frames)
//!
//! VirtQueue: shared data structure between driver and hypervisor.
//!   - Descriptor Table: array of descriptors (buffer ptr + len + flags + next)
//!   - Available Ring:   driver → device (which buffers are ready)
//!   - Used Ring:        device → driver (which buffers have been processed)

use alloc::alloc::{alloc, Layout};
use core::mem::size_of;
use core::ptr::NonNull;
use x86_64::instructions::port::Port;
use crate::pci::PciDevice;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// VirtQueue size (must be a power of two).
pub const QUEUE_SIZE: usize = 64;

/// Virtio PCI legacy registers (offsets from I/O base).
const VIRTIO_PCI_HOST_FEATURES: u16 = 0x00;
const VIRTIO_PCI_GUEST_FEATURES: u16 = 0x04;
const VIRTIO_PCI_QUEUE_ADDR:   u16 = 0x08;
const VIRTIO_PCI_QUEUE_SIZE:   u16 = 0x0C;
const VIRTIO_PCI_QUEUE_SEL:    u16 = 0x0E;
const VIRTIO_PCI_QUEUE_NOTIFY: u16 = 0x10;
const VIRTIO_PCI_STATUS:       u16 = 0x12;

/// Virtqueue descriptor flags.
const VIRTQ_DESC_F_NEXT:  u16 = 0x01;
const VIRTQ_DESC_F_WRITE: u16 = 0x02;
const VIRTQ_DESC_F_INDIRECT: u16 = 0x04;

/// Virtio device status bits.
const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 0x01;
const VIRTIO_STATUS_DRIVER:       u8 = 0x02;
const VIRTIO_STATUS_DRIVER_OK:    u8 = 0x0F;
const VIRTIO_STATUS_FAILED:       u8 = 0x80;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during virtio device initialisation or operation.
#[derive(Debug, Error)]
pub enum VirtioError {
    #[error("VirtQueue size is zero or not supported by device")]
    InvalidQueueSize,
    #[error("Memory allocation failed for VirtQueue (size {size} bytes)")]
    AllocationFailed { size: usize },
    #[error("PCI device does not have I/O BAR or BAR address is invalid")]
    NoIoBar,
    #[error("Device is in FAILED state after reset")]
    DeviceFailed,
    #[error("Request timeout waiting for used buffer")]
    Timeout,
}

pub type VirtioResult<T> = Result<T, VirtioError>;

// -----------------------------------------------------------------------------
// Virtqueue descriptor structures
// -----------------------------------------------------------------------------

/// Virtio descriptor – a single buffer in the queue.
#[repr(C)]
#[derive(Debug)]
pub struct VirtqDesc {
    pub addr:  u64,   // physical address of the buffer
    pub len:   u32,   // length in bytes
    pub flags: u16,   // NEXT, WRITE, INDIRECT
    pub next:  u16,   // next descriptor index if NEXT flag set
}

/// Available ring – driver → device.
#[repr(C)]
pub struct VirtqAvail {
    pub flags: u16,
    pub idx:   u16,
    pub ring:  [u16; QUEUE_SIZE],
    pub used_event: u16,
}

/// Used ring element.
#[repr(C)]
pub struct VirtqUsedElem {
    pub id:  u32,   // descriptor index
    pub len: u32,   // number of bytes written by device
}

/// Used ring – device → driver.
#[repr(C)]
pub struct VirtqUsed {
    pub flags: u16,
    pub idx:   u16,
    pub ring:  [VirtqUsedElem; QUEUE_SIZE],
    pub avail_event: u16,
}

// -----------------------------------------------------------------------------
// VirtQueue
// -----------------------------------------------------------------------------

/// Complete VirtQueue – descriptor table + available ring + used ring.
pub struct VirtQueue {
    /// Pointer to descriptor table (aligned to 4 KiB).
    desc: NonNull<VirtqDesc>,
    /// Pointer to available ring.
    avail: NonNull<VirtqAvail>,
    /// Pointer to used ring.
    used: NonNull<VirtqUsed>,
    queue_index: u16,
    io_base: u16,
    next_desc: usize,
    last_used: u16,
}

impl VirtQueue {
    /// Initialise a VirtQueue for a legacy PCI virtio device.
    ///
    /// # Safety
    /// This function allocates a block of memory that must stay alive for the
    /// lifetime of the VirtQueue. The caller must ensure that the allocated
    /// memory is not freed prematurely.
    pub unsafe fn new(io_base: u16, queue_index: u16) -> VirtioResult<Self> {
        // Select the queue.
        Port::<u16>::new(io_base + VIRTIO_PCI_QUEUE_SEL).write(queue_index);

        // Read the maximum queue size supported by the device.
        let max_size = Port::<u16>::new(io_base + VIRTIO_PCI_QUEUE_SIZE).read();
        if max_size == 0 {
            return Err(VirtioError::InvalidQueueSize);
        }
        let size = (max_size as usize).min(QUEUE_SIZE) as u16;

        // Calculate total memory needed.
        // Layout: descriptor table | available ring | padding | used ring
        let desc_size  = size as usize * size_of::<VirtqDesc>();
        let avail_size = size_of::<u16>() * 3 + size as usize * 2;
        let used_size  = size_of::<VirtqUsed>();
        // Align used ring to a page boundary (4 KiB) for efficiency.
        let aligned_used_offset = (desc_size + avail_size + 4095) & !4095;
        let total_size = aligned_used_offset + used_size;

        // Allocate memory with page alignment.
        let layout = Layout::from_size_align(total_size, 4096)
            .map_err(|_| VirtioError::AllocationFailed { size: total_size })?;
        let ptr = alloc(layout);
        if ptr.is_null() {
            return Err(VirtioError::AllocationFailed { size: total_size });
        }
        // Zero initialise the whole block.
        ptr.write_bytes(0, total_size);

        let desc_ptr = ptr as *mut VirtqDesc;
        let avail_ptr = unsafe { ptr.add(desc_size) as *mut VirtqAvail };
        let used_ptr = unsafe { ptr.add(aligned_used_offset) as *mut VirtqUsed };

        // Tell the device about the queue.
        Port::<u16>::new(io_base + VIRTIO_PCI_QUEUE_SIZE).write(size);
        let phys_addr = (ptr as u64) >> 12; // Page number (assumes identity mapping).
        Port::<u32>::new(io_base + VIRTIO_PCI_QUEUE_ADDR).write(phys_addr as u32);

        Ok(Self {
            desc: NonNull::new(desc_ptr).ok_or(VirtioError::AllocationFailed { size: total_size })?,
            avail: NonNull::new(avail_ptr).ok_or(VirtioError::AllocationFailed { size: total_size })?,
            used: NonNull::new(used_ptr).ok_or(VirtioError::AllocationFailed { size: total_size })?,
            queue_index,
            io_base,
            next_desc: 0,
            last_used: 0,
        })
    }

    /// Add a descriptor to the queue and notify the device.
    pub fn send(&mut self, phys_addr: u64, len: u32, flags: u16) -> u16 {
        let idx = self.next_desc % QUEUE_SIZE;
        unsafe {
            let desc = self.desc.as_ptr().add(idx);
            (*desc).addr = phys_addr;
            (*desc).len = len;
            (*desc).flags = flags;
            (*desc).next = 0;

            let avail = self.avail.as_mut();
            let avail_idx = (avail.idx as usize) % QUEUE_SIZE;
            avail.ring[avail_idx] = idx as u16;
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            avail.idx = avail.idx.wrapping_add(1);
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        }
        // Notify the device (queue kick).
        unsafe { Port::<u16>::new(self.io_base + VIRTIO_PCI_QUEUE_NOTIFY).write(self.queue_index); }
        self.next_desc += 1;
        idx as u16
    }

    /// Wait for a descriptor to be processed and return its index.
    pub fn wait_used(&mut self) -> u16 {
        loop {
            let used_idx = unsafe { self.used.as_ref().idx };
            if used_idx != self.last_used {
                let elem = unsafe {
                    self.used.as_ref().ring[(self.last_used as usize) % QUEUE_SIZE]
                };
                self.last_used = self.last_used.wrapping_add(1);
                return elem.id as u16;
            }
            core::hint::spin_loop();
        }
    }

    /// Try to get a used descriptor without blocking.
    pub fn try_wait_used(&mut self) -> Option<u16> {
        let used_idx = unsafe { self.used.as_ref().idx };
        if used_idx != self.last_used {
            let elem = unsafe {
                self.used.as_ref().ring[(self.last_used as usize) % QUEUE_SIZE]
            };
            self.last_used = self.last_used.wrapping_add(1);
            Some(elem.id as u16)
        } else {
            None
        }
    }
}

// -----------------------------------------------------------------------------
// Device initialisation helpers
// -----------------------------------------------------------------------------

/// Initialise a legacy virtio PCI device (negotiate features, set status).
pub fn init_device(dev: &PciDevice) -> VirtioResult<u16> {
    // Read I/O BAR (bar[0]).
    let io_base = (dev.bar[0] & !3) as u16;
    if io_base == 0 {
        return Err(VirtioError::NoIoBar);
    }

    unsafe {
        // Reset device.
        Port::<u8>::new(io_base + VIRTIO_PCI_STATUS).write(0);

        // Acknowledge + Driver.
        Port::<u8>::new(io_base + VIRTIO_PCI_STATUS).write(VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);

        // Feature negotiation: read device features, accept all (no special features).
        let _features = Port::<u32>::new(io_base + VIRTIO_PCI_HOST_FEATURES).read();
        Port::<u32>::new(io_base + VIRTIO_PCI_GUEST_FEATURES).write(0);

        // Driver OK.
        Port::<u8>::new(io_base + VIRTIO_PCI_STATUS).write(VIRTIO_STATUS_DRIVER_OK);
    }

    // Enable bus mastering for the device.
    crate::pci::enable_device(dev.addr.bus, dev.addr.device, dev.addr.function);

    Ok(io_base)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(QUEUE_SIZE, 64);
        assert_eq!(VIRTQ_DESC_F_NEXT, 0x01);
        assert_eq!(VIRTQ_DESC_F_WRITE, 0x02);
    }

    // Additional tests would require a real PCI device or a mock.
}
