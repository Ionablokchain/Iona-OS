//! VirtIO network device driver.
//!
//! This driver implements the VirtIO network device protocol. It can send
//! and receive raw Ethernet frames, suitable for use with the `smoltcp` stack.
//!
//! # Features
//! - Uses two virtqueues: receive queue (index 0) and transmit queue (index 1).
//! - Prepends a virtio‑net header (currently all zeroes, no checksum offload).
//! - Reads the MAC address from the device configuration space.
//!
//! # Example
//! ```rust,ignore
//! use crate::drivers::virtio::net::{send_frame, recv_frame, mac, is_present};
//!
//! if is_present() {
//!     let my_mac = mac().unwrap();
//!     send_frame(&eth_frame);
//!     if let Some(frame) = recv_frame() {
//!         // process
//!     }
//! }
//! ```

use alloc::vec::Vec;
use spin::Mutex;
use super::{VirtQueue, init_device};
use crate::pci::PciDevice;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Size of the virtio‑net header that precedes each packet.
const NET_HDR_SIZE: usize = core::mem::size_of::<NetHeader>();

// -----------------------------------------------------------------------------
// VirtIO net header structure
// -----------------------------------------------------------------------------

/// VirtIO network header (prepended to each packet).
/// All fields are zero when checksum offload is disabled.
#[repr(C)]
struct NetHeader {
    /// Flags (e.g., VIRTIO_NET_HDR_F_NEEDS_CSUM).
    flags: u8,
    /// GSO type (VIRTIO_NET_HDR_GSO_NONE = 0).
    gso_type: u8,
    /// Header length (for GSO).
    hdr_len: u16,
    /// GSO size (for GSO).
    gso_size: u16,
    /// Checksum start offset.
    csum_start: u16,
    /// Checksum offset.
    csum_offset: u16,
}

// -----------------------------------------------------------------------------
// Device state
// -----------------------------------------------------------------------------

/// VirtIO network device state.
pub struct VirtioNet {
    /// Transmit queue (index 1).
    tx_queue: VirtQueue,
    /// Receive queue (index 0).
    rx_queue: VirtQueue,
    /// MAC address of the device.
    pub mac: [u8; 6],
}

// Safe to send between cores because all operations are locked.
unsafe impl Send for VirtioNet {}

/// Global network device instance.
static NIC: Mutex<Option<VirtioNet>> = Mutex::new(None);

// -----------------------------------------------------------------------------
// Initialisation
// -----------------------------------------------------------------------------

/// Try to initialise the VirtIO network device from a PCI device.
/// Returns `true` on success, `false` otherwise.
pub fn try_init(dev: &PciDevice) -> bool {
    let io_base = match init_device(dev) {
        Some(b) => b,
        None => return false,
    };

    // Read the MAC address from the device configuration space.
    // VirtIO network config layout: MAC address at offsets 0x14‑0x19.
    let mac_lo = crate::pci::config_read_u32(dev.addr.bus, dev.addr.device, dev.addr.function, 0x14);
    let mac_hi = crate::pci::config_read_u32(dev.addr.bus, dev.addr.device, dev.addr.function, 0x18);
    let mac = [
        (mac_lo & 0xFF) as u8,
        ((mac_lo >> 8) & 0xFF) as u8,
        ((mac_lo >> 16) & 0xFF) as u8,
        ((mac_lo >> 24) & 0xFF) as u8,
        (mac_hi & 0xFF) as u8,
        ((mac_hi >> 8) & 0xFF) as u8,
    ];

    // Initialise virtqueues: queue 0 = receive, queue 1 = transmit.
    let rx = match VirtQueue::new(io_base, 0) {
        Some(q) => q,
        None => return false,
    };
    let tx = match VirtQueue::new(io_base, 1) {
        Some(q) => q,
        None => return false,
    };

    crate::serial_println!(
        "  [VIRTIO-NET] MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );

    *NIC.lock() = Some(VirtioNet {
        rx_queue: rx,
        tx_queue: tx,
        mac,
    });
    true
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Send an Ethernet frame (raw bytes).
///
/// The function prepends a zeroed virtio‑net header (no checksum offload),
/// places the packet in the transmit queue, and waits for the device to
/// consume it.
pub fn send_frame(frame: &[u8]) {
    let mut lock = NIC.lock();
    let nic = match lock.as_mut() {
        Some(n) => n,
        None => return,
    };

    // Prepend the virtio‑net header (all zeros = no offload).
    let mut packet = alloc::vec![0u8; NET_HDR_SIZE + frame.len()];
    packet[NET_HDR_SIZE..].copy_from_slice(frame);

    // Submit the packet to the TX queue.
    nic.tx_queue.send(packet.as_ptr() as u64, packet.len() as u32, 0);
    nic.tx_queue.wait_used();
}

/// Receive an Ethernet frame (non‑blocking).
///
/// Returns `Some(frame)` if a frame is available, `None` otherwise.
/// The received frame does **not** include the virtio‑net header.
pub fn recv_frame() -> Option<Vec<u8>> {
    let mut lock = NIC.lock();
    let nic = match lock.as_mut() {
        Some(n) => n,
        None => return None,
    };

    // Prepare a buffer large enough for the maximum Ethernet frame plus header.
    let mut buf = alloc::vec![0u8; 1514 + NET_HDR_SIZE];
    // WRITE flag (2) indicates the device will write into the buffer.
    nic.rx_queue.send(buf.as_mut_ptr() as u64, buf.len() as u32, 2);

    // Check if the device has placed a packet in the queue.
    // The used index is updated by the device when a packet is received.
    let used_idx = unsafe { (*nic.rx_queue.used).idx };
    if used_idx != nic.rx_queue.last_used {
        nic.rx_queue.last_used = nic.rx_queue.last_used.wrapping_add(1);
        // Return the packet without the virtio‑net header.
        Some(buf[NET_HDR_SIZE..].to_vec())
    } else {
        None
    }
}

/// Returns the MAC address of the network device, if available.
#[must_use]
pub fn mac() -> Option<[u8; 6]> {
    NIC.lock().as_ref().map(|n| n.mac)
}

/// Returns `true` if a VirtIO network device is present and initialised.
#[must_use]
pub fn is_present() -> bool {
    NIC.lock().is_some()
}
