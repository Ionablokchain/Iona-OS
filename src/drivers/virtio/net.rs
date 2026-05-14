//! Virtio Network Device Driver
//! Trimite/primește frame-uri Ethernet raw pentru smoltcp

use alloc::vec::Vec;
use spin::Mutex;
use super::{VirtQueue, init_device};
use crate::pci::PciDevice;

pub struct VirtioNet {
    tx_queue: VirtQueue,
    rx_queue: VirtQueue,
    pub mac:  [u8; 6],
}

unsafe impl Send for VirtioNet {}
static NIC: Mutex<Option<VirtioNet>> = Mutex::new(None);

/// Header virtio-net (prepended la fiecare packet)
#[repr(C)]
struct NetHeader {
    flags:       u8,
    gso_type:    u8,
    hdr_len:     u16,
    gso_size:    u16,
    csum_start:  u16,
    csum_offset: u16,
}

const NET_HDR_SIZE: usize = core::mem::size_of::<NetHeader>();

pub fn try_init(dev: &PciDevice) -> bool {
    let io_base = match init_device(dev) {
        Some(b) => b,
        None    => return false,
    };

    // Citim MAC address din config space virtio-net (offset 0x14)
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

    let rx = match VirtQueue::new(io_base, 0) { Some(q) => q, None => return false };
    let tx = match VirtQueue::new(io_base, 1) { Some(q) => q, None => return false };

    crate::serial_println!("  [VIRTIO-NET] MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    *NIC.lock() = Some(VirtioNet { rx_queue: rx, tx_queue: tx, mac });
    true
}

pub fn send_frame(frame: &[u8]) {
    let mut lock = NIC.lock();
    let nic = match lock.as_mut() { Some(n) => n, None => return };

    // Prepend virtio-net header (zeros = no checksum offload)
    let mut packet = alloc::vec![0u8; NET_HDR_SIZE + frame.len()];
    packet[NET_HDR_SIZE..].copy_from_slice(frame);

    nic.tx_queue.send(packet.as_ptr() as u64, packet.len() as u32, 0);
    nic.tx_queue.wait_used();
}

pub fn recv_frame() -> Option<Vec<u8>> {
    let mut lock = NIC.lock();
    let nic = match lock.as_mut() { Some(n) => n, None => return None };

    let mut buf = alloc::vec![0u8; 1514 + NET_HDR_SIZE];
    nic.rx_queue.send(buf.as_mut_ptr() as u64, buf.len() as u32, 2); // WRITE
    // Non-blocking check
    let used_idx = unsafe { (*nic.rx_queue.used).idx };
    if used_idx != nic.rx_queue.last_used {
        nic.rx_queue.last_used = nic.rx_queue.last_used.wrapping_add(1);
        // Returnăm frame fără header virtio
        Some(buf[NET_HDR_SIZE..].to_vec())
    } else {
        None
    }
}

pub fn mac() -> Option<[u8; 6]> {
    NIC.lock().as_ref().map(|n| n.mac)
}

pub fn is_present() -> bool { NIC.lock().is_some() }
