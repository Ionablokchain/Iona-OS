//! Intel e1000 NIC driver — TX/RX ring DMA (full implementation)
//!
//! This module provides a driver for Intel e1000 family network adapters.
//! It uses a standard descriptor ring model:
//! - **RX ring**: 32 descriptors, each with a 2 KB physically contiguous buffer.
//! - **TX ring**: 8 descriptors, each with a 2 KB buffer.
//!
//! # Features
//! - Reset and initialisation of the NIC.
//! - MAC address read from EEPROM.
//! - Interrupt masking (polling‑based operation).
//! - Frame transmission and reception via DMA rings.
//! - Descriptor status polling with timeouts.
//!
//! # Usage
//! ```rust,ignore
//! use iona::drivers::e1000::{send_frame, recv_frame, mac_address};
//!
//! let mac = mac_address().unwrap();
//! send_frame(&eth_frame).unwrap();
//! if let Some(frame) = recv_frame() {
//!     // process
//! }
//! ```

use alloc::vec::Vec;
use spin::Mutex;
use crate::pci::PciDevice;

// -----------------------------------------------------------------------------
// Constants – MMIO register offsets
// -----------------------------------------------------------------------------

const REG_CTRL:   u32 = 0x0000;
const REG_STATUS: u32 = 0x0008;
const REG_EECD:   u32 = 0x0010;
const REG_EERD:   u32 = 0x0014;
const REG_ICR:    u32 = 0x00C0;
const REG_IMS:    u32 = 0x00D0;
const REG_IMC:    u32 = 0x00D8;
const REG_RCTL:   u32 = 0x0100;
const REG_TCTL:   u32 = 0x0400;
const REG_TIPG:   u32 = 0x0410;
const REG_RDBAL:  u32 = 0x2800;
const REG_RDBAH:  u32 = 0x2804;
const REG_RDLEN:  u32 = 0x2808;
const REG_RDH:    u32 = 0x2810;
const REG_RDT:    u32 = 0x2818;
const REG_TDBAL:  u32 = 0x3800;
const REG_TDBAH:  u32 = 0x3804;
const REG_TDLEN:  u32 = 0x3808;
const REG_TDH:    u32 = 0x3810;
const REG_TDT:    u32 = 0x3818;
const REG_RAL:    u32 = 0x5400;
const REG_RAH:    u32 = 0x5404;

// -----------------------------------------------------------------------------
// Control register bits
// -----------------------------------------------------------------------------

const CTRL_SLU:   u32 = 1 << 6;   // Set Link Up
const CTRL_RST:   u32 = 1 << 26;  // Device Reset

// -----------------------------------------------------------------------------
// Receive Control Register bits
// -----------------------------------------------------------------------------

const RCTL_EN:    u32 = 1 << 1;   // Receiver Enable
const RCTL_UPE:   u32 = 1 << 3;   // Unicast Promiscuous Enable
const RCTL_MPE:   u32 = 1 << 4;   // Multicast Promiscuous Enable
const RCTL_BAM:   u32 = 1 << 15;  // Broadcast Accept Mode
const RCTL_BSIZE: u32 = 0 << 16;  // 2048‑byte buffers (0 = 2048)

// -----------------------------------------------------------------------------
// Transmit Control Register bits
// -----------------------------------------------------------------------------

const TCTL_EN:    u32 = 1 << 1;   // Transmitter Enable
const TCTL_PSP:   u32 = 1 << 3;   // Pad Short Packets

// -----------------------------------------------------------------------------
// Descriptor counts and buffer sizes
// -----------------------------------------------------------------------------

/// Number of receive descriptors (must be power of two).
const RX_DESC_COUNT: usize = 32;
/// Number of transmit descriptors.
const TX_DESC_COUNT: usize = 8;
/// Buffer size for each descriptor (bytes).
const BUF_SIZE: usize = 2048;

/// Virtual‑to‑physical offset (identity mapping).
const PHYS_OFFSET: usize = 0xFFFF_8000_0000_0000;

// -----------------------------------------------------------------------------
// Descriptor structures (legacy, 16 bytes each)
// -----------------------------------------------------------------------------

/// Legacy Receive Descriptor (16 bytes).
#[repr(C)]
struct RxDesc {
    addr:    u64,      // Physical address of the buffer
    length:  u16,      // Length of received packet
    chksum:  u16,      // Checksum
    status:  u8,       // Bits: 0 = DD (Descriptor Done), 1 = EOP
    errors:  u8,       // Error flags
    special: u16,
}

/// Legacy Transmit Descriptor (16 bytes).
#[repr(C)]
struct TxDesc {
    addr:    u64,      // Physical address of the buffer
    length:  u16,      // Length of the packet
    cso:     u8,       // Checksum offset
    cmd:     u8,       // Command: bit0 = EOP, bit1 = IFCS, bit3 = RS (Report Status)
    sta:     u8,       // Status: bit0 = DD (Descriptor Done)
    css:     u8,       // Checksum start
    special: u16,
}

// -----------------------------------------------------------------------------
// Device structure
// -----------------------------------------------------------------------------

/// e1000 NIC device state.
pub struct E1000 {
    /// Virtual MMIO base address.
    pub mmio: usize,
    /// MAC address (6 bytes).
    pub mac: [u8; 6],
    /// Receive descriptor list (owned buffer, 16‑byte aligned).
    rx_descs: Vec<u8>,
    /// Transmit descriptor list (owned buffer).
    tx_descs: Vec<u8>,
    /// Receive data buffers (one per descriptor).
    rx_bufs: Vec<Vec<u8>>,
    /// Transmit data buffers.
    tx_bufs: Vec<Vec<u8>>,
    /// Current RX tail index (next descriptor the driver will process).
    rx_tail: usize,
    /// Current TX tail index (next descriptor available for transmission).
    tx_tail: usize,
}

// -----------------------------------------------------------------------------
// Global device instance
// -----------------------------------------------------------------------------

static E1000_DEV: Mutex<Option<E1000>> = Mutex::new(None);

// -----------------------------------------------------------------------------
// Initialisation
// -----------------------------------------------------------------------------

/// Try to initialise an Intel e1000 NIC from a PCI device.
/// Returns `true` on success, `false` otherwise.
pub fn try_init(dev: &PciDevice) -> bool {
    // Must be Intel vendor.
    if dev.vendor_id != 0x8086 {
        return false;
    }
    // List of supported e1000 device IDs.
    let known = [
        0x100E, 0x100F, 0x1010, 0x1011, 0x1015, 0x1016, 0x1017, 0x1018,
        0x1019, 0x101A, 0x101D, 0x1026, 0x1027, 0x1028, 0x1075, 0x1076,
        0x107C, 0x108A, 0x1099, 0x10D3, 0x10EA,
    ];
    if !known.contains(&dev.device_id) {
        return false;
    }

    let mmio_phys = dev.bar[0] as usize & !0xF;
    if mmio_phys == 0 {
        return false;
    }
    let mmio = mmio_phys + PHYS_OFFSET;

    unsafe {
        // Reset the device.
        write32(mmio, REG_CTRL, read32(mmio, REG_CTRL) | CTRL_RST);
        for _ in 0..100_000 {
            core::hint::spin_loop();
        }

        // Set link up.
        write32(mmio, REG_CTRL, read32(mmio, REG_CTRL) | CTRL_SLU);

        // Mask all interrupts (we use polling).
        write32(mmio, REG_IMC, 0xFFFF_FFFF);
        write32(mmio, REG_ICR, 0xFFFF_FFFF);

        // Read MAC address from EEPROM (using EERD method).
        let mut mac = [0u8; 6];
        for i in 0u32..3 {
            write32(mmio, REG_EERD, (i << 8) | 1);
            let mut word = 0u32;
            for _ in 0..10_000 {
                let v = read32(mmio, REG_EERD);
                if v & (1 << 4) != 0 {
                    word = v >> 16;
                    break;
                }
                core::hint::spin_loop();
            }
            mac[(i * 2) as usize] = (word & 0xFF) as u8;
            mac[(i * 2 + 1) as usize] = ((word >> 8) & 0xFF) as u8;
        }

        // ---------------------------------------------------------------------
        // Allocate RX descriptors and buffers
        // ---------------------------------------------------------------------
        let mut rx_descs = alloc::vec![0u8; RX_DESC_COUNT * 16 + 16];
        let mut rx_bufs: Vec<Vec<u8>> = (0..RX_DESC_COUNT)
            .map(|_| alloc::vec![0u8; BUF_SIZE])
            .collect();

        let rd_ptr = (rx_descs.as_ptr() as usize + 15) & !15;
        for i in 0..RX_DESC_COUNT {
            let desc = &mut *((rd_ptr + i * 16) as *mut RxDesc);
            let buf_phys = rx_bufs[i].as_ptr() as usize - PHYS_OFFSET;
            desc.addr = buf_phys as u64;
            desc.status = 0;
        }
        let rd_phys = rd_ptr - PHYS_OFFSET;
        write32(mmio, REG_RDBAL, (rd_phys & 0xFFFF_FFFF) as u32);
        write32(mmio, REG_RDBAH, (rd_phys >> 32) as u32);
        write32(mmio, REG_RDLEN, (RX_DESC_COUNT * 16) as u32);
        write32(mmio, REG_RDH, 0);
        write32(mmio, REG_RDT, (RX_DESC_COUNT - 1) as u32);
        write32(mmio, REG_RCTL, RCTL_EN | RCTL_UPE | RCTL_MPE | RCTL_BAM | RCTL_BSIZE);

        // ---------------------------------------------------------------------
        // Allocate TX descriptors and buffers
        // ---------------------------------------------------------------------
        let mut tx_descs = alloc::vec![0u8; TX_DESC_COUNT * 16 + 16];
        let mut tx_bufs: Vec<Vec<u8>> = (0..TX_DESC_COUNT)
            .map(|_| alloc::vec![0u8; BUF_SIZE])
            .collect();

        let td_ptr = (tx_descs.as_ptr() as usize + 15) & !15;
        for i in 0..TX_DESC_COUNT {
            let desc = &mut *((td_ptr + i * 16) as *mut TxDesc);
            let buf_phys = tx_bufs[i].as_ptr() as usize - PHYS_OFFSET;
            desc.addr = buf_phys as u64;
            desc.sta = 1; // Set DD = 1 (slot available)
        }
        let td_phys = td_ptr - PHYS_OFFSET;
        write32(mmio, REG_TDBAL, (td_phys & 0xFFFF_FFFF) as u32);
        write32(mmio, REG_TDBAH, (td_phys >> 32) as u32);
        write32(mmio, REG_TDLEN, (TX_DESC_COUNT * 16) as u32);
        write32(mmio, REG_TDH, 0);
        write32(mmio, REG_TDT, 0);
        write32(mmio, REG_TCTL, TCTL_EN | TCTL_PSP | (0x10 << 4) | (0x40 << 12));
        write32(mmio, REG_TIPG, 0x00602006);

        crate::serial_println!(
            "  [e1000] MAC {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} — TX/RX rings ready",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );

        *E1000_DEV.lock() = Some(E1000 {
            mmio,
            mac,
            rx_descs,
            tx_descs,
            rx_bufs,
            tx_bufs,
            rx_tail: RX_DESC_COUNT - 1,
            tx_tail: 0,
        });
        true
    }
}

// -----------------------------------------------------------------------------
// Public API: frame transmission
// -----------------------------------------------------------------------------

/// Send an Ethernet frame (raw bytes). The frame must fit in the TX buffer.
/// Returns `true` on success, `false` if the TX ring is full or an error occurs.
pub fn send_frame(frame: &[u8]) -> bool {
    if frame.len() > BUF_SIZE {
        return false;
    }
    let mut dev_lock = E1000_DEV.lock();
    let dev = match dev_lock.as_mut() {
        Some(d) => d,
        None => return false,
    };

    unsafe {
        let td_ptr = (dev.tx_descs.as_ptr() as usize + 15) & !15;
        let slot = dev.tx_tail;
        let desc = &mut *((td_ptr + slot * 16) as *mut TxDesc);

        // Wait for the slot to become free (DD bit set by hardware).
        let mut available = false;
        for _ in 0..50_000 {
            if desc.sta & 1 != 0 {
                available = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !available {
            // TX ring full – report status.
            let tdh = read32(dev.mmio, REG_TDH);
            let tdt = read32(dev.mmio, REG_TDT);
            crate::serial_println!("[e1000] TX ring full: TDH={} TDT={}", tdh, tdt);
            return false;
        }

        // Copy the frame into the data buffer.
        dev.tx_bufs[slot][..frame.len()].copy_from_slice(frame);
        let buf_phys = dev.tx_bufs[slot].as_ptr() as usize - PHYS_OFFSET;

        // Set up the descriptor.
        desc.addr = buf_phys as u64;
        desc.length = frame.len() as u16;
        desc.cso = 0;
        desc.cmd = 0x0B; // EOP | IFCS | RS (Report Status)
        desc.sta = 0;    // Clear DD – hardware will set it when done.
        desc.css = 0;

        // Advance the tail to trigger transmission.
        dev.tx_tail = (slot + 1) % TX_DESC_COUNT;
        write32(dev.mmio, REG_TDT, dev.tx_tail as u32);
        true
    }
}

// -----------------------------------------------------------------------------
// Public API: frame reception
// -----------------------------------------------------------------------------

/// Receive one Ethernet frame.
/// Returns `Some(Vec<u8>)` with the frame bytes, or `None` if no frame is ready.
pub fn recv_frame() -> Option<Vec<u8>> {
    let mut dev_lock = E1000_DEV.lock();
    let dev = match dev_lock.as_mut() {
        Some(d) => d,
        None => return None,
    };

    unsafe {
        let rd_ptr = (dev.rx_descs.as_ptr() as usize + 15) & !15;
        let next = (dev.rx_tail + 1) % RX_DESC_COUNT;
        let desc = &mut *((rd_ptr + next * 16) as *mut RxDesc);

        // Check if the descriptor is done (DD bit).
        if desc.status & 1 == 0 {
            return None;
        }

        // If there are receive errors, drop the packet.
        if desc.errors != 0 {
            crate::serial_println!(
                "[e1000] RX error bits={:#x} (dropping frame)",
                desc.errors
            );
            desc.status = 0;
            dev.rx_tail = next;
            write32(dev.mmio, REG_RDT, dev.rx_tail as u32);
            return None;
        }

        let len = desc.length as usize;
        if len == 0 || len > BUF_SIZE {
            desc.status = 0;
            return None;
        }

        let frame = dev.rx_bufs[next][..len].to_vec();

        // Give the descriptor back to the hardware.
        desc.status = 0;
        dev.rx_tail = next;
        write32(dev.mmio, REG_RDT, dev.rx_tail as u32);

        Some(frame)
    }
}

// -----------------------------------------------------------------------------
// Public query functions
// -----------------------------------------------------------------------------

/// Returns the MAC address of the e1000 NIC, if available.
pub fn mac_address() -> Option<[u8; 6]> {
    E1000_DEV.lock().as_ref().map(|d| d.mac)
}

/// Returns `true` if an e1000 NIC is initialised.
pub fn is_available() -> bool {
    E1000_DEV.lock().is_some()
}

// -----------------------------------------------------------------------------
// Low‑level MMIO helpers (volatile reads/writes)
// -----------------------------------------------------------------------------

#[inline(always)]
unsafe fn read32(base: usize, offset: u32) -> u32 {
    core::ptr::read_volatile((base + offset as usize) as *const u32)
}

#[inline(always)]
unsafe fn write32(base: usize, offset: u32, value: u32) {
    core::ptr::write_volatile((base + offset as usize) as *mut u32, value);
}
