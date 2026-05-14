//! PCI bus enumeration — descoperim device-urile hardware
//!
//! PCI Configuration Space accesat via port I/O:
//!   Port 0xCF8 = CONFIG_ADDRESS (scriem adresa)
//!   Port 0xCFC = CONFIG_DATA    (citim/scriem date)
//!
//! CONFIG_ADDRESS format:
//!   [31]    = enable bit
//!   [23:16] = bus number (0-255)
//!   [15:11] = device number (0-31)
//!   [10:8]  = function number (0-7)
//!   [7:2]   = register offset (DWORD aligned)

use alloc::vec::Vec;
use x86_64::instructions::port::Port;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PciAddress { pub bus: u8, pub device: u8, pub function: u8 }

#[derive(Debug, Clone)]
pub struct PciDevice {
    pub addr:      PciAddress,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class:     u8,
    pub subclass:  u8,
    pub prog_if:   u8,
    pub revision:  u8,
    pub bar:       [u32; 6],   // Base Address Registers
    pub irq_line:  u8,
}

impl PciDevice {
    /// Virtio block device: vendor=0x1AF4, device=0x1001
    pub fn is_virtio_blk(&self) -> bool {
        self.vendor_id == 0x1AF4 && self.device_id == 0x1001
    }
    /// Virtio network device: vendor=0x1AF4, device=0x1000
    pub fn is_virtio_net(&self) -> bool {
        self.vendor_id == 0x1AF4 && self.device_id == 0x1000
    }
    /// Virtio (any): vendor=0x1AF4
    pub fn is_virtio(&self) -> bool {
        self.vendor_id == 0x1AF4
    }
}

fn config_address(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    (1u32 << 31)
        | ((bus  as u32) << 16)
        | ((dev  as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC)
}

pub fn config_read_u32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    unsafe {
        Port::<u32>::new(0xCF8).write(config_address(bus, dev, func, offset));
        Port::<u32>::new(0xCFC).read()
    }
}

pub fn config_read_u16(bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
    let v = config_read_u32(bus, dev, func, offset);
    if offset & 2 != 0 { (v >> 16) as u16 } else { v as u16 }
}

pub fn config_write_u32(bus: u8, dev: u8, func: u8, offset: u8, val: u32) {
    unsafe {
        Port::<u32>::new(0xCF8).write(config_address(bus, dev, func, offset));
        Port::<u32>::new(0xCFC).write(val);
    }
}

/// Enable Bus Master + Memory Space + I/O Space în Command register
pub fn enable_device(bus: u8, dev: u8, func: u8) {
    let cmd = config_read_u16(bus, dev, func, 0x04);
    config_write_u32(bus, dev, func, 0x04, (cmd | 0x07) as u32);
}

fn probe_device(bus: u8, dev: u8, func: u8) -> Option<PciDevice> {
    let id = config_read_u32(bus, dev, func, 0x00);
    let vendor = (id & 0xFFFF) as u16;
    if vendor == 0xFFFF { return None; }  // nu există device

    let device = (id >> 16) as u16;
    let cc     = config_read_u32(bus, dev, func, 0x08);
    let class   = (cc >> 24) as u8;
    let subclass = (cc >> 16) as u8;
    let prog_if  = (cc >> 8) as u8;
    let revision = cc as u8;

    let mut bar = [0u32; 6];
    for i in 0..6 {
        bar[i] = config_read_u32(bus, dev, func, 0x10 + i as u8 * 4);
    }
    let irq_line = config_read_u16(bus, dev, func, 0x3C) as u8;

    Some(PciDevice {
        addr: PciAddress { bus, device: dev, function: func },
        vendor_id: vendor, device_id: device,
        class, subclass, prog_if, revision,
        bar, irq_line,
    })
}

pub fn config_write_u16(bus: u8, dev: u8, func: u8, offset: u8, val: u16) {
    let old = config_read_u32(bus, dev, func, offset);
    let new_val = if offset & 2 != 0 {
        (old & 0x0000FFFF) | ((val as u32) << 16)
    } else {
        (old & 0xFFFF0000) | (val as u32)
    };
    config_write_u32(bus, dev, func, offset, new_val);
}

/// Walk PCI capability list to find a capability by ID
pub fn find_capability(bus: u8, dev: u8, func: u8, cap_id: u8) -> u8 {
    let status = config_read_u16(bus, dev, func, 0x06);
    if status & 0x10 == 0 { return 0; } // no capabilities list
    let mut ptr = config_read_u16(bus, dev, func, 0x34) as u8;
    ptr &= 0xFC; // mask low 2 bits
    while ptr != 0 {
        let id = config_read_u16(bus, dev, func, ptr) as u8;
        if id == cap_id { return ptr; }
        ptr = (config_read_u16(bus, dev, func, ptr) >> 8) as u8;
        ptr &= 0xFC;
    }
    0
}

// Aliases used by NVMe driver
pub fn read_config_u16(bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
    config_read_u16(bus, dev, func, offset)
}
pub fn read_config_u32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    config_read_u32(bus, dev, func, offset)
}
pub fn write_config_u16(bus: u8, dev: u8, func: u8, offset: u8, val: u16) {
    config_write_u16(bus, dev, func, offset, val);
}

/// Enumerează toate device-urile PCI din sistem
pub fn enumerate() -> Vec<PciDevice> {
    let mut devices = Vec::new();
    for bus in 0u8..=255 {
        for dev in 0u8..32 {
            for func in 0u8..8 {
                if let Some(d) = probe_device(bus, dev, func) {
                    crate::serial_println!(
                        "  [PCI] {:02x}:{:02x}.{} vendor={:04x} dev={:04x} class={:02x}:{:02x}",
                        bus, dev, func, d.vendor_id, d.device_id, d.class, d.subclass
                    );
                    devices.push(d);
                    if func == 0 {
                        // Check multi-function flag
                        let hdr = config_read_u16(bus, dev, 0, 0x0E);
                        if (hdr & 0x80) == 0 { break; }
                    }
                }
            }
        }
    }
    crate::serial_println!("  [PCI] {} devices found", devices.len());
    devices
}

/// Alias pentru enumerate() — scanned boot
pub fn pci_scan() -> alloc::vec::Vec<PciDevice> { enumerate() }

/// PCI device count
pub fn device_count() -> usize { enumerate().len() }
