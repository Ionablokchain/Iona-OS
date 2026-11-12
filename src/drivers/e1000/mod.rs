//! Intel e1000 NIC driver — TX/RX ring DMA.
//!
//! Descriptor-ring model for the Intel 8254x family (e1000 and close
//! relatives) using legacy 16-byte descriptors.
//!
//! # Layout
//!
//! * RX ring: 32 descriptors, each pointing at a 2 KiB buffer.
//! * TX ring: 32 descriptors, each pointing at a 2 KiB buffer.
//!
//! All DMA buffers and descriptor rings are 16-byte aligned as required
//! by the e1000 datasheet. Alignment is enforced by allocating a single
//! over-sized `Vec<u8>` per region and aligning the base pointer inside.
//!
//! # Features
//!
//! * Controller reset (polled to completion), link up.
//! * MAC address from RAL0/RAH0 when valid, else from EEPROM.
//! * Promiscuous mode off by default; enabled via [`set_promiscuous`].
//! * Polling-based TX/RX with timeout and error reporting.
//! * Minimum-frame enforcement (padding done by HW via TCTL.PSP).
//!
//! # Not supported
//!
//! * Interrupt-driven completion (polling only).
//! * Multiple TX/RX queues (82574/82576 advanced descriptors).
//! * Jumbo frames, RSS, checksum offload.
//! * EEPROM writes; hardware autonegotiation control.
//!
//! # Preconditions
//!
//! * Physical memory is identity-mapped at [`PHYS_OFFSET`].
//! * The global allocator returns physically-contiguous memory in that
//!   range (required for the DMA rings and buffers).
//! * Only one e1000 controller per system is supported by the global
//!   state; subsequent [`try_init`] calls for other devices are ignored.

use alloc::vec::Vec;
use core::sync::atomic::{compiler_fence, Ordering};
use spin::Mutex;

use crate::pci::PciDevice;

// ---------------------------------------------------------------------------
// MMIO registers
// ---------------------------------------------------------------------------

const REG_CTRL:   u32 = 0x0000;
const REG_STATUS: u32 = 0x0008;
const REG_EERD:   u32 = 0x0014;
const REG_ICR:    u32 = 0x00C0;
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
const REG_RAL0:   u32 = 0x5400;
const REG_RAH0:   u32 = 0x5404;

// CTRL bits
const CTRL_SLU: u32 = 1 << 6;
const CTRL_RST: u32 = 1 << 26;

// STATUS bits
const STATUS_LU: u32 = 1 << 1;

// RCTL bits
const RCTL_EN:    u32 = 1 << 1;
const RCTL_UPE:   u32 = 1 << 3;
const RCTL_MPE:   u32 = 1 << 4;
const RCTL_BAM:   u32 = 1 << 15;
const RCTL_BSIZE: u32 = 0 << 16; // 0 = 2048-byte buffers
const RCTL_SECRC: u32 = 1 << 26; // strip Ethernet CRC

// TCTL bits
const TCTL_EN:   u32 = 1 << 1;
const TCTL_PSP:  u32 = 1 << 3;
// COLD = 0x200 (40 * 5) for full-duplex gigabit
const TCTL_COLD_FULL: u32 = 0x200 << 12;
const TCTL_CT:   u32 = 0x10 << 4; // collision threshold

// EERD bits
const EERD_START: u32 = 1 << 0;
const EERD_DONE:  u32 = 1 << 4;

// RAH0 bits
const RAH_AV: u32 = 1 << 31;

// ---------------------------------------------------------------------------
// Sizing and layout
// ---------------------------------------------------------------------------

const RX_DESC_COUNT: usize = 32;
const TX_DESC_COUNT: usize = 32;

const BUF_SIZE:   usize = 2048;
const BUF_ALIGN:  usize = 16;
const DESC_SIZE:  usize = 16;
const DESC_ALIGN: usize = 16;

/// Minimum Ethernet frame size (excluding FCS). HW pads shorter frames
/// because TCTL.PSP is set.
const MIN_FRAME: usize = 60;
/// Maximum frame that fits in a single RX buffer.
const MAX_FRAME: usize = BUF_SIZE - 4; // leave room for stripped CRC

/// Virtual-to-physical offset (identity map of physical memory).
const PHYS_OFFSET: usize = 0xFFFF_8000_0000_0000;

// ---------------------------------------------------------------------------
// Polling budgets
// ---------------------------------------------------------------------------

const RESET_TIMEOUT:   usize = 1_000_000;
const EEPROM_TIMEOUT:  usize = 10_000;
const TX_AVAIL_TIMEOUT: usize = 100_000;

// ---------------------------------------------------------------------------
// Legacy descriptors (16 bytes each, e1000 datasheet §3.2.3 / §3.3.3)
// ---------------------------------------------------------------------------

#[repr(C)]
struct RxDesc {
    addr:    u64,
    length:  u16,
    chksum:  u16,
    status:  u8, // bit 0 = DD, bit 1 = EOP
    errors:  u8,
    special: u16,
}

#[repr(C)]
struct TxDesc {
    addr:    u64,
    length:  u16,
    cso:     u8,
    cmd:     u8, // bit 0 = EOP, bit 1 = IFCS, bit 3 = RS
    sta:     u8, // bit 0 = DD
    css:     u8,
    special: u16,
}

const _: () = {
    assert!(core::mem::size_of::<RxDesc>() == DESC_SIZE);
    assert!(core::mem::size_of::<TxDesc>() == DESC_SIZE);
};

// ---------------------------------------------------------------------------
// Device
// ---------------------------------------------------------------------------

pub struct E1000 {
    pub mmio: usize,
    pub mac: [u8; 6],

    // RX: one owned allocation for descriptors, one for all buffers.
    _rx_desc_mem: Vec<u8>,
    _rx_buf_mem:  Vec<u8>,
    rx_desc_off:  usize,       // byte offset of aligned descriptor list
    rx_buf_off:   usize,       // byte offset of aligned buffer region
    rx_buf_phys:  Vec<u64>,    // cached physical addresses, one per slot
    rx_head:      usize,       // SW next-to-check (should track RDH)

    // TX.
    _tx_desc_mem: Vec<u8>,
    _tx_buf_mem:  Vec<u8>,
    tx_desc_off:  usize,
    tx_buf_off:   usize,
    tx_buf_phys:  Vec<u64>,
    tx_tail:      usize,
}

impl E1000 {
    #[inline]
    fn rx_desc_ptr(&self, i: usize) -> *mut RxDesc {
        unsafe {
            (self._rx_desc_mem.as_ptr() as usize + self.rx_desc_off + i * DESC_SIZE)
                as *mut RxDesc
        }
    }

    #[inline]
    fn tx_desc_ptr(&self, i: usize) -> *mut TxDesc {
        unsafe {
            (self._tx_desc_mem.as_ptr() as usize + self.tx_desc_off + i * DESC_SIZE)
                as *mut TxDesc
        }
    }

    #[inline]
    fn rx_buf_ptr(&self, i: usize) -> *mut u8 {
        unsafe {
            (self._rx_buf_mem.as_ptr() as usize + self.rx_buf_off + i * BUF_SIZE)
                as *mut u8
        }
    }

    #[inline]
    fn tx_buf_ptr(&self, i: usize) -> *mut u8 {
        unsafe {
            (self._tx_buf_mem.as_ptr() as usize + self.tx_buf_off + i * BUF_SIZE)
                as *mut u8
        }
    }

    #[inline]
    fn tx_buf_slice(&self, i: usize, len: usize) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.tx_buf_ptr(i), len) }
    }

    #[inline]
    fn rx_buf_slice(&self, i: usize, len: usize) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.rx_buf_ptr(i), len) }
    }
}

// ---------------------------------------------------------------------------
// Global instance
// ---------------------------------------------------------------------------

static E1000_DEV: Mutex<Option<E1000>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

/// Try to initialise the e1000 controller from a PCI device.
///
/// Idempotent: if a controller is already installed, returns `false`
/// without disturbing the existing device.
pub fn try_init(dev: &PciDevice) -> bool {
    if dev.vendor_id != 0x8086 {
        return false;
    }
    if !SUPPORTED_DEVICE_IDS.contains(&dev.device_id) {
        return false;
    }
    if dev.bar[0] & 1 != 0 {
        return false; // BAR0 is I/O space, not MMIO
    }
    let mmio_phys = (dev.bar[0] as usize) & !0xF;
    if mmio_phys == 0 {
        return false;
    }
    let Some(mmio) = mmio_phys.checked_add(PHYS_OFFSET) else {
        return false;
    };

    // Guard against double init.
    if E1000_DEV.lock().is_some() {
        return false;
    }

    // Allocate DMA memory up front so failure is detected before any HW
    // state is touched.
    let rx_desc_alloc = vec![0u8; RX_DESC_COUNT * DESC_SIZE + DESC_ALIGN];
    let rx_buf_alloc  = vec![0u8; RX_DESC_COUNT * BUF_SIZE  + BUF_ALIGN];
    let tx_desc_alloc = vec![0u8; TX_DESC_COUNT * DESC_SIZE + DESC_ALIGN];
    let tx_buf_alloc  = vec![0u8; TX_DESC_COUNT * BUF_SIZE  + BUF_ALIGN];

    let rx_desc_off = align_offset(rx_desc_alloc.as_ptr(), DESC_ALIGN);
    let rx_buf_off  = align_offset(rx_buf_alloc.as_ptr(),  BUF_ALIGN);
    let tx_desc_off = align_offset(tx_desc_alloc.as_ptr(), DESC_ALIGN);
    let tx_buf_off  = align_offset(tx_buf_alloc.as_ptr(),  BUF_ALIGN);

    // Physical addresses of the descriptor rings themselves.
    let Some(rx_desc_phys) = virt_to_phys(
        (rx_desc_alloc.as_ptr() as usize + rx_desc_off) as *const u8,
    ) else {
        return false;
    };
    let Some(tx_desc_phys) = virt_to_phys(
        (tx_desc_alloc.as_ptr() as usize + tx_desc_off) as *const u8,
    ) else {
        return false;
    };

    unsafe {
        // ---- Reset and verify (§13.3.3) -----------------------------------
        write32(mmio, REG_IMC, 0xFFFF_FFFF);
        write32(mmio, REG_CTRL, read32(mmio, REG_CTRL) | CTRL_RST);
        if !wait_until(RESET_TIMEOUT, || read32(mmio, REG_CTRL) & CTRL_RST == 0) {
            return false;
        }

        // ---- Link up ------------------------------------------------------
        write32(mmio, REG_CTRL, read32(mmio, REG_CTRL) | CTRL_SLU);

        // ---- Mask interrupts (polling driver) -----------------------------
        write32(mmio, REG_IMC, 0xFFFF_FFFF);
        write32(mmio, REG_ICR, 0xFFFF_FFFF);

        // ---- MAC address --------------------------------------------------
        let Some(mac) = read_mac(mmio) else {
            crate::serial_println!("[e1000] failed to obtain a valid MAC");
            return false;
        };

        // Program the MAC into RAH0/RAL0 so HW filters correctly.
        let ral = u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]);
        let rah = u32::from_le_bytes([mac[4], mac[5], 0, 0]) | RAH_AV;
        write32(mmio, REG_RAL0, ral);
        write32(mmio, REG_RAH0, rah);

        // ---- RX ring ------------------------------------------------------
        let rx_buf_phys: Vec<u64> = (0..RX_DESC_COUNT)
            .map(|i| {
                virt_to_phys(
                    (rx_buf_alloc.as_ptr() as usize + rx_buf_off + i * BUF_SIZE) as *const u8,
                )
                .unwrap_or(0)
            })
            .collect();
        if rx_buf_phys.iter().any(|&p| p == 0) {
            return false;
        }

        for i in 0..RX_DESC_COUNT {
            let d = &mut *((rx_desc_alloc.as_ptr() as usize
                + rx_desc_off
                + i * DESC_SIZE) as *mut RxDesc);
            d.addr    = rx_buf_phys[i];
            d.length  = 0;
            d.chksum  = 0;
            d.status  = 0;
            d.errors  = 0;
            d.special = 0;
        }

        write32(mmio, REG_RDBAL, rx_desc_phys as u32);
        write32(mmio, REG_RDBAH, (rx_desc_phys >> 32) as u32);
        write32(mmio, REG_RDLEN, (RX_DESC_COUNT * DESC_SIZE) as u32);
        write32(mmio, REG_RDH, 0);
        write32(mmio, REG_RDT, (RX_DESC_COUNT - 1) as u32);
        write32(
            mmio,
            REG_RCTL,
            RCTL_EN | RCTL_BAM | RCTL_SECRC | RCTL_BSIZE,
        );

        // ---- TX ring ------------------------------------------------------
        let tx_buf_phys: Vec<u64> = (0..TX_DESC_COUNT)
            .map(|i| {
                virt_to_phys(
                    (tx_buf_alloc.as_ptr() as usize + tx_buf_off + i * BUF_SIZE) as *const u8,
                )
                .unwrap_or(0)
            })
            .collect();
        if tx_buf_phys.iter().any(|&p| p == 0) {
            return false;
        }

        for i in 0..TX_DESC_COUNT {
            let d = &mut *((tx_desc_alloc.as_ptr() as usize
                + tx_desc_off
                + i * DESC_SIZE) as *mut TxDesc);
            d.addr    = tx_buf_phys[i];
            d.length  = 0;
            d.cso     = 0;
            d.cmd     = 0;
            d.sta     = 1; // DD = 1 → slot free
            d.css     = 0;
            d.special = 0;
        }

        write32(mmio, REG_TDBAL, tx_desc_phys as u32);
        write32(mmio, REG_TDBAH, (tx_desc_phys >> 32) as u32);
        write32(mmio, REG_TDLEN, (TX_DESC_COUNT * DESC_SIZE) as u32);
        write32(mmio, REG_TDH, 0);
        write32(mmio, REG_TDT, 0);
        write32(mmio, REG_TCTL, TCTL_EN | TCTL_PSP | TCTL_CT | TCTL_COLD_FULL);
        write32(mmio, REG_TIPG, 0x00602006);

        // Wait for the link to come up (best-effort; some hardware takes
        // several hundred ms via autoneg, so cap the wait).
        let _ = wait_until(200_000, || read32(mmio, REG_STATUS) & STATUS_LU != 0);

        crate::serial_println!(
            "  [e1000] MAC {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} — rings ready",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );

        *E1000_DEV.lock() = Some(E1000 {
            mmio,
            mac,
            _rx_desc_mem: rx_desc_alloc,
            _rx_buf_mem:  rx_buf_alloc,
            rx_desc_off,
            rx_buf_off,
            rx_buf_phys,
            rx_head: 0,

            _tx_desc_mem: tx_desc_alloc,
            _tx_buf_mem:  tx_buf_alloc,
            tx_desc_off,
            tx_buf_off,
            tx_buf_phys,
            tx_tail: 0,
        });
    }
    true
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Send an Ethernet frame.
///
/// Returns `false` if the driver is not initialised, the frame is empty
/// or larger than the buffer, or the TX ring is congested.
pub fn send_frame(frame: &[u8]) -> bool {
    if frame.is_empty() || frame.len() > BUF_SIZE {
        return false;
    }
    let mut lock = E1000_DEV.lock();
    let Some(dev) = lock.as_mut() else {
        return false;
    };

    let slot = dev.tx_tail;

    unsafe {
        let desc = &mut *dev.tx_desc_ptr(slot);

        // Wait for the slot to be reclaimed by hardware (DD = 1).
        if !wait_until(TX_AVAIL_TIMEOUT, || desc.sta & 1 != 0) {
            let tdh = read32(dev.mmio, REG_TDH);
            let tdt = read32(dev.mmio, REG_TDT);
            crate::serial_println!(
                "[e1000] TX ring congested: TDH={} TDT={}",
                tdh, tdt,
            );
            return false;
        }

        // Copy the frame into the slot's buffer.
        let dst = core::slice::from_raw_parts_mut(dev.tx_buf_ptr(slot), BUF_SIZE);
        dst[..frame.len()].copy_from_slice(frame);

        // Publish descriptor fields. DD is cleared before notifying HW.
        desc.addr   = dev.tx_buf_phys[slot];
        desc.length = frame.len() as u16;
        desc.cso    = 0;
        desc.cmd    = 0x0B; // EOP | IFCS | RS
        desc.sta    = 0;    // HW-owned until DD is set again
        desc.css    = 0;
        desc.special = 0;

        // Ensure descriptor writes hit memory before TDT advances.
        compiler_fence(Ordering::SeqCst);

        dev.tx_tail = (slot + 1) % TX_DESC_COUNT;
        write32(dev.mmio, REG_TDT, dev.tx_tail as u32);
    }
    true
}

/// Receive a single Ethernet frame, if one is ready.
///
/// Uses `RDH` as the source of truth for the current descriptor, so
/// dropped packets on the hardware side do not stall the driver.
pub fn recv_frame() -> Option<Vec<u8>> {
    let mut lock = E1000_DEV.lock();
    let dev = lock.as_mut()?;

    unsafe {
        let rdh = (read32(dev.mmio, REG_RDH) as usize) % RX_DESC_COUNT;
        let desc = &mut *dev.rx_desc_ptr(rdh);

        compiler_fence(Ordering::SeqCst);
        if desc.status & 1 == 0 {
            return None; // no packet ready
        }

        let len = desc.length as usize;
        let errors = desc.errors;

        // Always return the slot to HW, even on error, so a single bad
        // packet cannot stall the ring.
        let result = if errors != 0 {
            crate::serial_println!(
                "[e1000] RX error bits={:#x} on desc {} (len={})",
                errors, rdh, len,
            );
            None
        } else if len == 0 || len > MAX_FRAME {
            crate::serial_println!(
                "[e1000] RX bad length {} on desc {}",
                len, rdh,
            );
            None
        } else {
            Some(dev.rx_buf_slice(rdh, len).to_vec())
        };

        // Reset and re-arm the descriptor.
        desc.length = 0;
        desc.status = 0;
        desc.errors = 0;

        compiler_fence(Ordering::SeqCst);

        dev.rx_head = rdh;
        write32(dev.mmio, REG_RDT, rdh as u32);

        result
    }
}

/// Enable or disable promiscuous mode (unicast + multicast).
pub fn set_promiscuous(enabled: bool) {
    let lock = E1000_DEV.lock();
    let Some(dev) = lock.as_ref() else {
        return;
    };
    unsafe {
        let mut rctl = read32(dev.mmio, REG_RCTL);
        if enabled {
            rctl |= RCTL_UPE | RCTL_MPE;
        } else {
            rctl &= !(RCTL_UPE | RCTL_MPE);
        }
        write32(dev.mmio, REG_RCTL, rctl);
    }
}

/// Return the MAC address of the installed NIC, if any.
pub fn mac_address() -> Option<[u8; 6]> {
    E1000_DEV.lock().as_ref().map(|d| d.mac)
}

/// Return `true` if a NIC has been successfully initialised.
pub fn is_available() -> bool {
    E1000_DEV.lock().is_some()
}

/// Return the current TX head/tail positions (for diagnostics).
pub fn tx_positions() -> Option<(u32, u32)> {
    let lock = E1000_DEV.lock();
    let dev = lock.as_ref()?;
    unsafe {
        Some((
            read32(dev.mmio, REG_TDH),
            read32(dev.mmio, REG_TDT),
        ))
    }
}

// ---------------------------------------------------------------------------
// MAC address discovery
// ---------------------------------------------------------------------------

/// Obtain a valid MAC address. Tries RAL0/RAH0 first (validated by the AV
/// bit), then EEPROM. Returns `None` if neither produces a usable value.
unsafe fn read_mac(mmio: usize) -> Option<[u8; 6]> {
    let ral = read32(mmio, REG_RAL0);
    let rah = read32(mmio, REG_RAH0);
    if rah & RAH_AV != 0 {
        let mut mac = [0u8; 6];
        mac[0] = (ral & 0xFF) as u8;
        mac[1] = ((ral >> 8) & 0xFF) as u8;
        mac[2] = ((ral >> 16) & 0xFF) as u8;
        mac[3] = ((ral >> 24) & 0xFF) as u8;
        mac[4] = (rah & 0xFF) as u8;
        mac[5] = ((rah >> 8) & 0xFF) as u8;
        if is_valid_mac(&mac) {
            return Some(mac);
        }
    }

    let mut mac = [0u8; 6];
    for i in 0..3u32 {
        let word = eeprom_read(mmio, i)?;
        mac[(i as usize) * 2]     = (word & 0xFF) as u8;
        mac[(i as usize) * 2 + 1] = ((word >> 8) & 0xFF) as u8;
    }
    if is_valid_mac(&mac) {
        Some(mac)
    } else {
        None
    }
}

/// Read a single 16-bit word from the EEPROM via the EERD register.
unsafe fn eeprom_read(mmio: usize, addr: u32) -> Option<u16> {
    write32(mmio, REG_EERD, (addr << 8) | EERD_START);
    for _ in 0..EEPROM_TIMEOUT {
        let v = read32(mmio, REG_EERD);
        if v & EERD_DONE != 0 {
            return Some((v >> 16) as u16);
        }
        core::hint::spin_loop();
    }
    None
}

fn is_valid_mac(mac: &[u8; 6]) -> bool {
    let all_zero = mac.iter().all(|&b| b == 0);
    let all_ff   = mac.iter().all(|&b| b == 0xFF);
    !all_zero && !all_ff
}

// ---------------------------------------------------------------------------
// Supported device IDs
// ---------------------------------------------------------------------------

const SUPPORTED_DEVICE_IDS: &[u16] = &[
    0x100E, 0x100F, 0x1010, 0x1011, 0x1015, 0x1016, 0x1017, 0x1018,
    0x1019, 0x101A, 0x101D, 0x1026, 0x1027, 0x1028, 0x1075, 0x1076,
    0x107C, 0x108A, 0x1099, 0x10D3, 0x10EA,
];

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

#[inline(always)]
unsafe fn read32(base: usize, offset: u32) -> u32 {
    core::ptr::read_volatile((base + offset as usize) as *const u32)
}

#[inline(always)]
unsafe fn write32(base: usize, offset: u32, value: u32) {
    core::ptr::write_volatile((base + offset as usize) as *mut u32, value);
}

#[inline]
fn wait_until<F: Fn() -> bool>(max_iters: usize, cond: F) -> bool {
    for _ in 0..max_iters {
        if cond() {
            return true;
        }
        core::hint::spin_loop();
    }
    cond()
}

/// Return the byte offset needed to align `ptr` upward to `align` bytes.
///
/// `align` must be a power of two.
#[inline]
fn align_offset(ptr: *const u8, align: usize) -> usize {
    debug_assert!(align.is_power_of_two(), "align must be a power of two");
    let addr = ptr as usize;
    (align - (addr & (align - 1))) & (align - 1)
}

/// Convert a virtual address to a physical one under the identity map.
#[inline]
fn virt_to_phys(ptr: *const u8) -> Option<u64> {
    let addr = ptr as usize;
    if addr < PHYS_OFFSET {
        return None;
    }
    Some((addr - PHYS_OFFSET) as u64)
}
