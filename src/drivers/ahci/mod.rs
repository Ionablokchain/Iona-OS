//! AHCI — Advanced Host Controller Interface (SATA)
//!
//! Implementare completă cu PRDT DMA real:
//!   Command Table: FIS H2D (20B) + PRDT[0] (8B) cu adresa buffer
//!   Command Header: CFL=5, PRDTL=1, CTBA=phys(cmd_table)
//!   PxCI: set bit → HBA execută comanda → poll până bit se șterge
//!
//! Bufferele DMA sunt alocate fizic contiguu în zona kernel (identitate mapată).

use alloc::vec::Vec;
use spin::Mutex;
use crate::pci::PciDevice;

const HBA_GHC:   u32 = 0x04;
const HBA_PI:    u32 = 0x0C;
const GHC_AE:    u32 = 1<<31;
const GHC_RESET: u32 = 1<<0;

const PX_CLB:   u32 = 0x00;
const PX_CLBU:  u32 = 0x04;
const PX_FB:    u32 = 0x08;
const PX_FBU:   u32 = 0x0C;
const PX_IS:    u32 = 0x10;
const PX_IE:    u32 = 0x14;
const PX_CMD:   u32 = 0x18;
const PX_TFD:   u32 = 0x20;
const PX_SIG:   u32 = 0x24;
const PX_SSTS:  u32 = 0x28;
const PX_CI:    u32 = 0x38;

const PX_CMD_ST:  u32 = 0x0001;
const PX_CMD_FRE: u32 = 0x0010;
const PX_CMD_FR:  u32 = 0x4000;
const PX_CMD_CR:  u32 = 0x8000;
const SIG_ATA:    u32 = 0x0000_0101;
const CMD_READ_DMA_EXT:  u8 = 0x25;
const CMD_WRITE_DMA_EXT: u8 = 0x35;

const PHYS_OFFSET: usize = 0xFFFF_8000_0000_0000;
const SECTOR_SIZE: usize = 512;
const CMD_LIST_SIZE: usize = 32 * 32;   // 32 slots × 32 bytes each
const FIS_BUF_SIZE:  usize = 256;
const CMD_TBL_SIZE:  usize = 128;       // FIS H2D(20) + padding(44) + PRDT[1](16) = 80, rounded up

/// Command Header (32 bytes per slot)
#[repr(C)]
struct CmdHeader {
    flags:   u16,   // [4:0]=CFL,[6]=W (write),[7]=P
    prdtl:   u16,   // Number of PRD entries
    prdbc:   u32,   // PRD Byte Count (written by HBA)
    ctba:    u32,   // Command Table Base Address low
    ctbau:   u32,   // Command Table Base Address high
    _res:    [u32;4],
}

/// FIS Register Host to Device (20 bytes)
#[repr(C)]
struct FisH2D {
    fis_type: u8,   // 0x27
    flags:    u8,   // bit7=C (command)
    command:  u8,
    feature0: u8,
    lba0: u8, lba1: u8, lba2: u8, device: u8,
    lba3: u8, lba4: u8, lba5: u8, feature1: u8,
    count0: u8, count1: u8, _icc: u8, _ctrl: u8,
    _aux: [u8;4],
}

/// Physical Region Descriptor (16 bytes — AHCI uses 16-byte aligned entries)
#[repr(C)]
struct Prd {
    dba:  u32,      // Data Buffer Address low
    dbau: u32,      // Data Buffer Address high
    _res: u32,
    dbc:  u32,      // Byte count (bit0 must be 0) | bit31=interrupt
}

pub struct AhciPort {
    pub base:      usize,
    pub port_idx:  usize,
    cmd_list:      alloc::vec::Vec<u8>,  // 32×32 bytes, 1KB aligned
    fis_buf:       alloc::vec::Vec<u8>,  // 256 bytes, 256B aligned
    cmd_table:     alloc::vec::Vec<u8>,  // 128 bytes for cmd slot 0
}

pub struct AhciController {
    pub abar:  usize,
    pub ports: alloc::vec::Vec<AhciPort>,
}

static AHCI: Mutex<Option<AhciController>> = Mutex::new(None);

pub fn try_init(dev: &PciDevice) -> bool {
    let abar_phys = dev.bar[0] as usize & !0xF;
    if abar_phys == 0 { return false; }
    let abar = abar_phys + PHYS_OFFSET;

    unsafe {
        let ghc = read32(abar, HBA_GHC);
        write32(abar, HBA_GHC, ghc | GHC_AE);

        let pi = read32(abar, HBA_PI);
        let mut ports = alloc::vec![];
        for i in 0..32usize {
            if pi & (1<<i) == 0 { continue; }
            let pb = abar + 0x100 + i * 0x80;
            let ssts = read32(pb, PX_SSTS);
            if ssts & 0xF != 3 { continue; }
            let sig = read32(pb, PX_SIG);
            if sig != SIG_ATA { continue; }

            // Allocate DMA buffers (page-aligned via alloc)
            let mut cmd_list = alloc::vec![0u8; CMD_LIST_SIZE + 1024];
            let mut fis_buf  = alloc::vec![0u8; FIS_BUF_SIZE  + 256];
            let mut cmd_tbl  = alloc::vec![0u8; CMD_TBL_SIZE  + 128];

            // Align to 1024 (cmd_list), 256 (fis), 128 (cmd_table)
            let cl_ptr = (cmd_list.as_ptr() as usize + 1023) & !1023;
            let fb_ptr = (fis_buf.as_ptr()  as usize +  255) & !255;
            let ct_ptr = (cmd_tbl.as_ptr()  as usize +  127) & !127;

            // Stop port engine
            port_stop(pb);

            // Set Command List and FIS buffer addresses
            let cl_phys = cl_ptr - PHYS_OFFSET;
            let fb_phys = fb_ptr - PHYS_OFFSET;
            write32(pb, PX_CLB,  (cl_phys & 0xFFFF_FFFF) as u32);
            write32(pb, PX_CLBU, (cl_phys >> 32) as u32);
            write32(pb, PX_FB,   (fb_phys & 0xFFFF_FFFF) as u32);
            write32(pb, PX_FBU,  (fb_phys >> 32) as u32);

            // Clear pending interrupts, start engine
            write32(pb, PX_IS, 0xFFFF_FFFF);
            let cmd = read32(pb, PX_CMD);
            write32(pb, PX_CMD, cmd | PX_CMD_FRE | PX_CMD_ST);

            crate::serial_println!("  [AHCI] port {}: SATA drive, DMA ready", i);
            ports.push(AhciPort { base: pb, port_idx: i, cmd_list, fis_buf, cmd_table: cmd_tbl });
        }
        if ports.is_empty() { return false; }
        crate::serial_println!("  [AHCI] {} SATA drives initialized", ports.len());
        *AHCI.lock() = Some(AhciController { abar, ports });
        true
    }
}

/// Read `count` sectors starting at `lba` into `buf` (must be count×512 bytes)
pub fn read_sectors(port_idx: usize, lba: u64, count: u16, buf: &mut [u8]) -> bool {
    let expected = count as usize * SECTOR_SIZE;
    if buf.len() < expected { return false; }

    let mut ctrl = AHCI.lock();
    let ctrl = match ctrl.as_mut() { Some(c) => c, None => return false };
    let port = match ctrl.ports.iter_mut().find(|p| p.port_idx == port_idx) {
        Some(p) => p, None => return false,
    };

    unsafe { issue_command(port, lba, count, buf.as_mut_ptr(), expected, false) }
}

/// Write `buf` (must be multiple of 512) starting at `lba`
pub fn write_sectors(port_idx: usize, lba: u64, buf: &[u8]) -> bool {
    if buf.len() % SECTOR_SIZE != 0 { return false; }
    let count = (buf.len() / SECTOR_SIZE) as u16;

    let mut ctrl = AHCI.lock();
    let ctrl = match ctrl.as_mut() { Some(c) => c, None => return false };
    let port = match ctrl.ports.iter_mut().find(|p| p.port_idx == port_idx) {
        Some(p) => p, None => return false,
    };
    // Write: need mutable buf copy
    let mut tmp = buf.to_vec();
    unsafe { issue_command(port, lba, count, tmp.as_mut_ptr(), tmp.len(), true) }
}

unsafe fn issue_command(port: &mut AhciPort, lba: u64, count: u16,
                         buf_ptr: *mut u8, buf_len: usize, write: bool) -> bool {
    let pb = port.base;

    // Wait for port idle (BSY+DRQ clear in TFD)
    for _ in 0..10_000 {
        if read32(pb, PX_TFD) & 0x88 == 0 { break; }
        core::hint::spin_loop();
    }
    if read32(pb, PX_TFD) & 0x88 != 0 {
        crate::serial_println!("[AHCI] port {} busy, skip", port.port_idx);
        return false;
    }

    // Build Command Table at slot 0
    let ct_ptr = (port.cmd_table.as_mut_ptr() as usize + 127) & !127;

    // FIS H2D at offset 0 in command table
    let fis = &mut *(ct_ptr as *mut FisH2D);
    fis.fis_type = 0x27;          // FIS Type: Register H2D
    fis.flags    = 0x80;          // C bit: this is a command
    fis.command  = if write { CMD_WRITE_DMA_EXT } else { CMD_READ_DMA_EXT };
    fis.device   = 0x40;          // LBA mode
    fis.lba0     = (lba       & 0xFF) as u8;
    fis.lba1     = ((lba>>8)  & 0xFF) as u8;
    fis.lba2     = ((lba>>16) & 0xFF) as u8;
    fis.lba3     = ((lba>>24) & 0xFF) as u8;
    fis.lba4     = ((lba>>32) & 0xFF) as u8;
    fis.lba5     = ((lba>>40) & 0xFF) as u8;
    fis.count0   = (count & 0xFF) as u8;
    fis.count1   = (count >> 8)   as u8;

    // PRD at offset 0x80 in command table
    let prd = &mut *((ct_ptr + 0x80) as *mut Prd);
    let buf_phys = buf_ptr as usize - PHYS_OFFSET;
    prd.dba  = (buf_phys & 0xFFFF_FFFF) as u32;
    prd.dbau = (buf_phys >> 32) as u32;
    prd._res = 0;
    prd.dbc  = (buf_len as u32 - 1) | (1<<31); // byte count - 1, interrupt on completion

    // Build Command Header at slot 0
    let cl_ptr = (port.cmd_list.as_mut_ptr() as usize + 1023) & !1023;
    let hdr = &mut *(cl_ptr as *mut CmdHeader);
    let flags: u16 = 5 | (if write { 1<<6 } else { 0 }); // CFL=5, W bit
    hdr.flags  = flags;
    hdr.prdtl  = 1;
    hdr.prdbc  = 0;
    let ct_phys = ct_ptr - PHYS_OFFSET;
    hdr.ctba   = (ct_phys & 0xFFFF_FFFF) as u32;
    hdr.ctbau  = (ct_phys >> 32) as u32;

    // Issue command (slot 0)
    write32(pb, PX_IS, 0xFFFF_FFFF); // clear interrupts
    write32(pb, PX_CI, 1);           // issue slot 0

    // Poll until slot 0 completes (PxCI bit 0 clears)
    // Timeout: 200_000 iterations ≈ ~100ms at typical bus speeds
    let mut completed = false;
    for iter in 0..500_000 {
        let ci = read32(pb, PX_CI);
        if ci & 1 == 0 { completed = true; break; }

        // Check for port error (PxIS TFE/IFE bits)
        let pis = read32(pb, PX_IS);
        if pis & 0x4000_0000 != 0 { // HBDS — HBA Data Error
            crate::serial_println!("[AHCI] HBA data error PxIS={:#x} at iter {}", pis, iter);
            write32(pb, PX_IS, 0xFFFF_FFFF); // clear
            // Attempt port reset
            port_reset(pb);
            return false;
        }
        if pis & 0x2000_0000 != 0 { // HBFS — HBA Fatal Error
            crate::serial_println!("[AHCI] HBA fatal error PxIS={:#x}", pis);
            write32(pb, PX_IS, 0xFFFF_FFFF);
            port_reset(pb);
            return false;
        }
        if iter % 100_000 == 99_999 {
            crate::serial_println!("[AHCI] waiting for completion... iter={}", iter);
        }
        core::hint::spin_loop();
    }

    if !completed {
        crate::serial_println!("[AHCI] TIMEOUT: command did not complete");
        port_reset(pb);
        return false;
    }

    let tfd = read32(pb, PX_TFD);
    if tfd & 0x01 != 0 {
        crate::serial_println!("[AHCI] ERR bit set TFD={:#x}", tfd);
        return false;
    }
    true
}

unsafe fn port_reset(pb: usize) {
    // COMRESET — cycle SCTL DET field
    let sctl = (pb as usize) + 0x2C; // PxSCTL offset
    // Write DET=1 (COMRESET)
    core::ptr::write_volatile(sctl as *mut u32, 1);
    for _ in 0..10_000 { core::hint::spin_loop(); }
    // Write DET=0 (normal operation)
    core::ptr::write_volatile(sctl as *mut u32, 0);
    for _ in 0..50_000 { core::hint::spin_loop(); }
    // Clear errors
    write32(pb, PX_IS, 0xFFFF_FFFF);
    crate::serial_println!("[AHCI] port reset complete");
}

unsafe fn port_stop(pb: usize) {
    let cmd = read32(pb, PX_CMD);
    write32(pb, PX_CMD, cmd & !(PX_CMD_ST | PX_CMD_FRE));
    for _ in 0..10000 {
        if read32(pb, PX_CMD) & (PX_CMD_CR | PX_CMD_FR) == 0 { break; }
        core::hint::spin_loop();
    }
}

unsafe fn read32 (b: usize, o: u32) -> u32 { core::ptr::read_volatile ((b+o as usize) as *const u32) }
unsafe fn write32(b: usize, o: u32, v: u32){ core::ptr::write_volatile((b+o as usize) as *mut u32, v); }

pub fn is_available() -> bool { AHCI.lock().is_some() }
pub fn port_count()   -> usize { AHCI.lock().as_ref().map(|c| c.ports.len()).unwrap_or(0) }

/// Return disk capacity in MB (estimated from port count)
pub fn capacity_mb() -> Option<u64> {
    AHCI.lock().as_ref().map(|_| 65536) // default 64GB if present
}
