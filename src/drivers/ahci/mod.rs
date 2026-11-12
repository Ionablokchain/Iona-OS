//! AHCI — Advanced Host Controller Interface (SATA)
//!
//! Production-grade AHCI SATA driver:
//!
//! * DMA transfers via Physical Region Descriptor Table (PRDT)
//! * Command tables and command headers per AHCI 1.3.1 §4.2
//! * Port init, COMRESET, and error recovery (§10.3, §10.4)
//! * Completion polling with timeouts and error detection
//! * IDENTIFY DEVICE via AHCI DMA for capacity reporting
//! * Full input validation on the public API
//!
//! # Operations
//!
//! * [`read_sectors`] — READ DMA EXT (0x25)
//! * [`write_sectors`] — WRITE DMA EXT (0x35)
//!
//! # Assumptions
//!
//! * Physical memory is identity-mapped at [`PHYS_OFFSET`].
//! * Sector size is 512 bytes (no 4K-native support yet).
//! * Buffers passed to the public API are handled via an internal
//!   bounce buffer, so caller alignment is not required.
//! * Single command in slot 0; no NCQ.
//! * Polling-based; interrupts are not used.
//!
//! # Limitations / TODO
//!
//! * No interrupt-driven completion.
//! * No NCQ / FPDMA QUEUED.
//! * No 4K-native sector support.
//! * IDENTIFY DEVICE (0xEC) is best-effort; some AHCI HBAs do not
//!   forward PIO-emulated commands. When it fails, [`capacity_mb`]
//!   returns `None`.
//! * No hot-plug support; ports are enumerated once at init.

use alloc::vec::Vec;
use spin::Mutex;

use crate::pci::PciDevice;

// ---------------------------------------------------------------------------
// Hardware constants
// ---------------------------------------------------------------------------

// Global HBA registers
const HBA_GHC: u32 = 0x04;
const HBA_PI:  u32 = 0x0C;

const GHC_AE:    u32 = 1 << 31; // AHCI Enable
const GHC_RESET: u32 = 1 << 0;  // HBA Reset

// Port registers (offset from port base)
const PX_CLB:  u32 = 0x00;
const PX_CLBU: u32 = 0x04;
const PX_FB:   u32 = 0x08;
const PX_FBU:  u32 = 0x0C;
const PX_IS:   u32 = 0x10;
const PX_IE:   u32 = 0x14;
const PX_CMD:  u32 = 0x18;
const PX_TFD:  u32 = 0x20;
const PX_SIG:  u32 = 0x24;
const PX_SSTS: u32 = 0x28;
const PX_SCTL: u32 = 0x2C;
const PX_SERR: u32 = 0x30;
const PX_CI:   u32 = 0x38;

// PxCMD bits
const PX_CMD_ST:  u32 = 0x0001;
const PX_CMD_FRE: u32 = 0x0010;
const PX_CMD_FR:  u32 = 0x4000;
const PX_CMD_CR:  u32 = 0x8000;

// PxTFD bits
const TFD_ERR: u32 = 0x01;
const TFD_BSY: u32 = 0x80;
const TFD_DRQ: u32 = 0x08;

// PxIS bits
const PX_IS_HBDS: u32 = 0x4000_0000; // HBA Data Error
const PX_IS_HBFS: u32 = 0x2000_0000; // HBA Fatal Error
const PX_IS_TFES: u32 = 0x4000_0000; // Task File Error (same bit, per ATA)
const PX_IS_ALL:  u32 = 0xFFFF_FFFF;

// PxSSTS bits
const SSTS_DET_PRESENT: u32 = 0x3;

// ATA device signature
const SIG_ATA: u32 = 0x0000_0101;

// ATA commands
const CMD_READ_DMA_EXT:  u8 = 0x25;
const CMD_WRITE_DMA_EXT: u8 = 0x35;
const CMD_IDENTIFY:      u8 = 0xEC;

// Buffer sizes and alignment (AHCI §4.2)
const CMD_LIST_SIZE:   usize = 32 * 32; // 32 slots × 32 bytes
const CMD_LIST_ALIGN:  usize = 1024;
const FIS_BUF_SIZE:    usize = 256;
const FIS_BUF_ALIGN:   usize = 256;

/// Command table layout (§4.2.2.1):
///   0x00..0x14 — H2D Register FIS (20 bytes)
///   0x14..0x80 — ACMD + reserved (unused here)
///   0x80..      — PRDT
///
/// Minimum size for one PRD is `0x80 + 16 = 0x90 = 144`, rounded up
/// to the 128-byte alignment requirement.
const CMD_TABLE_OFFSET_PRDT: usize = 0x80;
const CMD_TABLE_SIZE:  usize = 256;
const CMD_TABLE_ALIGN: usize = 128;

const SECTOR_SIZE: usize = 512;

/// Maximum byte count a single PRD may describe (AHCI 1.3.1 §3.3.3.1).
const PRD_MAX_BYTES: usize = 4 * 1024 * 1024;

/// Maximum sector count per single-slot command.
const MAX_SECTORS_PER_CMD: u16 = (PRD_MAX_BYTES / SECTOR_SIZE) as u16; // 8192

/// 48-bit LBA limit.
const MAX_LBA_48: u64 = 1u64 << 48;

// Virtual→physical offset (identity mapping of physical memory).
const PHYS_OFFSET: usize = 0xFFFF_8000_0000_0000;

// Polling iteration budgets (empirical; ~500 ms on a 1 GHz core).
const POLL_MAX_ITER:     usize = 500_000;
const RESET_DELAY_SHORT: usize = 10_000;
const RESET_DELAY_LONG:  usize = 50_000;

// ---------------------------------------------------------------------------
// Data structures (AHCI 1.3.1)
// ---------------------------------------------------------------------------

#[repr(C)]
struct CmdHeader {
    /// bits[4:0]=CFL (command FIS length in dwords), bit[6]=W (write),
    /// bit[7]=P (prefetchable)
    flags: u16,
    /// Number of PRD entries.
    prdtl: u16,
    /// PRD Byte Count (written by HBA).
    prdbc: u32,
    /// Command Table Base Address, low.
    ctba: u32,
    /// Command Table Base Address, high.
    ctbau: u32,
    /// Reserved (16 bytes, per §4.2.1).
    _res: [u32; 4],
}

#[repr(C)]
struct FisH2D {
    fis_type: u8,
    flags:    u8,
    command:  u8,
    feature0: u8,
    lba0: u8,
    lba1: u8,
    lba2: u8,
    device: u8,
    lba3: u8,
    lba4: u8,
    lba5: u8,
    feature1: u8,
    count0: u8,
    count1: u8,
    icc:  u8,
    ctrl: u8,
    aux: [u8; 4],
}

#[repr(C)]
struct Prd {
    dba:  u32,
    dbau: u32,
    _res: u32,
    /// bit[31]=IOC, bits[30:0]=byte count minus 1.
    dbc: u32,
}

const _: () = {
    assert!(core::mem::size_of::<CmdHeader>() == 32);
    assert!(core::mem::size_of::<FisH2D>()    == 20);
    assert!(core::mem::size_of::<Prd>()       == 16);
};

// ---------------------------------------------------------------------------
// Port
// ---------------------------------------------------------------------------

pub struct AhciPort {
    base: usize,
    port_idx: usize,

    // Owning allocations; the virtual pointers below are aligned inside.
    _cmd_list: Vec<u8>,
    _fis_buf:  Vec<u8>,
    _cmd_table: Vec<u8>,

    cmd_list_virt:  *mut u8,
    cmd_list_phys:  u64,
    fis_buf_virt:   *mut u8,
    fis_buf_phys:   u64,
    cmd_table_virt: *mut u8,
    cmd_table_phys: u64,

    /// Total addressable sectors reported by IDENTIFY DEVICE, if known.
    pub sector_count: Option<u64>,
}

impl AhciPort {
    /// Initialise an AHCI port and bring the engines up.
    ///
    /// # Safety
    /// `base` must point at the port's MMIO register window, and the port
    /// must not be in use by any other driver.
    unsafe fn new(base: usize, port_idx: usize) -> Option<Self> {
        // Allocate DMA buffers with slack for alignment.
        let mut cmd_list  = vec![0u8; CMD_LIST_SIZE  + CMD_LIST_ALIGN];
        let mut fis_buf   = vec![0u8; FIS_BUF_SIZE   + FIS_BUF_ALIGN];
        let mut cmd_table = vec![0u8; CMD_TABLE_SIZE + CMD_TABLE_ALIGN];

        let cmd_list_virt  = align_ptr(cmd_list.as_mut_ptr(),  CMD_LIST_ALIGN);
        let fis_buf_virt   = align_ptr(fis_buf.as_mut_ptr(),   FIS_BUF_ALIGN);
        let cmd_table_virt = align_ptr(cmd_table.as_mut_ptr(), CMD_TABLE_ALIGN);

        let cmd_list_phys  = virt_to_phys(cmd_list_virt)?;
        let fis_buf_phys   = virt_to_phys(fis_buf_virt)?;
        let cmd_table_phys = virt_to_phys(cmd_table_virt)?;

        // Zero the DMA regions.
        core::ptr::write_bytes(cmd_list_virt,  0, CMD_LIST_SIZE);
        core::ptr::write_bytes(fis_buf_virt,   0, FIS_BUF_SIZE);
        core::ptr::write_bytes(cmd_table_virt, 0, CMD_TABLE_SIZE);

        // Stop the port engines (ST → wait CR → FRE → wait FR) per §10.3.1.
        if !port_stop(base) {
            return None;
        }

        // Program base addresses.
        write32(base, PX_CLB,  cmd_list_phys as u32);
        write32(base, PX_CLBU, (cmd_list_phys >> 32) as u32);
        write32(base, PX_FB,   fis_buf_phys as u32);
        write32(base, PX_FBU,  (fis_buf_phys >> 32) as u32);

        // Clear any pending interrupt state, then start the engines.
        write32(base, PX_IS, PX_IS_ALL);
        let cmd = read32(base, PX_CMD);
        write32(base, PX_CMD, cmd | PX_CMD_FRE | PX_CMD_ST);

        let mut port = AhciPort {
            base,
            port_idx,
            _cmd_list:  cmd_list,
            _fis_buf:   fis_buf,
            _cmd_table: cmd_table,
            cmd_list_virt,
            cmd_list_phys,
            fis_buf_virt,
            fis_buf_phys,
            cmd_table_virt,
            cmd_table_phys,
            sector_count: None,
        };

        // Best-effort IDENTIFY DEVICE. Failure is not fatal; capacity
        // will simply be reported as unknown.
        port.sector_count = port.identify();

        crate::serial_println!(
            "  [AHCI] port {}: ready, capacity={:?} sectors",
            port_idx,
            port.sector_count,
        );

        Some(port)
    }

    /// Read the total addressable sector count via IDENTIFY DEVICE (0xEC).
    ///
    /// Not all AHCI HBAs forward the PIO-emulated 0xEC command. Failure
    /// is expected on some hardware and simply yields `None`.
    unsafe fn identify(&mut self) -> Option<u64> {
        let mut buf = [0u8; 512];
        if !self.issue_ata_command(CMD_IDENTIFY, 0, 1, false, &mut buf) {
            return None;
        }

        // LBA48 sector count: bytes 200..208 (words 100..104).
        let lo = u32::from_le_bytes([buf[200], buf[201], buf[202], buf[203]]);
        let hi = u32::from_le_bytes([buf[204], buf[205], buf[206], buf[207]]);
        let sectors_48 = ((hi as u64) << 32) | (lo as u64);
        if sectors_48 > 0 {
            return Some(sectors_48);
        }

        // LBA28 fallback: bytes 120..124 (words 60..62).
        let sectors_28 = u32::from_le_bytes([buf[120], buf[121], buf[122], buf[123]]);
        if sectors_28 > 0 {
            return Some(sectors_28 as u64);
        }
        None
    }

    /// Issue a single ATA command via DMA on slot 0.
    ///
    /// # Parameters
    ///
    /// * `command` — ATA command byte (0x25, 0x35, 0xEC, …).
    /// * `lba`     — 48-bit starting LBA (ignored for non-data commands).
    /// * `count`   — Sector count (1..=8192 for data commands).
    /// * `is_write` — Sets `W` in the command header (HBA reads host memory).
    /// * `buffer`  — DMA target buffer; length must be ≤ 4 MiB.
    ///
    /// On any error the port is reset so subsequent commands start from a
    /// known state.
    unsafe fn issue_ata_command(
        &mut self,
        command: u8,
        lba: u64,
        count: u16,
        is_write: bool,
        buffer: &mut [u8],
    ) -> bool {
        // ---- Validation ---------------------------------------------------
        if buffer.is_empty() || buffer.len() > PRD_MAX_BYTES {
            return false;
        }
        if is_write {
            if count == 0 || count > MAX_SECTORS_PER_CMD {
                return false;
            }
        }
        if lba >= MAX_LBA_48 {
            return false;
        }
        let buffer_phys = match virt_to_phys(buffer.as_mut_ptr()) {
            Some(p) => p,
            None => return false,
        };

        let pb = self.base;

        // ---- Wait for the port to become idle -----------------------------
        if !wait_not_busy(pb, self.port_idx) {
            return false;
        }

        // ---- Build FIS ----------------------------------------------------
        let fis = &mut *(self.cmd_table_virt as *mut FisH2D);
        *fis = FisH2D {
            fis_type: 0x27,           // Register H2D
            flags:    0x80,           // C = 1
            command,
            feature0: 0,
            lba0: (lba       & 0xFF) as u8,
            lba1: ((lba >>  8) & 0xFF) as u8,
            lba2: ((lba >> 16) & 0xFF) as u8,
            // For non-LBA commands (IDENTIFY), the device field is ignored
            // by compliant drives; 0x40 is the canonical value.
            device: 0x40,
            lba3: ((lba >> 24) & 0xFF) as u8,
            lba4: ((lba >> 32) & 0xFF) as u8,
            lba5: ((lba >> 40) & 0xFF) as u8,
            feature1: 0,
            count0: (count       & 0xFF) as u8,
            count1: ((count >> 8) & 0xFF) as u8,
            icc: 0,
            ctrl: 0,
            aux: [0; 4],
        };

        // ---- Build PRD ----------------------------------------------------
        let prd = &mut *((self.cmd_table_virt.add(CMD_TABLE_OFFSET_PRDT)) as *mut Prd);
        prd.dba  = buffer_phys as u32;
        prd.dbau = (buffer_phys >> 32) as u32;
        prd._res = 0;
        prd.dbc  = ((buffer.len() as u32) - 1) | (1 << 31); // IOC=1

        // ---- Build command header -----------------------------------------
        let hdr = &mut *(self.cmd_list_virt as *mut CmdHeader);
        // CFL = 5 dwords; W bit set for write-style transfers.
        hdr.flags = 5 | if is_write { 1 << 6 } else { 0 };
        hdr.prdtl = 1;
        hdr.prdbc = 0;
        hdr.ctba  = self.cmd_table_phys as u32;
        hdr.ctbau = (self.cmd_table_phys >> 32) as u32;

        // ---- Issue --------------------------------------------------------
        write32(pb, PX_IS, PX_IS_ALL);
        write32(pb, PX_CI, 1);

        // ---- Poll for completion ------------------------------------------
        let mut completed = false;
        for _ in 0..POLL_MAX_ITER {
            if read32(pb, PX_CI) & 1 == 0 {
                completed = true;
                break;
            }
            let pis = read32(pb, PX_IS);
            if pis & PX_IS_HBDS != 0 || pis & PX_IS_HBFS != 0 {
                crate::serial_println!(
                    "[AHCI] port {}: HBA error (PxIS={:#x}), resetting",
                    self.port_idx, pis
                );
                write32(pb, PX_IS, PX_IS_ALL);
                port_reset(pb);
                return false;
            }
            core::hint::spin_loop();
        }

        if !completed {
            crate::serial_println!("[AHCI] port {}: command timeout", self.port_idx);
            port_reset(pb);
            return false;
        }

        // ---- Post-completion validation -----------------------------------
        let tfd = read32(pb, PX_TFD);
        if tfd & TFD_ERR != 0 {
            crate::serial_println!(
                "[AHCI] port {}: TFD ERR set ({:#x}), PxSERR={:#x}",
                self.port_idx, tfd, read32(pb, PX_SERR)
            );
            write32(pb, PX_IS, PX_IS_ALL);
            port_reset(pb);
            return false;
        }

        let serr = read32(pb, PX_SERR);
        if serr != 0 {
            crate::serial_println!(
                "[AHCI] port {}: SATA error ({:#x})",
                self.port_idx, serr
            );
            write32(pb, PX_SERR, serr); // W1C
            port_reset(pb);
            return false;
        }

        // PRDBC = bytes actually transferred. Must equal requested length.
        let transferred = read32(pb, PX_IS); // dummy read keeps ordering
        let _ = transferred;
        let prdbc = hdr.prdbc as usize;
        if prdbc != buffer.len() {
            crate::serial_println!(
                "[AHCI] port {}: short transfer ({} of {} bytes)",
                self.port_idx, prdbc, buffer.len()
            );
            port_reset(pb);
            return false;
        }

        true
    }
}

// ---------------------------------------------------------------------------
// Controller
// ---------------------------------------------------------------------------

pub struct AhciController {
    _abar: usize,
    pub ports: Vec<AhciPort>,
    /// Sum of `sector_count` across all ports that reported one.
    pub total_sectors: u64,
}

impl AhciController {
    /// Initialise the controller from a PCI device.
    ///
    /// # Safety
    /// The PCI device must be a SATA controller with a valid MMIO BAR0.
    pub unsafe fn try_from_pci(dev: &PciDevice) -> Option<Self> {
        // AHCI is class 0x01 (mass storage), subclass 0x06 (SATA),
        // prog_if 0x01 (AHCI). We accept prog_if 0x00 (IDE) only if the
        // HBA exposes an AHCI capability via ABAR.
        if dev.class != 0x01 || dev.subclass != 0x06 {
            return None;
        }

        let abar_phys = (dev.bar[0] as usize) & !0xF;
        if abar_phys == 0 {
            return None;
        }
        let abar = abar_phys.checked_add(PHYS_OFFSET)?;

        // Enable AHCI mode and verify the write stuck.
        let ghc = read32(abar, HBA_GHC);
        write32(abar, HBA_GHC, ghc | GHC_AE);
        if read32(abar, HBA_GHC) & GHC_AE == 0 {
            return None;
        }

        // NOTE: we deliberately do not perform a full HBA reset here, as
        // it would discard any firmware-configured state (e.g. UEFI
        // boot-drive mappings). Per-port COMRESET is used only on error
        // recovery.

        let pi = read32(abar, HBA_PI);
        let mut ports = Vec::new();
        let mut total_sectors: u64 = 0;

        for i in 0..32u32 {
            if pi & (1 << i) == 0 {
                continue;
            }
            let port_base = abar + 0x100 + (i as usize) * 0x80;
            let ssts = read32(port_base, PX_SSTS);
            if ssts & 0xF != SSTS_DET_PRESENT {
                continue;
            }
            if read32(port_base, PX_SIG) != SIG_ATA {
                continue; // not an ATA drive (ATAPI, port multiplier, …)
            }
            if let Some(port) = AhciPort::new(port_base, i as usize) {
                if let Some(s) = port.sector_count {
                    total_sectors = total_sectors.saturating_add(s);
                }
                ports.push(port);
            }
        }

        if ports.is_empty() {
            return None;
        }

        crate::serial_println!(
            "  [AHCI] {} SATA drive(s), {} total sectors",
            ports.len(),
            total_sectors
        );

        Some(AhciController {
            _abar: abar,
            ports,
            total_sectors,
        })
    }
}

// ---------------------------------------------------------------------------
// Global state and public API
// ---------------------------------------------------------------------------

static AHCI: Mutex<Option<AhciController>> = Mutex::new(None);

/// Initialise AHCI from a PCI device. Idempotent; the first call wins.
pub fn try_init(dev: &PciDevice) -> bool {
    let controller = unsafe { AhciController::try_from_pci(dev) };
    let mut global = AHCI.lock();
    if controller.is_some() && global.is_none() {
        *global = controller;
        true
    } else {
        false
    }
}

/// Read `count` sectors starting at `lba` from AHCI port `port_idx`.
///
/// `buf` must be at least `count * 512` bytes. A driver-internal bounce
/// buffer handles alignment; the caller's buffer has no special
/// requirements.
///
/// Returns `true` on success.
pub fn read_sectors(port_idx: usize, lba: u64, count: u16, buf: &mut [u8]) -> bool {
    if count == 0 || count > MAX_SECTORS_PER_CMD {
        return false;
    }
    let expected = count as usize * SECTOR_SIZE;
    if buf.len() < expected {
        return false;
    }

    let mut guard = match AHCI.lock().as_mut() {
        Some(c) => c,
        None => return false,
    };
    let port = match guard.ports.iter_mut().find(|p| p.port_idx == port_idx) {
        Some(p) => p,
        None => return false,
    };

    let mut bounce = AlignedBounce::zeroed(expected);
    let ok = unsafe {
        port.issue_ata_command(CMD_READ_DMA_EXT, lba, count, false, bounce.as_mut())
    };
    if ok {
        buf[..expected].copy_from_slice(bounce.as_ref());
    }
    ok
}

/// Write `buf` to AHCI port `port_idx` starting at `lba`.
///
/// `buf.len()` must be a non-zero multiple of 512 and ≤ 4 MiB.
///
/// Returns `true` on success.
pub fn write_sectors(port_idx: usize, lba: u64, buf: &[u8]) -> bool {
    if buf.is_empty() || buf.len() % SECTOR_SIZE != 0 || buf.len() > PRD_MAX_BYTES {
        return false;
    }
    let count = (buf.len() / SECTOR_SIZE) as u16;

    let mut guard = match AHCI.lock().as_mut() {
        Some(c) => c,
        None => return false,
    };
    let port = match guard.ports.iter_mut().find(|p| p.port_idx == port_idx) {
        Some(p) => p,
        None => return false,
    };

    let mut bounce = AlignedBounce::from_slice(buf);
    unsafe { port.issue_ata_command(CMD_WRITE_DMA_EXT, lba, count, true, bounce.as_mut()) }
}

/// Returns `true` if an AHCI controller is initialised.
pub fn is_available() -> bool {
    AHCI.lock().is_some()
}

/// Number of active AHCI ports (drives) on the controller.
pub fn port_count() -> usize {
    AHCI.lock().as_ref().map(|c| c.ports.len()).unwrap_or(0)
}

/// Total disk capacity in megabytes, if any port reported capacity via
/// IDENTIFY DEVICE. Returns `None` if the controller is not initialised
/// or no drive reported its capacity.
pub fn capacity_mb() -> Option<u64> {
    AHCI.lock().as_ref().and_then(|c| {
        if c.total_sectors == 0 {
            None
        } else {
            Some(c.total_sectors.saturating_mul(SECTOR_SIZE as u64) / (1024 * 1024))
        }
    })
}

// ---------------------------------------------------------------------------
// Aligned bounce buffer
// ---------------------------------------------------------------------------

/// A byte buffer guaranteed to be 8-byte aligned (via `Vec<u64>`), used to
/// satisfy AHCI's DMA alignment requirement without constraining callers.
struct AlignedBounce {
    words: Vec<u64>,
    len: usize,
}

impl AlignedBounce {
    fn zeroed(len: usize) -> Self {
        let words = (len + 7) / 8;
        Self { words: vec![0u64; words], len }
    }

    fn from_slice(src: &[u8]) -> Self {
        let mut b = Self::zeroed(src.len());
        b.as_mut().copy_from_slice(src);
        b
    }

    fn as_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.words.as_mut_ptr() as *mut u8, self.len) }
    }
}

impl AsRef<[u8]> for AlignedBounce {
    fn as_ref(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.words.as_ptr() as *const u8, self.len) }
    }
}

// ---------------------------------------------------------------------------
// Low-level MMIO helpers
// ---------------------------------------------------------------------------

unsafe fn read32(base: usize, reg: u32) -> u32 {
    core::ptr::read_volatile((base + reg as usize) as *const u32)
}

unsafe fn write32(base: usize, reg: u32, val: u32) {
    core::ptr::write_volatile((base + reg as usize) as *mut u32, val);
}

/// Convert a virtual address to a physical address under the identity map.
/// Returns `None` if the pointer does not lie in the identity-mapped range.
fn virt_to_phys<T>(ptr: *const T) -> Option<u64> {
    let addr = ptr as usize;
    if addr < PHYS_OFFSET {
        return None;
    }
    Some((addr - PHYS_OFFSET) as u64)
}

/// Stop the port engines per AHCI 1.3.1 §10.3.1:
///
/// 1. Clear `ST`; wait for `CR` to clear.
/// 2. Clear `FRE`; wait for `FR` to clear.
///
/// Returns `true` if both engines stopped within budget.
unsafe fn port_stop(base: usize) -> bool {
    // Step 1: stop the command list engine.
    let mut cmd = read32(base, PX_CMD);
    cmd &= !PX_CMD_ST;
    write32(base, PX_CMD, cmd);

    let mut cr_stopped = false;
    for _ in 0..POLL_MAX_ITER {
        if read32(base, PX_CMD) & PX_CMD_CR == 0 {
            cr_stopped = true;
            break;
        }
        core::hint::spin_loop();
    }
    if !cr_stopped {
        return false;
    }

    // Step 2: stop the FIS receive engine.
    cmd = read32(base, PX_CMD);
    cmd &= !PX_CMD_FRE;
    write32(base, PX_CMD, cmd);

    for _ in 0..POLL_MAX_ITER {
        if read32(base, PX_CMD) & PX_CMD_FR == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Perform a COMRESET on the given port and re-enable the engines.
///
/// Assumes the command and FIS buffers have been previously programmed.
/// Returns `true` if the device is detected and ready.
unsafe fn port_reset(base: usize) -> bool {
    // Stop the port before resetting (AHCI §10.3.2).
    if !port_stop(base) {
        return false;
    }

    // COMRESET: DET=1 for a while, then DET=0.
    let sctl = (base + PX_SCTL as usize) as *mut u32;
    core::ptr::write_volatile(sctl, 1);
    for _ in 0..RESET_DELAY_SHORT {
        core::hint::spin_loop();
    }
    core::ptr::write_volatile(sctl, 0);

    // Wait for the device to become present and ready.
    let mut ready = false;
    for _ in 0..RESET_DELAY_LONG {
        if read32(base, PX_SSTS) & 0xF == SSTS_DET_PRESENT {
            ready = true;
            break;
        }
        core::hint::spin_loop();
    }
    if !ready {
        return false;
    }

    // Clear pending errors and restart the engines.
    write32(base, PX_IS, PX_IS_ALL);
    let cmd = read32(base, PX_CMD);
    write32(base, PX_CMD, cmd | PX_CMD_ST | PX_CMD_FRE);
    crate::serial_println!("[AHCI] port reset complete");
    true
}

/// Wait until the port's task file reports the device is idle (BSY/DRQ clear).
unsafe fn wait_not_busy(base: usize, port_idx: usize) -> bool {
    for _ in 0..POLL_MAX_ITER {
        let tfd = read32(base, PX_TFD);
        if tfd & (TFD_BSY | TFD_DRQ) == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    crate::serial_println!(
        "[AHCI] port {}: busy after {} iterations, TFD={:#x}",
        port_idx,
        POLL_MAX_ITER,
        read32(base, PX_TFD)
    );
    false
}

/// Align a pointer upwards to `align` bytes. `align` must be a power of two.
fn align_ptr(ptr: *mut u8, align: usize) -> *mut u8 {
    debug_assert!(align.is_power_of_two(), "align must be a power of two");
    let addr = ptr as usize;
    ((addr + align - 1) & !(align - 1)) as *mut u8
}
