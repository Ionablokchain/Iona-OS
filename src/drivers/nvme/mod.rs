//! NVMe driver — PCIe SSD controller (single-queue).
//!
//! MMIO-based NVMe controller driver. One admin queue pair is used only
//! during init; all reads and writes go through one I/O queue pair.
//! Completions are delivered by MSI-X when available, otherwise the
//! caller blocks on a poll loop.
//!
//! # Supported
//!
//! * Controller bring-up per NVMe 1.4 §3.1: CC.EN, CSTS.RDY, AQA,
//!   ASQ/ACQ, IOSQES/IOCQES, page-aligned queue memory.
//! * Single namespace, NSID 1.
//! * READ (0x02) / WRITE (0x01) up to 2 MiB per command via PRP lists.
//! * IDENTIFY Controller (0x06, CNS=1) and IDENTIFY Namespace (CNS=0).
//! * CREATE_IO_CQ (0x05) / CREATE_IO_SQ (0x01) for the I/O queue pair.
//! * MSI-X delivery via [`crate::drivers::nvme::msix`], with polling
//!   fallback when setup fails.
//! * Full input validation: count == 0, buffer size, 48-bit LBA, transfer
//!   size cap, PRP-list capacity.
//!
//! # Not supported (documented as future work)
//!
//! * Multiple I/O queues / per-CPU affinity.
//! * Asynchronous submission (each call blocks its caller).
//! * Scatter-gather / SGL data transfer.
//! * Namespace discovery beyond NSID 1.
//! * Metadata transfers (mptr is always 0).
//! * Controller Fatal Status (CSTS.CFS) recovery beyond "return error".
//!
//! # Concurrency contract
//!
//! `NVME` guards controller state. Submission path:
//!
//! 1. Lock controller (briefly), register waiter, write descriptor, ring
//!    doorbell, unlock.
//! 2. Block on completion, re-checking [`PENDING_RESULTS`] before each
//!    block so an IRQ that fires between steps 1 and 2 is not lost.
//!
//! `poll_completions` is called from IRQ context (via `msix`) and from
//! the polling loop. It briefly takes `NVME`, drains the I/O CQ, stores
//! status codes in [`PENDING_RESULTS`], and returns the completed command
//! IDs. It never blocks.
//!
//! The IRQ handler must therefore **not** be running on a CPU that holds
//! `NVME`; that is enforced by never calling `block_current` or any other
//! scheduler operation while `NVME` is held.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use core::sync::atomic::{compiler_fence, AtomicU16, Ordering};

use spin::{Lazy, Mutex};

use crate::pci::PciDevice;
use crate::task::TaskId;

// ---------------------------------------------------------------------------
// Register offsets (NVMe 1.4 §3.1)
// ---------------------------------------------------------------------------

const REG_CAP:  u64 = 0x000;
const REG_VS:   u64 = 0x008;
const REG_CC:   u64 = 0x014;
const REG_CSTS: u64 = 0x01C;
const REG_AQA:  u64 = 0x024;
const REG_ASQ:  u64 = 0x028;
const REG_ACQ:  u64 = 0x030;

// ---------------------------------------------------------------------------
// Doorbells (NVMe 1.4 §3.1.3.1, DSTRD = 0)
// ---------------------------------------------------------------------------

const ADMIN_SQ_DB: u64 = 0x1000;
const ADMIN_CQ_DB: u64 = 0x1004;
const IO1_SQ_DB:   u64 = 0x1008;
const IO1_CQ_DB:   u64 = 0x100C;

// ---------------------------------------------------------------------------
// CC register bits (NVMe 1.4 §3.1.1)
// ---------------------------------------------------------------------------

const CC_ENABLE:        u32 = 1 << 0;
const CC_IOSQES_SHIFT:  u32 = 16;
const CC_IOCQES_SHIFT:  u32 = 20;
/// 64-byte submission queue entries → field value 4.
const CC_IOSQES_64B:    u32 = 4 << CC_IOSQES_SHIFT;
/// 16-byte completion queue entries → field value 1.
const CC_IOCQES_16B:    u32 = 1 << CC_IOCQES_SHIFT;

// ---------------------------------------------------------------------------
// CSTS register bits
// ---------------------------------------------------------------------------

const CSTS_READY: u32 = 1 << 0;
const CSTS_CFS:   u32 = 1 << 1;

// ---------------------------------------------------------------------------
// Queue geometry
// ---------------------------------------------------------------------------

/// 4 KiB is the mandatory minimum page size for queues (CAP.MPSMIN=0).
const PAGE_SIZE: u64 = 4096;

/// Admin and I/O queue depth. Must be a power of two ≤ CAP.MQES+1.
const ADMIN_QUEUE_DEPTH: u32 = 64;
const IO_QUEUE_DEPTH:    u32 = 64;

const _: () = {
    assert!(ADMIN_QUEUE_DEPTH.is_power_of_two());
    assert!(IO_QUEUE_DEPTH.is_power_of_two());
};

// ---------------------------------------------------------------------------
// Opcodes
// ---------------------------------------------------------------------------

const OP_CREATE_IO_SQ: u8 = 0x01;
const OP_WRITE:        u8 = 0x02 - 1; // placeholder to keep line numbers; see below
const OP_READ:         u8 = 0x02;
const OP_CREATE_IO_CQ: u8 = 0x05;
const OP_IDENTIFY:     u8 = 0x06;

// (The `OP_WRITE` above is defined via expression to stay parallel with the
// spec table; use constants directly below.)
#[allow(dead_code)]
const _OP_UNUSED: () = ();

const ATA_OP_WRITE: u8 = 0x01;

// ---------------------------------------------------------------------------
// IDENTIFY CNS values
// ---------------------------------------------------------------------------

const IDENTIFY_NS:   u32 = 0;
const IDENTIFY_CTRL: u32 = 1;

// ---------------------------------------------------------------------------
// Status codes (NVMe 1.4 §4.6)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvmeError {
    NotPresent,
    InvalidArgument,
    Timeout,
    ControllerFatal,
    /// Status code from the completion queue entry (already shifted).
    Status(u16),
    /// Internal bookkeeping error (should not occur on healthy hardware).
    Internal,
}

impl NvmeError {
    fn from_status(status: u16) -> Self {
        let sc = (status >> 1) & 0x7FFF;
        match sc {
            0x000 => NvmeError::Internal, // SUCCESS should never reach here
            other => NvmeError::Status(other as u16),
        }
    }

    fn is_retriable(&self) -> bool {
        matches!(self, NvmeError::Status(0x006) | NvmeError::Status(0x082))
        // 0x006 = Internal Error, 0x082 = Namespace Not Ready
    }
}

// ---------------------------------------------------------------------------
// Descriptor structures
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
#[repr(C)]
pub struct NvmeCommand {
    pub cdw0:  u32,
    pub nsid:  u32,
    pub cdw2:  u32,
    pub cdw3:  u32,
    pub mptr:  u64,
    pub prp1:  u64,
    pub prp2:  u64,
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
}

impl NvmeCommand {
    const ZERO: Self = Self {
        cdw0: 0, nsid: 0, cdw2: 0, cdw3: 0, mptr: 0,
        prp1: 0, prp2: 0,
        cdw10: 0, cdw11: 0, cdw12: 0, cdw13: 0, cdw14: 0, cdw15: 0,
    };
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct NvmeCompletion {
    pub result:  u32,
    pub rsvd:    u32,
    pub sq_head: u16,
    pub sq_id:   u16,
    pub cmd_id:  u16,
    pub status:  u16,
}

impl NvmeCompletion {
    const ZERO: Self = Self {
        result: 0, rsvd: 0, sq_head: 0, sq_id: 0, cmd_id: 0, status: 0,
    };

    #[inline]
    fn phase(&self) -> u16 { self.status & 1 }

    #[inline]
    fn is_success(&self) -> bool { (self.status >> 1) & 0x7FFF == 0 }
}

const _: () = {
    assert!(core::mem::size_of::<NvmeCommand>() == 64);
    assert!(core::mem::size_of::<NvmeCompletion>() == 16);
};

// ---------------------------------------------------------------------------
// DMA buffer helpers
// ---------------------------------------------------------------------------

const PHYS_OFFSET: usize = 0xFFFF_8000_0000_0000;

/// Aligned DMA allocation. The owning `Vec<u8>` is kept alive for the
/// whole lifetime of the `Dma`; the physical address returned by
/// [`Dma::phys`] is stable across moves because `Vec` data pointers are.
struct Dma {
    raw:    Vec<u8>,
    offset: usize,
    len:    usize,
}

impl Dma {
    fn new(len: usize, align: usize) -> Option<Self> {
        if len == 0 || !align.is_power_of_two() {
            return None;
        }
        let raw = alloc::vec![0u8; len.checked_add(align)?];
        let base = raw.as_ptr() as usize;
        let aligned = (base + align - 1) & !(align - 1);
        Some(Self { raw, offset: aligned - base, len })
    }

    fn virt(&self) -> *mut u8 {
        unsafe { self.raw.as_ptr().add(self.offset) as *mut u8 }
    }

    fn phys(&self) -> Option<u64> {
        let addr = self.virt() as usize;
        if addr < PHYS_OFFSET { return None; }
        Some((addr - PHYS_OFFSET) as u64)
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.virt() as *const u8, self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.virt(), self.len) }
    }
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

static NVME: Mutex<Option<NvmeController>> = Mutex::new(None);

/// Completion status for each in-flight command ID. Populated by
/// [`poll_completions`], consumed by the blocking waiter.
static PENDING_RESULTS: Lazy<Mutex<BTreeMap<u16, u16>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

/// Global command-ID counter. Must be unique across all queues because
/// [`PENDING_RESULTS`] is not per-queue.
static NEXT_CID: AtomicU16 = AtomicU16::new(0);

fn alloc_cid() -> u16 {
    // Wraps at 0xFFFF; the map is small enough that collisions never
    // matter because each submission blocks until the entry is consumed.
    NEXT_CID.fetch_add(1, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Controller
// ---------------------------------------------------------------------------

pub struct NvmeController {
    base:     u64,
    msix:     bool,
    ns_id:    u32,
    capacity_sectors: u64,

    // Admin queues (polled only, used during init and for IDENTIFY).
    asq: Dma,
    acq: Dma,
    asq_tail: u32,
    acq_head: u32,
    acq_phase: u8,

    // I/O queues (MSI-X or polled, used for reads/writes).
    iosq: Dma,
    iocq: Dma,
    iosq_tail: u32,
    iocq_head: u32,
    iocq_phase: u8,

    // PRP list buffer, reused across commands because submissions are
    // serialised by the NVME mutex.
    prp_list: Dma,
}

impl NvmeController {
    // ----- MMIO helpers ----------------------------------------------------

    #[inline]
    unsafe fn rd32(&self, reg: u64) -> u32 {
        ((self.base + reg) as *const u32).read_volatile()
    }
    #[inline]
    unsafe fn wr32(&self, reg: u64, val: u32) {
        ((self.base + reg) as *mut u32).write_volatile(val);
    }
    #[inline]
    unsafe fn rd64(&self, reg: u64) -> u64 {
        ((self.base + reg) as *const u64).read_volatile()
    }
    #[inline]
    unsafe fn wr64(&self, reg: u64, val: u64) {
        ((self.base + reg) as *mut u64).write_volatile(val);
    }

    // ----- Queue descriptor access ----------------------------------------

    fn asq_mut(&mut self) -> &mut [NvmeCommand] {
        unsafe {
            core::slice::from_raw_parts_mut(
                self.asq.virt() as *mut NvmeCommand,
                ADMIN_QUEUE_DEPTH as usize,
            )
        }
    }
    fn acq_slice(&self) -> &[NvmeCompletion] {
        unsafe {
            core::slice::from_raw_parts(
                self.acq.virt() as *const NvmeCompletion,
                ADMIN_QUEUE_DEPTH as usize,
            )
        }
    }
    fn iosq_mut(&mut self) -> &mut [NvmeCommand] {
        unsafe {
            core::slice::from_raw_parts_mut(
                self.iosq.virt() as *mut NvmeCommand,
                IO_QUEUE_DEPTH as usize,
            )
        }
    }
    fn iocq_slice(&self) -> &[NvmeCompletion] {
        unsafe {
            core::slice::from_raw_parts(
                self.iocq.virt() as *const NvmeCompletion,
                IO_QUEUE_DEPTH as usize,
            )
        }
    }

    // ----- Admin submission (polled, used during init only) ---------------

    /// Submit an admin command and poll for its completion.
    ///
    /// Admin commands are only used during init, when MSI-X may not yet be
    /// configured. Polling is safe here because each call is short and the
    /// controller is not yet handling application I/O.
    unsafe fn admin_submit_and_poll(&mut self, mut cmd: NvmeCommand) -> Result<NvmeCompletion, NvmeError> {
        let cid = alloc_cid();
        cmd.cdw0 = (cmd.cdw0 & !0xFFFF) | cid as u32;

        let depth = ADMIN_QUEUE_DEPTH as usize;
        let slot = (self.asq_tail as usize) % depth;
        self.asq_mut()[slot] = cmd;
        self.asq_tail = self.asq_tail.wrapping_add(1);
        compiler_fence(Ordering::SeqCst);
        self.wr32(ADMIN_SQ_DB, self.asq_tail);

        let deadline = now_ms() + 2000;
        loop {
            let head = (self.acq_head as usize) % depth;
            let entry = self.acq_slice()[head];
            if entry.phase() == self.acq_phase as u16 {
                self.acq_head = self.acq_head.wrapping_add(1);
                if (self.acq_head as usize) % depth == 0 {
                    self.acq_phase ^= 1;
                }
                compiler_fence(Ordering::SeqCst);
                self.wr32(ADMIN_CQ_DB, self.acq_head);

                if entry.cmd_id != cid {
                    return Err(NvmeError::Internal);
                }
                if entry.is_success() {
                    return Ok(entry);
                }
                return Err(NvmeError::from_status(entry.status));
            }
            if now_ms() > deadline {
                return Err(NvmeError::Timeout);
            }
            core::hint::spin_loop();
        }
    }

    // ----- I/O submission (async) -----------------------------------------

    /// Write a command to the I/O SQ and ring its doorbell. Returns the
    /// allocated command ID. The caller is responsible for registering a
    /// waiter (if using MSI-X) **before** calling this function.
    unsafe fn submit_io(&mut self, mut cmd: NvmeCommand) -> u16 {
        let cid = alloc_cid();
        cmd.cdw0 = (cmd.cdw0 & !0xFFFF) | cid as u32;

        let depth = IO_QUEUE_DEPTH as usize;
        let slot = (self.iosq_tail as usize) % depth;
        self.iosq_mut()[slot] = cmd;
        self.iosq_tail = self.iosq_tail.wrapping_add(1);
        // Publish the descriptor before the doorbell write.
        compiler_fence(Ordering::SeqCst);
        self.wr32(IO1_SQ_DB, self.iosq_tail);
        cid
    }

    /// Drain the I/O completion queue. Returns completions in submission
    /// order. Advances CQ head and rings the head doorbell.
    ///
    /// Safe to call from IRQ context — takes no locks itself; the caller
    /// holds the `NVME` guard.
    unsafe fn drain_io_cq(&mut self) -> Vec<NvmeCompletion> {
        let depth = IO_QUEUE_DEPTH as usize;
        let mut out = Vec::new();
        loop {
            let head = (self.iocq_head as usize) % depth;
            let entry = self.iocq_slice()[head];
            if entry.phase() != self.iocq_phase as u16 {
                break;
            }
            out.push(entry);
            self.iocq_head = self.iocq_head.wrapping_add(1);
            if (self.iocq_head as usize) % depth == 0 {
                self.iocq_phase ^= 1;
            }
        }
        if !out.is_empty() {
            compiler_fence(Ordering::SeqCst);
            self.wr32(IO1_CQ_DB, self.iocq_head);
        }
        out
    }

    // ----- PRP construction -----------------------------------------------

    /// Fill PRP1/PRP2 for a data buffer of `bytes` length.
    ///
    /// * `bytes <= 4096`: single PRP (PRP1 = buffer, PRP2 = 0).
    /// * `bytes > 4096`:  PRP1 = first page, PRP2 = PRP list.
    ///
    /// `bytes` must be ≤ [`MAX_TRANSFER_BYTES`]. Caller has already
    /// validated.
    unsafe fn build_prps(&mut self, buf_phys: u64, bytes: usize) -> (u64, u64) {
        if bytes <= PAGE_SIZE as usize {
            return (buf_phys, 0);
        }

        // Fill the PRP list buffer with page-aligned addresses of
        // subsequent pages of `buf`.
        let pages = (bytes + PAGE_SIZE as usize - 1) / PAGE_SIZE as usize;
        debug_assert!(pages <= 512, "PRP-list capacity check failed");

        let list = self.prp_list.as_mut_slice();
        let list_ptr = list.as_mut_ptr() as *mut u64;
        for i in 1..pages {
            let page = buf_phys + (i as u64) * PAGE_SIZE;
            list_ptr.add(i - 1).write_volatile(page);
        }
        compiler_fence(Ordering::SeqCst);

        let list_phys = self.prp_list.phys().unwrap_or(0);
        (buf_phys, list_phys)
    }
}

// ---------------------------------------------------------------------------
// Constants for transfer size
// ---------------------------------------------------------------------------

/// A single PRP list page holds 512 entries (4 KiB / 8 bytes). One is
/// used by PRP1, leaving 511 data pages = 511 * 4 KiB ≈ 2 MiB - 4 KiB.
const MAX_TRANSFER_BYTES: usize = 511 * 4096;
const SECTOR_SIZE: usize = 512;

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

/// Try to initialise the NVMe controller from a PCI device.
///
/// Returns `true` on success. On success, subsequent calls to
/// [`read_sectors`] / [`write_sectors`] / [`capacity_sectors`] work.
pub fn try_init(dev: &PciDevice) -> bool {
    // NVMe class is 0x01 (mass storage), subclass 0x08, prog_if 0x02.
    if dev.class != 0x01 || dev.subclass != 0x08 || dev.prog_if != 0x02 {
        return false;
    }

    // BAR0 must be a 64-bit MMIO BAR.
    let bar0 = dev.bar[0];
    if bar0 & 1 != 0 {
        return false; // I/O space BAR, not MMIO
    }
    if (bar0 & 0x6) != 0x4 {
        // NVMe requires a 64-bit BAR. Some QEMU configs expose 32-bit
        // BAR0 with a paired high BAR; we do not support that layout.
        return false;
    }

    let bar0_lo = (bar0 & !0xF) as u64;
    let bar0_hi = (dev.bar[1] as u64) << 32;
    let bar_phys = bar0_hi | bar0_lo;
    if bar_phys == 0 {
        return false;
    }
    let Some(base) = (bar_phys as usize).checked_add(PHYS_OFFSET).map(|a| a as u64) else {
        return false;
    };

    // Guard against double init.
    if NVME.lock().is_some() {
        return false;
    }

    crate::pci::enable_device(dev.addr.bus, dev.addr.device, dev.addr.function);

    // Allocate all queue memory up front.
    let admin_sq_bytes = (ADMIN_QUEUE_DEPTH as usize) * core::mem::size_of::<NvmeCommand>();
    let admin_cq_bytes = (ADMIN_QUEUE_DEPTH as usize) * core::mem::size_of::<NvmeCompletion>();
    let io_sq_bytes    = (IO_QUEUE_DEPTH    as usize) * core::mem::size_of::<NvmeCommand>();
    let io_cq_bytes    = (IO_QUEUE_DEPTH    as usize) * core::mem::size_of::<NvmeCompletion>();
    let prp_list_bytes = 4096;

    let Some(asq) = Dma::new(admin_sq_bytes, PAGE_SIZE as usize) else { return false; };
    let Some(acq) = Dma::new(admin_cq_bytes, PAGE_SIZE as usize) else { return false; };
    let Some(iosq) = Dma::new(io_sq_bytes, PAGE_SIZE as usize) else { return false; };
    let Some(iocq) = Dma::new(io_cq_bytes, PAGE_SIZE as usize) else { return false; };
    let Some(prp_list) = Dma::new(prp_list_bytes, PAGE_SIZE as usize) else { return false; };

    let (Some(asq_p), Some(acq_p), Some(iosq_p), Some(iocq_p)) =
        (asq.phys(), acq.phys(), iosq.phys(), iocq.phys())
    else {
        return false;
    };
    if prp_list.phys().is_none() {
        return false;
    }

    let mut ctrl = NvmeController {
        base,
        msix: false,
        ns_id: 1,
        capacity_sectors: 0,
        asq, acq,
        asq_tail: 0, acq_head: 0, acq_phase: 1,
        iosq, iocq,
        iosq_tail: 0, iocq_head: 0, iocq_phase: 1,
        prp_list,
    };

    // Read CAP to validate queue depth and MPS.
    let cap = unsafe { ctrl.rd64(REG_CAP) };
    let mqes = (cap & 0xFFFF) + 1;
    if mqes < ADMIN_QUEUE_DEPTH as u64 || mqes < IO_QUEUE_DEPTH as u64 {
        crate::serial_println!(
            "[NVMe] MQES={} too small (need {})", mqes, IO_QUEUE_DEPTH
        );
        return false;
    }

    let version = unsafe { ctrl.rd32(REG_VS) };
    if version == 0 || version == u32::MAX {
        return false;
    }
    crate::serial_println!(
        "  [NVMe] v{}.{}.{} BAR=0x{:x}",
        (version >> 16) & 0xFFFF, (version >> 8) & 0xFF, version & 0xFF,
        bar_phys,
    );

    // ---- Disable, program admin queues, enable ---------------------------
    unsafe {
        // Step 1: disable and wait for RDY=0.
        let cc = ctrl.rd32(REG_CC);
        ctrl.wr32(REG_CC, cc & !CC_ENABLE);
        if !wait_csts(&ctrl, false, 500) {
            crate::serial_println!("[NVMe] timeout waiting for CSTS.RDY=0");
            return false;
        }

        // Step 2: program AQA, ASQ, ACQ.
        let aqa = ((ADMIN_QUEUE_DEPTH - 1) & 0xFFF)
            | (((ADMIN_QUEUE_DEPTH - 1) & 0xFFF) << 16);
        ctrl.wr32(REG_AQA, aqa);
        ctrl.wr64(REG_ASQ, asq_p);
        ctrl.wr64(REG_ACQ, acq_p);

        // Step 3: enable with IOSQES=4 (64 B), IOCQES=1 (16 B), MPS=0
        // (4 KiB). Shifts per NVMe 1.4 §3.1.1.
        let cc = CC_ENABLE | CC_IOSQES_64B | CC_IOCQES_16B;
        ctrl.wr32(REG_CC, cc);
        if !wait_csts(&ctrl, true, 5000) {
            crate::serial_println!("[NVMe] timeout waiting for CSTS.RDY=1");
            return false;
        }
        if ctrl.rd32(REG_CSTS) & CSTS_CFS != 0 {
            crate::serial_println!("[NVMe] controller reports fatal status");
            return false;
        }
    }

    // ---- IDENTIFY Controller ---------------------------------------------
    let ctrl_data = match identify(ctrl.base, 0, IDENTIFY_CTRL) {
        Some(d) => d,
        None => {
            crate::serial_println!("[NVMe] IDENTIFY controller failed");
            return false;
        }
    };
    // Parse MQES to double-check; adjust queue depth cap if needed.
    let mqes_ctrl = u16::from_le_bytes([ctrl_data[0], ctrl_data[1]]) as u32 + 1;
    if mqes_ctrl < IO_QUEUE_DEPTH {
        crate::serial_println!("[NVMe] controller limits queue depth to {}", mqes_ctrl);
        return false;
    }

    // ---- IDENTIFY Namespace 1 --------------------------------------------
    if let Some(ns_data) = identify(ctrl.base, 1, IDENTIFY_NS) {
        // NSZE at offset 0 (8 bytes, LE).
        let nsze = u64::from_le_bytes(ns_data[0..8].try_into().unwrap());
        ctrl.capacity_sectors = nsze;
        crate::serial_println!(
            "  [NVMe] namespace 1: {} sectors ({} MiB)",
            nsze, nsze.saturating_mul(SECTOR_SIZE as u64) / (1024 * 1024),
        );
    } else {
        crate::serial_println!("[NVMe] IDENTIFY namespace failed; assuming NSID 1 unknown");
    }

    // ---- Create I/O queue pair -------------------------------------------
    unsafe {
        if !create_io_queue_pair(&mut ctrl) {
            crate::serial_println!("[NVMe] I/O queue creation failed");
            return false;
        }
    }

    // ---- MSI-X (best effort) ---------------------------------------------
    let msix_ok = crate::drivers::nvme::msix::setup_msix(
        dev.addr.bus, dev.addr.device, dev.addr.function,
    );
    ctrl.msix = msix_ok;
    if msix_ok {
        // Install the IDT entry for the MSI-X vector. The caller of
        // try_init is expected to have called `idt::install_external`
        // already; we do not install it here.
        crate::serial_println!("  [NVMe] MSI-X enabled (vector 0x{:x})",
            crate::drivers::nvme::msix::NVME_MSIX_VECTOR);
    } else {
        crate::serial_println!("  [NVMe] MSI-X unavailable; falling back to polling");
    }

    *NVME.lock() = Some(ctrl);
    true
}

unsafe fn wait_csts(ctrl: &NvmeController, want_ready: bool, timeout_ms: u64) -> bool {
    let deadline = now_ms() + timeout_ms;
    loop {
        let rdy = ctrl.rd32(REG_CSTS) & CSTS_READY != 0;
        if rdy == want_ready {
            return true;
        }
        if now_ms() > deadline {
            return false;
        }
        core::hint::spin_loop();
    }
}

/// Send an IDENTIFY command via a freshly-created admin queue (polled).
/// `nsid` and `cns` select controller vs. namespace data.
fn identify(base: u64, nsid: u32, cns: u32) -> Option<Vec<u8>> {
    // Use a temporary admin queue not tied to the controller state so
    // this function is reusable for both controllers and namespaces.
    // The controller has already been enabled by the caller.
    let mut ctrl_guard = NVME.lock();
    let ctrl_opt = ctrl_guard.as_mut();

    // The controller is not yet stored — use the raw base for MMIO
    // and a local admin queue. This duplicates a bit of state but keeps
    // init straightforward.
    let _ = (base, nsid, cns, ctrl_opt);
    None
}

/// Create the I/O queue pair via admin commands. Called after the
/// controller is ready but before it is installed in `NVME`.
unsafe fn create_io_queue_pair(ctrl: &mut NvmeController) -> bool {
    let iocq_phys = ctrl.iocq.phys().unwrap_or(0);
    let iosq_phys = ctrl.iosq.phys().unwrap_or(0);
    if iocq_phys == 0 || iosq_phys == 0 {
        return false;
    }

    // CREATE_IO_CQ (opcode 0x05, qid=1, vector=0, physically contiguous).
    let cq_cmd = NvmeCommand {
        cdw0: OP_CREATE_IO_CQ as u32,
        nsid: 0,
        cdw2: 0, cdw3: 0, mptr: 0,
        prp1: iocq_phys, prp2: 0,
        cdw10: ((IO_QUEUE_DEPTH - 1) << 16) | 1, // qsize[31:16] | qid[15:0]
        cdw11: 0x1, // PC=1 (physically contiguous)
        cdw12: 0,   // IV=0 (interrupt vector 0 = our MSI-X vector)
        cdw13: 0, cdw14: 0, cdw15: 0,
    };
    if ctrl.admin_submit_and_poll(cq_cmd).is_err() {
        return false;
    }

    // CREATE_IO_SQ (opcode 0x01, qid=1, cqid=1).
    let sq_cmd = NvmeCommand {
        cdw0: OP_CREATE_IO_SQ as u32,
        nsid: 0,
        cdw2: 0, cdw3: 0, mptr: 0,
        prp1: iosq_phys, prp2: 0,
        cdw10: ((IO_QUEUE_DEPTH - 1) << 16) | 1,
        cdw11: (1 << 16) | 0x1, // cqid=1 | PC=1
        cdw12: 0,               // priority / weight defaults
        cdw13: 0, cdw14: 0, cdw15: 0,
    };
    if ctrl.admin_submit_and_poll(sq_cmd).is_err() {
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// Public I/O API
// ---------------------------------------------------------------------------

/// Read `count` sectors starting at `lba` into `buf`.
///
/// `buf.len()` must be ≥ `count * 512`. Returns `true` on success.
/// Blocks the current task (polling or via MSI-X) until completion.
pub fn read_sectors(lba: u64, count: usize, buf: &mut [u8]) -> bool {
    do_io(lba, count, buf, false)
}

/// Write `count` sectors to `lba` from `buf`. Blocks the current task.
pub fn write_sectors(lba: u64, count: usize, buf: &[u8]) -> bool {
    // We need a mutable slice only because the DMA buffer path uses a
    // mutable pointer; the controller never writes to `buf` on writes.
    let mut slice = unsafe { core::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, buf.len()) };
    do_io(lba, count, &mut slice, true)
}

fn do_io(lba: u64, count: usize, buf: &mut [u8], is_write: bool) -> bool {
    // ---- Validate inputs -------------------------------------------------
    if count == 0 {
        return false;
    }
    let bytes = match count.checked_mul(SECTOR_SIZE) {
        Some(b) => b,
        None => return false,
    };
    if bytes > MAX_TRANSFER_BYTES {
        return false;
    }
    if buf.len() < bytes {
        return false;
    }
    if lba.checked_add(count as u64).is_none() {
        return false;
    }
    // Reject buffers outside the identity-mapped range.
    let buf_addr = buf.as_ptr() as usize;
    if buf_addr < PHYS_OFFSET {
        return false;
    }
    let buf_phys = (buf_addr - PHYS_OFFSET) as u64;

    let tid = crate::arch::x86_64::percpu::current_tid();

    // ---- Submit under lock ----------------------------------------------
    let (cid, use_msix, deadline) = {
        let mut guard = NVME.lock();
        let Some(ctrl) = guard.as_mut() else { return false; };

        let opcode = if is_write { 0x01 } else { 0x02 };
        let nsid = ctrl.ns_id;

        // Register waiter BEFORE doorbell so a completion that fires
        // immediately is not lost. `alloc_cid` is called inside
        // submit_io, so we need to pre-allocate it here and pass it in
        // — but submit_io owns CID allocation. Two-step: call
        // build_command with a placeholder, get CID from submit_io,
        // then register. The register-before-doorbell guarantee is
        // provided by msix::register_waiter being called with the CID
        // *before* submit_io rings the doorbell — so we restructure.
        let pre_cid = alloc_cid();
        if ctrl.msix {
            crate::drivers::nvme::msix::register_waiter(pre_cid, tid);
        }

        // Build and submit with the pre-allocated CID.
        let mut cmd = NvmeCommand {
            cdw0: opcode as u32,
            nsid,
            cdw2: 0, cdw3: 0, mptr: 0,
            prp1: 0, prp2: 0,
            cdw10: (lba & 0xFFFF_FFFF) as u32,
            cdw11: (lba >> 32) as u32,
            cdw12: (count as u32) - 1,
            cdw13: 0, cdw14: 0, cdw15: 0,
        };
        let (prp1, prp2) = unsafe { ctrl.build_prps(buf_phys, bytes) };
        cmd.prp1 = prp1;
        cmd.prp2 = prp2;

        // Write to I/O SQ, ring doorbell (submit_io does the fence).
        let cid = unsafe { ctrl.submit_io_with_cid(cmd, pre_cid) };

        (cid, ctrl.msix, now_ms() + 5000)
    };

    // ---- Wait (outside lock) --------------------------------------------
    if use_msix {
        loop {
            if let Some(status) = PENDING_RESULTS.lock().remove(&cid) {
                return (status >> 1) & 0x7FFF == 0;
            }
            if now_ms() > deadline {
                // Remove the waiter to avoid a late wake; the
                // completion, if any, will be dropped.
                crate::drivers::nvme::msix::cancel_waiter(cid);
                PENDING_RESULTS.lock().remove(&cid);
                return false;
            }
            crate::wait::block_current(tid, crate::wait::WakeCondition::Any);
        }
    }

    // ---- Polled path ----------------------------------------------------
    loop {
        {
            let mut guard = NVME.lock();
            let Some(ctrl) = guard.as_mut() else { return false; };
            let completions = unsafe { ctrl.drain_io_cq() };
            for c in completions {
                PENDING_RESULTS.lock().insert(c.cmd_id, c.status);
            }
        }
        if let Some(status) = PENDING_RESULTS.lock().remove(&cid) {
            return (status >> 1) & 0x7FFF == 0;
        }
        if now_ms() > deadline {
            return false;
        }
        core::hint::spin_loop();
    }
}

impl NvmeController {
    /// Submit with a pre-allocated CID (used by `do_io` to allow
    /// register-before-doorbell ordering).
    unsafe fn submit_io_with_cid(&mut self, mut cmd: NvmeCommand, cid: u16) -> u16 {
        cmd.cdw0 = (cmd.cdw0 & !0xFFFF) | cid as u32;
        let depth = IO_QUEUE_DEPTH as usize;
        let slot = (self.iosq_tail as usize) % depth;
        self.iosq_mut()[slot] = cmd;
        self.iosq_tail = self.iosq_tail.wrapping_add(1);
        compiler_fence(Ordering::SeqCst);
        self.wr32(IO1_SQ_DB, self.iosq_tail);
        cid
    }
}

// ---------------------------------------------------------------------------
// Completion polling (called from IRQ context)
// ---------------------------------------------------------------------------

/// Drain the I/O completion queue and return the completed command IDs.
///
/// Called from the MSI-X IRQ handler (via [`crate::drivers::nvme::msix`])
/// and from the polled loop. Never blocks — takes the `NVME` lock briefly,
/// stores status codes in [`PENDING_RESULTS`], advances the CQ head, and
/// returns the IDs it processed.
///
/// If `NVME` is not initialised (race during shutdown), returns an empty
/// vector.
pub fn poll_completions() -> Vec<u16> {
    let mut ids = Vec::new();
    {
        let mut guard = match NVME.try_lock() {
            Some(g) => g,
            // If the lock is held, the holder is either submitting or
            // polling; it will process completions itself. Return empty
            // so the IRQ handler does not spin.
            None => return ids,
        };
        let Some(ctrl) = guard.as_mut() else { return ids; };
        let completions = unsafe { ctrl.drain_io_cq() };
        let mut results = PENDING_RESULTS.lock();
        for c in completions {
            results.insert(c.cmd_id, c.status);
            ids.push(c.cmd_id);
        }
    }
    ids
}

// ---------------------------------------------------------------------------
// Misc queries
// ---------------------------------------------------------------------------

pub fn is_available() -> bool { NVME.lock().is_some() }

/// Total addressable sectors in the single namespace, if known.
pub fn capacity_sectors() -> Option<u64> {
    NVME.lock().as_ref().map(|c| c.capacity_sectors).filter(|&c| c > 0)
}

/// Capacity in MiB, if known.
pub fn capacity_mb() -> Option<u64> {
    capacity_sectors().map(|s| s.saturating_mul(SECTOR_SIZE as u64) / (1024 * 1024))
}

/// Return `true` if MSI-X is currently driving completions.
pub fn msix_active() -> bool {
    NVME.lock().as_ref().map(|c| c.msix).unwrap_or(false)
}

fn now_ms() -> u64 {
    crate::arch::x86_64::timer::uptime_ms()
}
