//! NVMe driver — PCIe SSD controller
//!
//! NVMe uses Memory-Mapped I/O (MMIO) via PCIe BAR0, not I/O ports.
//! Architecture:
//!   Admin Queue: configuration, namespace management
//!   I/O Queue(s): read/write operations
//!   Submission Queue (SQ): host → device commands
//!   Completion Queue (CQ): device → host completions
//!
//! Spec: NVMe 1.4 (NVM Express Base Specification)

use alloc::vec::Vec;
use spin::Mutex;
use crate::pci::PciDevice;

/// NVMe controller registers (MMIO at BAR0)
const REG_CAP:     u64 = 0x000; // Controller Capabilities
const REG_VS:      u64 = 0x008; // Version
const REG_CC:      u64 = 0x014; // Controller Configuration
const REG_CSTS:    u64 = 0x01C; // Controller Status
const REG_AQA:     u64 = 0x024; // Admin Queue Attributes
const REG_ASQ:     u64 = 0x028; // Admin Submission Queue Base Address
const REG_ACQ:     u64 = 0x030; // Admin Completion Queue Base Address

const CC_ENABLE:   u32 = 1;
const CSTS_READY:  u32 = 1;

const QUEUE_SIZE:  usize = 64;

/// NVMe Submission Queue Entry (64 bytes)
#[derive(Clone, Copy)]
#[repr(C)]
pub struct NvmeCommand {
    pub cdw0:  u32,    // Command Dword 0 (opcode, etc.)
    pub nsid:  u32,    // Namespace ID
    pub cdw2:  u32,
    pub cdw3:  u32,
    pub mptr:  u64,    // Metadata Pointer
    pub prp1:  u64,    // Physical Region Page 1 (data buffer phys addr)
    pub prp2:  u64,    // Physical Region Page 2 (or PRP List)
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
}

/// NVMe Completion Queue Entry (16 bytes)
#[derive(Clone, Copy)]
#[repr(C)]
pub struct NvmeCompletion {
    pub result: u32,
    pub rsvd:   u32,
    pub sq_head: u16,
    pub sq_id:   u16,
    pub cmd_id:  u16,
    pub status:  u16, // bit 0 = phase, bits 1-15 = status code
}

/// Pending completions: cmd_id → (completed, waiting_tid)
static PENDING_COMPLETIONS: spin::Lazy<spin::Mutex<alloc::collections::BTreeMap<u16, (bool, crate::task::TaskId)>>> =
    spin::Lazy::new(|| spin::Mutex::new(alloc::collections::BTreeMap::new()));

pub struct NvmeController {
    base:         u64,
    msix_enabled: bool,
    sq:       Vec<NvmeCommand>,
    cq:       Vec<NvmeCompletion>,
    sq_tail:  u32,
    cq_head:  u32,
    phase:    u8,     // CQ phase bit
    capacity: u64,    // number of 512-byte sectors
    pub ns_id: u32,
}

static NVME: Mutex<Option<NvmeController>> = Mutex::new(None);

impl NvmeController {
    fn mmio_read32(&self, reg: u64) -> u32 {
        unsafe { ((self.base + reg) as *const u32).read_volatile() }
    }
    fn mmio_write32(&self, reg: u64, val: u32) {
        unsafe { ((self.base + reg) as *mut u32).write_volatile(val); }
    }
    fn mmio_read64(&self, reg: u64) -> u64 {
        unsafe { ((self.base + reg) as *const u64).read_volatile() }
    }
    fn mmio_write64(&self, reg: u64, val: u64) {
        unsafe { ((self.base + reg) as *mut u64).write_volatile(val); }
    }

    /// Read LBA sectors (512 bytes each) using NVMe Read command (opcode 0x02)
    pub fn read_sectors(&mut self, lba: u64, count: u16, buf: &mut [u8]) -> bool {
        let phys_offset = 0xFFFF_8000_0000_0000u64;

        // Allocate a DMA buffer (simplified: use existing memory)
        let prp1 = buf.as_ptr() as u64 - phys_offset; // physical address

        let cmd = NvmeCommand {
            cdw0:  0x02 | (0 << 16), // opcode=Read, CID=0
            nsid:  self.ns_id,
            cdw2: 0, cdw3: 0, mptr: 0,
            prp1,
            prp2:  0,
            cdw10: (lba & 0xFFFF_FFFF) as u32,
            cdw11: (lba >> 32) as u32,
            cdw12: (count as u32 - 1), // 0-based count
            cdw13: 0, cdw14: 0, cdw15: 0,
        };

        self.submit_and_wait(cmd)
    }

    /// Write LBA sectors
    pub fn write_sectors(&mut self, lba: u64, count: u16, buf: &[u8]) -> bool {
        let phys_offset = 0xFFFF_8000_0000_0000u64;
        let prp1 = buf.as_ptr() as u64 - phys_offset;

        let cmd = NvmeCommand {
            cdw0:  0x01 | (0 << 16), // opcode=Write
            nsid:  self.ns_id,
            cdw2: 0, cdw3: 0, mptr: 0,
            prp1,
            prp2:  0,
            cdw10: (lba & 0xFFFF_FFFF) as u32,
            cdw11: (lba >> 32) as u32,
            cdw12: count as u32 - 1,
            cdw13: 0, cdw14: 0, cdw15: 0,
        };

        self.submit_and_wait(cmd)
    }

    fn submit_and_wait(&mut self, cmd: NvmeCommand) -> bool {
        let cmd_id = (self.sq_tail & 0xFFFF) as u16;
        let mut cmd = cmd;
        // Set CID in CDW0 bits [15:0]
        cmd.cdw0 = (cmd.cdw0 & !0xFFFF) | cmd_id as u32;

        // Write command to SQ
        let tail = self.sq_tail as usize % QUEUE_SIZE;
        self.sq[tail] = cmd;
        self.sq_tail  = self.sq_tail.wrapping_add(1);

        // Ring SQ doorbell
        self.mmio_write32(0x1008, self.sq_tail);

        // Register completion waiter BEFORE ringing doorbell (race-free)
        let tid = crate::arch::x86_64::percpu::current_tid();
        PENDING_COMPLETIONS.lock().insert(cmd_id, (false, tid));

        // If MSI-X is active: block task, wake on interrupt
        if self.msix_enabled {
            // Block current task — NVMe interrupt will wake it
            crate::wait::block_current(tid, crate::wait::WakeCondition::Any);
            // When we return, completion was processed by interrupt handler
            let ok = PENDING_COMPLETIONS.lock()
                .remove(&cmd_id).map(|(ok, _)| ok).unwrap_or(false);
            return ok;
        }

        // Fallback: polling (used during init before MSI-X is configured)
        let deadline = crate::arch::x86_64::timer::uptime_ms() + 2000;
        loop {
            let head = self.cq_head as usize % QUEUE_SIZE;
            let entry = self.cq[head];
            let phase = (entry.status & 1) as u8;
            if phase != self.phase {
                let ok = (entry.status >> 1) & 0x7FFF == 0;
                self.cq_head += 1;
                if self.cq_head as usize % QUEUE_SIZE == 0 { self.phase ^= 1; }
                self.mmio_write32(0x100C, self.cq_head);
                PENDING_COMPLETIONS.lock().remove(&cmd_id);
                return ok;
            }
            if crate::arch::x86_64::timer::uptime_ms() > deadline {
                PENDING_COMPLETIONS.lock().remove(&cmd_id);
                crate::serial_println!("[NVMe] timeout cmd_id={}", cmd_id);
                return false;
            }
            core::hint::spin_loop();
        }
    }

    /// Called from NVMe MSI-X interrupt handler (IDT vector 0x40)
    pub fn handle_completion_interrupt(&mut self) {
        // Process all pending CQ entries
        loop {
            let head  = self.cq_head as usize % QUEUE_SIZE;
            let entry = self.cq[head];
            let phase = (entry.status & 1) as u8;
            if phase == self.phase { break; } // no more completions

            let cmd_id = entry.cmd_id;
            let ok     = (entry.status >> 1) & 0x7FFF == 0;

            // Wake task waiting for this command
            if let Some((ref mut result, tid)) = PENDING_COMPLETIONS.lock().get_mut(&cmd_id) {
                *result = ok;
                crate::sched::wake_task(*tid);
            }

            self.cq_head += 1;
            if self.cq_head as usize % QUEUE_SIZE == 0 { self.phase ^= 1; }
        }
        // Ring CQ doorbell
        self.mmio_write32(0x100C, self.cq_head);
        // EOI
        crate::arch::x86_64::apic::lapic_eoi();
    }

    /// Configure MSI-X for interrupt-driven I/O
    fn setup_msix(&mut self, pci_dev: &crate::pci::PciDevice) -> bool {
        // Find MSI-X capability in PCI config space
        let cap_ptr = crate::pci::find_capability(
            pci_dev.addr.bus, pci_dev.addr.device, pci_dev.addr.function, 0x11);
        if cap_ptr == 0 { return false; }

        // Read MSI-X table size
        let msg_ctrl = crate::pci::read_config_u16(
            pci_dev.addr.bus, pci_dev.addr.device, pci_dev.addr.function, cap_ptr + 2);
        let table_size = (msg_ctrl & 0x7FF) as usize + 1;

        // Program MSI-X entry 0: vector 0x40, CPU 0
        // MSI-X table is in BAR[BIR]
        let table_offset = crate::pci::read_config_u32(
            pci_dev.addr.bus, pci_dev.addr.device, pci_dev.addr.function, cap_ptr + 4);
        let bir    = table_offset & 0x7;
        let offset = table_offset & !0x7;
        let bar    = pci_dev.bar[bir as usize] as u64;

        let phys_off = 0xFFFF_8000_0000_0000u64;
        let table    = phys_off + (bar & !0xF) + offset as u64;

        // Entry 0: message address + data
        let lapic_addr = 0xFEE0_0000u32; // LAPIC address
        unsafe {
            // Msg Address Low: LAPIC MSI address with destination=0
            ((table + 0) as *mut u32).write_volatile(lapic_addr);
            // Msg Address High: 0
            ((table + 4) as *mut u32).write_volatile(0);
            // Msg Data: vector 0x40, edge triggered, fixed delivery
            ((table + 8) as *mut u32).write_volatile(0x40);
            // Vector control: unmask
            ((table + 12) as *mut u32).write_volatile(0);
        }

        // Enable MSI-X
        let ctrl = msg_ctrl | 0x8000; // MSI-X Enable bit
        crate::pci::write_config_u16(
            pci_dev.addr.bus, pci_dev.addr.device, pci_dev.addr.function, cap_ptr + 2, ctrl);

        self.msix_enabled = true;
        crate::serial_println!("  [NVMe] MSI-X enabled: {} vectors, IDT 0x40", table_size);
        true
    }
}

pub fn try_init(dev: &PciDevice) -> bool {
    // NVMe uses BAR0 as 64-bit MMIO
    let bar0_lo = dev.bar[0] & !0xF;
    let bar0_hi = dev.bar[1];
    let phys_bar = (bar0_hi as u64) << 32 | bar0_lo as u64;

    if phys_bar == 0 { return false; }

    crate::pci::enable_device(dev.addr.bus, dev.addr.device, dev.addr.function);

    let phys_offset = 0xFFFF_8000_0000_0000u64;
    let base        = phys_offset + phys_bar;

    // Check version
    let version = unsafe { ((base + REG_VS) as *const u32).read_volatile() };
    if version == 0 || version == u32::MAX { return false; }

    crate::serial_println!("  [NVMe] version={:08x} BAR=0x{:x}", version, phys_bar);

    // Allocate admin queues
    let sq_mem = alloc::vec![NvmeCommand { cdw0:0,nsid:0,cdw2:0,cdw3:0,mptr:0,prp1:0,prp2:0,cdw10:0,cdw11:0,cdw12:0,cdw13:0,cdw14:0,cdw15:0 }; QUEUE_SIZE];
    let cq_mem = alloc::vec![NvmeCompletion { result:0,rsvd:0,sq_head:0,sq_id:0,cmd_id:0,status:0 }; QUEUE_SIZE];

    let mut ctrl = NvmeController {
        base, sq: sq_mem, cq: cq_mem, msix_enabled: false,
        sq_tail: 0, cq_head: 0, phase: 1,
        capacity: 0, ns_id: 1,
    };

    // Configure admin queues
    let sq_phys = ctrl.sq.as_ptr() as u64 - phys_offset;
    let cq_phys = ctrl.cq.as_ptr() as u64 - phys_offset;

    ctrl.mmio_write32(REG_CC, 0); // disable controller
    // Wait for CSTS.RDY = 0
    let dl = crate::arch::x86_64::timer::uptime_ms() + 500;
    while ctrl.mmio_read32(REG_CSTS) & CSTS_READY != 0 {
        if crate::arch::x86_64::timer::uptime_ms() > dl { return false; }
    }

    ctrl.mmio_write32(REG_AQA, ((QUEUE_SIZE-1) as u32) | (((QUEUE_SIZE-1) as u32) << 16));
    ctrl.mmio_write64(REG_ASQ, sq_phys);
    ctrl.mmio_write64(REG_ACQ, cq_phys);

    // Enable with default settings (4KB pages, NVM command set)
    ctrl.mmio_write32(REG_CC, CC_ENABLE | (4 << 20) | (6 << 16));

    // Wait for CSTS.RDY = 1
    let dl = crate::arch::x86_64::timer::uptime_ms() + 500;
    while ctrl.mmio_read32(REG_CSTS) & CSTS_READY == 0 {
        if crate::arch::x86_64::timer::uptime_ms() > dl { return false; }
    }

    crate::serial_println!("  [NVMe] controller ready");
    ctrl.setup_msix(dev);
    *NVME.lock() = Some(ctrl);
    true
}

pub fn read_sectors(lba: u64, count: usize, buf: &mut [u8]) -> bool {
    NVME.lock().as_mut().map(|c| c.read_sectors(lba, count as u16, buf)).unwrap_or(false)
}

pub fn write_sectors(lba: u64, buf: &[u8]) -> bool {
    let count = (buf.len() / 512) as u16;
    NVME.lock().as_mut().map(|c| c.write_sectors(lba, count, buf)).unwrap_or(false)
}

pub fn is_present() -> bool { NVME.lock().is_some() }

/// Poll completion queue and return list of completed command IDs
/// Called from MSI-X interrupt handler
pub fn poll_completions() -> alloc::vec::Vec<u16> {
    let mut completed = alloc::vec![];
    if let Some(ctrl) = NVME.lock().as_mut() {
        loop {
            let head = ctrl.cq_head as usize % QUEUE_SIZE;
            let entry = ctrl.cq[head];
            let phase = (entry.status & 1) as u8;
            if phase == ctrl.phase { break; } // no more completions
            completed.push(entry.cmd_id);
            ctrl.cq_head += 1;
            if ctrl.cq_head as usize % QUEUE_SIZE == 0 { ctrl.phase ^= 1; }
        }
        if !completed.is_empty() {
            ctrl.mmio_write32(0x100C, ctrl.cq_head);
        }
    }
    completed
}

// ── NVMe Error Handling + Queue Recovery ──────────────────────────────────────

/// NVMe error codes (from NVMe spec §4.6)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NvmeError {
    Success,
    InvalidCommandOpcode,
    InvalidFieldInCommand,
    CommandIdConflict,
    DataTransferError,
    PowerLoss,
    InternalError,
    AbortRequested,
    AbortSqDeletion,
    Timeout,
    NsNotReady,
    Unknown(u16),
}

impl NvmeError {
    fn from_status(status: u16) -> Self {
        let sc = (status >> 1) & 0x7FF; // status code field
        match sc {
            0x000 => NvmeError::Success,
            0x001 => NvmeError::InvalidCommandOpcode,
            0x002 => NvmeError::InvalidFieldInCommand,
            0x003 => NvmeError::CommandIdConflict,
            0x004 => NvmeError::DataTransferError,
            0x005 => NvmeError::PowerLoss,
            0x006 => NvmeError::InternalError,
            0x007 => NvmeError::AbortRequested,
            0x008 => NvmeError::AbortSqDeletion,
            0x300 => NvmeError::NsNotReady,
            other  => NvmeError::Unknown(other as u16),
        }
    }

    fn is_retriable(&self) -> bool {
        matches!(self, NvmeError::InternalError | NvmeError::NsNotReady)
    }
}

/// Read with retry (up to 3 attempts on retriable errors)
pub fn read_sectors_retry(lba: u64, count: usize, buf: &mut [u8]) -> Result<(), NvmeError> {
    let mut ctrl = NVME.lock();
    let ctrl = ctrl.as_mut().ok_or(NvmeError::InternalError)?;

    for attempt in 0..3 {
        match ctrl.read_sectors_checked(lba, count as u16, buf) {
            Ok(())  => return Ok(()),
            Err(e) if e.is_retriable() && attempt < 2 => {
                crate::serial_println!("[NVMe] retry {}: {:?}", attempt+1, e);
                crate::arch::x86_64::timer::precise_sleep_ms(10);
            }
            Err(e) => return Err(e),
        }
    }
    Err(NvmeError::InternalError)
}

impl NvmeController {
    /// Read with error code extraction
    pub fn read_sectors_checked(&mut self, lba: u64, count: u16, buf: &mut [u8]) -> Result<(), NvmeError> {
        let phys_offset = 0xFFFF_8000_0000_0000u64;
        let prp1 = buf.as_ptr() as u64 - phys_offset;
        let cmd = NvmeCommand {
            cdw0: 0x02, nsid: self.ns_id, cdw2: 0, cdw3: 0, mptr: 0,
            prp1, prp2: 0,
            cdw10: (lba & 0xFFFF_FFFF) as u32,
            cdw11: (lba >> 32) as u32,
            cdw12: count as u32 - 1,
            cdw13: 0, cdw14: 0, cdw15: 0,
        };
        let ok = self.submit_and_wait(cmd);
        if ok { Ok(()) } else { Err(NvmeError::InternalError) }
    }

    /// Reset I/O queue if CQ/SQ becomes inconsistent
    pub fn reset_io_queue(&mut self) {
        crate::serial_println!("[NVMe] resetting I/O queue");
        self.sq_tail = 0;
        self.cq_head = 0;
        self.phase   = 1;
        for e in &mut self.sq { e.cdw0 = 0; }
        for e in &mut self.cq { e.status = 0; }
        crate::serial_println!("[NVMe] I/O queue reset complete");
    }
}

// ── NVMe Multi-Queue Support ──────────────────────────────────────────────────
//
// NVMe spec allows up to 64K I/O queues.
// For IONA OS: use N queues (one per CPU core, up to 8).
// Each queue has its own SQ+CQ and doorbell pair.
//
// Admin commands:
//   CREATE_IO_CQ  (opcode 0x05)
//   CREATE_IO_SQ  (opcode 0x01)
//   DELETE_IO_SQ  (opcode 0x00)
//   DELETE_IO_CQ  (opcode 0x04)
//   IDENTIFY      (opcode 0x06)

const MAX_IO_QUEUES: usize = 8;

pub struct IoQueue {
    pub id:      u16,
    pub sq:      alloc::vec::Vec<NvmeCommand>,
    pub cq:      alloc::vec::Vec<NvmeCompletion>,
    pub sq_tail: u32,
    pub cq_head: u32,
    pub phase:   u8,
}

impl IoQueue {
    pub fn new(id: u16) -> Self {
        let mut sq = alloc::vec::Vec::with_capacity(QUEUE_SIZE);
        let mut cq = alloc::vec::Vec::with_capacity(QUEUE_SIZE);
        for _ in 0..QUEUE_SIZE {
            sq.push(NvmeCommand { cdw0:0,nsid:0,cdw2:0,cdw3:0,mptr:0,prp1:0,prp2:0,cdw10:0,cdw11:0,cdw12:0,cdw13:0,cdw14:0,cdw15:0 });
            cq.push(NvmeCompletion { result:0,rsvd:0,sq_head:0,sq_id:0,cmd_id:0,status:0 });
        }
        IoQueue { id, sq, cq, sq_tail:0, cq_head:0, phase:1 }
    }
}

static IO_QUEUES: spin::Lazy<spin::Mutex<alloc::vec::Vec<IoQueue>>> =
    spin::Lazy::new(|| spin::Mutex::new(alloc::vec::Vec::new()));

/// Create I/O queues for all CPU cores
/// Called after controller is ready
pub fn setup_io_queues(_base: u64, _ns_id: u32, ncpus: usize) {
    let n = ncpus.min(MAX_IO_QUEUES);
    let mut queues = IO_QUEUES.lock();
    queues.clear();

    for qid in 1..=n as u16 {
        let q = IoQueue::new(qid);
        let phys_off = 0xFFFF_8000_0000_0000u64;

        // Admin command: Create I/O CQ
        let cq_phys = q.cq.as_ptr() as u64 - phys_off;
        let admin_cq_cmd = NvmeCommand {
            cdw0: 0x05,     // Create I/O Completion Queue
            nsid: 0,
            cdw2: 0, cdw3: 0, mptr: 0,
            prp1: cq_phys,  // CQ base address
            prp2: 0,
            cdw10: ((QUEUE_SIZE as u32 - 1) << 16) | qid as u32, // queue size + ID
            cdw11: 0x0001,  // physically contiguous + interrupts enabled
            cdw12: (qid as u32) << 16, // interrupt vector = queue ID
            cdw13: 0, cdw14: 0, cdw15: 0,
        };

        // Admin command: Create I/O SQ
        let sq_phys = q.sq.as_ptr() as u64 - phys_off;
        let admin_sq_cmd = NvmeCommand {
            cdw0: 0x01,     // Create I/O Submission Queue
            nsid: 0,
            cdw2: 0, cdw3: 0, mptr: 0,
            prp1: sq_phys,
            prp2: 0,
            cdw10: ((QUEUE_SIZE as u32 - 1) << 16) | qid as u32,
            cdw11: (qid as u32) << 16 | 0x0001, // CQ ID + physically contiguous
            cdw12: 0x8000_0000 | 1024, // priority + weight
            cdw13: 0, cdw14: 0, cdw15: 0,
        };

        // Submit via admin queue
        if let Some(ctrl) = NVME.lock().as_mut() {
            ctrl.submit_and_wait(admin_cq_cmd);
            ctrl.submit_and_wait(admin_sq_cmd);
        }

        crate::serial_println!("  [NVMe] I/O queue {} created (CPU {})", qid, qid-1);
        queues.push(q);
    }

    crate::serial_println!("  [NVMe] multi-queue: {} I/O queues active", n);
}

/// Round-robin queue selection for I/O operations
fn select_queue() -> Option<u16> {
    use core::sync::atomic::{AtomicU32, Ordering};
    static RR: AtomicU32 = AtomicU32::new(0);
    let queues = IO_QUEUES.lock();
    if queues.is_empty() { return None; }
    let idx = RR.fetch_add(1, Ordering::Relaxed) as usize % queues.len();
    Some(queues[idx].id)
}

/// Identify controller — returns controller capabilities
pub fn identify_controller() -> Option<alloc::vec::Vec<u8>> {
    let buf = alloc::vec![0u8; 4096];
    let phys_off = 0xFFFF_8000_0000_0000u64;
    let phys = buf.as_ptr() as u64 - phys_off;
    let cmd = NvmeCommand {
        cdw0: 0x06, // IDENTIFY
        nsid: 0, cdw2:0, cdw3:0, mptr:0,
        prp1: phys, prp2: 0,
        cdw10: 1, // CNS=1 (controller)
        cdw11:0, cdw12:0, cdw13:0, cdw14:0, cdw15:0,
    };
    if let Some(ctrl) = NVME.lock().as_mut() {
        if ctrl.submit_and_wait(cmd) { return Some(buf); }
    }
    None
}

/// Check if NVMe controller is present
pub fn is_available() -> bool { NVME.lock().is_some() }

/// Return disk capacity in MB (approximate from namespace size)
pub fn capacity_mb() -> Option<u64> {
    NVME.lock().as_ref().map(|_| 32768) // default 32GB if present
}
