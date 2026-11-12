//! XHCI USB 3.0 Host Controller Driver.
//!
//! # What is implemented
//!
//! * Controller reset and bring-up per xHCI 1.2 §4.2.
//! * Command Ring (producer ring, wraps via Link TRB).
//! * Event Ring (linear ring, wraps via cycle bit; no Link TRB).
//! * Event Ring Segment Table (ERST) and DCBAAP, both persistent,
//!   64-byte aligned, zeroed at init.
//! * Interrupter 0 enable (IMAN.IE), ERDP management.
//! * Port power-on, connect detection, port reset (PR / WPR), PED check.
//! * HID Usage → ASCII mapping including Shift and full US punctuation.
//! * Small HID boot-keyboard state machine (modifiers, CapsLock, key
//!   rollover, new-press detection).
//!
//! # What is **not** implemented (honest list)
//!
//! * **Device enumeration.** `Address Device`, `Get Descriptor`,
//!   `Set Configuration`, `Configure Endpoint`, and HID Report Descriptor
//!   parsing are not implemented. Ports detect as enabled, but no slot,
//!   device context, or endpoint ring is created. No HID interrupt
//!   transfer is submitted.
//! * **Control transfers.** Setup → Data → Status staging is not
//!   implemented.
//! * **MSI-X.** Interrupts arrive through the legacy INTx path.
//! * **USB 3.0 link training.** WPR is issued, but link-state handling
//!   (U0/U1/U2/U3) beyond PED is not tracked.
//! * **Hub support / tier topology.** Only root ports are probed.
//!
//! Because enumeration is unimplemented, no USB keyboard or mouse will
//! actually work through this driver today. The rest of the module is a
//! correct foundation that a future enumeration implementation can build
//! on without re-addressing any of the bring-up code.
//!
//! # Preconditions
//!
//! * Physical memory is identity-mapped at [`PHYS_OFFSET`].
//! * The global allocator returns physically-contiguous memory in that
//!   range (required for DMA rings).
//! * PCI bus mastering is enabled by the caller or by
//!   [`crate::pci::enable_device`].

use alloc::vec::Vec;

use core::sync::atomic::{compiler_fence, Ordering};

use spin::Mutex;

use crate::pci::PciDevice;

// ---------------------------------------------------------------------------
// Register offsets
// ---------------------------------------------------------------------------

const CAP_CAPLENGTH:  u64 = 0x00;
const CAP_HCSPARAMS1: u64 = 0x04;
const CAP_HCSPARAMS2: u64 = 0x08;
const CAP_DBOFF:      u64 = 0x14;
const CAP_RTSOFF:     u64 = 0x18;

const OP_USBCMD:   u64 = 0x00;
const OP_USBSTS:   u64 = 0x04;
const OP_PAGESIZE: u64 = 0x08;
const OP_CRCR:     u64 = 0x18;
const OP_DCBAAP:   u64 = 0x30;
const OP_CONFIG:   u64 = 0x38;

const USBCMD_RUN:   u32 = 1 << 0;
const USBCMD_HCRST: u32 = 1 << 1;
const USBCMD_INTE:  u32 = 1 << 2;

const USBSTS_HCH: u32 = 1 << 0;
const USBSTS_CNR: u32 = 1 << 11;

// Interrupter 0 offsets relative to RT_BASE + 0x20.
const IR_IMAN:   u64 = 0x00;
const IR_ERSTSZ: u64 = 0x08;
const IR_ERSTBA: u64 = 0x10;
const IR_ERDP:   u64 = 0x18;

const IMAN_IE: u32 = 1 << 1;

// ---------------------------------------------------------------------------
// PORTSC bits (xHCI 1.2 §5.4.8)
// ---------------------------------------------------------------------------

const PORTSC_CCS:  u32 = 1 << 0;
const PORTSC_PED:  u32 = 1 << 1;
const PORTSC_PR:   u32 = 1 << 4;
const PORTSC_PLS_SHIFT: u32 = 5;
const PORTSC_PP:   u32 = 1 << 9;
const PORTSC_CSC:  u32 = 1 << 17;
const PORTSC_WRC:  u32 = 1 << 19;
const PORTSC_PRC:  u32 = 1 << 21;
const PORTSC_PLC:  u32 = 1 << 22;
const PORTSC_WPR:  u32 = 1 << 31;

/// All W1C change bits we care to clear after reset.
const PORTSC_CHANGE_BITS: u32 =
    PORTSC_CSC | PORTSC_WRC | PORTSC_PRC | PORTSC_PLC;

/// Port register spacing (xHCI 1.2 §5.4.8).
const PORT_REG_STRIDE: u64 = 0x10;
const PORT_REG_BASE_OFF: u64 = 0x400;

// ---------------------------------------------------------------------------
// Ring geometry
// ---------------------------------------------------------------------------

/// Command ring depth in TRBs (one slot is the Link TRB).
const COMMAND_RING_SIZE: usize = 64;

/// Event ring depth in TRBs (linear, no link).
const EVENT_RING_SIZE: usize = 64;

const TRB_SIZE: usize = 16;

/// All xHCI DMA structures require 64-byte alignment.
const RING_ALIGN: usize = 64;

// ---------------------------------------------------------------------------
// TRB types (xHCI 1.2 Table 6-91)
// ---------------------------------------------------------------------------

const TRB_TYPE_LINK:              u32 = 6;
const TRB_TYPE_ENABLE_SLOT:       u32 = 9;
const TRB_TYPE_TRANSFER_EVENT:    u32 = 32;
const TRB_TYPE_CMD_COMPLETION:    u32 = 33;
const TRB_TYPE_PORT_STATUS_CHG:   u32 = 34;
const TRB_TYPE_HOST_CONTROLLER:   u32 = 37;

const COMPLETION_SUCCESS: u8 = 1;

// ---------------------------------------------------------------------------
// Timeouts (milliseconds)
// ---------------------------------------------------------------------------

const HC_HALT_TIMEOUT_MS: u64 = 100;
const HC_RESET_TIMEOUT_MS: u64 = 500;
const CNR_TIMEOUT_MS:      u64 = 500;
const PORT_RESET_TIMEOUT_MS: u64 = 500;

// ---------------------------------------------------------------------------
// Physical memory offset
// ---------------------------------------------------------------------------

const PHYS_OFFSET: usize = 0xFFFF_8000_0000_0000;

// ---------------------------------------------------------------------------
// DMA buffer
// ---------------------------------------------------------------------------

/// Persistent, aligned DMA allocation. The owning `Vec<u8>` is kept
/// alive for the whole lifetime of the `Dma`, so the virtual pointer
/// (and therefore the physical address) is stable across moves of the
/// containing struct.
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

    fn len(&self) -> usize { self.len }
}

// ---------------------------------------------------------------------------
// TRB
// ---------------------------------------------------------------------------

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct Trb {
    param:   u64,
    status:  u32,
    control: u32,
}

impl Trb {
    const ZERO: Self = Self { param: 0, status: 0, control: 0 };

    #[inline]
    fn trb_type(&self) -> u32 { (self.control >> 10) & 0x3F }

    #[inline]
    fn cycle(&self) -> u8 { (self.control & 1) as u8 }

    #[inline]
    fn completion_code(&self) -> u8 { (self.status >> 24) as u8 }

    fn link(ring_phys: u64, cycle: u8) -> Self {
        Self {
            param: ring_phys,
            status: 0,
            // Type=6, TC=1 (toggle cycle on wrap), cycle bit in bit 0.
            control: (TRB_TYPE_LINK << 10) | (1 << 1) | (cycle as u32),
        }
    }

    fn enable_slot() -> Self {
        Self { param: 0, status: 0, control: (TRB_TYPE_ENABLE_SLOT << 10) }
    }
}

const _: () = {
    assert!(core::mem::size_of::<Trb>() == TRB_SIZE);
    assert!(core::mem::align_of::<Trb>() == 16);
};

// ---------------------------------------------------------------------------
// Command ring (producer ring, wraps via Link TRB)
// ---------------------------------------------------------------------------

struct CommandRing {
    mem:     Dma,
    enqueue: u32,
    cycle:   u8,
}

impl CommandRing {
    fn new() -> Option<Self> {
        let mem = Dma::new(COMMAND_RING_SIZE * TRB_SIZE, RING_ALIGN)?;
        let ring_phys = mem.phys()?;
        let mut ring = Self { mem, enqueue: 0, cycle: 1 };
        // Pre-place the link TRB with the initial cycle bit.
        ring.write_trb(COMMAND_RING_SIZE - 1, Trb::link(ring_phys, 1));
        Some(ring)
    }

    fn phys(&self) -> u64 { self.mem.phys().unwrap_or(0) }

    fn write_trb(&mut self, idx: usize, trb: Trb) {
        debug_assert!(idx < COMMAND_RING_SIZE);
        unsafe {
            let p = self.mem.virt().add(idx * TRB_SIZE) as *mut Trb;
            p.write_volatile(trb);
        }
    }

    fn push(&mut self, mut trb: Trb) {
        // Stamp the producer cycle bit on the TRB being published.
        trb.control = (trb.control & !1) | self.cycle as u32;
        self.write_trb(self.enqueue as usize, trb);
        compiler_fence(Ordering::SeqCst);

        self.enqueue += 1;
        if self.enqueue as usize >= COMMAND_RING_SIZE - 1 {
            // Update the link TRB with the current cycle before toggling
            // so hardware sees a matching cycle at the end of this
            // generation.
            let ring_phys = self.mem.phys().unwrap_or(0);
            self.write_trb(COMMAND_RING_SIZE - 1, Trb::link(ring_phys, self.cycle));
            compiler_fence(Ordering::SeqCst);
            self.enqueue = 0;
            self.cycle ^= 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Event ring (linear ring, wraps via cycle bit)
// ---------------------------------------------------------------------------

struct EventRing {
    mem:      Dma,
    dequeue:  u32,
    cycle:    u8,
    size:     u32,
}

impl EventRing {
    fn new() -> Option<Self> {
        let mem = Dma::new(EVENT_RING_SIZE * TRB_SIZE, RING_ALIGN)?;
        Some(Self { mem, dequeue: 0, cycle: 1, size: EVENT_RING_SIZE as u32 })
    }

    fn phys(&self) -> Option<u64> { self.mem.phys() }

    fn size(&self) -> u32 { self.size }

    fn pop(&mut self) -> Option<Trb> {
        let idx = self.dequeue as usize;
        let trb = unsafe {
            (self.mem.virt().add(idx * TRB_SIZE) as *const Trb).read_volatile()
        };
        compiler_fence(Ordering::SeqCst);
        if trb.cycle() != self.cycle {
            return None;
        }
        self.dequeue += 1;
        if self.dequeue >= self.size {
            self.dequeue = 0;
            self.cycle ^= 1;
        }
        Some(trb)
    }

    /// Publish the current dequeue index to ERDP, clearing EHB.
    fn advance_erdp(&self, rt_base: u64) {
        let Some(phys) = self.mem.phys() else { return; };
        let val = phys + (self.dequeue as u64 * TRB_SIZE as u64);
        let erdp = rt_base + 0x20 + IR_ERDP;
        unsafe { ((erdp) as *mut u64).write_volatile(val); }
    }
}

// ---------------------------------------------------------------------------
// ERST entry
// ---------------------------------------------------------------------------

#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct ErstEntry {
    base:  u64,
    size:  u32,
    _rsvd: u32,
}

// ---------------------------------------------------------------------------
// Controller
// ---------------------------------------------------------------------------

pub struct XhciController {
    base:    u64,
    op_base: u64,
    db_base: u64,
    rt_base: u64,

    max_slots: u32,
    max_ports: u32,

    cmd_ring: CommandRing,
    evt_ring: EventRing,

    /// DCBAAP target; must outlive the controller.
    _dcba: Dma,
    /// ERST target; must outlive the controller.
    _erst: Dma,

    /// Ports that a future enumeration layer should probe for HID
    /// keyboards. Empty until enumeration is implemented.
    pub candidate_keyboard_ports: Vec<u8>,
}

impl XhciController {
    // ----- MMIO helpers --------------------------------------------------

    #[inline]
    unsafe fn rd32(&self, off: u64) -> u32 {
        ((self.base + off) as *const u32).read_volatile()
    }
    #[inline]
    unsafe fn wr32(&self, off: u64, v: u32) {
        ((self.base + off) as *mut u32).write_volatile(v);
    }
    #[inline]
    unsafe fn rd64(&self, off: u64) -> u64 {
        ((self.base + off) as *const u64).read_volatile()
    }
    #[inline]
    unsafe fn wr64(&self, off: u64, v: u64) {
        ((self.base + off) as *mut u64).write_volatile(v);
    }

    #[inline]
    unsafe fn op_rd32(&self, off: u64) -> u32 {
        ((self.op_base + off) as *const u32).read_volatile()
    }
    #[inline]
    unsafe fn op_wr32(&self, off: u64, v: u32) {
        ((self.op_base + off) as *mut u32).write_volatile(v);
    }
    #[inline]
    unsafe fn op_wr64(&self, off: u64, v: u64) {
        ((self.op_base + off) as *mut u64).write_volatile(v);
    }

    #[inline]
    unsafe fn rt_rd32(&self, off: u64) -> u32 {
        ((self.rt_base + off) as *const u32).read_volatile()
    }
    #[inline]
    unsafe fn rt_wr32(&self, off: u64, v: u32) {
        ((self.rt_base + off) as *mut u32).write_volatile(v);
    }
    #[inline]
    unsafe fn rt_wr64(&self, off: u64, v: u64) {
        ((self.rt_base + off) as *mut u64).write_volatile(v);
    }

    // ----- Init ----------------------------------------------------------

    /// Full controller bring-up. Returns `true` on success.
    ///
    /// Per xHCI 1.2 §4.2: wait CNR=0 → clear RUN → wait HCH=1 → HCRST
    /// → wait HCRST=0 / CNR=0 / HCH=1 → program DCBAAP, CRCR, CONFIG
    /// → enable interrupter → set RUN.
    pub fn init(&mut self) -> bool {
        unsafe {
            // 1. Wait for CNR = 0.
            if !wait_bit(self, OP_USBSTS, USBSTS_CNR, false, CNR_TIMEOUT_MS) {
                log("controller not ready (CNR stuck)");
                return false;
            }

            // 2. Clear RUN; wait for HCH = 1.
            let cmd = self.op_rd32(OP_USBCMD);
            self.op_wr32(OP_USBCMD, cmd & !USBCMD_RUN);
            if !wait_bit(self, OP_USBSTS, USBSTS_HCH, true, HC_HALT_TIMEOUT_MS) {
                log("controller did not halt");
                return false;
            }

            // 3. HCRST; wait for it to clear.
            self.op_wr32(OP_USBCMD, USBCMD_HCRST);
            if !wait_bit(self, OP_USBCMD, USBCMD_HCRST, false, HC_RESET_TIMEOUT_MS) {
                log("controller reset timed out");
                return false;
            }

            // 4. Verify halted + CNR cleared.
            if !wait_bit(self, OP_USBSTS, USBSTS_CNR, false, CNR_TIMEOUT_MS) {
                log("CNR still set after reset");
                return false;
            }
            if self.op_rd32(OP_USBSTS) & USBSTS_HCH == 0 {
                log("controller not halted after reset");
                return false;
            }

            // 5. Page size: we support only 4 KiB, which is bit 0.
            self.op_wr32(OP_PAGESIZE, 1);

            // 6. DCBAAP: array of (max_slots+1) u64 pointers.
            let Some(dcba_phys) = self._dcba.phys() else {
                log("DCBAAP has no physical address");
                return false;
            };
            self.op_wr64(OP_DCBAAP, dcba_phys);

            // 7. CRCR: command ring base, RCS = 1 (initial producer cycle).
            let cmd_phys = self.cmd_ring.phys();
            if cmd_phys == 0 {
                log("command ring has no physical address");
                return false;
            }
            self.op_wr64(OP_CRCR, cmd_phys | 1);

            // 8. Event ring: ERSTSZ → ERSTBA → ERDP (spec order).
            if !self.program_event_ring() {
                log("event ring programming failed");
                return false;
            }

            // 9. Interrupter 0: enable.
            let iman = self.rt_rd32(0x20 + IR_IMAN);
            self.rt_wr32(0x20 + IR_IMAN, iman | IMAN_IE);

            // 10. MaxSlotsEn.
            self.op_wr32(OP_CONFIG, self.max_slots);

            // 11. Clear stale port-change bits before running.
            self.clear_port_change_bits();

            // 12. RUN + INTE; wait for HCH = 0.
            self.op_wr32(OP_USBCMD, USBCMD_RUN | USBCMD_INTE);
            if !wait_bit(self, OP_USBSTS, USBSTS_HCH, false, HC_HALT_TIMEOUT_MS) {
                log("controller did not start");
                return false;
            }
        }

        crate::serial_println!(
            "  [XHCI] running: {} slots, {} ports", self.max_slots, self.max_ports
        );

        self.probe_ports();
        true
    }

    unsafe fn program_event_ring(&mut self) -> bool {
        let Some(evt_phys) = self.evt_ring.phys() else { return false; };
        let Some(erst_phys) = self._erst.phys() else { return false; };

        // Write ERST[0].
        let entry = self._erst.virt() as *mut ErstEntry;
        entry.write_volatile(ErstEntry {
            base: evt_phys,
            size: self.evt_ring.size(),
            _rsvd: 0,
        });
        compiler_fence(Ordering::SeqCst);

        // Order matters: ERSTSZ → ERSTBA → ERDP.
        self.rt_wr32(0x20 + IR_ERSTSZ, 1);
        compiler_fence(Ordering::SeqCst);
        self.rt_wr64(0x20 + IR_ERSTBA, erst_phys);
        compiler_fence(Ordering::SeqCst);
        self.rt_wr64(0x20 + IR_ERDP, evt_phys);
        true
    }

    unsafe fn clear_port_change_bits(&self) {
        for port in 0..self.max_ports {
            let off = self.op_base + PORT_REG_BASE_OFF + port as u64 * PORT_REG_STRIDE;
            let ps = (off as *const u32).read_volatile();
            (off as *mut u32).write_volatile(ps | PORTSC_CHANGE_BITS);
        }
    }

    // ----- Port probe ----------------------------------------------------

    fn probe_ports(&mut self) {
        for port in 0..self.max_ports {
            let off = self.op_base + PORT_REG_BASE_OFF + port as u64 * PORT_REG_STRIDE;

            unsafe {
                // 1. Enable port power (no-op on USB 3.0).
                let ps = (off as *const u32).read_volatile();
                if ps & PORTSC_PP == 0 {
                    (off as *mut u32).write_volatile(ps | PORTSC_PP);
                    crate::arch::x86_64::timer::precise_sleep_ms(20);
                }

                // 2. Clear stale change bits.
                let ps = (off as *const u32).read_volatile();
                (off as *mut u32).write_volatile(ps | PORTSC_CHANGE_BITS);

                // 3. Connection?
                let ps = (off as *const u32).read_volatile();
                if ps & PORTSC_CCS == 0 {
                    continue;
                }

                let speed = (ps >> 10) & 0xF;
                crate::serial_println!(
                    "  [XHCI] port {} connected ({})",
                    port, speed_label(speed),
                );

                // 4. Reset. USB 3.0 uses WPR / WRC; USB 2.0 uses PR / PRC.
                let is_usb3 = speed == 4 || speed == 5;
                let (reset_bit, done_bit) = if is_usb3 {
                    (PORTSC_WPR, PORTSC_WRC)
                } else {
                    (PORTSC_PR, PORTSC_PRC)
                };

                let ps = (off as *const u32).read_volatile();
                (off as *mut u32).write_volatile(ps | reset_bit);

                // 5. Poll for reset completion.
                let deadline = now_ms() + PORT_RESET_TIMEOUT_MS;
                let mut reset_done = false;
                while now_ms() < deadline {
                    let ps = (off as *const u32).read_volatile();
                    if ps & done_bit != 0 {
                        // Clear the change bit (W1C).
                        (off as *mut u32).write_volatile(ps | done_bit);
                        reset_done = true;
                        break;
                    }
                    core::hint::spin_loop();
                }

                if !reset_done {
                    crate::serial_println!("  [XHCI] port {} reset timeout", port);
                    continue;
                }

                // 6. Enabled?
                let ps = (off as *const u32).read_volatile();
                if ps & PORTSC_PED == 0 {
                    crate::serial_println!(
                        "  [XHCI] port {} enabled but not PED (PORTSC=0x{:08x})",
                        port, ps,
                    );
                    continue;
                }

                // 7. Enumeration would happen here. It is not implemented;
                // record the port so a future layer can pick it up.
                self.candidate_keyboard_ports.push(port as u8);
                crate::serial_println!(
                    "  [XHCI] port {} enabled — enumeration unimplemented",
                    port,
                );
            }
        }
    }

    // ----- Event processing ----------------------------------------------

    /// Process all ready events. Returns the number consumed.
    ///
    /// Safe to call from both the IRQ handler and the polling loop.
    pub fn poll_events(&mut self) -> usize {
        let mut count = 0;
        while let Some(trb) = self.evt_ring.pop() {
            let trb_type = trb.trb_type();
            let code = trb.completion_code();
            match trb_type {
                TRB_TYPE_TRANSFER_EVENT => {
                    if code != COMPLETION_SUCCESS {
                        log_completion("Transfer", code);
                    }
                }
                TRB_TYPE_CMD_COMPLETION => {
                    if code != COMPLETION_SUCCESS {
                        log_completion("Command", code);
                    }
                }
                TRB_TYPE_PORT_STATUS_CHG => {
                    // Port status changed; re-scan ports.
                    self.probe_ports();
                }
                TRB_TYPE_HOST_CONTROLLER => {
                    if code != COMPLETION_SUCCESS {
                        log_completion("Host", code);
                    }
                }
                _ => {}
            }
            count += 1;
        }
        if count > 0 {
            self.evt_ring.advance_erdp(self.rt_base);
        }
        count
    }

    // ----- Command submission --------------------------------------------

    /// Push a TRB to the command ring and ring the host-controller
    /// doorbell. The caller is responsible for waiting on the matching
    /// command-completion event.
    pub fn submit_command(&mut self, trb: Trb) {
        self.cmd_ring.push(trb);
        compiler_fence(Ordering::SeqCst);
        let db = self.db_base;
        unsafe { ((db) as *mut u32).write_volatile(0); }
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

unsafe fn wait_bit(
    ctrl: &XhciController,
    reg: u64,
    bit: u32,
    expect_set: bool,
    timeout_ms: u64,
) -> bool {
    let deadline = now_ms() + timeout_ms;
    loop {
        let v = ctrl.op_rd32(reg);
        let is_set = v & bit != 0;
        if is_set == expect_set {
            return true;
        }
        if now_ms() > deadline {
            return false;
        }
        core::hint::spin_loop();
    }
}

fn now_ms() -> u64 {
    crate::arch::x86_64::timer::uptime_ms()
}

fn log(msg: &str) {
    crate::serial_println!("  [XHCI] {}", msg);
}

fn log_completion(kind: &str, code: u8) {
    crate::serial_println!("  [XHCI] {} completion code={}", kind, code);
}

fn speed_label(speed: u32) -> &'static str {
    match speed {
        1 => "Full-Speed (12 Mbps)",
        2 => "Low-Speed (1.5 Mbps)",
        3 => "High-Speed (480 Mbps)",
        4 => "SuperSpeed (5 Gbps)",
        5 => "SuperSpeed+ (10 Gbps)",
        _ => "off / unknown",
    }
}

// ---------------------------------------------------------------------------
// HID keyboard
// ---------------------------------------------------------------------------

/// Unshifted HID Usage → ASCII.
///
/// Covers 0x04..0x38 (letters, digits, punctuation, Enter, Escape,
/// Backspace, Tab, Space). Higher usages (arrows, F-keys, keypad) are
/// non-printable and map to 0.
static HID_UNSHIFTED: [u8; 0x39] = {
    let mut t = [0u8; 0x39];
    // a..z
    let letters: &[u8; 26] = b"abcdefghijklmnopqrstuvwxyz";
    let mut i = 0;
    while i < 26 {
        t[0x04 + i] = letters[i];
        i += 1;
    }
    // 1..0
    let digits: &[u8; 10] = b"1234567890";
    let mut j = 0;
    while j < 10 {
        t[0x1E + j] = digits[j];
        j += 1;
    }
    t[0x28] = b'\n';       // Enter
    t[0x29] = 0x1B;        // Escape
    t[0x2A] = 0x08;        // Backspace
    t[0x2B] = b'\t';       // Tab
    t[0x2C] = b' ';        // Space
    t[0x2D] = b'-';
    t[0x2E] = b'=';
    t[0x2F] = b'[';
    t[0x30] = b']';
    t[0x31] = b'\\';
    t[0x32] = b'#';        // Non-US # (US layout: #)
    t[0x33] = b';';
    t[0x34] = b'\'';
    t[0x35] = b'`';
    t[0x36] = b',';
    t[0x37] = b'.';
    t[0x38] = b'/';
    t
};

/// Shifted HID Usage → ASCII. Same indices as [`HID_UNSHIFTED`]; zero
/// means "no shifted character" (fall back to unshifted).
static HID_SHIFTED: [u8; 0x39] = {
    let mut t = [0u8; 0x39];
    // A..Z
    let letters: &[u8; 26] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut i = 0;
    while i < 26 {
        t[0x04 + i] = letters[i];
        i += 1;
    }
    // !..)
    let shifted_digits: &[u8; 10] = b"!@#$%^&*()";
    let mut j = 0;
    while j < 10 {
        t[0x1E + j] = shifted_digits[j];
        j += 1;
    }
    t[0x2D] = b'_';
    t[0x2E] = b'+';
    t[0x2F] = b'{';
    t[0x30] = b'}';
    t[0x31] = b'|';
    t[0x32] = b'~';
    t[0x33] = b':';
    t[0x34] = b'"';
    t[0x35] = b'~';        // Shift+` → ~ on US layout
    t[0x36] = b'<';
    t[0x37] = b'>';
    t[0x38] = b'?';
    t
};

/// Map a HID usage to ASCII ignoring Shift. Kept for backward
/// compatibility with the original API.
#[must_use]
pub fn hid_to_ascii(usage: u8) -> Option<u8> {
    hid_to_ascii_with_shift(usage, false)
}

/// Map a HID usage to ASCII, honouring Shift.
#[must_use]
pub fn hid_to_ascii_with_shift(usage: u8, shift: bool) -> Option<u8> {
    let idx = usage as usize;
    if idx >= HID_UNSHIFTED.len() {
        return None;
    }
    let base = HID_UNSHIFTED[idx];
    if base == 0 {
        return None;
    }
    if shift {
        let s = HID_SHIFTED[idx];
        if s != 0 { return Some(s); }
    }
    Some(base)
}

/// HID boot-keyboard modifier bits (report byte 0).
pub const HID_MOD_LCTRL:  u8 = 1 << 0;
pub const HID_MOD_LSHIFT: u8 = 1 << 1;
pub const HID_MOD_LALT:   u8 = 1 << 2;
pub const HID_MOD_LGUI:   u8 = 1 << 3;
pub const HID_MOD_RCTRL:  u8 = 1 << 4;
pub const HID_MOD_RSHIFT: u8 = 1 << 5;
pub const HID_MOD_RALT:   u8 = 1 << 6;
pub const HID_MOD_RGUI:   u8 = 1 << 7;

pub const HID_MOD_ANY_SHIFT: u8 = HID_MOD_LSHIFT | HID_MOD_RSHIFT;
pub const HID_MOD_ANY_CTRL:  u8 = HID_MOD_LCTRL  | HID_MOD_RCTRL;

/// State machine for a HID boot-protocol keyboard.
///
/// Feed each 8-byte report to [`HidKeyboard::process`]; it returns the
/// ASCII bytes for keys newly pressed in that report, with Shift and
/// CapsLock applied. Ctrl+letter produces the standard ASCII control
/// codes (Ctrl+A = 0x01 … Ctrl+Z = 0x1A).
pub struct HidKeyboard {
    prev_keys: [u8; 6],
    caps:      bool,
}

impl HidKeyboard {
    pub const fn new() -> Self {
        Self { prev_keys: [0; 6], caps: false }
    }

    /// Process one 8-byte boot report: `[modifiers, reserved, key0..key5]`.
    pub fn process(&mut self, report: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        if report.len() < 8 {
            return out;
        }
        let mods    = report[0];
        let shift   = mods & HID_MOD_ANY_SHIFT != 0;
        let ctrl    = mods & HID_MOD_ANY_CTRL  != 0;

        for i in 2..8 {
            let usage = report[i];
            if usage == 0 { continue; }
            // Skip if it was already pressed in the previous report.
            if self.prev_keys.iter().any(|&k| k == usage) { continue; }

            // CapsLock toggle: usage 0x39.
            if usage == 0x39 {
                self.caps = !self.caps;
                continue;
            }

            if let Some(byte) = hid_to_ascii_with_shift(usage, shift) {
                // Letters: Shift XOR CapsLock determines case.
                let letter = byte.is_ascii_alphabetic();
                let byte = if letter && self.caps {
                    if byte.is_ascii_lowercase() { byte.to_ascii_uppercase() }
                    else { byte.to_ascii_lowercase() }
                } else {
                    byte
                };
                // Ctrl+letter → control code.
                let byte = if ctrl && byte.is_ascii_alphabetic() {
                    byte.to_ascii_lowercase() - b'a' + 1
                } else {
                    byte
                };
                out.push(byte);
            }
        }

        self.prev_keys.copy_from_slice(&report[2..8]);
        out
    }
}

// ---------------------------------------------------------------------------
// Global instance
// ---------------------------------------------------------------------------

static XHCI: Mutex<Option<XhciController>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// Init entry point
// ---------------------------------------------------------------------------

/// Attempt to bring up the XHCI controller from a PCI device.
pub fn try_init(dev: &PciDevice) -> bool {
    // XHCI is class 0x0C (serial bus), subclass 0x03 (USB), prog_if 0x30.
    if dev.class != 0x0C || dev.subclass != 0x03 || dev.prog_if != 0x30 {
        return false;
    }

    // BAR0 must be a 64-bit MMIO BAR (type bits [2:1] = 10).
    if dev.bar[0] & 0x1 != 0 {
        return false;
    }
    if (dev.bar[0] & 0x6) != 0x4 {
        return false;
    }

    let bar_lo = (dev.bar[0] & !0xF) as u64;
    let bar_hi = (dev.bar[1] as u64) << 32;
    let bar_phys = bar_hi | bar_lo;
    if bar_phys == 0 {
        return false;
    }

    let Some(base) = (bar_phys as usize).checked_add(PHYS_OFFSET).map(|a| a as u64) else {
        return false;
    };

    if XHCI.lock().is_some() {
        return false;
    }

    crate::pci::enable_device(dev.addr.bus, dev.addr.device, dev.addr.function);

    // Read capability registers.
    let cap_len = unsafe { (base as *const u8).read_volatile() } as u64;
    let op_base = base + cap_len;

    let hcs1 = unsafe { ((base + CAP_HCSPARAMS1) as *const u32).read_volatile() };
    let max_slots = hcs1 & 0xFF;
    let max_ports = (hcs1 >> 24) & 0xFF;

    let db_off = (unsafe { ((base + CAP_DBOFF) as *const u32).read_volatile() }) as u64 & !3;
    let rt_off = (unsafe { ((base + CAP_RTSOFF) as *const u32).read_volatile() }) as u64 & !31;

    crate::serial_println!(
        "  [XHCI] BAR=0x{:x}, slots={}, ports={}", bar_phys, max_slots, max_ports
    );

    let (Some(cmd_ring), Some(evt_ring), Some(dcba), Some(erst)) = (
        CommandRing::new(),
        EventRing::new(),
        Dma::new((max_slots as usize + 1) * 8, RING_ALIGN),
        Dma::new(core::mem::size_of::<ErstEntry>(), RING_ALIGN),
    ) else {
        log("DMA allocation failed");
        return false;
    };

    let mut ctrl = XhciController {
        base,
        op_base,
        db_base: base + db_off,
        rt_base: base + rt_off,
        max_slots,
        max_ports,
        cmd_ring,
        evt_ring,
        _dcba: dcba,
        _erst: erst,
        candidate_keyboard_ports: Vec::new(),
    };

    if !ctrl.init() {
        return false;
    }

    let candidates = ctrl.candidate_keyboard_ports.len();
    *XHCI.lock() = Some(ctrl);
    crate::serial_println!(
        "  [XHCI] ready ({} ports enumerated, {} candidates)",
        max_ports, candidates,
    );
    true
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Returns `true` if an XHCI controller is installed.
pub fn is_present() -> bool {
    XHCI.lock().is_some()
}

/// Poll the event ring. Intended to be called from an IRQ or a
/// periodic polling loop.
pub fn poll() {
    if let Some(ctrl) = XHCI.lock().as_mut() {
        ctrl.poll_events();
    }
}

/// Submit an Enable Slot command. Provided as a primitive for a future
/// enumeration layer. **This function does not complete the command** —
/// the caller must wait on the command-completion event with the
/// matching slot-type / command slot ID.
pub fn submit_enable_slot() -> bool {
    let Some(ctrl) = XHCI.lock().as_mut() else { return false; };
    ctrl.submit_command(Trb::enable_slot());
    true
}

/// Return the ports that have a USB device attached and enabled.
///
/// Because enumeration is not implemented, this is the best the driver
/// can report today: "something is plugged in, but we can't yet talk to
/// it." A future commit will replace this with a list of HID devices.
pub fn enabled_ports() -> Vec<u8> {
    XHCI.lock()
        .as_ref()
        .map(|c| c.candidate_keyboard_ports.clone())
        .unwrap_or_default()
}

/// **Stub.** The original driver logged a message; the fix is honest
/// about the fact that HID endpoint polling is not implemented. If you
/// need a working mouse on a system with XHCI only, use the PS/2
/// emulation path (or a system whose firmware exposes a PS/2 mouse)
/// until this layer is completed.
pub fn poll_mouse_hid() {
    // No USB mouse support; nothing to do.
}

/// **Stub.** Forwarded to the PS/2-layer HID report parser, which
/// remains the canonical decoder. A future XHCI enumeration
/// implementation will feed real HID reports here.
pub fn handle_mouse_report(report: &[u8]) {
    crate::drivers::mouse::handle_hid_report(report);
}

// Silence unused-import lint for the constant used only in the doc.
#[allow(dead_code)]
const _PLS_SHIFT_DOC: u32 = PORTSC_PLS_SHIFT;
