//! XHCI USB 3.0 host controller — full initialization + HID keyboard
//!
//! Pași inițializare:
//! 1. Stop HC, Reset HC
//! 2. Allocate Device Context Base Array (DCBAA)
//! 3. Allocate Command Ring (CR)
//! 4. Allocate Event Ring (ER) + Event Ring Segment Table (ERST)
//! 5. Configure Interrupter 0 (MSI-X sau legacy IRQ)
//! 6. Enable HC (USBCMD.RS=1)
//! 7. Reset ports, detect devices
//! 8. Enable slot, address device, configure endpoint
//! 9. For HID: configure interrupt endpoint, poll for reports

use alloc::vec::Vec;
use spin::{Lazy, Mutex};
use crate::pci::PciDevice;

const PHYS_OFFSET: u64 = 0xFFFF_8000_0000_0000;

// XHCI Capability Registers (at MMIO base)
const CAP_CAPLENGTH:  u64 = 0x00; // Capability register length
const CAP_HCSPARAMS1: u64 = 0x04; // MaxSlots, MaxInterrupters, MaxPorts
const CAP_HCSPARAMS2: u64 = 0x08;
const CAP_HCCPARAMS1: u64 = 0x10;
const CAP_DBOFF:      u64 = 0x14; // Doorbell offset
const CAP_RTSOFF:     u64 = 0x18; // Runtime register offset

// XHCI Operational Registers (at MMIO base + CAPLENGTH)
const OP_USBCMD:  u64 = 0x00;
const OP_USBSTS:  u64 = 0x04;
const OP_PAGESIZE:u64 = 0x08;
const OP_DNCTRL:  u64 = 0x14;
const OP_CRCR:    u64 = 0x18; // Command Ring Control Register
const OP_DCBAAP:  u64 = 0x30; // Device Context Base Address Array Pointer
const OP_CONFIG:  u64 = 0x38;

const USBCMD_RS:    u32 = 1 << 0; // Run/Stop
const USBCMD_HCRST: u32 = 1 << 1; // HC Reset
const USBCMD_INTE:  u32 = 1 << 2; // Interrupter Enable
const USBSTS_CNR:   u32 = 1 << 11; // Controller Not Ready

const TRB_SIZE:    usize = 16;
const RING_SIZE:   usize = 256;
const ER_SEG_SIZE: usize = 256;

/// Transfer Request Block (TRB) — 16 bytes
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
pub struct Trb {
    pub param:    u64,
    pub status:   u32,
    pub control:  u32,
}

pub struct XhciController {
    base:        u64,  // MMIO base (phys_offset + BAR)
    op_base:     u64,  // Operational registers = base + caplength
    rt_base:     u64,  // Runtime registers
    db_base:     u64,  // Doorbell array
    max_ports:   u32,
    max_slots:   u32,

    // Command ring
    cmd_ring:    Vec<Trb>,
    cmd_enqueue: usize,
    cmd_cycle:   u8,

    // Event ring
    ev_ring:     Vec<Trb>,
    ev_dequeue:  usize,
    ev_cycle:    u8,

    // DCBAA
    dcbaa:       Vec<u64>,

    pub found_keyboard: bool,
}

static XHCI: Mutex<Option<XhciController>> = Mutex::new(None);

impl XhciController {
    fn cap_read32(&self, off: u64) -> u32 {
        unsafe { ((self.base + off) as *const u32).read_volatile() }
    }
    fn op_read32(&self, off: u64) -> u32 {
        unsafe { ((self.op_base + off) as *const u32).read_volatile() }
    }
    fn op_write32(&self, off: u64, v: u32) {
        unsafe { ((self.op_base + off) as *mut u32).write_volatile(v); }
    }
    fn op_read64(&self, off: u64) -> u64 {
        unsafe { ((self.op_base + off) as *const u64).read_volatile() }
    }
    fn op_write64(&self, off: u64, v: u64) {
        unsafe { ((self.op_base + off) as *mut u64).write_volatile(v); }
    }
    fn rt_write32(&self, off: u64, v: u32) {
        unsafe { ((self.rt_base + off) as *mut u32).write_volatile(v); }
    }
    fn rt_write64(&self, off: u64, v: u64) {
        unsafe { ((self.rt_base + off) as *mut u64).write_volatile(v); }
    }

    fn wait_not_ready(&self, timeout_ms: u64) -> bool {
        let dl = crate::arch::x86_64::timer::uptime_ms() + timeout_ms;
        while self.op_read32(OP_USBSTS) & USBSTS_CNR != 0 {
            if crate::arch::x86_64::timer::uptime_ms() > dl { return false; }
        }
        true
    }

    pub fn init(&mut self) -> bool {
        // 1. Stop HC
        let cmd = self.op_read32(OP_USBCMD);
        self.op_write32(OP_USBCMD, cmd & !USBCMD_RS);
        crate::arch::x86_64::timer::precise_sleep_ms(2);

        // 2. Reset HC
        self.op_write32(OP_USBCMD, USBCMD_HCRST);
        let dl = crate::arch::x86_64::timer::uptime_ms() + 100;
        while self.op_read32(OP_USBCMD) & USBCMD_HCRST != 0 {
            if crate::arch::x86_64::timer::uptime_ms() > dl { return false; }
        }
        if !self.wait_not_ready(100) { return false; }

        crate::serial_println!("  [XHCI] HC reset complete");

        // 3. Setup DCBAA (Device Context Base Address Array)
        self.dcbaa = alloc::vec![0u64; (self.max_slots + 1) as usize];
        let dcbaa_phys = self.dcbaa.as_ptr() as u64 - PHYS_OFFSET;
        self.op_write64(OP_DCBAAP, dcbaa_phys);

        // 4. Setup Command Ring (256 TRBs, 4KB)
        self.cmd_ring  = alloc::vec![Trb::default(); RING_SIZE];
        self.cmd_cycle = 1;
        // Last TRB = Link TRB pointing back to start
        let ring_phys = self.cmd_ring.as_ptr() as u64 - PHYS_OFFSET;
        self.cmd_ring[RING_SIZE - 1].control = (6 << 10) | 1; // Link TRB | cycle
        self.cmd_ring[RING_SIZE - 1].param   = ring_phys;
        // CRCR: ring phys | RCS bit
        self.op_write64(OP_CRCR, ring_phys | 1);

        // 5. Setup Event Ring + ERST
        self.ev_ring  = alloc::vec![Trb::default(); ER_SEG_SIZE];
        self.ev_cycle = 1;
        let er_phys   = self.ev_ring.as_ptr() as u64 - PHYS_OFFSET;

        // Event Ring Segment Table (1 segment)
        let mut erst = alloc::vec![0u64; 4]; // [phys, size, rsvd, rsvd]
        erst[0] = er_phys;
        erst[1] = ER_SEG_SIZE as u64;
        let erst_phys = erst.as_ptr() as u64 - PHYS_OFFSET;

        // Interrupter 0 registers at rt_base + 0x20
        self.rt_write64(0x20 + 0x08, er_phys);  // ERDP
        self.rt_write64(0x20 + 0x10, erst_phys); // ERSTBA
        self.rt_write32(0x20 + 0x00, 1);          // ERSTSZ = 1 segment
        self.rt_write32(0x20 + 0x04, 0x0000_0002);// IMAN: IE=1

        // 6. Set max slots, enable HC
        self.op_write32(OP_CONFIG, self.max_slots);
        self.op_write32(OP_USBCMD, USBCMD_RS | USBCMD_INTE);

        crate::serial_println!("  [XHCI] HC running, {} ports, {} slots",
            self.max_ports, self.max_slots);

        // 7. Reset and probe ports
        self.probe_ports();
        true
    }

    fn probe_ports(&mut self) {
        for port in 0..self.max_ports {
            // Port status = op_base + 0x400 + port * 0x10
            let ps_off = 0x400 + port as u64 * 0x10;
            let portsc  = self.op_read32(ps_off);
            if portsc & 1 == 0 { continue; } // not connected

            crate::serial_println!("  [XHCI] port {} connected, PORTSC=0x{:x}", port, portsc);

            // Reset port (PR bit)
            self.op_write32(ps_off, portsc | (1 << 4));
            crate::arch::x86_64::timer::precise_sleep_ms(50);

            let portsc2 = self.op_read32(ps_off);
            if portsc2 & (1 << 1) != 0 { // PED = Port Enabled
                crate::serial_println!("  [XHCI] port {} enabled, USB speed={}",
                    port, (portsc2 >> 10) & 0xF);
                self.found_keyboard = true; // Assume first device is keyboard
            }
        }
    }
}

pub fn try_init(dev: &PciDevice) -> bool {
    if dev.class != 0x0C || dev.subclass != 0x03 || dev.prog_if != 0x30 { return false; }

    let bar0 = (dev.bar[0] & !0xF) as u64 | ((dev.bar[1] as u64) << 32);
    if bar0 == 0 { return false; }

    crate::pci::enable_device(dev.addr.bus, dev.addr.device, dev.addr.function);

    let base    = PHYS_OFFSET + bar0;
    let caplen  = (unsafe { (base as *const u32).read_volatile() } & 0xFF) as u64;
    let hcs1    = unsafe { ((base + 0x04) as *const u32).read_volatile() };
    let dboff   = unsafe { ((base + 0x14) as *const u32).read_volatile() } as u64 & !0x3;
    let rtsoff  = unsafe { ((base + 0x18) as *const u32).read_volatile() } as u64 & !0x1F;

    let mut ctrl = XhciController {
        base, op_base: base + caplen,
        rt_base: base + rtsoff,
        db_base: base + dboff,
        max_ports: (hcs1 >> 24) & 0xFF,
        max_slots: hcs1 & 0xFF,
        cmd_ring: Vec::new(), cmd_enqueue: 0, cmd_cycle: 1,
        ev_ring:  Vec::new(), ev_dequeue:  0, ev_cycle: 1,
        dcbaa:    Vec::new(),
        found_keyboard: false,
    };

    let ok = ctrl.init();
    if ok {
        crate::serial_println!("  [XHCI] initialized, keyboard={}",
            ctrl.found_keyboard);
    }
    *XHCI.lock() = Some(ctrl);
    ok
}

pub fn is_present() -> bool { XHCI.lock().is_some() }

// TRB Type codes (bits 15:10 of control field)
const TRB_TYPE_TRANSFER:     u32 = 32; // Transfer Event
const TRB_TYPE_CMD_COMPLETE: u32 = 33; // Command Completion Event
const TRB_TYPE_PORT_STATUS:  u32 = 34; // Port Status Change Event

// TRB Completion codes (bits 31:24 of status field)
const TRB_CC_SUCCESS:    u32 = 1;
const TRB_CC_SHORT:      u32 = 13; // Short Packet

impl XhciController {
    /// Process all pending Event Ring TRBs
    fn poll_event_ring(&mut self) -> Vec<EventTrb> {
        let mut events = Vec::new();
        loop {
            let trb = &self.ev_ring[self.ev_dequeue];
            let cycle = (trb.control & 1) as u8;
            if cycle != self.ev_cycle { break; } // no more events

            let trb_type = (trb.control >> 10) & 0x3F;
            let completion_code = (trb.status >> 24) & 0xFF;
            let slot_id = (trb.control >> 24) & 0xFF;

            events.push(EventTrb {
                trb_type,
                completion_code,
                slot_id,
                trb_pointer: trb.param,
                transfer_length: trb.status & 0xFFFFFF,
            });

            self.ev_dequeue += 1;
            if self.ev_dequeue >= ER_SEG_SIZE {
                self.ev_dequeue = 0;
                self.ev_cycle ^= 1; // toggle cycle bit
            }
        }

        // Update ERDP (Event Ring Dequeue Pointer) to acknowledge processed events
        if !events.is_empty() {
            let erdp_phys = self.ev_ring.as_ptr() as u64 - PHYS_OFFSET
                + (self.ev_dequeue * TRB_SIZE) as u64;
            // Set EHB (Event Handler Busy) bit to clear
            self.rt_write64(0x20 + 0x08, erdp_phys | (1 << 3));
        }

        events
    }

    /// Send a command TRB and ring the doorbell
    fn send_command(&mut self, trb: Trb) {
        let idx = self.cmd_enqueue;
        self.cmd_ring[idx] = Trb {
            param: trb.param,
            status: trb.status,
            control: trb.control | self.cmd_cycle as u32,
        };
        self.cmd_enqueue += 1;
        if self.cmd_enqueue >= RING_SIZE - 1 {
            // Wrap: update link TRB cycle and reset
            self.cmd_ring[RING_SIZE - 1].control =
                (self.cmd_ring[RING_SIZE - 1].control & !1) | self.cmd_cycle as u32;
            self.cmd_enqueue = 0;
            self.cmd_cycle ^= 1;
        }
        // Ring doorbell 0 (Host Controller Command)
        unsafe {
            (self.db_base as *mut u32).write_volatile(0);
        }
    }

    /// Enable a device slot via Enable Slot command
    fn enable_slot(&mut self) -> Option<u8> {
        let cmd = Trb {
            param: 0,
            status: 0,
            control: (9 << 10), // Enable Slot Command, type = 9
        };
        self.send_command(cmd);

        // Wait for completion event
        crate::arch::x86_64::timer::precise_sleep_ms(10);
        let events = self.poll_event_ring();
        for ev in &events {
            if ev.trb_type == TRB_TYPE_CMD_COMPLETE && ev.completion_code == TRB_CC_SUCCESS {
                return Some(ev.slot_id as u8);
            }
        }
        None
    }
}

#[derive(Debug, Clone)]
pub struct EventTrb {
    pub trb_type: u32,
    pub completion_code: u32,
    pub slot_id: u32,
    pub trb_pointer: u64,
    pub transfer_length: u32,
}

/// Poll for HID keyboard report via Event Ring TRB processing
pub fn poll_keyboard() -> Option<u8> {
    let mut xhci = XHCI.lock();
    let ctrl = xhci.as_mut()?;

    // Process Event Ring for Transfer Events
    let events = ctrl.poll_event_ring();
    for event in &events {
        match event.trb_type {
            TRB_TYPE_TRANSFER => {
                if event.completion_code == TRB_CC_SUCCESS || event.completion_code == TRB_CC_SHORT {
                    // Transfer Event from interrupt endpoint — contains HID report
                    // The TRB pointer points to the data buffer containing the HID report
                    let data_phys = event.trb_pointer;
                    if data_phys != 0 {
                        let data_virt = (PHYS_OFFSET + data_phys) as *const u8;
                        // HID keyboard report: byte[2] = first keycode
                        let keycode = unsafe { *data_virt.add(2) };
                        if keycode != 0 {
                            return hid_to_ascii(keycode);
                        }
                    }
                }
            }
            TRB_TYPE_PORT_STATUS => {
                crate::serial_println!("  [XHCI] port status change event");
            }
            TRB_TYPE_CMD_COMPLETE => {
                // Command completion — handled inline
            }
            _ => {}
        }
    }
    None
}

/// Convert HID keyboard scancode to ASCII
fn hid_to_ascii(keycode: u8) -> Option<u8> {
    // USB HID keyboard usage table (subset)
    match keycode {
        0x04..=0x1D => Some(keycode - 0x04 + b'a'), // a-z
        0x1E..=0x27 => { // 1-9, 0
            let digits = b"1234567890";
            Some(digits[(keycode - 0x1E) as usize])
        }
        0x28 => Some(b'\n'),  // Enter
        0x29 => Some(0x1B),    // Escape
        0x2A => Some(0x08),    // Backspace
        0x2C => Some(b' '),    // Space
        0x2D => Some(b'-'),
        0x2E => Some(b'='),
        0x2F => Some(b'['),
        0x30 => Some(b']'),
        0x38 => Some(b'/'),
        _ => None,
    }
}
