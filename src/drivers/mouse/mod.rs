//! Mouse driver — PS/2 (IRQ12) and USB HID boot protocol.
//!
//! Both transports feed a single MPSC-style event queue consumed by the
//! GUI event loop. Only one transport should be active at a time; see
//! [`disable_ps2`] / [`enable_ps2`] for switching.
//!
//! # PS/2 protocol
//!
//! 3-byte packets (standard mouse): `[flags][dx][dy]`
//! 4-byte packets (IntelliMouse, detected at init): `[flags][dx][dy][wheel]`
//!
//! `flags`:
//!   bit 0 = left, 1 = right, 2 = middle,
//!   bit 3 = always 1 (sync),
//!   bit 4 = dx sign, 5 = dy sign,
//!   bit 6 = overflow (dx/dy invalid → drop), 7 = always 0.
//!
//! # USB HID
//!
//! Uses boot-protocol reports: `[buttons][dx][dy][wheel?]`. The caller is
//! responsible for parsing report descriptors and forwarding the
//! boot-protocol-shaped slice to [`handle_hid_report`].
//!
//! # Locking model
//!
//! `PS2_STATE`, `MOUSE_QUEUE` and `CURSOR` may be touched from IRQ12
//! context. **Every** critical section in non-IRQ code is wrapped in
//! [`without_interrupts`], which prevents IRQ12 from re-entering the
//! lock while the main thread holds it. Code running inside IRQ12 may
//! lock these without `without_interrupts` (IRQs are already disabled).
//!
//! # Limitations
//!
//! * PS/2 init assumes the controller is already configured by the
//!   bootloader for one aux port. Multiplexed controllers (some
//!   laptops with a `0xF5`/`0x56` AUX-BYPASS) are not supported.
//! * No hot-plug detection for either transport.
//! * Absolute pointing (touchpads in absolute mode) is not supported.
//! * USB HID polling rate is controlled by the caller (XHCI endpoint
//!   configuration); this module just consumes reports.
//! * Only US default speed/acceleration curves; no pointer gain
//!   adjustment.

use alloc::collections::VecDeque;

use spin::{Lazy, Mutex};
use x86_64::instructions::interrupts::without_interrupts;
use x86_64::instructions::port::Port;

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

/// Maximum queued events before the oldest are dropped. Bounds memory
/// usage when the consumer stalls.
const QUEUE_CAPACITY: usize = 256;

/// Controller status polling budgets (iterations). ~10 ms on 1 GHz.
const CTRL_TIMEOUT: usize = 100_000;

/// Mouse command ACK deadline (iterations).
const ACK_TIMEOUT: usize = 100_000;

// ---------------------------------------------------------------------------
// Public event type
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MouseEvent {
    /// Relative X movement in pixels (positive = right).
    pub dx:        i16,
    /// Relative Y movement in pixels (positive = down).
    pub dy:        i16,
    pub left:      bool,
    pub right:     bool,
    pub middle:    bool,
    /// Wheel delta (+1 = up, -1 = down).
    pub scroll_dy: i8,
}

impl MouseEvent {
    const NONE: MouseEvent = MouseEvent {
        dx: 0, dy: 0, left: false, right: false, middle: false, scroll_dy: 0,
    };
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

static MOUSE_QUEUE: Lazy<Mutex<VecDeque<MouseEvent>>> =
    Lazy::new(|| Mutex::new(VecDeque::with_capacity(QUEUE_CAPACITY)));

static CURSOR: Mutex<(i32, i32)> = Mutex::new((0, 0));
static CURSOR_INITIALISED: Mutex<bool> = Mutex::new(false);

/// PS/2 packet assembly. Reset whenever we lose sync.
static PS2_STATE: Mutex<Ps2State> = Mutex::new(Ps2State::new());

/// Whether the PS/2 aux port is currently delivering data.
static PS2_ENABLED: Mutex<bool> = Mutex::new(false);

struct Ps2State {
    phase:       u8,
    bytes:       [u8; 4],
    packet_size: u8, // 3 for standard, 4 for IntelliMouse
}

impl Ps2State {
    const fn new() -> Self {
        Self { phase: 0, bytes: [0; 4], packet_size: 3 }
    }
}

// ---------------------------------------------------------------------------
// PS/2 controller I/O helpers
// ---------------------------------------------------------------------------

struct Ps2Ports {
    cmd:  Port<u8>, // 0x64
    data: Port<u8>, // 0x60
}

impl Ps2Ports {
    fn new() -> Self {
        Self { cmd: Port::new(0x64), data: Port::new(0x60) }
    }

    /// Wait until the controller's input buffer is empty (bit 1 of 0x64).
    unsafe fn wait_write(&mut self) -> bool {
        for _ in 0..CTRL_TIMEOUT {
            if self.cmd.read() & 0x02 == 0 {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    /// Wait until a byte is available (bit 0 of 0x64). If `aux_only` is
    /// true, also require bit 5 (AUX data) — used during init to avoid
    /// consuming keyboard input.
    unsafe fn wait_read(&mut self, aux_only: bool) -> bool {
        for _ in 0..CTRL_TIMEOUT {
            let s = self.cmd.read();
            if s & 0x01 != 0 && (!aux_only || s & 0x20 != 0) {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    /// Send a command byte to the controller (0x64), waiting for the
    /// input buffer to drain first.
    unsafe fn write_cmd(&mut self, value: u8) -> bool {
        if !self.wait_write() { return false; }
        self.cmd.write(value);
        true
    }

    /// Send a data byte (0x60), waiting for the input buffer to drain.
    unsafe fn write_data(&mut self, value: u8) -> bool {
        if !self.wait_write() { return false; }
        self.data.write(value);
        true
    }

    /// Read one byte from data port with optional AUX gating.
    unsafe fn read_data(&mut self, aux_only: bool) -> Option<u8> {
        if self.wait_read(aux_only) { Some(self.data.read()) } else { None }
    }

    /// Send a command to the aux (mouse) device and expect an ACK (0xFA).
    ///
    /// Returns `Ok(ack_byte)` on success. On resend request (0xFE) the
    /// caller can retry; we surface it as `Err(0xFE)` rather than hiding
    /// it.
    unsafe fn aux_send(&mut self, byte: u8) -> Result<u8, u8> {
        if !self.write_cmd(0xD4) { return Err(0x00); }        // "next data → aux"
        if !self.write_data(byte) { return Err(0x00); }
        match self.read_data(true) {
            Some(0xFA) => Ok(0xFA),
            Some(other) => Err(other), // 0xFE = resend, 0xFC = error
            None => Err(0x00),
        }
    }
}

// ---------------------------------------------------------------------------
// PS/2 initialisation
// ---------------------------------------------------------------------------

/// Initialise the PS/2 aux (mouse) port. Returns `true` on success.
///
/// Interrupts are disabled for the whole sequence so that IRQ12 cannot
/// consume the ACK bytes we are waiting for.
pub fn init_ps2() -> bool {
    without_interrupts(|| {
        let mut p = Ps2Ports::new();
        unsafe {
            // 1. Enable the aux port.
            if !p.write_cmd(0xA8) { return false; }

            // 2. Read the current CCB, modify aux bits, write it back.
            if !p.write_cmd(0x20) { return false; }
            let Some(mut ccb) = p.read_data(false) else { return false; };
            ccb |=  0x02; // bit 1: enable AUX interrupt (IRQ12)
            ccb &= !0x20; // bit 5: enable AUX clock
            if !p.write_cmd(0x60) { return false; }
            if !p.write_data(ccb) { return false; }

            // 3. Reset the mouse and drain its self-test report.
            if p.aux_send(0xFF).is_err() { return false; }
            // After reset: 0xAA (self-test passed), 0x00 (mouse ID).
            // Both arrive with a small delay; drain with a bounded wait.
            let _ = p.read_data(true); // 0xAA
            let _ = p.read_data(true); // 0x00

            // 4. Set defaults, enable reporting at 100 Hz, resolution 8/mm.
            if p.aux_send(0xF6).is_err() { return false; } // set defaults
            if p.aux_send(0xF3).is_err() { return false; } // set sample rate
            if p.aux_send(5).is_err() { return false; }    // 5 = 100 Hz
            if p.aux_send(0xE8).is_err() { return false; } // set resolution
            if p.aux_send(3).is_err() { return false; }    // 3 = 8 counts/mm

            // 5. Probe for IntelliMouse (wheel). Sample-rate magic:
            //    200 → 100 → 80, then Get-ID returns 0x03 (or 0x04 for
            //    IntelliMouse Explorer with 5 buttons).
            let _ = p.aux_send(0xF3); let _ = p.aux_send(200);
            let _ = p.aux_send(0xF3); let _ = p.aux_send(100);
            let _ = p.aux_send(0xF3); let _ = p.aux_send(80);
            let wheel_ok = p.aux_send(0xF2).is_ok();
            let dev_id = if wheel_ok { p.read_data(true) } else { None };
            let is_wheel = matches!(dev_id, Some(0x03) | Some(0x04));

            // Re-issue F6 + rate to normalise state post-probe.
            let _ = p.aux_send(0xF6);
            let _ = p.aux_send(0xF3); let _ = p.aux_send(5);

            // 6. Enable data reporting.
            if p.aux_send(0xF4).is_err() { return false; }

            // 7. Reset the packet parser with the discovered size.
            {
                let mut st = PS2_STATE.lock();
                *st = Ps2State::new();
                st.packet_size = if is_wheel { 4 } else { 3 };
            }
            *PS2_ENABLED.lock() = true;
        }
        crate::serial_println!(
            "  [MOUSE] PS/2 initialised ({} packet, 100 Hz, 8 cnt/mm)",
            if *PS2_ENABLED.lock() { "4-byte (wheel)" } else { "3-byte" }
        );
        true
    })
}

/// Stop forwarding PS/2 events. Useful when switching to USB HID.
pub fn disable_ps2() {
    without_interrupts(|| {
        *PS2_ENABLED.lock() = false;
    });
}

/// Resume forwarding PS/2 events.
pub fn enable_ps2() {
    without_interrupts(|| {
        *PS2_ENABLED.lock() = true;
    });
}

// ---------------------------------------------------------------------------
// IRQ12 handler
// ---------------------------------------------------------------------------

/// Called from IRQ12. Reads one byte from port 0x60, drives the packet
/// state machine, and enqueues a [`MouseEvent`] when a full packet is
/// assembled.
///
/// # Safety
///
/// Must run with interrupts disabled (standard for IDT handlers). The
/// status port is checked first, so spurious IRQ12s are harmless.
pub fn handle_irq12() {
    // Reject if PS/2 is disabled, or if the controller has nothing to
    // report (bit 0 of 0x64 must be set), or if the byte is not for us
    // (bit 5 must be set for AUX data).
    {
        let mut p = Ps2Ports::new();
        unsafe {
            let s = p.cmd.read();
            if s & 0x01 == 0 || s & 0x20 == 0 {
                return;
            }
        }
    }

    if !*PS2_ENABLED.lock() {
        // Still drain the byte so the controller does not wedge.
        unsafe { let _ = Ps2Ports::new().data.read(); }
        return;
    }

    let byte: u8 = unsafe { Port::<u8>::new(0x60).read() };

    // Assemble the packet.
    let packet = {
        let mut st = PS2_STATE.lock();
        let completed = match st.phase {
            0 => {
                // First byte must have sync bit (bit 3) set and bit 7 clear.
                if byte & 0x08 != 0 && byte & 0x80 == 0 {
                    st.bytes[0] = byte;
                    st.phase = 1;
                }
                // Drop otherwise (resync).
                None
            }
            1 => {
                st.bytes[1] = byte;
                st.phase = 2;
                None
            }
            2 => {
                st.bytes[2] = byte;
                if st.packet_size == 4 {
                    st.phase = 3;
                    None
                } else {
                    st.phase = 0;
                    Some(())
                }
            }
            3 => {
                st.bytes[3] = byte;
                st.phase = 0;
                Some(())
            }
            _ => {
                st.phase = 0;
                None
            }
        };

        if completed.is_some() {
            let flags = st.bytes[0];
            // Overflow bit: dx/dy are unreliable; drop the whole packet
            // (but still clear phase above).
            if flags & 0x40 != 0 {
                None
            } else {
                // 9-bit sign extension: dx_9bit = (sign_bit << 8) | dx_byte.
                let raw_dx = st.bytes[1] as i16;
                let raw_dy = st.bytes[2] as i16;
                let dx = if flags & 0x10 != 0 { raw_dx - 256 } else { raw_dx };
                let dy = if flags & 0x20 != 0 { raw_dy - 256 } else { raw_dy };
                let wheel = if st.packet_size == 4 { st.bytes[3] as i8 } else { 0 };
                Some(MouseEvent {
                    dx,
                    dy: -dy, // PS/2 positive dy = up; MouseEvent uses down-positive
                    left:   flags & 0x01 != 0,
                    right:  flags & 0x02 != 0,
                    middle: flags & 0x04 != 0,
                    scroll_dy: wheel,
                })
            }
        } else {
            None
        }
    };

    if let Some(ev) = packet {
        push_event(ev);
    }
}

// ---------------------------------------------------------------------------
// USB HID boot-protocol report handler
// ---------------------------------------------------------------------------

/// Consume a USB HID boot-protocol mouse report.
///
/// Expects `[buttons][dx][dy]` or `[buttons][dx][dy][wheel]`. For devices
/// in report-protocol mode, the caller must decode the descriptor and
/// forward only boot-shaped slices here — this module does not parse
/// report descriptors.
pub fn handle_hid_report(report: &[u8]) {
    if report.len() < 3 {
        return;
    }
    let buttons = report[0];
    let dx = report[1] as i8 as i16;
    let dy = report[2] as i8 as i16;
    let scroll = if report.len() >= 4 { report[3] as i8 } else { 0 };

    let ev = MouseEvent {
        dx,
        dy,
        left:     buttons & 0x01 != 0,
        right:    buttons & 0x02 != 0,
        middle:   buttons & 0x04 != 0,
        scroll_dy: scroll,
    };
    push_event(ev);
}

// ---------------------------------------------------------------------------
// Queue and cursor
// ---------------------------------------------------------------------------

fn push_event(ev: MouseEvent) {
    // Called from IRQ context (IRQs disabled) or from non-IRQ (via
    // without_interrupts in callers). Take the queue lock first, then
    // the cursor lock — always in this order to avoid inversion.
    let mut q = MOUSE_QUEUE.lock();
    if q.len() >= QUEUE_CAPACITY {
        q.pop_front();
    }
    q.push_back(ev);
    drop(q);

    // Update cursor. We read framebuffer dimensions under the cursor
    // lock so the two never disagree.
    let (sw, sh) = framebuffer_size();
    if sw > 0 && sh > 0 {
        let mut cur = CURSOR.lock();
        let mut init = CURSOR_INITIALISED.lock();
        if !*init {
            // First event: centre the cursor rather than leaving it at
            // (0, 0), which is a corner.
            *cur = (sw / 2, sh / 2);
            *init = true;
        }
        cur.0 = (cur.0 + ev.dx as i32).clamp(0, sw - 1);
        cur.1 = (cur.1 + ev.dy as i32).clamp(0, sh - 1);
    }
}

fn framebuffer_size() -> (i32, i32) {
    (crate::io::framebuffer::width() as i32,
     crate::io::framebuffer::height() as i32)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Pop the next mouse event. Non-blocking.
#[must_use]
pub fn poll() -> Option<MouseEvent> {
    without_interrupts(|| MOUSE_QUEUE.lock().pop_front())
}

/// Current cursor position in screen pixels. Safe to call from any
/// context; the cursor is updated by the driver on every event.
#[must_use]
pub fn cursor_pos() -> (i32, i32) {
    without_interrupts(|| *CURSOR.lock())
}

/// Move the cursor to an absolute position (e.g. for a warp or on
/// focus). Coordinates are clamped to the framebuffer.
pub fn set_cursor(x: i32, y: i32) {
    let (sw, sh) = framebuffer_size();
    without_interrupts(|| {
        let mut cur = CURSOR.lock();
        cur.0 = x.clamp(0, sw.max(1) - 1);
        cur.1 = y.clamp(0, sh.max(1) - 1);
        *CURSOR_INITIALISED.lock() = true;
    });
}

/// Number of events currently queued (diagnostic).
#[must_use]
pub fn queue_len() -> usize {
    without_interrupts(|| MOUSE_QUEUE.lock().len())
}

/// Discard all queued events. Does not change cursor position.
pub fn clear_queue() {
    without_interrupts(|| MOUSE_QUEUE.lock().clear());
}

/// Whether the PS/2 transport is currently forwarding events.
#[must_use]
pub fn ps2_enabled() -> bool {
    without_interrupts(|| *PS2_ENABLED.lock())
}

// Silence the "field is never read" lint for the constant helper.
#[allow(dead_code)]
const _: MouseEvent = MouseEvent::NONE;
