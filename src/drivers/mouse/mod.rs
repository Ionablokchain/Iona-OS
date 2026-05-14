//! Mouse driver — PS/2 (IRQ12) + USB HID fallback
//!
//! PS/2 mouse protocol:
//!   - 3-byte packets: [flags][dx][dy]
//!   - flags byte: bit0=left, bit1=right, bit2=middle, bit4=dx_sign, bit5=dy_sign
//!   - Port 0x60 = data, 0x64 = status/command
//!
//! USB HID mouse: handled via XHCI interrupt → hid_report → MouseEvent
//! Both paths push events into MOUSE_QUEUE consumed by the GUI event loop.

use alloc::collections::VecDeque;
use spin::{Lazy, Mutex};
use x86_64::instructions::port::Port;

// ── Mouse event ───────────────────────────────────────────────────────────────
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MouseEvent {
    pub dx:          i16,    // relative X movement (pixels)
    pub dy:          i16,    // relative Y movement (positive = down)
    pub left:        bool,
    pub right:       bool,
    pub middle:      bool,
    pub scroll_dy:   i8,     // scroll wheel (-1=down, +1=up)
}

// ── Global state ──────────────────────────────────────────────────────────────
static MOUSE_QUEUE: Lazy<Mutex<VecDeque<MouseEvent>>> =
    Lazy::new(|| Mutex::new(VecDeque::with_capacity(64)));

// Cursor absolute position — updated by driver, clamped to screen bounds
static CURSOR: Mutex<(i32, i32)> = Mutex::new((400, 300));

// PS/2 packet reassembly state
static PS2_STATE: Mutex<Ps2State> = Mutex::new(Ps2State {
    phase:  0,
    bytes:  [0u8; 3],
});

struct Ps2State {
    phase: u8,
    bytes: [u8; 3],
}

// ── PS/2 initialisation ───────────────────────────────────────────────────────
pub fn init_ps2() {
    unsafe {
        let mut cmd:  Port<u8> = Port::new(0x64);
        let mut data: Port<u8> = Port::new(0x60);

        // Step 1: Enable second PS/2 port (aux/mouse)
        wait_write(); cmd.write(0xA8); // Enable aux device

        // Step 2: Flush output buffer
        for _ in 0..16 { let _ = data.read(); }

        // Step 3: Read current CCB (Command Control Byte)
        wait_write(); cmd.write(0x20); // Read CCB command
        wait_read();  let mut ccb = data.read();

        // Step 4: Enable aux clock + aux interrupt (bits 1 and 5 in CCB)
        // bit 1 = aux interrupt enable, bit 5 = aux clock (must be 0 to enable)
        ccb |=  0x02; // enable aux IRQ12 interrupt
        ccb &= !0x20; // enable aux clock (clear disable bit)

        wait_write(); cmd.write(0x60); // Write CCB command
        wait_write(); data.write(ccb);

        // Step 5: Mouse setup via aux port
        aux_send(0xFF); // Reset mouse
        for _ in 0..1000 {} // short delay for reset ACK

        // Flush any ACK/self-test bytes
        for _ in 0..8 {
            let st = Port::<u8>::new(0x64).read();
            if st & 0x01 != 0 { let _ = data.read(); }
        }

        aux_send(0xF6); // Set default parameters
        aux_send(0xF3); aux_send(100); // Set sample rate = 100 Hz
        aux_send(0xE8); aux_send(0x03); // Set resolution = 8 counts/mm
        aux_send(0xF4); // Enable data reporting
    }
    crate::serial_println!("  [MOUSE] PS/2 mouse initialized (IRQ12, 100Hz, 8cnt/mm)");
}

unsafe fn wait_write() {
    let mut status: Port<u8> = Port::new(0x64);
    for _ in 0..10000 { if status.read() & 0x02 == 0 { return; } }
}
unsafe fn wait_read() {
    let mut status: Port<u8> = Port::new(0x64);
    for _ in 0..10000 { if status.read() & 0x01 != 0 { return; } }
}
unsafe fn aux_send(byte: u8) {
    let mut cmd:  Port<u8> = Port::new(0x64);
    let mut data: Port<u8> = Port::new(0x60);
    wait_write(); cmd.write(0xD4);   // Route to aux port
    wait_write(); data.write(byte);
    wait_read();  let _ack = data.read(); // consume ACK
}

// ── IRQ12 handler (called from IDT) ──────────────────────────────────────────
pub fn handle_irq12() {
    let byte: u8 = unsafe { Port::<u8>::new(0x60).read() };
    let mut st = PS2_STATE.lock();

    match st.phase {
        0 => {
            // First byte must have bit 3 set (always-1 in flags byte)
            if byte & 0x08 != 0 { st.bytes[0] = byte; st.phase = 1; }
        }
        1 => { st.bytes[1] = byte; st.phase = 2; }
        2 => {
            st.bytes[2] = byte; st.phase = 0;
            let flags = st.bytes[0];
            let raw_dx = st.bytes[1] as i16;
            let raw_dy = st.bytes[2] as i16;
            // Apply sign extension from flags
            let dx = if flags & 0x10 != 0 { raw_dx - 256 } else { raw_dx };
            let dy = if flags & 0x20 != 0 { raw_dy - 256 } else { raw_dy };
            // PS/2 dy is inverted (positive = up in hardware)
            let ev = MouseEvent {
                dx, dy: -dy,
                left:   flags & 0x01 != 0,
                right:  flags & 0x02 != 0,
                middle: flags & 0x04 != 0,
                scroll_dy: 0,
            };
            drop(st);
            push_event(ev);
        }
        _ => { st.phase = 0; }
    }
}

// ── USB HID report handler ────────────────────────────────────────────────────
/// Called from XHCI interrupt handler with raw HID boot-protocol report
/// HID mouse boot protocol: [buttons][dx][dy][wheel] (4 bytes)
pub fn handle_hid_report(report: &[u8]) {
    if report.len() < 3 { return; }
    let buttons = report[0];
    let dx = report[1] as i8 as i16;
    let dy = report[2] as i8 as i16;
    let scroll = if report.len() >= 4 { report[3] as i8 } else { 0 };
    let ev = MouseEvent {
        dx, dy,
        left:     buttons & 0x01 != 0,
        right:    buttons & 0x02 != 0,
        middle:   buttons & 0x04 != 0,
        scroll_dy: scroll,
    };
    push_event(ev);
}

fn push_event(ev: MouseEvent) {
    let mut q = MOUSE_QUEUE.lock();
    if q.len() < 256 { q.push_back(ev); }
    // Update cursor position
    let (sw, sh) = (crate::io::framebuffer::width() as i32,
                    crate::io::framebuffer::height() as i32);
    if sw > 0 && sh > 0 {
        let mut cur = CURSOR.lock();
        cur.0 = (cur.0 + ev.dx as i32).clamp(0, sw - 1);
        cur.1 = (cur.1 + ev.dy as i32).clamp(0, sh - 1);
    }
}

/// Poll next mouse event (non-blocking)
pub fn poll() -> Option<MouseEvent> { MOUSE_QUEUE.lock().pop_front() }

/// Current cursor position (x, y) in screen pixels
pub fn cursor_pos() -> (i32, i32) { *CURSOR.lock() }

/// Set cursor position directly (e.g. on warp)
pub fn set_cursor(x: i32, y: i32) {
    let sw = crate::io::framebuffer::width() as i32;
    let sh = crate::io::framebuffer::height() as i32;
    let mut cur = CURSOR.lock();
    cur.0 = x.clamp(0, sw - 1);
    cur.1 = y.clamp(0, sh - 1);
}
