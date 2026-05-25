//! PS/2 Keyboard driver — scancode set 1 → ASCII
//!
//! This module provides a simple PS/2 keyboard driver that translates
//! scancodes from Set 1 (the default for PS/2 keyboards) into ASCII
//! characters. It is intended for use in a kernel or embedded environment.
//!
//! # Usage
//!
//! 1. The interrupt handler (IRQ1) calls `handle_scancode()`.
//! 2. Call `read_char()` to retrieve a single character (non‑blocking).
//! 3. Call `read_line()` to block until a newline is received.
//!
//! # Notes
//! - Only key presses are processed; key releases are ignored.
//! - Modifier keys (Shift, Ctrl, Alt) are not yet handled.
//! - The mapping table covers only the basic US layout.

use x86_64::instructions::port::Port;
use alloc::collections::VecDeque;
use spin::{Lazy, Mutex};

// -----------------------------------------------------------------------------
// Global key queue
// -----------------------------------------------------------------------------

/// Thread‑safe queue of received characters.
static KEY_QUEUE: Lazy<Mutex<VecDeque<u8>>> = Lazy::new(|| Mutex::new(VecDeque::new()));

// -----------------------------------------------------------------------------
// Scancode to ASCII mapping (Set 1)
// -----------------------------------------------------------------------------

/// Mapping from PS/2 scancode (Set 1) to ASCII character.
/// Index 0 is unused (scancodes start at 1). 0 means “no mapping” (ignored).
const SCANCODE_TO_ASCII: [u8; 58] = [
    0, 0,           // 0x00, 0x01 (escape, F9)
    b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', // 0x02–0x0B
    b'-', b'=', b'\x08',        // 0x0C = '-', 0x0D = '=', 0x0E = Backspace
    b'\t',                      // 0x0F = Tab
    b'q', b'w', b'e', b'r', b't', b'y', b'u', b'i', b'o', b'p', // 0x10–0x19
    b'[', b']', b'\n',          // 0x1A = '[', 0x1B = ']', 0x1C = Enter
    0,                          // 0x1D = Left Ctrl (ignored)
    b'a', b's', b'd', b'f', b'g', b'h', b'j', b'k', b'l', // 0x1E–0x26
    b';', b'\'', b'`',         // 0x27 = ';', 0x28 = '\'', 0x29 = '`'
    0,                          // 0x2A = Left Shift (ignored)
    b'\\', b'z', b'x', b'c', b'v', b'b', b'n', b'm', // 0x2B–0x32
    b',', b'.', b'/', 0,       // 0x33 = ',', 0x34 = '.', 0x35 = '/', 0x36 = Right Shift
    b'*', 0, b' ',             // 0x37 = '*', 0x38 = Right Alt, 0x39 = Space
];

// -----------------------------------------------------------------------------
// Interrupt handler
// -----------------------------------------------------------------------------

/// Interrupt handler for PS/2 keyboard (IRQ1).
///
/// Reads the scancode from port 0x60, ignores key releases (bit 7 set),
/// translates the scancode to ASCII (if possible), and pushes it onto the
/// global queue.
///
/// # Safety
/// Called from an interrupt context. Must be installed in the IDT.
pub fn handle_scancode() {
    let scancode: u8 = unsafe { Port::new(0x60).read() };

    // Bit 7 indicates key release; we only process key presses.
    if scancode & 0x80 == 0 {
        let idx = scancode as usize;
        if idx < SCANCODE_TO_ASCII.len() {
            let ch = SCANCODE_TO_ASCII[idx];
            if ch != 0 {
                KEY_QUEUE.lock().push_back(ch);
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Read a single character from the keyboard queue.
///
/// Returns `Some(byte)` if a character is available, `None` otherwise.
/// This function is non‑blocking.
#[must_use]
pub fn read_char() -> Option<u8> {
    KEY_QUEUE.lock().pop_front()
}

/// Read a line of input (blocks until a newline is received).
///
/// Returns a `String` containing all characters typed before the Enter key.
/// Backspaces are handled by removing the last character from the string.
#[must_use]
pub fn read_line() -> alloc::string::String {
    let mut s = alloc::string::String::new();
    loop {
        if let Some(c) = read_char() {
            match c {
                b'\n' => break,
                b'\x08' => {  // Backspace
                    s.pop();
                }
                ch => {
                    s.push(ch as char);
                }
            }
        } else {
            // No character available – yield CPU.
            core::hint::spin_loop();
        }
    }
    s
}
