//! PS/2 Keyboard driver — scancode Set 1 → ASCII.
//!
//! Translates scancode Set 1 (the PC/AT default, used by all modern
//! PS/2 and USB-legacy keyboards behind the i8042 controller) into
//! ASCII bytes.
//!
//! # Features
//!
//! * Press/release detection.
//! * Left/right Shift, Left/Right Ctrl, Left/Right Alt.
//! * CapsLock (toggle on press).
//! * NumLock (toggle on press; affects keypad 0-9, `.`).
//! * Extended scancode prefix (`0xE0`).
//! * Pause-key prefix (`0xE1`) discarded as a single 6-byte sequence.
//! * Ctrl+letter → ASCII control code (Ctrl+C → 0x03, etc.).
//! * Bounded input queue (prevents DoS from a stuck key).
//! * PS/2 controller status check before reading port 0x60.
//!
//! # Usage
//!
//! 1. Install the IRQ1 handler so it calls [`handle_scancode`].
//! 2. Call [`read_char`] for non-blocking single-character reads.
//! 3. Call [`read_line`] to block until Enter (or Ctrl+C / Ctrl+D).
//!
//! # Layout
//!
//! Only the US QWERTY layout is implemented. Other layouts (AZERTY,
//! QWERTZ, Dvorak, …) require a pluggable layout table and are out of
//! scope for this driver.
//!
//! # Not supported
//!
//! * Non-US layouts.
//! * Keyboard-command I/O (setting LEDs, changing scancode set,
//!   toggling typematic rate). This driver is receive-only.
//! * System-request (SysRq) handling.
//! * Multi-byte UTF-8 input methods.
//!
//! # Assumptions
//!
//! * The controller is already initialised (e.g. by the bootloader or
//!   an earlier boot stage) and IRQ1 is unmasked.
//! * Scancode Set 1 is active. Set 2, used by some PS/2 keyboards
//!   until the controller is told otherwise, will produce garbage.
//! * NumLock is initially ON (matches typical BIOS behaviour). Press
//!   the NumLock key to toggle.

use alloc::collections::VecDeque;
use alloc::string::String;

use spin::{Lazy, Mutex};
use x86_64::instructions::port::Port;

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

/// Maximum number of characters buffered between the IRQ handler and
/// the reader. Anything beyond this is silently dropped; a stuck key
/// cannot exhaust kernel memory.
const QUEUE_CAPACITY: usize = 256;

/// Maximum length of a single line produced by [`read_line`].
const MAX_LINE_LEN: usize = 4096;

/// Size of the scancode table. Covers all base Set 1 codes through
/// keypad `.` (0x53).
const SCANCODE_TABLE_SIZE: usize = 0x54;

// ---------------------------------------------------------------------------
// Modifier bits
// ---------------------------------------------------------------------------

const MOD_LSHIFT: u8 = 1 << 0;
const MOD_RSHIFT: u8 = 1 << 1;
const MOD_LCTRL:  u8 = 1 << 2;
const MOD_RCTRL:  u8 = 1 << 3;
const MOD_LALT:   u8 = 1 << 4;
const MOD_RALT:   u8 = 1 << 5;
const MOD_CAPS:   u8 = 1 << 6;
const MOD_NUM:    u8 = 1 << 7;

const MOD_SHIFT_ANY: u8 = MOD_LSHIFT | MOD_RSHIFT;
const MOD_CTRL_ANY:  u8 = MOD_LCTRL  | MOD_RCTRL;

// Initial modifier state: NumLock on, everything else off.
const MOD_INITIAL: u8 = MOD_NUM;

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

static KEY_QUEUE: Lazy<Mutex<VecDeque<u8>>> =
    Lazy::new(|| Mutex::new(VecDeque::with_capacity(QUEUE_CAPACITY)));

static MODIFIERS: Mutex<u8> = Mutex::new(MOD_INITIAL);

/// Extended-prefix state machine. Values:
/// * 0 = none
/// * 1 = saw `0xE0`, expecting one more byte
/// * 2 = saw `0xE1`, expecting five more bytes (Pause sequence)
static EXT_STATE: Mutex<u8> = Mutex::new(0);

// ---------------------------------------------------------------------------
// Scancode → ASCII tables (US QWERTY, Set 1)
// ---------------------------------------------------------------------------

/// Unshifted mapping. `0` means "no printable output".
const SCANCODE_BASE: [u8; SCANCODE_TABLE_SIZE] = [
    0x00,       // 0x00 — unused
    0x1B,       // 0x01 — Escape
    b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', // 0x02–0x0B
    b'-', b'=', // 0x0C–0x0D
    0x08,       // 0x0E — Backspace
    0x09,       // 0x0F — Tab
    b'q', b'w', b'e', b'r', b't', b'y', b'u', b'i', b'o', b'p', // 0x10–0x19
    b'[', b']', // 0x1A–0x1B
    b'\n',      // 0x1C — Enter
    0x00,       // 0x1D — Left Ctrl (modifier)
    b'a', b's', b'd', b'f', b'g', b'h', b'j', b'k', b'l', // 0x1E–0x26
    b';', b'\'', b'`', // 0x27–0x29
    0x00,       // 0x2A — Left Shift (modifier)
    b'\\',      // 0x2B
    b'z', b'x', b'c', b'v', b'b', b'n', b'm', // 0x2C–0x32
    b',', b'.', b'/', // 0x33–0x35
    0x00,       // 0x36 — Right Shift (modifier)
    b'*',       // 0x37 — Keypad * (also PrtSc when preceded by 0xE0)
    0x00,       // 0x38 — Left Alt (modifier; Right Alt is 0xE0 0x38)
    b' ',       // 0x39 — Space
    0x00,       // 0x3A — CapsLock (modifier)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x3B–0x44 — F1-F10
    0x00,       // 0x45 — NumLock (modifier)
    0x00,       // 0x46 — ScrollLock
    b'7', b'8', b'9',       // 0x47–0x49 — KP 7/8/9 (with NumLock)
    b'-',                    // 0x4A — KP -
    b'4', b'5', b'6',       // 0x4B–0x4D — KP 4/5/6
    b'+',                    // 0x4E — KP +
    b'1', b'2', b'3',       // 0x4F–0x51 — KP 1/2/3
    b'0',                    // 0x52 — KP 0
    b'.',                    // 0x53 — KP .
];

/// Shifted mapping. Only positions that differ from [`SCANCODE_BASE`]
/// are meaningful; entries equal to the base entry fall through.
const SCANCODE_SHIFT: [u8; SCANCODE_TABLE_SIZE] = [
    0x00, 0x1B,
    b'!', b'@', b'#', b'$', b'%', b'^', b'&', b'*', b'(', b')',
    b'_', b'+',
    0x08, 0x09,
    b'Q', b'W', b'E', b'R', b'T', b'Y', b'U', b'I', b'O', b'P',
    b'{', b'}',
    b'\n',
    0x00,
    b'A', b'S', b'D', b'F', b'G', b'H', b'J', b'K', b'L',
    b':', b'"', b'~',
    0x00,
    b'|',
    b'Z', b'X', b'C', b'V', b'B', b'N', b'M',
    b'<', b'>', b'?',
    0x00,
    b'*', 0x00, b' ',
    0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
    b'7', b'8', b'9',
    b'-',
    b'4', b'5', b'6',
    b'+',
    b'1', b'2', b'3',
    b'0',
    b'.',
];

const _: () = {
    assert!(SCANCODE_BASE.len()  == SCANCODE_TABLE_SIZE);
    assert!(SCANCODE_SHIFT.len() == SCANCODE_TABLE_SIZE);
};

// ---------------------------------------------------------------------------
// Keypad ranges (gated on NumLock)
// ---------------------------------------------------------------------------

/// `true` if `sc` is a keypad digit / decimal-point whose meaning
/// depends on NumLock. `KP -` (0x4A) and `KP +` (0x4E) are excluded —
/// they always produce `-` and `+`.
#[inline]
fn is_numlock_gated(sc: u8) -> bool {
    matches!(sc, 0x47..=0x49 | 0x4B..=0x4D | 0x4F..=0x53)
}

// ---------------------------------------------------------------------------
// Interrupt handler
// ---------------------------------------------------------------------------

/// IRQ1 handler. Reads one byte from the PS/2 data port, updates
/// modifier state, and enqueues an ASCII byte if the scancode
/// represents a printable character.
///
/// # Safety
///
/// Must be called from the IRQ1 handler (or with IRQ1 masked). Safe to
/// call even if the controller has nothing to report — the status port
/// is checked first.
pub fn handle_scancode() {
    // Port 0x64 bit 0: Output Buffer Full. If the controller has nothing
    // for us (spurious IRQ), return without touching port 0x60.
    let status: u8 = unsafe { Port::new(0x64).read() };
    if status & 0x01 == 0 {
        return;
    }

    let sc: u8 = unsafe { Port::new(0x60).read() };

    // 0xFF indicates a controller buffer overrun or self-test; discard.
    if sc == 0xFF {
        return;
    }

    dispatch(sc);
}

/// Route a byte through the extended-prefix state machine.
fn dispatch(sc: u8) {
    let mut ext = EXT_STATE.lock();
    match *ext {
        0 => match sc {
            0xE0 => *ext = 1,       // E0: one following byte is extended
            0xE1 => *ext = 2,       // E1: five following bytes (Pause)
            _    => process_base(sc),
        },
        1 => {
            *ext = 0;
            process_extended(sc);
        }
        2 => {
            // Pause sequence: E1 1D 45 E1 9D C5. Decrement on each byte.
            *ext = ext.saturating_sub(1);
            if *ext == 0 {
                // end of Pause sequence — nothing to emit
            }
        }
        _ => *ext = 0, // defensive
    }
}

/// Process a base-set scancode (no extended prefix).
fn process_base(sc: u8) {
    let release = sc & 0x80 != 0;
    let code = sc & 0x7F;

    // Modifier updates happen on both press and release.
    match code {
        0x2A => { update_mod(MOD_LSHIFT, !release); return; }
        0x36 => { update_mod(MOD_RSHIFT, !release); return; }
        0x1D => { update_mod(MOD_LCTRL,  !release); return; }
        0x38 => { update_mod(MOD_LALT,   !release); return; }
        0x3A if !release => { toggle_mod(MOD_CAPS); return; }
        0x45 if !release => { toggle_mod(MOD_NUM);  return; }
        _ => {}
    }

    if release {
        return;
    }

    if (code as usize) >= SCANCODE_TABLE_SIZE {
        return;
    }

    // Keypad gating: with NumLock off, KP 7/8/9/4/5/6/1/2/3/0/. are
    // navigation keys (Home, arrows, PgUp, …) which we do not emit.
    if is_numlock_gated(code) && !(current_mods() & MOD_NUM != 0) {
        return;
    }

    let shift = current_mods() & MOD_SHIFT_ANY != 0;
    let caps  = current_mods() & MOD_CAPS != 0;
    let ctrl  = current_mods() & MOD_CTRL_ANY != 0;

    let byte = select_byte(code, shift, caps);

    if byte != 0 {
        // Ctrl+letter → ASCII control code (Ctrl+A = 0x01, …, Ctrl+Z = 0x1A).
        let out = if ctrl {
            ctrl_to_ascii(byte).unwrap_or(byte)
        } else {
            byte
        };
        push(out);
    }
}

/// Handle the byte following `0xE0`.
fn process_extended(sc: u8) {
    let release = sc & 0x80 != 0;
    let code = sc & 0x7F;

    match code {
        0x1D => { update_mod(MOD_RCTRL, !release); return; }
        0x38 => { update_mod(MOD_RALT,  !release); return; }
        _ => {}
    }

    if release {
        return;
    }

    // Extended keys with a well-defined ASCII output.
    let out = match code {
        0x1C => b'\n', // Keypad Enter
        0x35 => b'/',  // Keypad /
        _    => return, // arrows, Home, End, PgUp, PgDn, Ins, Del, Win keys…
    };
    push(out);
}

/// Choose the output byte for `code`, applying Shift and CapsLock.
fn select_byte(code: u8, shift: bool, caps: bool) -> u8 {
    let base  = SCANCODE_BASE[code as usize];
    let shift_byte = SCANCODE_SHIFT[code as usize];

    // Letters: Shift XOR CapsLock determines case.
    let is_letter = base.is_ascii_lowercase();
    if is_letter {
        return if shift ^ caps { shift_byte } else { base };
    }

    // Non-letters: Shift alone determines.
    if shift { shift_byte } else { base }
}

/// Map a lowercase letter `a..=z` to the ASCII control code produced by
/// Ctrl+letter. Returns `None` for other bytes.
fn ctrl_to_ascii(byte: u8) -> Option<u8> {
    if (b'a'..=b'z').contains(&byte) {
        Some(byte - b'a' + 1)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Modifier helpers
// ---------------------------------------------------------------------------

fn update_mod(bit: u8, set: bool) {
    let mut m = MODIFIERS.lock();
    if set {
        *m |= bit;
    } else {
        *m &= !bit;
    }
}

fn toggle_mod(bit: u8) {
    *MODIFIERS.lock() ^= bit;
}

fn current_mods() -> u8 {
    *MODIFIERS.lock()
}

fn push(byte: u8) {
    let mut q = KEY_QUEUE.lock();
    if q.len() < QUEUE_CAPACITY {
        q.push_back(byte);
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Read a single character from the keyboard queue.
///
/// Non-blocking. Returns `None` if no character is pending.
#[must_use]
pub fn read_char() -> Option<u8> {
    KEY_QUEUE.lock().pop_front()
}

/// Read a line of input, blocking until Enter is pressed.
///
/// * Backspace removes the last character.
/// * Ctrl+C aborts and returns the line typed so far (the caller is
///   expected to discard it; we do not raise a signal from here).
/// * Ctrl+D (0x04) at an empty line returns an empty string.
/// * The returned string never exceeds [`MAX_LINE_LEN`] characters;
///   input beyond that is silently dropped.
///
/// # CPU usage
///
/// This function busy-waits with a `spin_loop()` hint. Because IRQ1
/// fires independently, characters are enqueued while we wait. Callers
/// that need to do other work should use [`read_char`] in their own
/// loop instead.
#[must_use]
pub fn read_line() -> String {
    let mut s = String::new();
    loop {
        match read_char() {
            Some(b'\n') => break,

            Some(0x03) => {
                // Ctrl+C: discard, return empty (caller may re-prompt).
                return String::new();
            }

            Some(0x04) => {
                // Ctrl+D: EOF. Return what we have.
                break;
            }

            Some(0x08) => {
                s.pop();
            }

            Some(ch) if s.len() < MAX_LINE_LEN => {
                s.push(ch as char);
            }

            Some(_) => { /* at MAX_LINE_LEN, drop further input */ }

            None => core::hint::spin_loop(),
        }
    }
    s
}

/// Clear any pending characters. Useful when returning to a known state
/// after an error, or when switching input focus.
pub fn clear_queue() {
    KEY_QUEUE.lock().clear();
}

/// Number of characters currently queued.
#[must_use]
pub fn queue_len() -> usize {
    KEY_QUEUE.lock().len()
}

/// Current modifier bitmask (see the `MOD_*` constants). Exposed for
/// diagnostic / test use; applications should generally not depend on
/// this.
#[must_use]
pub fn modifier_state() -> u8 {
    current_mods()
}
