//! PS/2 Keyboard driver — scancode set 1 → ASCII
use x86_64::instructions::port::Port;
use alloc::collections::VecDeque;
use spin::{Lazy, Mutex};

static KEYQUEUE: Lazy<Mutex<VecDeque<u8>>> = Lazy::new(|| Mutex::new(VecDeque::new()));

const SCANCODE_TO_ASCII: [u8; 58] = [
    0, 0, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'-', b'=', b'\x08',
    b'\t', b'q', b'w', b'e', b'r', b't', b'y', b'u', b'i', b'o', b'p', b'[', b']', b'\n',
    0, b'a', b's', b'd', b'f', b'g', b'h', b'j', b'k', b'l', b';', b'\'', b'`',
    0, b'\\', b'z', b'x', b'c', b'v', b'b', b'n', b'm', b',', b'.', b'/', 0, b'*', 0, b' ',
];

/// Apelat de interrupt handler IRQ1
pub fn handle_scancode() {
    let code: u8 = unsafe { Port::new(0x60).read() };
    // Bit 7 = key release — ignorăm
    if code & 0x80 == 0 {
        let idx = code as usize;
        if idx < SCANCODE_TO_ASCII.len() && SCANCODE_TO_ASCII[idx] != 0 {
            KEYQUEUE.lock().push_back(SCANCODE_TO_ASCII[idx]);
        }
    }
}

pub fn read_char() -> Option<u8> { KEYQUEUE.lock().pop_front() }
pub fn read_line() -> alloc::string::String {
    let mut s = alloc::string::String::new();
    loop {
        if let Some(c) = read_char() {
            if c == b'\n' { break; }
            s.push(c as char);
        } else {
            core::hint::spin_loop();
        }
    }
    s
}
