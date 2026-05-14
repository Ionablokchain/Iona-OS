//! Clipboard — copy/paste între aplicații
//!
//! Model simplu: un buffer global text + binary.
//! Apps copiază via syscall 360: clipboard_set(ptr, len, type)
//! Apps lipesc via syscall 361: clipboard_get(buf_ptr, buf_len) → bytes_copied
//!
//! Types: 0=text/plain, 1=text/html, 2=image/png (raw bytes)

use alloc::vec::Vec;
use spin::{Lazy, Mutex};

#[derive(Clone, Debug)]
pub struct ClipboardEntry {
    pub data:      Vec<u8>,
    pub mime_type: u8,      // 0=text, 1=html, 2=image
    pub timestamp: u64,
}

static CLIPBOARD: Lazy<Mutex<Option<ClipboardEntry>>> = Lazy::new(|| Mutex::new(None));

/// Set clipboard content
pub fn set(data: Vec<u8>, mime_type: u8) {
    let ts = crate::arch::x86_64::timer::uptime_ms();
    *CLIPBOARD.lock() = Some(ClipboardEntry { data, mime_type, timestamp: ts });
}

/// Get clipboard content — returns (data, mime_type) or None if empty
pub fn get() -> Option<ClipboardEntry> {
    CLIPBOARD.lock().clone()
}

/// Get clipboard as string (text/plain only)
pub fn get_text() -> Option<alloc::string::String> {
    let entry = CLIPBOARD.lock().clone()?;
    if entry.mime_type != 0 { return None; }
    alloc::string::String::from_utf8(entry.data).ok()
}

/// Set clipboard to a text string
pub fn set_text(s: &str) {
    set(s.as_bytes().to_vec(), 0);
}

/// Clear clipboard
pub fn clear() { *CLIPBOARD.lock() = None; }

pub fn init() {
    crate::serial_println!("  [CLIPBOARD] initialized (syscalls 360-361)");
}
