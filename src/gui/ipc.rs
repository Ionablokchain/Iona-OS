//! GUI IPC — kernel ↔ userspace GUI event protocol
//!
//! Userspace apps (ring 3) comunică cu GUI kernel prin syscalls:
//!
//!   350: gui_create_window(title_ptr, title_len, x, y, w, h) → wid
//!   351: gui_destroy_window(wid) → 0
//!   352: gui_draw_pixels(wid, x, y, w, h, pixels_ptr, pixels_len) → 0
//!   353: gui_set_title(wid, title_ptr, title_len) → 0
//!   354: gui_poll_event(wid, buf_ptr, buf_len) → bytes_written (0=no event)
//!   355: gui_flush(wid) → 0  (mark window as needing redraw)
//!   356: gui_set_cursor_shape(shape) → 0
//!
//! Event encoding (returned by gui_poll_event):
//!   [1: type][4: wid][8: data...]
//!   type 1 = MouseMove: [4:x][4:y][2:dx][2:dy]
//!   type 2 = MouseDown: [4:x][4:y][1:button]
//!   type 3 = MouseUp:   [4:x][4:y][1:button]
//!   type 4 = KeyDown:   [4:keycode][1:ascii]
//!   type 5 = KeyUp:     [4:keycode]
//!   type 6 = Close:     (no data)
//!   type 7 = Resize:    [4:new_w][4:new_h]

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use spin::{Lazy, Mutex};
use crate::task::TaskId;
use crate::gui::events::GuiEvent;

// Per-window event queue (tid → queue of encoded events)
static APP_QUEUES: Lazy<Mutex<BTreeMap<u32, VecDeque<Vec<u8>>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

pub fn init() { crate::serial_println!("  [GUI/IPC] GUI syscall interface ready (350-356)"); }

/// Flush pending GUI events — routes WM-dispatched events to per-window queues.
///
/// The WM calls push_window_event(wid, bytes) directly when it processes
/// keyboard/mouse events. This function ensures queues are not overflowing
/// and handles any cleanup. The routing is done at dispatch time in wm.rs.
pub fn flush_to_apps() {
    // Trim overflow: if any window queue exceeds 256 events, drop oldest
    let mut qs = APP_QUEUES.lock();
    for queue in qs.values_mut() {
        while queue.len() > 256 {
            queue.pop_front();
        }
    }
}

/// Route a GUI event to the appropriate window queue based on focus.
/// Called by the GUI event pump after wm::dispatch_event to ensure
/// keyboard events actually reach apps via poll_window_event().
pub fn route_to_focused(ev: &crate::gui::events::GuiEvent) {
    use crate::gui::events::GuiEvent;
    let focused = crate::gui::wm::WM.lock().focused;
    let wid = match focused { Some(w) => w, None => return };

    let encoded: Option<alloc::vec::Vec<u8>> = match ev {
        GuiEvent::KeyDown { key, ch, .. } => {
            let ascii = ch.map(|c| c as u8).unwrap_or(0);
            let keycode = match key {
                crate::gui::events::Key::Enter     => 0x0Du32,
                crate::gui::events::Key::Backspace => 0x08,
                crate::gui::events::Key::Escape    => 0x1B,
                crate::gui::events::Key::Tab       => 0x09,
                crate::gui::events::Key::Left      => 0x25,
                crate::gui::events::Key::Right     => 0x27,
                crate::gui::events::Key::Up        => 0x26,
                crate::gui::events::Key::Down      => 0x28,
                crate::gui::events::Key::Delete    => 0x2E,
                crate::gui::events::Key::Home      => 0x24,
                crate::gui::events::Key::End       => 0x23,
                crate::gui::events::Key::Char(c)   => *c as u32,
                _                                  => 0,
            };
            Some(encode_key(wid, keycode, ascii, true))
        }
        GuiEvent::MouseDown { x, y, button } => {
            let btn = match button {
                crate::gui::events::MouseBtn::Left   => 0u8,
                crate::gui::events::MouseBtn::Right  => 1,
                crate::gui::events::MouseBtn::Middle => 2,
            };
            Some(encode_mouse_btn(wid, *x, *y, btn, true))
        }
        GuiEvent::MouseUp { x, y, button } => {
            let btn = match button {
                crate::gui::events::MouseBtn::Left   => 0u8,
                crate::gui::events::MouseBtn::Right  => 1,
                crate::gui::events::MouseBtn::Middle => 2,
            };
            Some(encode_mouse_btn(wid, *x, *y, btn, false))
        }
        GuiEvent::MouseMove { x, y, dx, dy } => {
            Some(encode_mouse_move(wid, *x, *y, *dx, *dy))
        }
        _ => None,
    };

    if let Some(bytes) = encoded {
        push_window_event(wid, bytes);
    }
}

/// Enqueue an encoded event for a window's owner
pub fn push_window_event(wid: u32, event_bytes: Vec<u8>) {
    let mut qs = APP_QUEUES.lock();
    qs.entry(wid).or_default().push_back(event_bytes);
}

/// Poll next event for a window (called from syscall 354)
pub fn poll_window_event(wid: u32) -> Option<Vec<u8>> {
    APP_QUEUES.lock().get_mut(&wid)?.pop_front()
}

/// Register window event queue
pub fn register_window(wid: u32) {
    APP_QUEUES.lock().entry(wid).or_default();
}

/// Unregister
pub fn unregister_window(wid: u32) {
    APP_QUEUES.lock().remove(&wid);
}

// ── Event encoding helpers ────────────────────────────────────────────────────
pub fn encode_mouse_move(wid: u32, x: i32, y: i32, dx: i16, dy: i16) -> Vec<u8> {
    let mut b = alloc::vec![1u8]; // type=MouseMove
    b.extend_from_slice(&wid.to_le_bytes());
    b.extend_from_slice(&x.to_le_bytes());
    b.extend_from_slice(&y.to_le_bytes());
    b.extend_from_slice(&dx.to_le_bytes());
    b.extend_from_slice(&dy.to_le_bytes());
    b
}

pub fn encode_mouse_btn(wid: u32, x: i32, y: i32, btn: u8, down: bool) -> Vec<u8> {
    let mut b = alloc::vec![if down { 2u8 } else { 3u8 }];
    b.extend_from_slice(&wid.to_le_bytes());
    b.extend_from_slice(&x.to_le_bytes());
    b.extend_from_slice(&y.to_le_bytes());
    b.push(btn);
    b
}

pub fn encode_key(wid: u32, keycode: u32, ascii: u8, down: bool) -> Vec<u8> {
    let mut b = alloc::vec![if down { 4u8 } else { 5u8 }];
    b.extend_from_slice(&wid.to_le_bytes());
    b.extend_from_slice(&keycode.to_le_bytes());
    b.push(ascii);
    b
}

pub fn encode_close(wid: u32) -> Vec<u8> {
    let mut b = alloc::vec![6u8];
    b.extend_from_slice(&wid.to_le_bytes());
    b
}

pub fn encode_resize(wid: u32, w: u32, h: u32) -> Vec<u8> {
    let mut b = alloc::vec![7u8];
    b.extend_from_slice(&wid.to_le_bytes());
    b.extend_from_slice(&w.to_le_bytes());
    b.extend_from_slice(&h.to_le_bytes());
    b
}
