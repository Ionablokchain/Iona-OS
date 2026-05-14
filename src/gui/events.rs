//! GUI Event System — unified input event queue
//!
//! All input (mouse, keyboard, timer, GUI) goes through this queue.
//! The GUI loop drains it once per frame.

use alloc::collections::VecDeque;
use spin::{Lazy, Mutex};

#[derive(Clone, Debug)]
pub enum GuiEvent {
    // Mouse events
    MouseMove   { x: i32, y: i32, dx: i16, dy: i16 },
    MouseDown   { x: i32, y: i32, button: MouseBtn },
    MouseUp     { x: i32, y: i32, button: MouseBtn },
    MouseScroll { x: i32, y: i32, dy: i8 },
    // Keyboard events
    KeyDown     { key: Key, ch: Option<char>, mods: Mods },
    KeyUp       { key: Key, mods: Mods },
    // Window lifecycle
    WindowClose    { wid: u32 },
    WindowFocus    { wid: u32 },
    WindowResize   { wid: u32, w: u32, h: u32 },
    // App events (from userspace via IPC)
    AppDraw     { wid: u32, x: u16, y: u16, w: u16, h: u16, pixels: alloc::vec::Vec<u32> },
    AppTitle    { wid: u32, title: alloc::string::String },
    AppClose    { wid: u32 },
    // Timer
    Timer       { id: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MouseBtn { Left, Right, Middle }

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Key {
    Char(char), Enter, Backspace, Delete, Tab, Escape,
    Left, Right, Up, Down, Home, End, PageUp, PageDown,
    F1, F2, F3, F4, F5, F6, F7, F8, F9, F10, F11, F12,
    Ctrl, Alt, Shift, Super,
    Unknown(u8),
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Mods {
    pub ctrl:  bool,
    pub alt:   bool,
    pub shift: bool,
    pub super_key: bool,
}

static EVENT_QUEUE: Lazy<Mutex<VecDeque<GuiEvent>>> =
    Lazy::new(|| Mutex::new(VecDeque::with_capacity(256)));

// Button state tracking (for click detection)
static BTN_STATE: Mutex<[bool; 3]> = Mutex::new([false; 3]);

pub fn init() { crate::serial_println!("  [GUI/EVENTS] event queue initialized"); }

/// Pump raw hardware events into the GUI event queue
/// Called once per frame from gui_loop_task
pub fn pump() {
    // Pump USB HID mouse events (if xHCI present)
    crate::drivers::usb::poll_mouse_hid();

    // Pump PS/2 + HID mouse events
    while let Some(me) = crate::drivers::mouse::poll() {
        let (cx, cy) = crate::drivers::mouse::cursor_pos();
        let x = cx; let y = cy;
        let mut q = EVENT_QUEUE.lock();

        if me.dx != 0 || me.dy != 0 {
            q.push_back(GuiEvent::MouseMove { x, y, dx: me.dx, dy: me.dy });
        }

        let mut state = BTN_STATE.lock();
        let btns = [(me.left, 0, MouseBtn::Left),
                    (me.right, 1, MouseBtn::Right),
                    (me.middle, 2, MouseBtn::Middle)];
        for (pressed, idx, btn) in btns {
            if pressed && !state[idx] {
                q.push_back(GuiEvent::MouseDown { x, y, button: btn });
            } else if !pressed && state[idx] {
                q.push_back(GuiEvent::MouseUp { x, y, button: btn });
            }
            state[idx] = pressed;
        }
        drop(state);

        if me.scroll_dy != 0 {
            q.push_back(GuiEvent::MouseScroll { x, y, dy: me.scroll_dy });
        }
    }

    // Pump keyboard events
    let mut mods = Mods::default();
    while let Some(raw) = crate::drivers::keyboard::read_char() {
        let key = scancode_to_key(raw, &mut mods);
        let ch  = if raw.is_ascii_graphic() || raw == b' ' { Some(raw as char) } else { None };
        EVENT_QUEUE.lock().push_back(GuiEvent::KeyDown { key, ch, mods });
    }
}

fn scancode_to_key(raw: u8, mods: &mut Mods) -> Key {
    match raw {
        b'\n' => Key::Enter,
        0x08  => Key::Backspace,
        0x7F  => Key::Delete,
        b'\t' => Key::Tab,
        0x1B  => Key::Escape,
        c if c.is_ascii_graphic() || c == b' ' => Key::Char(c as char),
        other => Key::Unknown(other),
    }
}

/// Drain one event from the queue
pub fn next() -> Option<GuiEvent> { EVENT_QUEUE.lock().pop_front() }

/// Push a synthetic event (e.g. from userspace IPC)
pub fn push(ev: GuiEvent) {
    let mut q = EVENT_QUEUE.lock();
    if q.len() < 512 { q.push_back(ev); }
}

/// Check if queue has events
pub fn has_events() -> bool { !EVENT_QUEUE.lock().is_empty() }
