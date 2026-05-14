//! Lock Screen — password entry, covers all other content
//!
//! FIX: static mut String (non-Sync, UB) replaced with fixed [u8; 64] arrays.
//! Sync-safe: all access is single-threaded (GUI loop) via unsafe blocks.
use crate::io::{font, framebuffer as fb};

// Fixed-size arrays — no heap, no String, no UB
static mut LOCKED:      bool     = false;
static mut PASSWORD:    [u8; 64] = [0u8; 64];  // empty = no password (any Enter unlocks)
static mut PASSWORD_LEN: usize   = 0;
static mut INPUT:       [u8; 64] = [0u8; 64];
static mut INPUT_LEN:   usize    = 0;

pub fn lock() {
    unsafe {
        LOCKED = true;
        INPUT = [0u8; 64];
        INPUT_LEN = 0;
    }
    crate::serial_println!("[LOCK] screen locked");
}

/// Set a password (empty = any key unlocks)
pub fn set_password(pass: &str) {
    unsafe {
        PASSWORD = [0u8; 64];
        PASSWORD_LEN = 0;
        for (i, &b) in pass.as_bytes().iter().take(64).enumerate() {
            PASSWORD[i] = b;
            PASSWORD_LEN += 1;
        }
    }
}

pub fn is_locked() -> bool { unsafe { LOCKED } }

/// Returns true = event consumed by lock screen
pub fn on_key(ascii: u8) -> bool {
    unsafe {
        if !LOCKED { return false; }
        match ascii {
            b'\r' | b'\n' => {
                // Check password: empty password → any Enter unlocks
                let ok = PASSWORD_LEN == 0
                    || (INPUT_LEN == PASSWORD_LEN
                        && INPUT[..INPUT_LEN] == PASSWORD[..PASSWORD_LEN]);
                if ok {
                    LOCKED = false;
                    INPUT = [0u8; 64];
                    INPUT_LEN = 0;
                    crate::serial_println!("[LOCK] unlocked");
                } else {
                    INPUT = [0u8; 64];
                    INPUT_LEN = 0;
                    crate::serial_println!("[LOCK] wrong password");
                }
            }
            0x08 | 0x7F => {  // Backspace
                if INPUT_LEN > 0 { INPUT_LEN -= 1; INPUT[INPUT_LEN] = 0; }
            }
            c if c >= 0x20 && INPUT_LEN < 63 => {
                INPUT[INPUT_LEN] = c;
                INPUT_LEN += 1;
            }
            _ => {}
        }
        true
    }
}

pub fn draw() {
    unsafe {
        if !LOCKED { return; }
        let (sw, sh) = fb::size();
        let fd = font::raw_font_data();
        fb::fill_rect(0, 0, sw, sh, 0x04, 0x07, 0x12);
        // IONA logo large — centered
        let lx = sw.saturating_sub(7 * font::FONT_WIDTH * 2) / 2;
        let ly = sh / 4;
        // 2× scale title via doubled pixel rows
        draw_2x(fd, "IONA OS", lx, ly, 0x3D8EF0, 0x04_07_12);
        // Time
        let ts = crate::arch::x86_64::timer::uptime_ms();
        let (h_, m_, s_) = (ts/3600000 % 24, ts/60000 % 60, ts/1000 % 60);
        let mut tbuf = [0u8; 8];
        write_time(&mut tbuf, h_ as u8, m_ as u8, s_ as u8);
        let time_str = core::str::from_utf8(&tbuf).unwrap_or("00:00:00");
        let tx = sw.saturating_sub(time_str.len() * font::FONT_WIDTH) / 2;
        draw_str_fb(fd, time_str, tx, ly + 38, 0xE8EDF8, 0x04_07_12);
        // Password box
        let bw = 260usize; let bh = 34usize;
        let bx = sw.saturating_sub(bw) / 2;
        let by = sh / 2 + 20;
        fb::draw_rect(bx, by, bw, bh, 0x1E, 0x30, 0x50);
        fb::fill_rect(bx+1, by+1, bw-2, bh-2, 0x0A, 0x15, 0x20);
        // Show dots for typed chars
        if INPUT_LEN == 0 {
            draw_str_fb(fd, "Enter password (Enter to unlock)", bx+8, by+9, 0x44_55_66, 0x0A_15_20);
        } else {
            let dots: [u8; 64] = {
                let mut d = [b' '; 64];
                for i in 0..INPUT_LEN.min(32) { d[i] = 0xE2; } // UTF8 bullet approx
                d
            };
            for i in 0..INPUT_LEN.min(32) {
                fb::set_pixel(bx + 12 + i * 8, by + 13, 0xE8, 0xED, 0xF8);
                fb::set_pixel(bx + 12 + i * 8, by + 14, 0xE8, 0xED, 0xF8);
                fb::set_pixel(bx + 13 + i * 8, by + 13, 0xE8, 0xED, 0xF8);
                fb::set_pixel(bx + 13 + i * 8, by + 14, 0xE8, 0xED, 0xF8);
            }
        }
        // Hint
        draw_str_fb(fd, "Ctrl+Alt+L to lock  |  Enter to unlock", 
                    sw.saturating_sub(38*font::FONT_WIDTH)/2, by+44, 0x33_44_55, 0x04_07_12);
    }
}

fn write_time(buf: &mut [u8; 8], h: u8, m: u8, s: u8) {
    buf[0] = b'0' + h / 10; buf[1] = b'0' + h % 10;
    buf[2] = b':';
    buf[3] = b'0' + m / 10; buf[4] = b'0' + m % 10;
    buf[5] = b':';
    buf[6] = b'0' + s / 10; buf[7] = b'0' + s % 10;
}

fn draw_str_fb(fd: &[u8], s: &str, mut x: usize, y: usize, fg: u32, bg: u32) {
    let (fr,fg_,fb_) = crate::gui::theme::rgb(fg);
    let (br,bg_,bb_) = crate::gui::theme::rgb(bg);
    for b in s.bytes() {
        let go = 32 + b as usize * 16;
        if go + 16 > fd.len() { x += font::FONT_WIDTH; continue; }
        for r in 0..font::FONT_HEIGHT {
            let byte = fd[go + r];
            for c in 0..font::FONT_WIDTH {
                if byte & (0x80 >> c) != 0 { fb::set_pixel(x+c, y+r, fr, fg_, fb_); }
                else                        { fb::set_pixel(x+c, y+r, br, bg_, bb_); }
            }
        }
        x += font::FONT_WIDTH;
    }
}

fn draw_2x(fd: &[u8], s: &str, mut x: usize, y: usize, fg: u32, bg: u32) {
    let (fr,fg_,fb_) = crate::gui::theme::rgb(fg);
    let (br,bg_,bb_) = crate::gui::theme::rgb(bg);
    for b in s.bytes() {
        let go = 32 + b as usize * 16;
        if go + 16 > fd.len() { x += 16; continue; }
        for r in 0..16usize {
            let byte = fd[go + r];
            for c in 0..8usize {
                let (pr,pg,pb) = if byte & (0x80>>c) != 0 { (fr,fg_,fb_) } else { (br,bg_,bb_) };
                fb::set_pixel(x+c*2,   y+r*2,   pr,pg,pb);
                fb::set_pixel(x+c*2+1, y+r*2,   pr,pg,pb);
                fb::set_pixel(x+c*2,   y+r*2+1, pr,pg,pb);
                fb::set_pixel(x+c*2+1, y+r*2+1, pr,pg,pb);
            }
        }
        x += 16;
    }
}

/// Called each frame — draws if locked
pub fn tick(_now: u64) -> bool {
    if is_locked() { draw(); true } else { false }
}

/// Launch lock screen (lock immediately)
pub fn launch(_x: i32, _y: i32) {
    lock();
}

pub fn get_wid() -> Option<u32> { None } // lock screen has no window
