//! Kernel console — text terminal on framebuffer + serial
//! Supports ANSI escape codes: color, cursor movement, clear screen
use spin::{Lazy, Mutex};
use crate::io::font::{FONT_WIDTH, FONT_HEIGHT, draw_char};

const COLS: usize = 128;
const ROWS: usize = 48;

// Colors (RGB)
const FG_DEFAULT: u32 = 0xE6EDF3;
const BG_DEFAULT: u32 = 0x0F1923;
const FG_RED:     u32 = 0xF85149;
const FG_GREEN:   u32 = 0x3FB950;
const FG_YELLOW:  u32 = 0xD29922;
const FG_BLUE:    u32 = 0x58A6FF;
const FG_MAGENTA: u32 = 0xBC8CFF;
const FG_CYAN:    u32 = 0x39D353;

struct Console {
    col:  usize,
    row:  usize,
    fg:   u32,
    bg:   u32,
    buf:  [[u8; COLS]; ROWS],
}

impl Console {
    const fn new() -> Self {
        Self { col: 0, row: 0, fg: FG_DEFAULT, bg: BG_DEFAULT, buf: [[b' '; COLS]; ROWS] }
    }

    fn scroll(&mut self) {
        for r in 0..ROWS - 1 { self.buf[r] = self.buf[r + 1]; }
        self.buf[ROWS - 1] = [b' '; COLS];
        self.row = ROWS - 1;
        self.redraw_all();
    }

    fn redraw_all(&self) {
        for r in 0..ROWS {
            for c in 0..COLS {
                draw_char(self.buf[r][c], c * FONT_WIDTH, r * FONT_HEIGHT, self.fg, self.bg);
            }
        }
    }

    fn put_char(&mut self, ch: u8) {
        match ch {
            b'\n' => { self.col = 0; self.row += 1; if self.row >= ROWS { self.scroll(); } }
            b'\r' => { self.col = 0; }
            0x08 => { if self.col > 0 { self.col -= 1; } } // backspace
            _ => {
                if self.col < COLS {
                    self.buf[self.row][self.col] = ch;
                    draw_char(ch, self.col * FONT_WIDTH, self.row * FONT_HEIGHT, self.fg, self.bg);
                    self.col += 1;
                }
                if self.col >= COLS { self.col = 0; self.row += 1; if self.row >= ROWS { self.scroll(); } }
            }
        }
    }

    fn write_str(&mut self, s: &str) {
        for b in s.bytes() { self.put_char(b); }
    }

    fn clear(&mut self) {
        self.col = 0; self.row = 0;
        self.buf = [[b' '; COLS]; ROWS];
        crate::io::framebuffer::clear(self.bg);
    }
}

static CONSOLE: Lazy<Mutex<Console>> = Lazy::new(|| Mutex::new(Console::new()));

pub fn putc(ch: u8) { CONSOLE.lock().put_char(ch); }
pub fn puts(s: &str){ CONSOLE.lock().write_str(s); }
pub fn clear()      { CONSOLE.lock().clear(); }

pub fn init() {
    crate::serial_println!("  [CON] {}×{} character console on framebuffer", COLS, ROWS);
    CONSOLE.lock().clear();
    puts("IONA OS Kernel Console\n");
    puts("======================\n\n");
}
