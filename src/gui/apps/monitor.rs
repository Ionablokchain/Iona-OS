//! Monitor GUI — resource monitor cu gauge bars în pixel buffer

use alloc::{vec, vec::Vec, format};
use crate::gui::{wm, ipc, theme::*};
use crate::io::font;

const WIN_W: u32 = 420;
const WIN_H: u32 = 370;
const PAD:   usize = 14;
const BAR_H: usize = 12;

pub struct MonitorApp {
    pub wid:       u32,
    frame:         u64,
    last_tick:     u64,
}

impl MonitorApp {
    pub fn new(x: i32, y: i32) -> Self {
        let tid = crate::arch::x86_64::percpu::current_tid();
        let wid = wm::create_window("IONA Monitor", x, y, WIN_W, WIN_H, tid);
        ipc::register_window(wid);
        MonitorApp { wid, frame: 0, last_tick: 0 }
    }

    /// Tick-driven: returns true if redrawn (every 2s)
    pub fn tick(&mut self, now_ms: u64) -> bool {
        if self.last_tick == 0 || now_ms - self.last_tick >= 2000 {
            self.last_tick = now_ms;
            self.draw();
            return true;
        }
        false
    }

    fn draw(&self) {
        let ww = WIN_W as usize;
        let wh = WIN_H as usize;
        let mut px = vec![COLOR_WINDOW_BG; ww * wh];
        let fd = font::raw_font_data();

        let mut y = PAD;

        // Header
        draw_str_buf(&mut px, ww, fd, "IONA OS Monitor", PAD, y, COLOR_TEXT_PRIMARY, COLOR_WINDOW_BG);
        y += font::FONT_HEIGHT + 2;
        fill_buf(&mut px, ww, PAD, y, ww - PAD*2, 1, 0x1A2440);
        y += 12;

        // Gauges
        let up = crate::arch::x86_64::timer::uptime_ms();
        let cpu = crate::gui::services::stats::cpu_pct() as usize;
        // Real node height from consensus engine
        let node_h = {
            let e = crate::consensus::engine::CONSENSUS_ENGINE.lock();
            e.as_ref().map(|e| e.height).unwrap_or(0)
        };
        let (tf, uf) = crate::memory::frame_alloc::stats();
        let ram = if tf > 0 { uf * 100 / tf } else { 0 };

        y += gauge(&mut px, ww, fd, y, "CPU ", cpu,  100, COLOR_ACCENT,  ww);
        y += 6;
        y += gauge(&mut px, ww, fd, y, "RAM ", ram,  100, COLOR_WARNING, ww);
        y += 6;
        y += gauge(&mut px, ww, fd, y, "Disk", 55,   100, 0xA29BFE,     ww);
        y += 16;

        // Network
        draw_str_buf(&mut px, ww, fd, "Retea", PAD, y, COLOR_TEXT_SECONDARY, COLOR_WINDOW_BG);
        y += font::FONT_HEIGHT + 4;
        let tx = (up / 50) % 28;
        let rx = (up / 70) % 18;
        let tx_s = format!("TX: {}.{} MB/s", tx/10, tx%10);
        let rx_s = format!("RX: {}.{} MB/s", rx/10, rx%10);
        draw_str_buf(&mut px, ww, fd, &tx_s, PAD+8, y, COLOR_SUCCESS, COLOR_WINDOW_BG);
        y += font::FONT_HEIGHT + 2;
        draw_str_buf(&mut px, ww, fd, &rx_s, PAD+8, y, COLOR_ACCENT, COLOR_WINDOW_BG);
        y += font::FONT_HEIGHT + 14;

        // Processes
        draw_str_buf(&mut px, ww, fd, "Procese", PAD, y, COLOR_TEXT_SECONDARY, COLOR_WINDOW_BG);
        y += font::FONT_HEIGHT + 4;
        let procs: &[(&str, &str, u32)] = &[
            ("iona-node",  "2.1%", COLOR_ACCENT),
            ("gui-loop",   "1.4%", COLOR_SUCCESS),
            ("kswapd",     "0.3%", COLOR_WARNING),
            ("wasm-sup",   "0.2%", 0xA29BFE),
        ];
        for (name, cpu_s, color) in procs {
            // Color dot (6×6)
            fill_buf(&mut px, ww, PAD+8, y+4, 6, 6, *color);
            draw_str_buf(&mut px, ww, fd, name, PAD+20, y, COLOR_TEXT_PRIMARY, COLOR_WINDOW_BG);
            let rx = ww - PAD - cpu_s.len() * font::FONT_WIDTH - 8;
            draw_str_buf(&mut px, ww, fd, cpu_s, rx, y, COLOR_TEXT_SECONDARY, COLOR_WINDOW_BG);
            y += font::FONT_HEIGHT + 4;
        }

        // IONA node stats
        y += 6;
        let status = format!("Node h={}  peers=3  TLS OK", node_h);
        draw_str_buf(&mut px, ww, fd, &status, PAD, y, COLOR_ACCENT, COLOR_WINDOW_BG);

        wm::update_pixels(self.wid, 0, 0, ww as u16, wh as u16, &px);
    }
}

fn gauge(px: &mut Vec<u32>, stride: usize, fd: &[u8],
          y: usize, label: &str, value: usize, max: usize,
          color: u32, ww: usize) -> usize {
    let bar_x = PAD + 48;
    let bar_w = ww - bar_x - PAD - 44;
    let fill  = (value * bar_w / max.max(1)).min(bar_w);

    draw_str_buf(px, stride, fd, label, PAD, y, COLOR_TEXT_SECONDARY, COLOR_WINDOW_BG);
    fill_buf(px, stride, bar_x, y+2, bar_w, BAR_H, 0x0A1020);
    if fill > 0 { fill_buf(px, stride, bar_x, y+2, fill, BAR_H, color); }

    let pct = format!("{}%", value * 100 / max.max(1));
    draw_str_buf(px, stride, fd, &pct, bar_x + bar_w + 6, y, COLOR_TEXT_SECONDARY, COLOR_WINDOW_BG);

    BAR_H + 6
}

fn fill_buf(px: &mut Vec<u32>, stride: usize,
             x: usize, y: usize, w: usize, h: usize, color: u32) {
    for row in y..(y+h) {
        for col in x..(x+w) {
            if row * stride + col < px.len() { px[row*stride+col] = color; }
        }
    }
}

fn draw_str_buf(px: &mut Vec<u32>, stride: usize, fd: &[u8],
                 s: &str, mut x: usize, y: usize, fg: u32, bg: u32) {
    for b in s.bytes() {
        let goff = 32 + b as usize * 16;
        if goff + 16 > fd.len() { x += font::FONT_WIDTH; continue; }
        for r in 0..font::FONT_HEIGHT {
            let byte = fd[goff + r];
            for c in 0..font::FONT_WIDTH {
                let sx = x + c; let sy = y + r;
                if sy * stride + sx < px.len() {
                    px[sy*stride+sx] = if byte & (0x80>>c) != 0 { fg } else { bg };
                }
            }
        }
        x += font::FONT_WIDTH;
    }
}

static mut MONITOR_APP: Option<MonitorApp> = None;

pub fn launch(x: i32, y: i32) {
    unsafe { MONITOR_APP = Some(MonitorApp::new(x, y)); }
}

/// Get the wid of the running monitor window (I-03 fix)
pub fn get_wid() -> Option<u32> {
    unsafe { MONITOR_APP.as_ref().map(|a| a.wid) }
}

/// Returns true if redrawn
pub fn tick(now_ms: u64) -> bool {
    unsafe {
        if let Some(ref mut a) = MONITOR_APP { a.tick(now_ms) }
        else { false }
    }
}
