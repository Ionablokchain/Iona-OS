//! Framebuffer — double buffer + dirty rect invalidation
//!
//! Design:
//!   BACK_BUF: Vec<u32>           – toate desenările merg aici (ARGB 32bpp)
//!   DIRTY_LIST: Vec<DirtyRect>   – zone marcate ca modificate (max 32)
//!   present()                    – copiază NUMAI zonele dirty în VRAM
//!   present_full()               – full blit (la boot sau dacă dirty > 32)
//!
//! Beneficiu dirty rects:
//!   Desktop static    → 0 bytes copiat în VRAM per frame
//!   Cursor drag       → ~14×22px per frame (nu 1920×1080)
//!   Fereastră mișcată → numai dreptunghiul frame-ului (nu tot ecranul)
//!
//! Merge strategy: dacă două rect-uri se suprapun sau sunt adiacente,
//!   le unim într-un bounding box. Dacă lista depășește 32, fallback full.

use bootloader_api::info::{FrameBuffer, PixelFormat};
use spin::{Mutex, Lazy};
use alloc::vec::Vec;

// ── Hardware framebuffer ──────────────────────────────────────────────────────
struct HwFb {
    base:   *mut u8,
    width:  usize,
    height: usize,
    stride: usize,
    bpp:    usize,
    format: PixelFormat,
}
unsafe impl Send for HwFb {}
static HW: Mutex<Option<HwFb>> = Mutex::new(None);

// ── Back buffer ───────────────────────────────────────────────────────────────
struct BackBuf {
    pixels: Vec<u32>,
    width:  usize,
    height: usize,
}
static BACK: Lazy<Mutex<BackBuf>> = Lazy::new(||
    Mutex::new(BackBuf { pixels: Vec::new(), width: 0, height: 0 })
);

// ── Dirty rect list ───────────────────────────────────────────────────────────
#[derive(Clone, Copy, Debug)]
pub struct DirtyRect { pub x: usize, pub y: usize, pub w: usize, pub h: usize }

impl DirtyRect {
    pub fn right (&self) -> usize { self.x + self.w }
    pub fn bottom(&self) -> usize { self.y + self.h }

    /// True if rectangles overlap or touch (horizontally or vertically adjacent)
    fn overlaps_or_adjacent(&self, o: &DirtyRect) -> bool {
        self.x <= o.right()  && o.x <= self.right() &&
        self.y <= o.bottom() && o.y <= self.bottom()
    }

    /// Merge into bounding box
    fn merge(&self, o: &DirtyRect) -> DirtyRect {
        let x1 = self.x.min(o.x);
        let y1 = self.y.min(o.y);
        let x2 = self.right().max(o.right());
        let y2 = self.bottom().max(o.bottom());
        DirtyRect { x: x1, y: y1, w: x2-x1, h: y2-y1 }
    }
}

const MAX_DIRTY: usize = 32;

struct DirtyList {
    rects:    [DirtyRect; MAX_DIRTY],
    count:    usize,
    full:     bool,   // if true, next present() will do full blit
}

impl DirtyList {
    const fn new() -> Self {
        Self {
            rects: [DirtyRect{x:0,y:0,w:0,h:0}; MAX_DIRTY],
            count: 0,
            full:  true,  // boot = full blit
        }
    }

    fn clear(&mut self) { self.count = 0; self.full = false; }

    fn push(&mut self, mut r: DirtyRect, sw: usize, sh: usize) {
        if self.full { return; }
        // Clamp to screen
        if r.x >= sw || r.y >= sh { return; }
        r.w = r.w.min(sw - r.x);
        r.h = r.h.min(sh - r.y);
        if r.w == 0 || r.h == 0 { return; }

        // Try to merge with existing rect
        for i in 0..self.count {
            if self.rects[i].overlaps_or_adjacent(&r) {
                self.rects[i] = self.rects[i].merge(&r);
                // Re-merge with other existing rects
                let merged = self.rects[i];
                let mut j = 0;
                while j < self.count {
                    if j != i && self.rects[j].overlaps_or_adjacent(&merged) {
                        self.rects[i] = self.rects[i].merge(&self.rects[j]);
                        self.rects[j] = self.rects[self.count-1];
                        self.count -= 1;
                    } else { j += 1; }
                }
                return;
            }
        }

        // Add new rect
        if self.count < MAX_DIRTY {
            self.rects[self.count] = r;
            self.count += 1;
        } else {
            // Too many rects → fallback to full blit
            self.full = true;
            self.count = 0;
        }
    }

    fn is_dirty(&self) -> bool { self.full || self.count > 0 }
}

static DIRTY: Mutex<DirtyList> = Mutex::new(DirtyList::new());

// ── Init ──────────────────────────────────────────────────────────────────────
pub fn init(fb: &'static mut FrameBuffer) {
    let info = fb.info();
    let base = fb.buffer_mut().as_mut_ptr();
    let w = info.width; let h = info.height;
    *HW.lock() = Some(HwFb {
        base, width: w, height: h,
        stride: info.stride, bpp: info.bytes_per_pixel,
        format: info.pixel_format,
    });
    let mut back = BACK.lock();
    back.width  = w; back.height = h;
    back.pixels = alloc::vec![0x000A0F1Eu32; w * h];
    DIRTY.lock().full = true;  // first frame = full blit
    crate::serial_println!("  [FB] double buffer {}x{}, dirty-rect ({} slots)", w, h, MAX_DIRTY);
}

// ── Mark dirty ────────────────────────────────────────────────────────────────
pub fn mark_dirty(x: usize, y: usize, w: usize, h: usize) {
    let (sw, sh) = size();
    DIRTY.lock().push(DirtyRect{x,y,w,h}, sw, sh);
}

/// Mark entire screen dirty (after desktop redraw, resize, etc.)
pub fn mark_all_dirty() { DIRTY.lock().full = true; }

// ── Draw API — all go to back buffer ─────────────────────────────────────────
#[inline(always)]
pub fn set_pixel(x: usize, y: usize, r: u8, g: u8, b: u8) {
    let mut back = BACK.lock();
    let w = back.width;
    let h = back.height;
    if x < w && y < h {
        back.pixels[y * w + x] = pack(r, g, b);
    }
}

#[inline(always)]
fn pack(r: u8, g: u8, b: u8) -> u32 { ((r as u32)<<16)|((g as u32)<<8)|b as u32 }

pub fn fill_rect(x: usize, y: usize, w: usize, h: usize, r: u8, g: u8, b: u8) {
    let color = pack(r,g,b);
    let mut back = BACK.lock();
    let bw = back.width; let bh = back.height;
    if x >= bw || y >= bh { return; }
    let x2 = (x+w).min(bw); let y2 = (y+h).min(bh);
    for row in y..y2 {
        let base = row * bw;
        for col in x..x2 { back.pixels[base+col] = color; }
    }
}

pub fn clear(rgb_val: u32) {
    let (r,g,b) = ((rgb_val>>16)as u8,((rgb_val>>8)&0xFF)as u8,(rgb_val&0xFF)as u8);
    let color = pack(r,g,b);
    let mut back = BACK.lock();
    back.pixels.fill(color);
    mark_all_dirty();
}

pub fn blend_pixel(x: usize, y: usize, r: u8, g: u8, b: u8, alpha: u8) {
    let a = alpha as u32; let ia = 255 - a;
    let mut back = BACK.lock();
    let w = back.width;
    let h = back.height;
    if x >= w || y >= h { return; }
    let idx = y * w + x;
    let dst = back.pixels[idx];
    let nr = ((r as u32 * a + ((dst>>16)&0xFF) * ia) / 255) as u8;
    let ng = ((g as u32 * a + ((dst>> 8)&0xFF) * ia) / 255) as u8;
    let nb = ((b as u32 * a + ( dst     &0xFF) * ia) / 255) as u8;
    back.pixels[idx] = pack(nr,ng,nb);
}

pub fn fill_rect_rounded(x: usize, y: usize, w: usize, h: usize,
                          r: u8, g: u8, b: u8, radius: usize) {
    if w == 0 || h == 0 { return; }
    if radius == 0 || w < 2*radius+1 || h < 2*radius+1 {
        fill_rect(x,y,w,h,r,g,b); return;
    }
    let rr = radius.min(w/2).min(h/2);
    fill_rect(x,      y+rr,  w,      h-2*rr, r,g,b);
    fill_rect(x+rr,   y,     w-2*rr, rr,     r,g,b);
    fill_rect(x+rr,   y+h-rr,w-2*rr, rr,     r,g,b);
    for cr in 0..rr {
        let span = rr - cr;
        fill_rect(x+rr-span, y+rr-cr-1, span, 1, r,g,b);
        fill_rect(x+w-rr,    y+rr-cr-1, span, 1, r,g,b);
        fill_rect(x+rr-span, y+h-rr+cr, span, 1, r,g,b);
        fill_rect(x+w-rr,    y+h-rr+cr, span, 1, r,g,b);
    }
}

pub fn draw_rect(x: usize, y: usize, w: usize, h: usize, r: u8, g: u8, b: u8) {
    if w == 0 || h == 0 { return; }
    fill_rect(x,        y,      w, 1, r,g,b);
    fill_rect(x,        y+h-1,  w, 1, r,g,b);
    fill_rect(x,        y,      1, h, r,g,b);
    fill_rect(x+w-1,    y,      1, h, r,g,b);
}
pub fn hline(x: usize, y: usize, w: usize, r: u8, g: u8, b: u8) { fill_rect(x,y,w,1,r,g,b); }
pub fn vline(x: usize, y: usize, h: usize, r: u8, g: u8, b: u8) { fill_rect(x,y,1,h,r,g,b); }

pub fn blit_mask(px: usize, py: usize, w: usize, h: usize,
                 mask: &[u8], r: u8, g: u8, b: u8) {
    let color = pack(r,g,b);
    let bpr = (w+7)/8;
    let mut back = BACK.lock();
    let bw = back.width; let bh = back.height;
    for row in 0..h {
        let sy = py+row; if sy >= bh { break; }
        for col in 0..w {
            let sx = px+col; if sx >= bw { continue; }
            let bi = row*bpr + col/8;
            if bi < mask.len() && mask[bi] & (0x80>>(col%8)) != 0 {
                back.pixels[sy*bw+sx] = color;
            }
        }
    }
}

pub fn blit_pixels(dx: usize, dy: usize, w: usize, h: usize,
                   pixels: &[u32], stride: usize) {
    let mut back = BACK.lock();
    let bw = back.width; let bh = back.height;
    if dx >= bw || dy >= bh { return; }
    let cols = w.min(bw-dx); let rows = h.min(bh-dy);
    for row in 0..rows {
        let src = row*stride;
        let dst = (dy+row)*bw+dx;
        let n = cols.min(pixels.len().saturating_sub(src));
        if dst+n <= back.pixels.len() && src+n <= pixels.len() {
            back.pixels[dst..dst+n].copy_from_slice(&pixels[src..src+n]);
        }
    }
}

pub fn draw_cursor(x: usize, y: usize) {
    use crate::io::font::{CURSOR_W, CURSOR_H, CURSOR_MASK, CURSOR_OUTLINE};
    blit_mask(x+1, y+1, CURSOR_W, CURSOR_H, &CURSOR_MASK,    30,30,30);
    blit_mask(x,   y,   CURSOR_W, CURSOR_H, &CURSOR_MASK,   255,255,255);
    blit_mask(x,   y,   CURSOR_W, CURSOR_H, &CURSOR_OUTLINE,  0,  0,  0);
    mark_dirty(x, y, CURSOR_W+2, CURSOR_H+2);
}

pub fn erase_cursor(x: usize, y: usize, bg_rgb: u32) {
    use crate::io::font::{CURSOR_W, CURSOR_H};
    let (r,g,b) = ((bg_rgb>>16)as u8,((bg_rgb>>8)&0xFF)as u8,(bg_rgb&0xFF)as u8);
    fill_rect(x, y, CURSOR_W+2, CURSOR_H+2, r, g, b);
    mark_dirty(x, y, CURSOR_W+2, CURSOR_H+2);
}

pub fn width()  -> usize { BACK.lock().width  }
pub fn height() -> usize { BACK.lock().height }
pub fn size()   -> (usize, usize) { let b=BACK.lock(); (b.width, b.height) }

// ── PRESENT ───────────────────────────────────────────────────────────────────
/// Partial present: copiază numai dirty rects din back buffer în VRAM.
/// Dacă full=true sau dirty>MAX_DIRTY, copiază tot ecranul.
pub fn present() {
    let mut dirty = DIRTY.lock();
    if !dirty.is_dirty() { return; }

    let hw_lock = HW.lock();
    let hw = match hw_lock.as_ref() { Some(h) => h, None => return };
    let back = BACK.lock();
    if back.pixels.is_empty() { return; }

    if dirty.full {
        blit_region_to_vram(hw, &back, 0, 0, back.width, back.height);
    } else {
        let count = dirty.count;
        for i in 0..count {
            let dr = dirty.rects[i];
            blit_region_to_vram(hw, &back, dr.x, dr.y, dr.w, dr.h);
        }
    }
    dirty.clear();
}

/// Force full blit (use at boot, after resize, or after full desktop redraw)
pub fn present_full() {
    DIRTY.lock().full = true;
    present();
}

unsafe fn write_pixel_to_vram(base: *mut u8, off: usize, bpp: usize, px: u32, fmt: PixelFormat) {
    let r = ((px>>16)&0xFF) as u8;
    let g = ((px>> 8)&0xFF) as u8;
    let b = ( px     &0xFF) as u8;
    match fmt {
        PixelFormat::Bgr => {
            *base.add(off)   = b;
            *base.add(off+1) = g;
            *base.add(off+2) = r;
            if bpp >= 4 { *base.add(off+3) = 0xFF; }
        }
        PixelFormat::Rgb => {
            *base.add(off)   = r;
            *base.add(off+1) = g;
            *base.add(off+2) = b;
            if bpp >= 4 { *base.add(off+3) = 0xFF; }
        }
        _ => {
            *base.add(off)   = b;
            *base.add(off+1) = g;
            *base.add(off+2) = r;
        }
    }
}

fn blit_region_to_vram(hw: &HwFb, back: &BackBuf,
                        x: usize, y: usize, w: usize, h: usize) {
    let x2 = (x+w).min(hw.width).min(back.width);
    let y2 = (y+h).min(hw.height).min(back.height);
    if x >= x2 || y >= y2 { return; }
    unsafe {
        for row in y..y2 {
            let src_base = row * back.width + x;
            // stride is in pixels; convert to bytes for VRAM offset
            let dst_base = (row * hw.stride + x) * hw.bpp;
            for col in 0..(x2-x) {
                let px = back.pixels[src_base + col];
                write_pixel_to_vram(hw.base, dst_base + col*hw.bpp, hw.bpp, px, hw.format);
            }
        }
    }
}

/// Draw IONA OS boot splash screen
pub fn draw_boot_splash() {
    let w = width(); let h = height();
    if w == 0 || h == 0 { return; }
    // Fill with dark blue background
    fill_rect(0, 0, w, h, 0x0A, 0x0E, 0x1A);
    // Draw IONA logo — centered text
    let logo = "IONA OS";
    let lw   = logo.len() * 8;
    let lx   = (w.saturating_sub(lw)) / 2;
    let ly   = h / 2 - 20;
    draw_text_col(lx, ly, logo, 0x4A, 0x9E, 0xFF);
    let sub  = "v0.6.0 — Booting...";
    let sw   = sub.len() * 8;
    let sx   = (w.saturating_sub(sw)) / 2;
    draw_text_col(sx, ly + 20, sub, 0x80, 0x80, 0xA0);
    present();
}

pub fn draw_logo() { draw_boot_splash(); }
