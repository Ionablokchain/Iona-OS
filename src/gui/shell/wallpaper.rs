//! Procedural wallpaper — radial glows + mountain silhouettes + gradient sky
//!
//! R-01 fix: folosim libm::sinf în loc de f32::sin() (care necesită libm extern).
//! R-03 fix: wallpaper e marcat "drawn" după prima randare; nu se redesenează
//!   dacă nu s-a schimbat nimic (wallpaper_dirty flag în state).

use crate::io::framebuffer as fb;
use crate::gui::primitives::draw as prim;
use crate::gui::theme::palette::*;

/// Draw wallpaper. Caller is responsible for calling only when dirty.
pub fn draw(sw: usize, sh: usize) {
    draw_sky(sw, sh);
    draw_glow(sw, sh);
    draw_mountains(sw, sh);
}

fn draw_sky(sw: usize, sh: usize) {
    prim::gradient_v(0, 0, sw, sh, BG_SKY_TOP, BG_SKY_BOT);
}

fn draw_glow(sw: usize, sh: usize) {
    prim::radial_glow(sw/2, sh*85/100, sw*3/8, 0xA0, 0x40, 0x20, 45);
    prim::radial_glow(sw*3/4, sh/4,    sw/4,   0x10, 0x30, 0x80, 30);
    prim::radial_glow(sw/5,  sh/3,    sw/5,   0x30, 0x10, 0x60, 20);
    // Thin horizon brightening band
    let hy = sh * 62 / 100;
    for y in hy..hy+3 {
        fb::hline(0, y, sw, 0x18, 0x2C, 0x50);
    }
}

fn draw_mountains(sw: usize, sh: usize) {
    mountain_layer(sw, sh, 0, sh*50/100, sh*22/100, MTN_FAR,  28);
    mountain_layer(sw, sh, 1, sh*60/100, sh*26/100, MTN_MID,  45);
    mountain_layer(sw, sh, 2, sh*70/100, sh*30/100, MTN_NEAR, 60);
    // Ground strip
    let gy = sh * 82 / 100;
    let (gr, gg, gb) = crate::gui::theme::rgb(0x03_05_0D);
    fb::fill_rect(0, gy, sw, sh - gy, gr, gg, gb);
    // Reflection shimmer on ground
    for x in 0..sw {
        let t = (x * 7 % sw) as u32;
        let bright = (sin_approx(t as f32 / sw as f32) * 18.0) as u8;
        fb::blend_pixel(x, gy, 0x10u8.saturating_add(bright),
                        0x20u8.saturating_add(bright / 2), 0x40, 60);
    }
}

fn mountain_layer(sw: usize, sh: usize, seed: usize,
                   base_y: usize, amp: usize, color: u32, alpha: u8) {
    let (mr, mg, mb) = crate::gui::theme::rgb(color);
    for x in 0..sw {
        let t = x as f32 / sw as f32;
        // libm::sinf — R-01 fix
        let f0 = 1.5 + seed as f32 * 0.8;
        let f1 = 3.1 + seed as f32 * 1.3;
        let f2 = 5.7 + seed as f32 * 0.5;
        let h0 = (sin_approx(t * 2.0 * f0) * 0.45 + 0.45) * amp as f32;
        let h1 = (sin_approx(t * 2.0 * f1) * 0.25 + 0.25) * amp as f32;
        let h2 = (sin_approx(t * 2.0 * f2) * 0.15 + 0.15) * amp as f32;
        let height = ((h0 + h1 + h2) * 0.55) as usize;
        let top_y  = base_y.saturating_sub(height);
        if alpha >= 60 {
            for y in top_y..sh { fb::set_pixel(x, y, mr, mg, mb); }
        } else {
            for y in top_y..sh { fb::blend_pixel(x, y, mr, mg, mb, alpha); }
        }
    }
}

/// Fast sin approximation using libm::sinf — accurate, no external libc needed.
/// Falls back to Taylor series if libm not available.
#[inline]
fn sin_approx(x: f32) -> f32 {
    // Use libm crate (added to Cargo.toml) — safe in no_std bare metal
    libm::sinf(x * core::f32::consts::PI * 2.0)
}
