//! Core draw primitives — all write to back buffer via fb::*
//!
//! These extend fb::* with higher-level operations needed by the shell:
//!   fill_card    — rounded rect + border + soft shadow
//!   soft_shadow  — layered alpha-blended shadow
//!   gradient_h   — horizontal linear gradient
//!   gradient_v   — vertical linear gradient
//!   radial_glow  — circular glow emanating from center point

use crate::io::framebuffer as fb;
use super::super::theme::rgb;

/// Draw a glass card: fill rounded rect + 1px border + shadow
pub fn fill_card(x: usize, y: usize, w: usize, h: usize,
                  fill: u32, border: u32, radius: usize, shadow_alpha: u8) {
    if shadow_alpha > 0 {
        soft_shadow(x, y, w, h, radius, 4, 6, shadow_alpha);
    }
    let (fr, fg, fb_) = rgb(fill);
    fb::fill_rect_rounded(x, y, w, h, fr, fg, fb_, radius);
    if border != fill {
        let (er, eg, eb) = rgb(border);
        stroke_rounded(x, y, w, h, er, eg, eb, radius);
    }
}

/// Soft shadow: N layers of blended dark rects offset by (dx,dy)
pub fn soft_shadow(x: usize, y: usize, w: usize, h: usize,
                    radius: usize, dx: usize, dy: usize, base_alpha: u8) {
    let spread = 3usize;
    let layers = 5usize;
    for i in 0..layers {
        let alpha = base_alpha.saturating_sub((i as u8) * (base_alpha / layers as u8));
        let sx = x.saturating_sub(i) + dx;
        let sy = y.saturating_sub(i) + dy;
        let sw = w + i * 2;
        let sh_h = h + i * 2;
        let (sw_, sh_) = fb::size();
        if sx >= sw_ || sy >= sh_ { continue; }
        let cw = sw.min(sw_.saturating_sub(sx));
        let ch = sh_h.min(sh_.saturating_sub(sy));
        for row in sy..(sy+ch) {
            for col in sx..(sx+cw) {
                fb::blend_pixel(col, row, 2, 4, 8, alpha.saturating_sub(i as u8 * 10));
            }
        }
    }
}

/// Stroke (outline) a rounded rect
pub fn stroke_rounded(x: usize, y: usize, w: usize, h: usize,
                       r: u8, g: u8, b: u8, radius: usize) {
    if w < 2 || h < 2 { return; }
    fb::hline(x + radius, y,     w.saturating_sub(radius*2), r, g, b);
    fb::hline(x + radius, y+h-1, w.saturating_sub(radius*2), r, g, b);
    fb::vline(x,     y + radius, h.saturating_sub(radius*2), r, g, b);
    fb::vline(x+w-1, y + radius, h.saturating_sub(radius*2), r, g, b);
    // Corner approximation (4 short diagonal lines)
    for i in 0..radius.min(4) {
        let f = radius - i;
        fb::set_pixel(x+i, y+f, r, g, b);
        fb::set_pixel(x+w-1-i, y+f, r, g, b);
        fb::set_pixel(x+i, y+h-1-f, r, g, b);
        fb::set_pixel(x+w-1-i, y+h-1-f, r, g, b);
    }
}

/// Horizontal gradient: left_color → right_color across rect
pub fn gradient_h(x: usize, y: usize, w: usize, h: usize,
                   left: u32, right: u32) {
    let (lr, lg, lb) = rgb(left);
    let (rr, rg, rb) = rgb(right);
    let (sw_, sh_) = fb::size();
    for col in x..(x+w).min(sw_) {
        let t = (col - x) as u32 * 255 / w.max(1) as u32;
        let it = 255 - t;
        let r = ((lr as u32 * it + rr as u32 * t) / 255) as u8;
        let g = ((lg as u32 * it + rg as u32 * t) / 255) as u8;
        let b = ((lb as u32 * it + rb as u32 * t) / 255) as u8;
        for row in y..(y+h).min(sh_) {
            fb::set_pixel(col, row, r, g, b);
        }
    }
}

/// Vertical gradient: top_color → bot_color
pub fn gradient_v(x: usize, y: usize, w: usize, h: usize,
                   top: u32, bot: u32) {
    let (tr, tg, tb_) = rgb(top);
    let (br, bg, bb) = rgb(bot);
    let (sw_, sh_) = fb::size();
    for row in y..(y+h).min(sh_) {
        let t = (row - y) as u32 * 255 / h.max(1) as u32;
        let it = 255 - t;
        let r = ((tr as u32 * it + br as u32 * t) / 255) as u8;
        let g = ((tg as u32 * it + bg as u32 * t) / 255) as u8;
        let b = ((tb_ as u32 * it + bb as u32 * t) / 255) as u8;
        fb::hline(x, row, w.min(sw_.saturating_sub(x)), r, g, b);
    }
}

/// Radial glow: blends color outward from (cx,cy) with given radius and alpha
pub fn radial_glow(cx: usize, cy: usize, radius: usize,
                    r: u8, g: u8, b: u8, max_alpha: u8) {
    let (sw_, sh_) = fb::size();
    let r2 = (radius * radius) as i64;
    let y0 = cy.saturating_sub(radius);
    let y1 = (cy + radius).min(sh_);
    let x0 = cx.saturating_sub(radius);
    let x1 = (cx + radius).min(sw_);
    for py in y0..y1 {
        for px in x0..x1 {
            let dx = px as i64 - cx as i64;
            let dy = py as i64 - cy as i64;
            let d2 = dx*dx + dy*dy;
            if d2 < r2 {
                let dist = (d2 * 255 / r2.max(1)) as u8;
                let alpha = max_alpha.saturating_sub(dist);
                if alpha > 0 {
                    fb::blend_pixel(px, py, r, g, b, alpha);
                }
            }
        }
    }
}
