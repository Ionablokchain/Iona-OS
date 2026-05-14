//! Text rendering helpers — wrappers around font::draw_string
use crate::io::font;
use super::metrics;
use crate::io::framebuffer as fb;

/// Draw text at (x,y)
pub fn draw_text(x: usize, y: usize, s: &str, fg: u32, bg: u32) {
    font::draw_string(s, x, y, fg, bg);
}

/// Draw text centered horizontally in a rect
pub fn draw_text_centered(rx: usize, ry: usize, rw: usize, rh: usize,
                            s: &str, fg: u32, bg: u32) {
    let tw = metrics::text_width(s);
    let tx = rx + rw.saturating_sub(tw) / 2;
    let ty = ry + rh.saturating_sub(font::FONT_HEIGHT) / 2;
    font::draw_string(s, tx, ty, fg, bg);
}

/// Draw text clipped to rect width (truncates)
pub fn draw_text_clipped(rx: usize, ry: usize, rw: usize, _rh: usize,
                           s: &str, fg: u32, bg: u32) {
    let clipped = metrics::truncate_to_width(s, rw);
    font::draw_string(clipped, rx, ry, fg, bg);
}

/// Draw text with ellipsis if too wide
pub fn draw_text_ellipsis(rx: usize, ry: usize, rw: usize, _rh: usize,
                            s: &str, fg: u32, bg: u32) {
    let out = metrics::ellipsis_to_width(s, rw);
    font::draw_string(&out, rx, ry, fg, bg);
}

/// Draw right-aligned text
pub fn draw_text_right(rx: usize, ry: usize, rw: usize, s: &str, fg: u32, bg: u32) {
    let tw = metrics::text_width(s);
    let tx = rx + rw.saturating_sub(tw);
    font::draw_string(s, tx, ry, fg, bg);
}

/// Draw text at 2× scale (character doubling — no new font needed)
pub fn draw_text_large(x: usize, y: usize, s: &str, fg: u32, bg: u32) {
    use crate::io::font;
    use crate::io::framebuffer as fb;
    use crate::gui::theme::rgb;
    let (fr, fg_, fb_) = rgb(fg);
    let (br, bg_, bb_) = rgb(bg);
    let fd = font::raw_font_data();
    let mut cx = x;
    for b in s.bytes() {
        let go = 32 + b as usize * 16;
        if go + 16 > fd.len() { cx += 16; continue; }
        for r in 0..16usize {
            let byte = fd[go + r];
            for c in 0..8usize {
                let on = byte & (0x80 >> c) != 0;
                let (r2,g2,b2) = if on { (fr,fg_,fb_) } else { (br,bg_,bb_) };
                fb::set_pixel(cx + c*2,     y + r*2,     r2, g2, b2);
                fb::set_pixel(cx + c*2 + 1, y + r*2,     r2, g2, b2);
                fb::set_pixel(cx + c*2,     y + r*2 + 1, r2, g2, b2);
                fb::set_pixel(cx + c*2 + 1, y + r*2 + 1, r2, g2, b2);
            }
        }
        cx += 16;
    }
}

/// Draw bold text — double-write shifted by 1px right
pub fn draw_text_bold(x: usize, y: usize, s: &str, fg: u32, bg: u32) {
    draw_text(x, y, s, fg, bg);
    draw_text(x + 1, y, s, fg, bg);  // shift 1px = bold approximation
}
