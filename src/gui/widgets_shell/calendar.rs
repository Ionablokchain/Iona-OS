use crate::io::font;
use crate::gui::{theme::{palette::*, spacing::*}, primitives::draw as prim,
                  icons::{Icon, draw_icon}, text};
use super::super::state::calendar::CalendarState;

pub fn draw(x: usize, y: usize, w: usize, h: usize, state: &CalendarState) {
    prim::fill_card(x, y, w, h, GLASS, GLASS_BORDER, 14, 50);
    let pad = MD;
    let mut iy = y + pad;

    // Header
    text::draw_text(x+pad, iy, &state.month_label, TEXT_PRIMARY, GLASS);
    draw_icon(x+w-pad-18, iy-1, Icon::Plus, ACCENT, GLASS);
    iy += font::FONT_HEIGHT + SM;

    // Today badge
    let today_str = alloc::format!("Today — {}",
        ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"][(state.day as usize) % 7]);
    text::draw_text(x+pad, iy, &today_str, TEXT_SECONDARY, GLASS);
    iy += font::FONT_HEIGHT + SM;

    crate::io::framebuffer::hline(x+pad, iy, w-pad*2, 0x1A, 0x2A, 0x40);
    iy += SM;

    // Event list
    for event in &state.events {
        if iy + font::FONT_HEIGHT + SM > y + h { break; }
        // Color bar
        let (er, eg, eb) = crate::gui::theme::rgb(event.color);
        crate::io::framebuffer::fill_rect(x+pad, iy+2, 3, font::FONT_HEIGHT-4, er, eg, eb);
        // Time
        text::draw_text(x+pad+8, iy, &event.time, TEXT_MUTED, GLASS);
        // Label
        text::draw_text_ellipsis(x+pad+8+5*font::FONT_WIDTH, iy,
            w.saturating_sub(pad*2+8+5*font::FONT_WIDTH), font::FONT_HEIGHT,
            &event.label, TEXT_PRIMARY, GLASS);
        iy += font::FONT_HEIGHT + XS;
    }
}
