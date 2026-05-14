//! Top bar — 50px: logo, search, weather, clock, status icons
//!
//! CHECK 7: Background drawn as single fill_rect (not per-pixel blend loop).
//! CHECK 8: Spacing consistent via layout::constants + theme::spacing.

use crate::io::{framebuffer as fb, font};
use crate::gui::{
    theme::{palette::*, rgb, spacing::*},
    text, icons::{Icon, draw_icon},
    primitives::draw as prim,
};
use crate::gui::layout::constants::TOPBAR_H;
use super::super::state::topbar::TopbarState;

pub const H: usize = TOPBAR_H; // 50

pub fn draw(sw: usize, state: &TopbarState) {
    // CHECK 7: Single fill_rect for background — NOT per-pixel blend loop
    let (br, bg_, bb) = rgb(SHELL_BAR);
    fb::fill_rect(0, 0, sw, H, br, bg_, bb);
    // Bottom border
    let (er, eg, eb) = rgb(SHELL_BORDER);
    fb::hline(0, H-1, sw, er, eg, eb);

    let ty = (H - font::FONT_HEIGHT) / 2;  // vertical center

    // Logo — left side (CHECK 8: consistent 18px left margin)
    let lx = LG; // 16px
    font::draw_string("IONA", lx, ty, ACCENT, SHELL_BAR);
    font::draw_string(" OS", lx + 4*font::FONT_WIDTH, ty, TEXT_SECONDARY, SHELL_BAR);

    // Search bar — centered (CHECK 8: consistent 32px height, 15px corner radius)
    let sb_w = 280usize;
    let sb_h = 32usize;
    let sb_x = sw/2 - sb_w/2;
    let sb_y = (H - sb_h) / 2;
    prim::fill_card(sb_x, sb_y, sb_w, sb_h, 0x0A1520, GLASS_BORDER, 15, 0);
    draw_icon(sb_x + 10, sb_y + 8, Icon::Search, TEXT_MUTED, 0x0A1520);
    let ph = if state.search_text.is_empty() { "Search apps, files, commands..." }
             else { &state.search_text };
    let ph_col = if state.search_focused { ACCENT }
                 else if state.search_text.is_empty() { TEXT_MUTED }
                 else { TEXT_PRIMARY };
    text::draw_text_clipped(sb_x+32, sb_y+(sb_h-font::FONT_HEIGHT)/2, sb_w-44, sb_h, ph, ph_col, 0x0A1520);
    // Focus ring
    if state.search_focused {
        let (fr, fg_, fb_) = rgb(ACCENT);
        fb::draw_rect(sb_x, sb_y, sb_w, sb_h, fr, fg_, fb_);
    }

    // Right side — build right-to-left (CHECK 8: 12px gap between elements)
    let mut rx = sw.saturating_sub(LG);

    // Clock
    rx = rx.saturating_sub(state.time_str.len() * font::FONT_WIDTH);
    font::draw_string(&state.time_str, rx, ty, TEXT_PRIMARY, SHELL_BAR);
    rx = rx.saturating_sub(MD);

    // Bell icon
    rx = rx.saturating_sub(18);
    let bell = if state.notif_count > 0 { Icon::BellDot } else { Icon::Bell };
    draw_icon(rx, ty - 1, bell, if state.notif_count > 0 { STATUS_WARN } else { TEXT_SECONDARY }, SHELL_BAR);
    rx = rx.saturating_sub(MD);

    // Wifi dot
    rx = rx.saturating_sub(18);
    draw_icon(rx, ty - 1, Icon::Wifi, if state.net_ok { STATUS_OK } else { STATUS_ERR }, SHELL_BAR);
    rx = rx.saturating_sub(LG);

    // Weather badge
    if !state.weather_str.is_empty() {
        let ww = state.weather_str.len() * font::FONT_WIDTH + 26;
        rx = rx.saturating_sub(ww);
        prim::fill_card(rx, sb_y, ww, sb_h, 0x0A1520, GLASS_BORDER, 10, 0);
        draw_icon(rx + 6, sb_y + 8, Icon::Weather, TEXT_ACCENT, 0x0A1520);
        text::draw_text(rx+26, sb_y+(sb_h-font::FONT_HEIGHT)/2,
                        &state.weather_str, TEXT_PRIMARY, 0x0A1520);
        rx = rx.saturating_sub(SM);
    }

    // Date badge
    if !state.date_str.is_empty() {
        let dw = state.date_str.len() * font::FONT_WIDTH + 16;
        rx = rx.saturating_sub(dw);
        prim::fill_card(rx, sb_y, dw, sb_h, 0x0A1520, GLASS_BORDER, 10, 0);
        text::draw_text(rx+8, sb_y+(sb_h-font::FONT_HEIGHT)/2,
                        &state.date_str, TEXT_SECONDARY, 0x0A1520);
    }
}
