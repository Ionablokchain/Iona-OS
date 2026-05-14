//! Bottom taskbar — centered row with running apps + separators
//!
//! CHECK 7: Background as fill_rect, not per-pixel blend loop.
//! CHECK 8: Item sizing from layout::constants, consistent underline dot.

use crate::io::{framebuffer as fb, font};
use crate::gui::{
    theme::{palette::*, rgb, spacing::*},
    primitives::draw as prim,
    icons::{Icon, draw_icon},
    layout::constants::*,
    text,
};
use super::super::state::taskbar::TaskbarState;

pub const H: usize = TASKBAR_H; // 56

pub fn draw(sw: usize, sh: usize, state: &TaskbarState) {
    let y0 = sh - H;

    // CHECK 7: Single fill_rect — not per-pixel blend
    let (br, bg_, bb) = rgb(SHELL_BAR);
    fb::fill_rect(0, y0, sw, H, br, bg_, bb);
    // Top border
    let (er, eg, eb) = rgb(SHELL_BORDER);
    fb::hline(0, y0, sw, er, eg, eb);

    if state.items.is_empty() { return; }

    // Center items row
    let n = state.items.len();
    let total_seps = n / TASKBAR_SEP_EVERY;
    let total_w = n * (TASKBAR_ITEM_W + TASKBAR_ITEM_GAP)
                  + total_seps * TASKBAR_SEP_W;
    let mut x = (sw as i32 / 2 - total_w as i32 / 2).max(SIDEBAR_W as i32 + 8);

    for (i, item) in state.items.iter().enumerate() {
        let is_active  = state.active == Some(i);
        let is_hovered = state.hovered == Some(i);

        let bg     = if is_active  { TASKBAR_ITEM_ACTIVE }
                     else if is_hovered { TASKBAR_ITEM_HOVER }
                     else { TASKBAR_ITEM };
        let border = if is_active  { ACCENT } else { GLASS_BORDER };

        // CHECK 8: item height from constants, vertical center in taskbar
        let iy = y0 + (H - TASKBAR_ITEM_H) / 2;
        prim::fill_card(x as usize, iy, TASKBAR_ITEM_W, TASKBAR_ITEM_H, bg, border, 10, 0);

        // Icon (CHECK 8: 16px, 10px from left)
        draw_icon(x as usize + 10, iy + (TASKBAR_ITEM_H - 16) / 2, item.icon,
                  if is_active { ACCENT } else { TEXT_SECONDARY }, bg);

        // Label clipped to available width
        text::draw_text_clipped(
            x as usize + 32,
            iy + (TASKBAR_ITEM_H - font::FONT_HEIGHT) / 2,
            TASKBAR_ITEM_W - 44, TASKBAR_ITEM_H,
            &item.label,
            if is_active { TEXT_PRIMARY } else { TEXT_SECONDARY },
            bg,
        );

        // Active indicator — 16px wide, 3px tall, centered under item
        if is_active {
            let (dr, dg, db) = rgb(ACCENT);
            fb::fill_rect_rounded(
                x as usize + (TASKBAR_ITEM_W - 16) / 2,
                iy + TASKBAR_ITEM_H - 4,
                16, 3, dr, dg, db, 2,
            );
        }

        x += (TASKBAR_ITEM_W + TASKBAR_ITEM_GAP) as i32;

        // Separator every TASKBAR_SEP_EVERY items
        if i < n - 1 && (i + 1) % TASKBAR_SEP_EVERY == 0 {
            let (sr, sg, sb) = rgb(TASKBAR_SEPARATOR);
            fb::vline(x as usize + TASKBAR_SEP_W / 2, iy + 8,
                      TASKBAR_ITEM_H - 16, sr, sg, sb);
            x += TASKBAR_SEP_W as i32;
        }
    }
}
