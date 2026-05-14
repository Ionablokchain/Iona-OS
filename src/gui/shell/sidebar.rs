//! Left sidebar dock — 72px wide, app icons + IONA orb at bottom
//!
//! CHECK 7: Background as fill_rect, not per-pixel blend loop.
//! CHECK 8: Icon size 28px, padding 12px, consistent gap DOCK_ITEM_STRIDE.

use crate::io::{framebuffer as fb, font};
use crate::gui::{
    theme::{palette::*, rgb, spacing::*},
    primitives::draw as prim,
    icons::{Icon, draw_icon},
    layout::constants::*,
};
use super::super::state::sidebar::SidebarState;

pub const W: usize = SIDEBAR_W; // 72

pub fn draw(sh: usize, top_offset: usize, bot_offset: usize, state: &SidebarState) {
    let y0 = top_offset;
    let h  = sh.saturating_sub(top_offset + bot_offset);

    // CHECK 7: Single fill_rect for glass background
    let (br, bg_, bb) = rgb(DOCK_BG);
    fb::fill_rect(0, y0, W, h, br, bg_, bb);
    // Right border
    let (er, eg, eb) = rgb(SHELL_BORDER);
    fb::vline(W-1, y0, h, er, eg, eb);

    // Active indicator bar (left edge, 3px wide, half item height)
    if state.active < state.items.len() {
        let iy = y0 + DOCK_ITEM_START_Y + state.active * DOCK_ITEM_STRIDE;
        let (ar, ag, ab) = rgb(ACCENT);
        fb::fill_rect(0, iy + DOCK_ITEM_H/4, 3, DOCK_ITEM_H/2, ar, ag, ab);
    }

    // Items — CHECK 8: icon_x centered in W, icon 28px, label 8px below
    let icon_x = (W - 28) / 2;

    for (i, item) in state.items.iter().enumerate() {
        let iy = y0 + DOCK_ITEM_START_Y + i * DOCK_ITEM_STRIDE;
        let is_active  = i == state.active;
        let is_hovered = state.hovered == Some(i);

        // Hover/active background
        if is_active || is_hovered {
            let bg = if is_active { DOCK_ITEM_ACTIVE } else { DOCK_ITEM_HOVER };
            let border = if is_active { GLASS_BORDER } else { 0x0A1830 };
            prim::fill_card(icon_x - 4, iy + 2, 36, DOCK_ITEM_H - 4, bg, border, 10, 0);
        }

        // Icon (CHECK 8: 28×28 centered, 8px from top of item)
        draw_icon(icon_x, iy + 8, item.icon,
                  if is_active { ACCENT } else { TEXT_SECONDARY },
                  0x00000000);

        // Label — 8px font, centered below icon
        let lbl = &item.label;
        let lw = lbl.len() * font::FONT_WIDTH;
        let lx = if lw < W { (W - lw) / 2 } else { 0 };
        font::draw_string(lbl, lx, iy + 8 + 28 + 2,
                          if is_active { TEXT_ACCENT } else { TEXT_MUTED }, DOCK_BG);
    }

    // IONA orb at bottom — CHECK 8: 44px, full radius (circle)
    let orb_y = y0 + h.saturating_sub(60);
    let orb_x = (W - 44) / 2;
    prim::fill_card(orb_x, orb_y, 44, 44, ACCENT_SOFT, ACCENT, 22, 40);
    draw_icon(orb_x + 14, orb_y + 14, Icon::Node, ACCENT, ACCENT_SOFT);
}
