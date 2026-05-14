use crate::io::font;
use crate::gui::{theme::{palette::*, spacing::*}, primitives::draw as prim,
                  icons::{Icon, draw_icon}, text};
use super::super::state::tasks::TasksState;

pub fn draw(x: usize, y: usize, w: usize, h: usize, state: &TasksState) {
    prim::fill_card(x, y, w, h, GLASS, GLASS_BORDER, 14, 50);
    let pad = MD;
    let mut iy = y + pad;
    text::draw_text(x+pad, iy, "Tasks", TEXT_SECONDARY, GLASS);
    draw_icon(x+w-pad-18, iy-1, Icon::Plus, ACCENT, GLASS);
    iy += font::FONT_HEIGHT + SM;

    for task in &state.items {
        if iy + font::FONT_HEIGHT + XS > y + h { break; }
        let (cr, cg, cb) = crate::gui::theme::rgb(if task.done { TEXT_MUTED } else { task.color });
        // Checkbox
        if task.done {
            crate::io::framebuffer::fill_rect_rounded(x+pad, iy+2, 12, 12, cr, cg, cb, 3);
            draw_icon(x+pad-2, iy, Icon::Check, 0xFFFFFF, task.color);
        } else {
            crate::io::framebuffer::draw_rect(x+pad, iy+2, 12, 12, cr, cg, cb);
        }
        let col = if task.done { TEXT_MUTED } else { TEXT_PRIMARY };
        text::draw_text_ellipsis(x+pad+16, iy+2, w.saturating_sub(pad*2+16), font::FONT_HEIGHT, &task.label, col, GLASS);
        iy += font::FONT_HEIGHT + XS;
    }
}
