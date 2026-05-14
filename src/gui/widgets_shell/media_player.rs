use crate::io::{framebuffer as fb, font};
use crate::gui::{theme::{palette::*, rgb, spacing::*}, primitives::draw as prim,
                  icons::{Icon, draw_icon}, text};
use super::super::state::media::MediaState;

pub fn draw(x: usize, y: usize, w: usize, h: usize, state: &MediaState) {
    prim::fill_card(x, y, w, h, GLASS_DARK, GLASS_BORDER, 14, 50);
    let pad = MD;
    // Album art placeholder (colored square)
    let art_s = h.saturating_sub(pad*2).min(60);
    let art_x = x + pad; let art_y = y + pad;
    prim::fill_card(art_x, art_y, art_s, art_s, ACCENT_SOFT, ACCENT, 10, 0);
    draw_icon(art_x + art_s/2 - 8, art_y + art_s/2 - 8, Icon::Music, ACCENT, ACCENT_SOFT);

    // Title + artist
    let tx = art_x + art_s + SM;
    let tw = w.saturating_sub(art_s + pad*2 + SM);
    text::draw_text_ellipsis(tx, art_y, tw, font::FONT_HEIGHT, &state.title, TEXT_PRIMARY, GLASS_DARK);
    text::draw_text_ellipsis(tx, art_y + font::FONT_HEIGHT + 4, tw, font::FONT_HEIGHT, &state.artist, TEXT_SECONDARY, GLASS_DARK);

    // Progress bar
    let pb_y = art_y + art_s + SM;
    let pb_w = w.saturating_sub(pad*2);
    let (tr, tg, tb_) = rgb(PROGRESS_BG);
    fb::fill_rect_rounded(x+pad, pb_y, pb_w, 5, tr, tg, tb_, 3);
    let fill = (pb_w as f32 * state.progress) as usize;
    let (pr, pg, pb_) = rgb(ACCENT);
    if fill > 0 { fb::fill_rect_rounded(x+pad, pb_y, fill.min(pb_w), 5, pr, pg, pb_, 3); }
    // Knob
    if fill > 0 && fill < pb_w {
        fb::fill_rect_rounded(x+pad+fill-3, pb_y-2, 6, 9, pr, pg, pb_, 4);
    }

    // Controls
    let ctrl_y = pb_y + 14;
    let ctrl_x = x + w/2 - 36;
    draw_icon(ctrl_x,    ctrl_y, Icon::Prev,  TEXT_SECONDARY, GLASS_DARK);
    let play_icon = if state.playing { Icon::Pause } else { Icon::Play };
    draw_icon(ctrl_x+20, ctrl_y, play_icon, ACCENT, GLASS_DARK);
    draw_icon(ctrl_x+40, ctrl_y, Icon::Next, TEXT_SECONDARY, GLASS_DARK);
    draw_icon(ctrl_x+62, ctrl_y, Icon::Heart, STATUS_ERR, GLASS_DARK);
}
