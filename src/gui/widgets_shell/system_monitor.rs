use crate::io::{framebuffer as fb, font};
use crate::gui::{theme::{palette::*, rgb, spacing::*}, primitives::draw as prim, text};
use super::super::state::monitor::MonitorState;

pub fn draw(x: usize, y: usize, w: usize, h: usize, state: &MonitorState) {
    prim::fill_card(x, y, w, h, GLASS, GLASS_BORDER, 14, 50);
    let pad = MD;
    let mut iy = y + pad;
    let iw = w - pad*2;

    text::draw_text(x+pad, iy, "System", TEXT_SECONDARY, GLASS); iy += font::FONT_HEIGHT + SM;

    gauge(x+pad, iy, iw, "CPU",  state.cpu_pct,  ACCENT);   iy += 18 + XS;
    gauge(x+pad, iy, iw, "RAM",  state.ram_pct,  STATUS_WARN); iy += 18 + XS;
    gauge(x+pad, iy, iw, "Disk", state.disk_pct, 0xA029BF); iy += 18 + LG;

    // Network row
    let net_str = alloc::format!("TX {:.1} MB/s  RX {:.1} MB/s", state.tx_mb, state.rx_mb);
    text::draw_text(x+pad, iy, &net_str, TEXT_MUTED, GLASS); iy += font::FONT_HEIGHT + SM;

    // Node stats
    let node_str = alloc::format!("Node h={}  peers={}", state.node_h, state.peers);
    text::draw_text(x+pad, iy, &node_str, TEXT_ACCENT, GLASS);
}

fn gauge(x: usize, y: usize, w: usize, label: &str, pct: u8, color: u32) {
    let lbl_w = 4 * font::FONT_WIDTH;
    let bar_x = x + lbl_w + 6;
    let bar_w = w.saturating_sub(lbl_w + 6 + 30);
    let val_x = bar_x + bar_w + 4;
    font::draw_string(label, x, y+1, TEXT_MUTED, GLASS);
    let (tr, tg, tb) = rgb(PROGRESS_BG);
    fb::fill_rect_rounded(bar_x, y, bar_w, 12, tr, tg, tb, 3);
    let fill = (bar_w * pct as usize / 100).min(bar_w);
    if fill > 0 { let (fr, fg, fb_) = rgb(color); fb::fill_rect_rounded(bar_x, y, fill, 12, fr, fg, fb_, 3); }
    let v_str = alloc::format!("{:3}%", pct);
    font::draw_string(&v_str, val_x, y+1, TEXT_MUTED, GLASS);
}
