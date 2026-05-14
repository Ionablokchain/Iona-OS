use crate::io::font;
use crate::gui::{theme::{palette::*, spacing::*}, primitives::draw as prim,
                  icons::{Icon, draw_icon}, text};
use super::super::state::weather::WeatherState;

pub fn draw(x: usize, y: usize, w: usize, h: usize, state: &WeatherState) {
    prim::fill_card(x, y, w, h, GLASS, GLASS_BORDER, 14, 50);
    let pad = MD;
    let mut iy = y + pad;
    text::draw_text(x+pad, iy, &state.city, TEXT_SECONDARY, GLASS);
    iy += font::FONT_HEIGHT + XS;
    let temp_str = alloc::format!("{}°C", state.temp);
    draw_icon(x+pad, iy, Icon::Weather, ACCENT, GLASS);
    font::draw_string(&temp_str, x+pad+24, iy, TEXT_PRIMARY, GLASS);
    iy += font::FONT_HEIGHT + XS;
    text::draw_text(x+pad, iy, &state.description, TEXT_MUTED, GLASS);
    iy += font::FONT_HEIGHT + SM;
    // Forecast row
    if w > 4 * (30 + XS) {
        let fw = (w - pad*2) / state.forecast.len().max(1);
        for (i, day) in state.forecast.iter().enumerate() {
            let fx = x + pad + i * fw;
            text::draw_text(fx, iy, &day.label, TEXT_MUTED, GLASS);
            let t_str = alloc::format!("{}°", day.temp);
            text::draw_text(fx, iy + font::FONT_HEIGHT + 2, &t_str, TEXT_PRIMARY, GLASS);
        }
    }
}
