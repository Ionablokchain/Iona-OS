//! Desktop shell top-level draw — one function composes the whole shell layer
//!
//! Composition order (from package spec):
//!   1. wallpaper
//!   2. shell background regions (topbar/sidebar/taskbar)
//!   3. widgets/cards/panels
//!   4. managed app windows (handled by compositor, not here)
//!   5. overlays/tooltips/menus
//!   6. cursor (handled by compositor)

use crate::io::framebuffer as fb;
use crate::gui::theme::{palette::*, spacing::*};
use super::{wallpaper, topbar, sidebar, taskbar, app_grid, right_panel};
use super::super::state::desktop::DesktopShellState;
use super::super::widgets_shell::{weather, tasks};

pub fn draw(state: &DesktopShellState) {
    let (sw, sh) = fb::size();
    if sw == 0 || sh == 0 { return; }

    // 1. Wallpaper — only on first draw or explicit dirty
    if state.regions.wallpaper { wallpaper::draw(sw, sh); }

    // 2. Shell chrome — per-region (only draw what changed)
    if state.regions.topbar || state.regions.wallpaper {
        topbar::draw(sw, &state.topbar);
        fb::mark_dirty(0, 0, sw, topbar::H);
    }
    if state.regions.sidebar || state.regions.wallpaper {
        sidebar::draw(sh, topbar::H, taskbar::H, &state.sidebar);
        fb::mark_dirty(0, topbar::H, sidebar::W, sh - topbar::H - taskbar::H);
    }
    if state.regions.taskbar || state.regions.wallpaper {
        taskbar::draw(sw, sh, &state.taskbar);
        fb::mark_dirty(0, sh - taskbar::H, sw, taskbar::H);
    }

    // 3. Content area layout
    let content_x = sidebar::W + XS;
    let content_y = topbar::H + XS;
    let content_w = sw.saturating_sub(content_x + XS);
    let content_h = sh.saturating_sub(content_y + taskbar::H + XS);

    // Left 2/3: app grid + weather + tasks (3-column layout)
    let right_panel_w = 240usize;
    let left_w = content_w.saturating_sub(right_panel_w + GUTTER);

    // App grid (top of left column)
    let grid_h = (content_h * 55 / 100).max(200);
    app_grid::draw(content_x, content_y, left_w, grid_h, state.hovered_app);

    // Weather widget below app grid
    let wx = content_x;
    let wy = content_y + grid_h + GUTTER;
    let wh = content_h.saturating_sub(grid_h + GUTTER);
    let ww = left_w / 2 - GUTTER/2;
    weather::draw(wx, wy, ww, wh.min(160), &state.weather);

    // Tasks widget next to weather
    tasks::draw(wx + ww + GUTTER, wy, left_w - ww - GUTTER, wh.min(160), &state.tasks);

    // Right panel (monitor + media + calendar)
    right_panel::draw(content_x + left_w + GUTTER, content_y, right_panel_w, content_h, state);

    // 4. Overlays
    if let Some(ref tt) = state.tooltip {
        draw_tooltip(tt.x, tt.y, &tt.text);
    }
    if state.show_context_menu {
        draw_context_menu(state.context_x, state.context_y);
    }
}

fn draw_tooltip(x: usize, y: usize, text: &str) {
    use crate::io::font;
    use crate::gui::{primitives::draw as prim, text as t};
    let w = text.len() * font::FONT_WIDTH + 16;
    let h = font::FONT_HEIGHT + 10;
    prim::fill_card(x, y.saturating_sub(h+4), w, h, GLASS, GLASS_BORDER, 6, 40);
    t::draw_text(x+8, y.saturating_sub(h+4) + 5, text, TEXT_PRIMARY, GLASS);
}

fn draw_context_menu(x: usize, y: usize) {
    use crate::io::font;
    use crate::gui::{primitives::draw as prim, text as t};
    let items = ["Terminal", "Files", "Monitor", "---", "Settings", "Shutdown"];
    let item_h = font::FONT_HEIGHT + 10;
    let w = 160usize;
    let h = items.len() * item_h + 8;
    prim::fill_card(x, y, w, h, GLASS_DARK, GLASS_BORDER, 10, 60);
    let mut iy = y + 4;
    for &item in &items {
        if item == "---" {
            use crate::gui::theme::rgb;
            let (er, eg, eb) = rgb(GLASS_BORDER);
            crate::io::framebuffer::hline(x+8, iy + item_h/2, w-16, er, eg, eb);
        } else {
            let col = if item == "Shutdown" { STATUS_ERR } else { TEXT_SECONDARY };
            t::draw_text(x+12, iy+5, item, col, GLASS_DARK);
        }
        iy += item_h;
    }
}
