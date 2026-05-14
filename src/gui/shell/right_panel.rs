//! Right column — monitor widget + media player cards
use crate::gui::primitives::draw as prim;
use super::super::widgets_shell::{system_monitor, media_player};
use super::super::state::desktop::DesktopShellState;
use crate::gui::theme::{palette::*, spacing::*};
use crate::gui::layout::{Rect, layout_column};

pub fn draw(x: usize, y: usize, w: usize, h: usize, state: &DesktopShellState) {
    let bounds = Rect::new(x as i32, y as i32, w as i32, h as i32);
    let rows = layout_column(bounds, GUTTER as i32, 3);

    // System monitor
    if let Some(r) = rows.get(0) {
        system_monitor::draw(r.ux(), r.uy(), r.uw(), r.uh(), &state.monitor);
    }
    // Media player
    if let Some(r) = rows.get(1) {
        media_player::draw(r.ux(), r.uy(), r.uw(), r.uh(), &state.media);
    }
    // Calendar (compact)
    if let Some(r) = rows.get(2) {
        super::super::widgets_shell::calendar::draw(r.ux(), r.uy(), r.uw(), r.uh(), &state.calendar);
    }
}
