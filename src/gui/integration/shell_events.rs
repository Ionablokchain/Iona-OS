//! Route pointer/key events to shell components
//!
//! CHECK 3: Returns bool — consumed events MUST NOT reach WM.
//! CHECK 4: All hit regions use layout::constants — same numbers as draw code.

use crate::gui::events::{GuiEvent, MouseBtn};
use crate::gui::state::desktop::DesktopShellState;
use crate::gui::layout::constants::*;
use super::launcher;

pub fn handle(ev: &GuiEvent, state: &mut DesktopShellState) -> bool {
    match ev {
        GuiEvent::MouseDown { x, y, button: MouseBtn::Left }  => on_left_click(*x, *y, state),
        GuiEvent::MouseDown { x, y, button: MouseBtn::Right } => on_right_click(*x, *y, state),
        GuiEvent::MouseMove { x, y, .. }                       => { on_hover(*x, *y, state); false }
        GuiEvent::MouseUp   { .. }                             => false,
        _                                                       => false,
    }
}

fn on_left_click(px: i32, py: i32, state: &mut DesktopShellState) -> bool {
    let (sw, sh) = crate::io::framebuffer::size();
    state.show_context_menu = false;

    // ── Sidebar dock (CHECK 4: uses DOCK_ITEM_STRIDE, DOCK_ITEM_START_Y) ────
    if px >= 0 && (px as usize) < SIDEBAR_W && py >= TOPBAR_H as i32 {
        let rel_y = py - TOPBAR_H as i32 - DOCK_ITEM_START_Y as i32;
        if rel_y >= 0 {
            let idx = rel_y as usize / DOCK_ITEM_STRIDE;
            if idx < state.sidebar.items.len() {
                state.sidebar.active = idx;
                state.regions.sidebar = true;
                state.regions.taskbar = true;
                state.dirty = true;
                launcher::launch_app(idx, &mut state.taskbar);
                return true; // consumed — WM must NOT see this
            }
        }
        // Click in sidebar but not on item (below items) — still consumed
        return true;
    }

    // ── Taskbar (CHECK 4: uses TASKBAR_ITEM_W, TASKBAR_ITEM_GAP) ────────────
    if py >= (sh as i32 - TASKBAR_H as i32) {
        let n = state.taskbar.items.len();
        if n == 0 { return true; } // in taskbar zone, consume
        let total_sep = (n / TASKBAR_SEP_EVERY) as i32 * TASKBAR_SEP_W as i32;
        let total_w = n as i32 * (TASKBAR_ITEM_W + TASKBAR_ITEM_GAP) as i32 + total_sep;
        let start_x = sw as i32 / 2 - total_w / 2;
        let rel_x = px - start_x;
        if rel_x >= 0 {
            // Account for separators
            let stride = (TASKBAR_ITEM_W + TASKBAR_ITEM_GAP) as i32;
            let raw_idx = rel_x / stride;
            if raw_idx >= 0 && (raw_idx as usize) < n {
                let idx = raw_idx as usize;
                state.taskbar.active = Some(idx);
                state.regions.taskbar = true;
                state.dirty = true;
                launcher::focus_taskbar_item(idx, &state.taskbar);
                return true;
            }
        }
        return true; // in taskbar zone always consumed
    }

    // ── App grid (CHECK 4: uses APP_CELL_W, APP_CELL_H, APP_GRID_COLS) ──────
    if (px as usize) >= CONTENT_X && (py as usize) >= CONTENT_Y {
        let rel_x = px as usize - CONTENT_X;
        let rel_y = py as usize - CONTENT_Y;
        let col = rel_x / (APP_CELL_W + APP_CELL_GAP);
        let row = rel_y / (APP_CELL_H + APP_CELL_GAP);
        let idx = row * APP_GRID_COLS + col;
        // Only consume if within a valid cell (not in gap)
        let cell_x = col * (APP_CELL_W + APP_CELL_GAP);
        let cell_y = row * (APP_CELL_H + APP_CELL_GAP);
        let in_cell = rel_x - cell_x < APP_CELL_W && rel_y - cell_y < APP_CELL_H;
        let max_idx = crate::gui::shell::app_grid::APPS.len();
        if in_cell && idx < max_idx {
            launcher::launch_app(idx, &mut state.taskbar);
            state.regions.taskbar = true;
            state.dirty = true;
            return true;
        }
    }

    // ── IONA orb (bottom of sidebar) ─────────────────────────────────────────
    let (_, sh2) = crate::io::framebuffer::size();
    let orb_y = TOPBAR_H + (sh2 - TOPBAR_H - TASKBAR_H).saturating_sub(TASKBAR_H + 72);
    if (px as usize) < SIDEBAR_W && (py as usize) >= orb_y {
        // Launch or show app launcher
        state.dirty = true;
        return true;
    }

    false // not consumed — let WM handle
}

fn on_right_click(px: i32, py: i32, state: &mut DesktopShellState) -> bool {
    // Right-click on desktop background (not in shell chrome) → context menu
    let in_chrome = (px as usize) < SIDEBAR_W
        || (py as usize) < TOPBAR_H
        || (py as usize) >= crate::io::framebuffer::size().1.saturating_sub(TASKBAR_H);
    if in_chrome { return false; } // let WM handle in chrome area

    state.show_context_menu = true;
    state.context_x = px as usize;
    state.context_y = py as usize;
    state.regions.overlay = true;
    state.dirty = true;
    true
}

fn on_hover(px: i32, py: i32, state: &mut DesktopShellState) {
    // Sidebar hover (CHECK 4: DOCK_ITEM_STRIDE matches draw)
    if (px as usize) < SIDEBAR_W && py >= TOPBAR_H as i32 {
        let rel_y = py - TOPBAR_H as i32 - DOCK_ITEM_START_Y as i32;
        let new_hover = if rel_y >= 0 {
            let idx = rel_y as usize / DOCK_ITEM_STRIDE;
            if idx < state.sidebar.items.len() { Some(idx) } else { None }
        } else { None };
        if state.sidebar.hovered != new_hover {
            state.sidebar.hovered = new_hover;
            state.regions.sidebar = true;
            state.dirty = true;
        }
        return;
    }
    if state.sidebar.hovered.is_some() {
        state.sidebar.hovered = None;
        state.regions.sidebar = true;
        state.dirty = true;
    }

    // App grid hover
    if (px as usize) >= CONTENT_X && (py as usize) >= CONTENT_Y {
        let rel_x = px as usize - CONTENT_X;
        let rel_y = py as usize - CONTENT_Y;
        let col = rel_x / (APP_CELL_W + APP_CELL_GAP);
        let row = rel_y / (APP_CELL_H + APP_CELL_GAP);
        let idx = row * APP_GRID_COLS + col;
        let max_idx = crate::gui::shell::app_grid::APPS.len();
        let new_hover = if idx < max_idx { Some(idx) } else { None };
        if state.hovered_app != new_hover {
            state.hovered_app = new_hover;
            state.regions.app_grid = true;
            state.dirty = true;
        }
    } else if state.hovered_app.is_some() {
        state.hovered_app = None;
        state.regions.app_grid = true;
        state.dirty = true;
    }

    // Taskbar hover
    let (sw, sh) = crate::io::framebuffer::size();
    if (py as usize) >= sh.saturating_sub(TASKBAR_H) {
        let n = state.taskbar.items.len();
        if n > 0 {
            let total_w = n as i32 * (TASKBAR_ITEM_W + TASKBAR_ITEM_GAP) as i32;
            let start_x = sw as i32 / 2 - total_w / 2;
            let idx = ((px - start_x) / (TASKBAR_ITEM_W + TASKBAR_ITEM_GAP) as i32)
                .max(0) as usize;
            let new_h = if idx < n { Some(idx) } else { None };
            if state.taskbar.hovered != new_h {
                state.taskbar.hovered = new_h;
                state.regions.taskbar = true;
                state.dirty = true;
            }
        }
    } else if state.taskbar.hovered.is_some() {
        state.taskbar.hovered = None;
        state.regions.taskbar = true;
        state.dirty = true;
    }
}
