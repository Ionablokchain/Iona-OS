//! IONA OS Compositor — dirty-rect aware, back→front composition + present()
//!
//! CHECK 2: Z-order garantat:
//!   Layer 0: wallpaper (bottom)
//!   Layer 1: shell chrome (topbar, sidebar, taskbar, widgets)
//!   Layer 2: app windows (WM managed, above shell)
//!   Layer 3: shell overlays (tooltips, context menus — above windows)
//!   Layer 4: cursor (always topmost)
//!
//! CHECK 3: Focus routing — shell events consumed before WM dispatch.
//!   compositor nu trimite events — asta e job-ul gui_loop_task.
//!   compositor NUMAI desenează, nu procesează input.

use alloc::vec::Vec;
use crate::io::{framebuffer as fb, font};
use crate::gui::{wm, theme::*};
use crate::gui::wm::{Window, TITLEBAR_H, BTN_SIZE, BTN_MARGIN, BTN_GAP, BORDER, RESIZE_ZONE};

/// Main compositor entry — called once per frame from gui_loop_task
///
/// Disables interrupts during the entire compose pass to prevent the scheduler
/// from preempting us while we hold framebuffer/WM/state locks. Without this,
/// millions of per-pixel lock acquisitions make the draw crawl (each set_pixel
/// acquires and releases the back-buffer spin lock; if preempted while held,
/// other tasks spin-wait indefinitely).
pub fn compose_and_present() {
    // Disable interrupts for the entire compose pass to avoid preemption deadlocks
    x86_64::instructions::interrupts::disable();

    // ── Layer 0+1: Shell (wallpaper + chrome + widgets) ─────────────────────
    // Only redraws when state.dirty=true (per-region dirty handled inside)
    let shell_redrew = {
        let state = crate::gui::SHELL_STATE.lock();
        state.dirty
    };
    crate::gui::draw_shell_layer();
    if shell_redrew {
        // Shell redrew → mark all dirty so windows re-composite on top
        fb::mark_all_dirty();
    }

    // ── Layer 2: App windows (WM managed — above shell) ─────────────────────
    // Z-order: z_order is sorted lowest-z first; we draw back→front
    let (sw, sh) = fb::size();
    let scene: Vec<(Window, bool)> = {
        let wm_lock = wm::WM.lock();
        let focused = wm_lock.focused;
        // z_order[0] = bottom window, z_order[last] = topmost
        // We draw in reverse (topmost last = painted on top)
        wm_lock.z_order.iter().rev()
            .filter_map(|&wid| {
                wm_lock.windows.get(&wid).map(|w| (w.clone(), focused == Some(wid)))
            })
            .collect()
    };

    for (win, is_focused) in &scene {
        if !win.visible || win.minimized { continue; }
        // Draw shadow → titlebar → border → client area
        // All drawn ABOVE shell layer, BELOW overlays
        draw_shadow(win);
        draw_titlebar(win, *is_focused);
        draw_border(win, *is_focused);
        draw_client(win, sw, sh);
        let (fx, fy, fw, fh) = win.frame_dirty_rect();
        fb::mark_dirty(fx, fy, fw, fh);
    }

    // ── Layer 3: Shell overlays (tooltips, context menus — above windows) ───
    // These are drawn AFTER windows so they appear above all app content
    {
        let state = crate::gui::SHELL_STATE.lock();
        if state.show_context_menu {
            let ox = state.context_x;
            let oy = state.context_y;
            fb::mark_dirty(ox, oy, 180, 200);
        }
        if let Some(ref tt) = state.tooltip {
            fb::mark_dirty(tt.x, tt.y.saturating_sub(32), tt.text.len()*8+16, 26);
        }
    }

    // ── Layer 4: Cursor (always topmost) ────────────────────────────────────
    let (cx, cy) = crate::drivers::mouse::cursor_pos();
    fb::draw_cursor(cx as usize, cy as usize);

    // ── Present — copy only dirty rects to VRAM ──────────────────────────────
    fb::present();

    // Re-enable interrupts after compose is done
    x86_64::instructions::interrupts::enable();
}

// ── Window rendering helpers ─────────────────────────────────────────────────

fn draw_shadow(win: &Window) {
    let (sw, sh) = fb::size();
    let fx = win.frame_x();
    let fy = win.frame_y();
    let fw = win.frame_w() as i32;
    let fh = win.frame_h() as i32;
    for d in 1..=4i32 {
        let sx = (fx + d).max(0) as usize;
        let sy = (fy + d).max(0) as usize;
        let sw_ = (fw + d as i32 * 2).max(0) as usize;
        let sh_ = (fh + d as i32 * 2).max(0) as usize;
        let cw = sw_.min(sw.saturating_sub(sx));
        let ch = sh_.min(sh.saturating_sub(sy));
        let alpha = 60u8.saturating_sub(d as u8 * 12);
        // Top scanline and bottom scanline only (outline shadow, not fill)
        if sy < sh { fb::blend_pixel(sx, sy, 2, 4, 8, alpha); }
        for px in sx..sx+cw { if sy < sh { fb::blend_pixel(px, sy, 2, 4, 8, alpha); } }
        if sy+ch > 0 && sy+ch <= sh {
            for px in sx..sx+cw { fb::blend_pixel(px, sy+ch-1, 2, 4, 8, alpha); }
        }
    }
}

fn draw_titlebar(win: &Window, focused: bool) {
    let (bx, by, bw, bh) = win.titlebar_rect();
    let bx = bx.max(0) as usize;
    let by = by.max(0) as usize;
    let bw = bw as usize;
    let bh = bh as usize;
    let bg = if focused { COLOR_TITLEBAR_FOCUSED } else { COLOR_TITLEBAR_UNFOCUSED };
    let (br, bg_, bb) = crate::gui::theme::rgb(bg);
    fb::fill_rect(bx, by, bw, bh, br, bg_, bb);

    // Window control buttons
    let (cx, cy) = win.btn_close();
    let (mx, my) = win.btn_min();
    let (mx2, my2) = win.btn_max();
    fb::fill_rect_rounded(cx.max(0) as usize, cy.max(0) as usize, BTN_SIZE as usize, BTN_SIZE as usize, 0xFF, 0x5F, 0x57, (BTN_SIZE/2) as usize);
    fb::fill_rect_rounded(mx.max(0) as usize, my.max(0) as usize, BTN_SIZE as usize, BTN_SIZE as usize, 0xFE, 0xBC, 0x2E, (BTN_SIZE/2) as usize);
    fb::fill_rect_rounded(mx2.max(0) as usize, my2.max(0) as usize, BTN_SIZE as usize, BTN_SIZE as usize, 0x28, 0xC8, 0x40, (BTN_SIZE/2) as usize);

    // Title — centered, clipped
    let title = &win.title;
    let max_chars = bw.saturating_sub(BTN_MARGIN as usize * 2 + BTN_SIZE as usize * 3 + BTN_GAP as usize * 2 + 8) / font::FONT_WIDTH;
    let display: alloc::string::String = if title.len() > max_chars && max_chars > 3 {
        let mut s: alloc::string::String = title[..max_chars-3].into();
        s.push_str("...");
        s
    } else { title.clone() };
    let tw = display.len() * font::FONT_WIDTH;
    let tx = bx + bw.saturating_sub(tw) / 2;
    let ty = by + bh.saturating_sub(font::FONT_HEIGHT) / 2;
    let (tr, tg, tb_) = crate::gui::theme::rgb(if focused { COLOR_TITLE_FOCUSED } else { COLOR_TITLE_UNFOCUSED });
    let (bgr, bgg, bgb) = crate::gui::theme::rgb(bg);
    font::draw_string_rgb(&display, tx, ty, (tr,tg,tb_), (bgr,bgg,bgb));
}

fn draw_border(win: &Window, focused: bool) {
    let fx = win.frame_x().max(0) as usize;
    let fy = win.frame_y().max(0) as usize;
    let fw = win.frame_w() as usize;
    let fh = win.frame_h() as usize;
    let (er, eg, eb) = crate::gui::theme::rgb(if focused { COLOR_BORDER_FOCUSED } else { COLOR_BORDER_UNFOCUSED });
    fb::draw_rect(fx, fy, fw, fh, er, eg, eb);
    // Resize handle — bottom-right corner, subtle indicator
    let (rsx, rsy, rsw, rsh) = win.resize_rect();
    if rsx >= 0 && rsy >= 0 {
        let (hr, hg, hb) = crate::gui::theme::rgb(COLOR_RESIZE_HANDLE);
        fb::fill_rect(rsx as usize, rsy as usize, rsw as usize, rsh as usize, hr, hg, hb);
    }
}

fn draw_client(win: &Window, sw: usize, sh: usize) {
    let dx = win.x.max(0) as usize;
    let dy = win.y.max(0) as usize;
    if dx >= sw || dy >= sh || win.pixels.is_empty() { return; }
    let w = (win.w as usize).min(sw.saturating_sub(dx));
    let h = (win.h as usize).min(sh.saturating_sub(dy));
    fb::blit_pixels(dx, dy, w, h, &win.pixels, win.w as usize);
}
