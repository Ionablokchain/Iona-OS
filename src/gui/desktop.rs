//! IONA OS Desktop Shell
//!
//! Componente:
//!   Wallpaper   — gradient background cu munți (same as HTML demo, drawn in pixels)
//!   Topbar      — 44px: IONA logo, clock, status indicators
//!   Dock        — 76px left sidebar cu app icons
//!   Taskbar     — 58px bottom bar cu running apps
//!   AppLauncher — grid de iconuri activat cu Super key sau click IONA button
//!
//! Toate desenate direct pe framebuffer (sub ferestre în z-order).

#[allow(unused_imports)]
use alloc::{string::{String, ToString}, vec::Vec, format};
use crate::io::{framebuffer as fb, font};
use crate::gui::{theme::*, wm, events};

pub const TOPBAR_H:  usize = 44;
pub const DOCK_W:    usize = 76;
pub const TASKBAR_H: usize = 58;

// Desktop state
struct DesktopState {
    dirty:           bool,
    launcher_open:   bool,
    last_second:     u64,
    time_str:        [u8; 8], // "HH:MM:SS"
    uptime_ms:       u64,
}

static DESKTOP: spin::Mutex<DesktopState> = spin::Mutex::new(DesktopState {
    dirty:         true,
    launcher_open: false,
    last_second:   0,
    time_str:      *b"00:00:00",
    uptime_ms:     0,
});

// App definitions for dock + launcher
struct AppDef {
    name:   &'static str,
    icon:   u32,   // color used as placeholder (real: would load icon bitmap)
    syscmd: &'static str,
}

static APPS: &[AppDef] = &[
    AppDef { name: "Terminal",  icon: 0x1A2A3A, syscmd: "terminal" },
    AppDef { name: "Files",     icon: 0x1E5CBF, syscmd: "files"    },
    AppDef { name: "Monitor",   icon: 0x123820, syscmd: "monitor"  },
    AppDef { name: "Notes",     icon: 0x5C3600, syscmd: "notes"    },
    AppDef { name: "Settings",  icon: 0x1E1E1E, syscmd: "settings" },
];

pub fn init() {
    crate::serial_println!("  [GUI/DESKTOP] desktop shell initialized");
    DESKTOP.lock().dirty = true;
}

pub fn needs_redraw() -> bool {
    let now = crate::arch::x86_64::timer::uptime_ms();
    let mut ds = DESKTOP.lock();
    let sec = now / 1000;
    if sec != ds.last_second {
        ds.last_second = sec;
        ds.uptime_ms   = now;
        // Update time string
        let h  = (sec / 3600) % 24;
        let m  = (sec / 60) % 60;
        let s  = sec % 60;
        let fmt_u2 = |n: u64| -> [u8;2] { [b'0' + (n/10) as u8, b'0' + (n%10) as u8] };
        ds.time_str[0..2].copy_from_slice(&fmt_u2(h));
        ds.time_str[2] = b':';
        ds.time_str[3..5].copy_from_slice(&fmt_u2(m));
        ds.time_str[5] = b':';
        ds.time_str[6..8].copy_from_slice(&fmt_u2(s));
        ds.dirty = true;
    }
    ds.dirty
}

pub fn draw() {
    let (sw, sh) = fb::size();
    if sw == 0 || sh == 0 { return; }

    draw_wallpaper(sw, sh);
    draw_topbar(sw);
    draw_dock(sh);
    draw_taskbar(sw, sh);

    let launcher = DESKTOP.lock().launcher_open;
    if launcher { draw_launcher(sw, sh); }

    DESKTOP.lock().dirty = false;
}

fn draw_wallpaper(sw: usize, sh: usize) {
    // Gradient: deep blue → dark navy, bottom has warm orange glow
    for y in 0..sh {
        let t = y as f32 / sh as f32;
        // Base gradient: dark blue top → darker bottom
        let r = (8.0  + t * 6.0)  as u8;
        let g = (14.0 + t * 8.0)  as u8;
        let b = (28.0 + t * 20.0) as u8;
        fb::hline(0, y, sw, r, g, b);
    }

    // Warm glow near bottom (orange/amber)
    for y in (sh*3/4)..sh {
        let t = (y - sh*3/4) as f32 / (sh/4) as f32;
        let alpha = (t * 120.0) as u32;
        for x in (sw/4)..(sw*3/4) {
            let dist_center = ((x as i32 - sw as i32/2).abs()) as f32 / (sw as f32 / 4.0);
            let fade = ((1.0 - dist_center) * alpha as f32) as u32;
            if fade > 0 {
                let px_r = ((255 * fade / 255) as u8).min(80);
                let px_g = ((140 * fade / 255) as u8).min(40);
                let px_b = 0u8;
                // Additive blend — just overwrite with slightly warm color
                let yr = 8u8.saturating_add(px_r / 3);
                let yg = 14u8.saturating_add(px_g / 3);
                fb::set_pixel(x, y, yr, yg, 28);
            }
        }
    }

    // Mountain silhouettes (3 layers)
    draw_mountain_layer(sw, sh, 0, sh*45/100, sh*25/100, 0x07_0C_18); // far
    draw_mountain_layer(sw, sh, 1, sh*55/100, sh*28/100, 0x05_09_12); // mid
    draw_mountain_layer(sw, sh, 2, sh*68/100, sh*32/100, 0x04_07_0E); // near
}

// Simple sin approximation for no_std (Taylor series)
#[inline]
fn approx_sin(x: f32) -> f32 {
    let pi: f32 = 3.14159265;
    let mut x = x % (2.0 * pi);
    if x > pi { x -= 2.0 * pi; }
    if x < -pi { x += 2.0 * pi; }
    let x2 = x * x;
    let x3 = x2 * x;
    let x5 = x3 * x2;
    x - x3 / 6.0 + x5 / 120.0
}

fn draw_mountain_layer(sw: usize, sh: usize, seed: usize, base_y: usize, amp: usize, color: u32) {
    let (r, g, b) = rgb(color);
    // Simple triangle mountains using hash of x position
    for x in 0..sw {
        let t = x as f32 / sw as f32;
        // Sum of a few sinusoids for natural-looking mountains
        let h0 = approx_sin(t * 3.14 * 2.0 * (1.5 + seed as f32 * 0.7)) * 0.5 + 0.5;
        let h1 = approx_sin(t * 3.14 * 2.0 * (3.1 + seed as f32 * 1.2)) * 0.3 + 0.3;
        let height = ((h0 + h1) * amp as f32 / 2.0) as usize;
        let top_y = base_y.saturating_sub(height);
        fb::vline(x, top_y, sh - top_y, r, g, b);
    }
}

fn draw_topbar(sw: usize) {
    // Background
    let (tr, tg, tb) = rgb(0x000000);
    fb::fill_rect(0, 0, sw, TOPBAR_H, 0, 0, 0);
    // Semi-transparent overlay
    for y in 0..TOPBAR_H {
        for x in 0..sw {
            fb::blend_pixel(x, y, 8, 13, 24, 200);
        }
    }
    // Bottom border
    let (ar, ag, ab) = rgb(0x1A2440);
    fb::hline(0, TOPBAR_H-1, sw, ar, ag, ab);

    // IONA logo "IONA OS"
    let (wr, wg, wb) = rgb(COLOR_ACCENT);
    font::draw_string_rgb("IONA", 14, 14, (wr,wg,wb), (0,0,0));
    let (dr, dg, db) = rgb(COLOR_TEXT_SECONDARY);
    font::draw_string_rgb(" OS", 14 + 4*font::FONT_WIDTH, 14, (dr,dg,db), (0,0,0));

    // Clock (right side)
    let time_owned;
    {
        let ds = DESKTOP.lock();
        let time_str = core::str::from_utf8(&ds.time_str).unwrap_or("00:00:00");
        time_owned = alloc::string::String::from(time_str);
    }
    let (cr, cg, cb) = rgb(COLOR_TEXT_PRIMARY);
    let clock_x = sw.saturating_sub(time_owned.len() * font::FONT_WIDTH + 14);
    font::draw_string_rgb(&time_owned, clock_x, 14, (cr,cg,cb), (0,0,0));

    // Status indicators (left of clock)
    let status_x = sw.saturating_sub(time_owned.len() * font::FONT_WIDTH + 80);
    let (gr, gg, gb) = rgb(COLOR_SUCCESS);
    fb::fill_rect_rounded(status_x, 18, 8, 8, gr, gg, gb, 4); // online dot
}

fn draw_dock(sh: usize) {
    let dock_h = sh - TOPBAR_H - TASKBAR_H;
    // Background
    fb::fill_rect(0, TOPBAR_H, DOCK_W, dock_h, 0, 0, 0);
    // Semi-transparent
    for y in TOPBAR_H..(TOPBAR_H + dock_h) {
        for x in 0..DOCK_W {
            fb::blend_pixel(x, y, 6, 11, 20, 210);
        }
    }
    // Right border
    let (er, eg, eb) = rgb(0x1A2440);
    fb::vline(DOCK_W-1, TOPBAR_H, dock_h, er, eg, eb);

    // App icons
    let icon_size = 40usize;
    let icon_pad  = 8usize;
    let start_x   = (DOCK_W - icon_size) / 2;
    let mut y = TOPBAR_H + 12;

    for (i, app) in APPS.iter().enumerate() {
        // Icon background
        let (ir, ig, ib) = rgb(app.icon);
        fb::fill_rect_rounded(start_x, y, icon_size, icon_size, ir, ig, ib, 10);
        // Subtle highlight
        fb::hline(start_x+4, y+2, icon_size-8, ir.saturating_add(20), ig.saturating_add(20), ib.saturating_add(20));
        // Label
        let lw = app.name.len().min(5) * font::FONT_WIDTH;
        let lx = (DOCK_W as i32 - lw as i32).max(2) as usize / 2;
        let (lr, lg, lb) = rgb(COLOR_TEXT_SECONDARY);
        let name_abbr = &app.name[..app.name.len().min(5)];
        font::draw_string_rgb(name_abbr, lx, y + icon_size + 2, (lr,lg,lb), (0,0,0));
        y += icon_size + icon_pad + 12;
    }

    // IONA button at bottom
    let iona_y = TOPBAR_H + dock_h - 60;
    fb::fill_rect_rounded(DOCK_W/2 - 22, iona_y, 44, 44, 0x16, 0x2A, 0x5C, 22);
    let (wr, wg, wb) = rgb(0xFFFFFF);
    font::draw_string_rgb("IONA", DOCK_W/2 - 14, iona_y + 14, (wr,wg,wb), (0x16,0x2A,0x5C));
}

fn draw_taskbar(sw: usize, sh: usize) {
    let ty = sh - TASKBAR_H;
    fb::fill_rect(DOCK_W, ty, sw - DOCK_W, TASKBAR_H, 0, 0, 0);
    for y in ty..(ty+TASKBAR_H) {
        for x in DOCK_W..sw {
            fb::blend_pixel(x, y, 5, 8, 16, 210);
        }
    }
    // Top border
    let (er, eg, eb) = rgb(0x1A2440);
    fb::hline(DOCK_W, ty, sw - DOCK_W, er, eg, eb);

    // Running app pills (centered)
    let pill_w = 44usize;
    let pill_h = 40usize;
    let pill_y = ty + (TASKBAR_H - pill_h) / 2;
    let mut pill_x = sw / 2 - (APPS.len() * (pill_w + 4)) / 2;

    // Desktop button
    let (pr, pg, pb) = rgb(0x1A2A4A);
    fb::fill_rect_rounded(DOCK_W + 10, pill_y, pill_w, pill_h, pr, pg, pb, 10);
    let (tr, tg, tb) = rgb(COLOR_TEXT_PRIMARY);
    font::draw_string_rgb("⊞", DOCK_W + 22, pill_y + 12, (tr,tg,tb), (pr,pg,pb));

    for app in APPS {
        let (ir, ig, ib) = rgb(app.icon);
        fb::fill_rect_rounded(pill_x, pill_y, pill_w, pill_h, ir, ig, ib, 10);
        // Running indicator dot (blue)
        let (dr, dg, db) = rgb(COLOR_ACCENT);
        fb::fill_rect_rounded(pill_x + pill_w/2 - 2, pill_y + pill_h - 5, 4, 4, dr, dg, db, 2);
        pill_x += pill_w + 6;
    }
}

fn draw_launcher(sw: usize, sh: usize) {
    // Full-screen overlay
    for y in TOPBAR_H..(sh - TASKBAR_H) {
        for x in DOCK_W..sw { fb::blend_pixel(x, y, 5, 10, 20, 220); }
    }
    // Title
    let (tr, tg, tb) = rgb(COLOR_TEXT_PRIMARY);
    font::draw_string_rgb("Aplicatii", sw/2 - 40, TOPBAR_H + 20, (tr,tg,tb), (5,10,20));

    // App grid
    let icon_size = 72usize;
    let cols = 4usize;
    let pad   = 24usize;
    let total_w = cols * (icon_size + pad);
    let start_x = sw / 2 - total_w / 2;
    let start_y = TOPBAR_H + 60;

    for (i, app) in APPS.iter().enumerate() {
        let col = i % cols;
        let row = i / cols;
        let x = start_x + col * (icon_size + pad);
        let y = start_y + row * (icon_size + pad + 20);
        let (ir, ig, ib) = rgb(app.icon);
        fb::fill_rect_rounded(x, y, icon_size, icon_size, ir, ig, ib, 16);
        let lw = app.name.len() * font::FONT_WIDTH;
        let lx = (x as i32 + (icon_size as i32 - lw as i32)/2).max(0) as usize;
        let (lr, lg, lb) = rgb(COLOR_TEXT_PRIMARY);
        font::draw_string_rgb(app.name, lx, y + icon_size + 4, (lr,lg,lb), (5,10,20));
    }
}

/// Handle click on desktop (dock/taskbar/launcher)
pub fn handle_click(px: i32, py: i32) -> bool {
    let (sw, sh) = fb::size();
    let is_dock = px < DOCK_W as i32 && py >= TOPBAR_H as i32;
    let is_taskbar = py >= (sh - TASKBAR_H) as i32;

    if is_dock {
        // Click on app icon in dock
        let icon_size = 40; let icon_pad = 8;
        let start_y = TOPBAR_H + 12;
        for (i, app) in APPS.iter().enumerate() {
            let iy = start_y + i * (icon_size + icon_pad + 12);
            if py >= iy as i32 && py < (iy + icon_size) as i32 {
                spawn_app(app.syscmd);
                return true;
            }
        }
        // IONA button
        let dock_h = sh - TOPBAR_H - TASKBAR_H;
        let iona_y = TOPBAR_H + dock_h - 60;
        if py >= iona_y as i32 {
            let mut ds = DESKTOP.lock();
            ds.launcher_open = !ds.launcher_open;
            ds.dirty = true;
            return true;
        }
    }
    false
}

fn spawn_app(cmd: &str) {
    // Spawn a userspace app window or kernel app via IPC
    let tid = crate::arch::x86_64::percpu::current_tid();
    match cmd {
        "terminal" => { wm::create_window("Terminal", 120, 80, 560, 340, tid); }
        "files"    => { wm::create_window("Fișiere — /home/iona", 160, 100, 600, 380, tid); }
        "monitor"  => { wm::create_window("IONA Monitor", 180, 120, 440, 460, tid); }
        "notes"    => { wm::create_window("Notițe", 200, 140, 540, 380, tid); }
        "settings" => { wm::create_window("Setări", 220, 160, 520, 400, tid); }
        _ => {}
    }
    DESKTOP.lock().dirty = true;
}

pub fn mark_dirty() { DESKTOP.lock().dirty = true; }

/// Draw desktop only if dirty — returns true if actually redrawn
pub fn draw_if_dirty() -> bool {
    if DESKTOP.lock().dirty || crate::gui::wm::WM.lock().focused.is_none() {
        draw();
        return true;
    }
    false
}

// ── System context menu ───────────────────────────────────────────────────────
/// Shows on right-click on desktop background
pub fn show_context_menu(x: i32, y: i32) {
    crate::serial_println!("[DESKTOP] system_menu at ({}, {})", x, y);
    DESKTOP.lock().dirty = true;
    draw_context_menu(x as usize, y as usize);
}

/// Handle click inside context menu — returns true if click was consumed
pub fn on_context_click(click_x: i32, click_y: i32) -> bool {
    // Context menu items (same order as draw_context_menu)
    let items: &[(&str, &str)] = &[
        ("Terminal",  "terminal"),
        ("Files",     "files"),
        ("Monitor",   "monitor"),
        ("---",       ""),
        ("Setari",    "settings"),
        ("Repornire", "reboot"),
        ("Inchidere", "shutdown"),
    ];
    let (sw, sh) = crate::io::framebuffer::size();
    let item_h = crate::io::font::FONT_HEIGHT + 10;
    let w = 180usize;
    let h = items.len() * item_h + 8;
    // Same clamping as draw_context_menu
    let mx = (click_x as usize).min(sw.saturating_sub(w));
    // We don't have stored menu position, use heuristic: if click is in right area
    for (i, &(label, cmd)) in items.iter().enumerate() {
        if label == "---" { continue; }
        let iy = 4 + i * item_h;
        // Approximate check (menu was at click origin − small offset)
        if cmd == "reboot"   { crate::acpi::power::acpi_s5_shutdown(); return true; }
        if cmd == "shutdown" { crate::acpi::power::acpi_s5_shutdown(); return true; }
        if !cmd.is_empty() {
            // Spawn app
            let tid = crate::arch::x86_64::percpu::current_tid();
            match cmd {
                "terminal" => { crate::gui::wm::create_window("Terminal",   100,60, 560,340, tid); }
                "files"    => { crate::gui::wm::create_window("Fisiere",    120,80, 600,380, tid); }
                "monitor"  => { crate::gui::wm::create_window("Monitor",    140,100,440,460, tid); }
                "settings" => { crate::gui::wm::create_window("Setari",     160,120,520,400, tid); }
                _ => {}
            }
            DESKTOP.lock().dirty = true;
            return true;
        }
    }
    false
}

fn draw_context_menu(x: usize, y: usize) {
    use crate::gui::theme::*;
    use crate::io::{framebuffer as fb, font};

    let items: &[&str] = &["Terminal", "Files", "Monitor", "---", "Setari", "Repornire", "Inchidere"];
    let item_h = font::FONT_HEIGHT + 10;
    let w = 180usize;
    let h = items.len() * item_h + 8;

    // Clamp to screen
    let (sw, sh) = fb::size();
    let mx = x.min(sw.saturating_sub(w));
    let my = y.min(sh.saturating_sub(h));

    // Background
    let (br, bg, bb) = rgb(0x0D1626);
    fb::fill_rect_rounded(mx, my, w, h, br, bg, bb, 8);
    fb::draw_rect(mx, my, w, h, 0x2A, 0x3A, 0x5A);

    // Items
    for (i, &item) in items.iter().enumerate() {
        let iy = my + 4 + i * item_h;
        if item == "---" {
            fb::hline(mx+8, iy+item_h/2, w-16, 0x2A, 0x3A, 0x5A);
        } else {
            let (tr, tg, tb) = rgb(COLOR_TEXT_PRIMARY);
            font::draw_string(item, mx+12, iy+5, COLOR_TEXT_PRIMARY, 0x0D1626);
        }
    }
    fb::mark_dirty(mx, my, w, h);
}
