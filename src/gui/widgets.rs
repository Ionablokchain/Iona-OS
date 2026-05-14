#[allow(unused_imports)]
use alloc::format;
// IONA OS Widget Toolkit — no_std GUI components
//
// Widgets render into a &mut [u32] pixel buffer (ARGB 32bpp).
// Each widget is a pure function: (state, rect, pixels) → ()
// No heap allocation for rendering — state is caller-managed.
//
// Widgets:
//   Button       — clickable rectangle with label
//   TextInput    — single-line text editor with cursor + selection
//   Label        — static text
//   ScrollView   — scrollable content area with thumb
//   ProgressBar  — horizontal fill indicator
//   Checkbox     — toggle with checkmark
//   Panel        — colored background rectangle

use alloc::{string::String, vec::Vec};
use crate::io::{framebuffer as fb, font};
use crate::gui::theme::*;

/// Pixel rectangle (all in screen coordinates)
#[derive(Clone, Copy, Debug)]
pub struct Rect { pub x: usize, pub y: usize, pub w: usize, pub h: usize }

impl Rect {
    pub fn contains(&self, px: i32, py: i32) -> bool {
        px >= self.x as i32 && px < (self.x + self.w) as i32
        && py >= self.y as i32 && py < (self.y + self.h) as i32
    }
}

// ── Button ────────────────────────────────────────────────────────────────────
#[derive(Clone, Debug, PartialEq)]
pub enum BtnState { Normal, Hover, Pressed, Disabled }

pub struct Button {
    pub rect:    Rect,
    pub label:   String,
    pub state:   BtnState,
}

impl Button {
    pub fn new(x: usize, y: usize, w: usize, h: usize, label: &str) -> Self {
        Self { rect: Rect{x,y,w,h}, label: label.into(), state: BtnState::Normal }
    }

    pub fn draw(&self) {
        let (br, bg, bb) = rgb(match self.state {
            BtnState::Normal   => COLOR_BTN_BG,
            BtnState::Hover    => COLOR_BTN_BG_HOVER,
            BtnState::Pressed  => COLOR_BTN_BG_PRESS,
            BtnState::Disabled => 0x0A1020,
        });
        fb::fill_rect_rounded(self.rect.x, self.rect.y, self.rect.w, self.rect.h, br, bg, bb, 6);
        let (er, eg, eb) = rgb(COLOR_BTN_BORDER);
        fb::draw_rect(self.rect.x, self.rect.y, self.rect.w, self.rect.h, er, eg, eb);

        // Center label
        let tw = self.label.len() * font::FONT_WIDTH;
        let tx = self.rect.x + self.rect.w.saturating_sub(tw) / 2;
        let ty = self.rect.y + self.rect.h.saturating_sub(font::FONT_HEIGHT) / 2;
        let (tr, tg, tb) = rgb(if self.state == BtnState::Pressed { COLOR_BTN_TEXT_PRESS } else { COLOR_BTN_TEXT });
        let (bgr, bgg, bgb) = rgb(match self.state {
            BtnState::Normal  => COLOR_BTN_BG,
            BtnState::Hover   => COLOR_BTN_BG_HOVER,
            BtnState::Pressed => COLOR_BTN_BG_PRESS,
            _                 => 0x0A1020,
        });
        font::draw_string_rgb(&self.label, tx, ty, (tr,tg,tb), (bgr,bgg,bgb));
    }

    pub fn on_mouse(&mut self, px: i32, py: i32, pressed: bool) -> bool {
        if self.state == BtnState::Disabled { return false; }
        let inside = self.rect.contains(px, py);
        let clicked = inside && self.state == BtnState::Pressed && !pressed;
        self.state = match (inside, pressed) {
            (true,  true)  => BtnState::Pressed,
            (true,  false) => BtnState::Hover,
            (false, _)     => BtnState::Normal,
        };
        clicked
    }
}

// ── TextInput ─────────────────────────────────────────────────────────────────
pub struct TextInput {
    pub rect:    Rect,
    pub value:   String,
    pub cursor:  usize,   // byte position
    pub sel_start: Option<usize>,
    pub focused: bool,
    pub placeholder: String,
    pub cursor_blink: u64, // uptime_ms when cursor last toggled
    pub cursor_on: bool,
}

impl TextInput {
    pub fn new(x: usize, y: usize, w: usize, placeholder: &str) -> Self {
        let h = font::FONT_HEIGHT + 8;
        Self {
            rect: Rect{x,y,w,h}, value: String::new(), cursor: 0,
            sel_start: None, focused: false,
            placeholder: placeholder.into(),
            cursor_blink: 0, cursor_on: true,
        }
    }

    pub fn draw(&mut self) {
        let (br, bg, bb) = rgb(COLOR_INPUT_BG);
        fb::fill_rect(self.rect.x, self.rect.y, self.rect.w, self.rect.h, br, bg, bb);
        let (er, eg, eb) = rgb(if self.focused { COLOR_INPUT_BORDER_FOCUS } else { COLOR_INPUT_BORDER });
        fb::draw_rect(self.rect.x, self.rect.y, self.rect.w, self.rect.h, er, eg, eb);
        if self.focused && self.value.is_empty() {
            // Just draw border highlight
        }

        let tx = self.rect.x + 6;
        let ty = self.rect.y + 4;
        let bg_tuple = rgb(COLOR_INPUT_BG);

        if self.value.is_empty() && !self.focused {
            let (pr, pg, pb) = rgb(COLOR_TEXT_MUTED);
            font::draw_string_rgb(&self.placeholder, tx, ty, (pr,pg,pb), bg_tuple);
        } else {
            // Draw text
            let (tr, tg, tb) = rgb(COLOR_INPUT_TEXT);
            // Clip text to visible area
            let max_chars = (self.rect.w.saturating_sub(12)) / font::FONT_WIDTH;
            let visible_start = self.cursor.saturating_sub(max_chars);
            let visible = &self.value[visible_start.min(self.value.len())..];
            let visible = &visible[..visible.len().min(max_chars)];
            font::draw_string_rgb(visible, tx, ty, (tr,tg,tb), bg_tuple);

            // Draw cursor
            if self.focused {
                let now = crate::arch::x86_64::timer::uptime_ms();
                if now - self.cursor_blink > 500 {
                    self.cursor_on = !self.cursor_on;
                    self.cursor_blink = now;
                }
                if self.cursor_on {
                    let cur_col = self.cursor.saturating_sub(visible_start);
                    let cx = tx + cur_col * font::FONT_WIDTH;
                    let (cr, cg, cb) = rgb(COLOR_INPUT_CURSOR);
                    fb::vline(cx, ty, font::FONT_HEIGHT, cr, cg, cb);
                }
            }
        }
    }

    pub fn on_click(&mut self, px: i32, py: i32) -> bool {
        let was = self.focused;
        self.focused = self.rect.contains(px, py);
        if self.focused && !was { self.cursor_blink = 0; self.cursor_on = true; }
        self.focused
    }

    pub fn on_key(&mut self, key: &crate::gui::events::Key, ch: Option<char>) {
        use crate::gui::events::Key;
        match key {
            Key::Char(c) => {
                self.value.insert(self.cursor, *c);
                self.cursor += 1;
            }
            Key::Backspace => {
                if self.cursor > 0 && !self.value.is_empty() {
                    self.cursor -= 1;
                    self.value.remove(self.cursor);
                }
            }
            Key::Delete => {
                if self.cursor < self.value.len() { self.value.remove(self.cursor); }
            }
            Key::Left  => { if self.cursor > 0 { self.cursor -= 1; } }
            Key::Right => { if self.cursor < self.value.len() { self.cursor += 1; } }
            Key::Home  => { self.cursor = 0; }
            Key::End   => { self.cursor = self.value.len(); }
            _ => {}
        }
    }
}

// ── Label ─────────────────────────────────────────────────────────────────────
pub fn draw_label(text: &str, x: usize, y: usize, color: u32, bg: u32) {
    let (r,g,b) = rgb(color);
    let (br,bg2,bb) = rgb(bg);
    font::draw_string_rgb(text, x, y, (r,g,b), (br,bg2,bb));
}

// ── ProgressBar ───────────────────────────────────────────────────────────────
pub struct ProgressBar {
    pub rect:  Rect,
    pub value: f32,  // 0.0..1.0
    pub color: u32,
}

impl ProgressBar {
    pub fn new(x: usize, y: usize, w: usize, h: usize) -> Self {
        Self { rect: Rect{x,y,w,h}, value: 0.0, color: COLOR_ACCENT }
    }
    pub fn draw(&self) {
        let (br,bg,bb) = rgb(0x0A1020);
        fb::fill_rect(self.rect.x, self.rect.y, self.rect.w, self.rect.h, br, bg, bb);
        fb::draw_rect(self.rect.x, self.rect.y, self.rect.w, self.rect.h, 0x2A, 0x3A, 0x5A);
        let filled = (self.rect.w as f32 * self.value.clamp(0.0, 1.0)) as usize;
        if filled > 0 {
            let (r,g,b) = rgb(self.color);
            fb::fill_rect_rounded(self.rect.x+1, self.rect.y+1, filled.saturating_sub(2), self.rect.h.saturating_sub(2), r, g, b, 3);
        }
    }
    pub fn set(&mut self, v: f32) { self.value = v.clamp(0.0, 1.0); }
}

// ── Checkbox ──────────────────────────────────────────────────────────────────
pub struct Checkbox {
    pub rect:    Rect,
    pub checked: bool,
    pub label:   String,
}

impl Checkbox {
    pub fn new(x: usize, y: usize, label: &str) -> Self {
        let sz = font::FONT_HEIGHT;
        Self { rect: Rect{x, y, w: sz, h: sz}, checked: false, label: label.into() }
    }
    pub fn draw(&self) {
        let sz = self.rect.w;
        let (br, bg, bb) = rgb(COLOR_INPUT_BG);
        fb::fill_rect(self.rect.x, self.rect.y, sz, sz, br, bg, bb);
        let (er, eg, eb) = rgb(if self.checked { COLOR_ACCENT } else { COLOR_INPUT_BORDER });
        fb::draw_rect(self.rect.x, self.rect.y, sz, sz, er, eg, eb);
        if self.checked {
            // Checkmark: two lines
            let (cr, cg, cb) = rgb(COLOR_ACCENT);
            fb::hline(self.rect.x+2, self.rect.y+sz/2, sz-4, cr, cg, cb);
            fb::vline(self.rect.x+sz/2, self.rect.y+2, sz-4, cr, cg, cb);
        }
        // Label
        let tx = self.rect.x + sz + 6;
        let ty = self.rect.y + (sz - font::FONT_HEIGHT) / 2;
        let (tr, tg, tb) = rgb(COLOR_TEXT_PRIMARY);
        font::draw_string_rgb(&self.label, tx, ty, (tr,tg,tb), rgb(COLOR_WINDOW_BG));
    }
    pub fn on_click(&mut self, px: i32, py: i32) -> bool {
        if self.rect.contains(px, py) { self.checked = !self.checked; true } else { false }
    }
}

// ── ScrollView ────────────────────────────────────────────────────────────────
pub struct ScrollView {
    pub rect:        Rect,
    pub content_h:   usize,  // total content height in pixels
    pub scroll_y:    usize,  // current scroll offset
    pub thumb_drag:  bool,
    pub drag_start:  (i32, i32),
    pub drag_scroll: usize,
}

const SCROLL_W: usize = 10;

impl ScrollView {
    pub fn new(x: usize, y: usize, w: usize, h: usize) -> Self {
        Self { rect: Rect{x,y,w,h}, content_h: h, scroll_y: 0,
               thumb_drag: false, drag_start: (0,0), drag_scroll: 0 }
    }

    pub fn scroll_by(&mut self, dy: i32) {
        if dy < 0 {
            self.scroll_y = self.scroll_y.saturating_sub((-dy) as usize * 20);
        } else {
            let max = self.content_h.saturating_sub(self.rect.h);
            self.scroll_y = (self.scroll_y + dy as usize * 20).min(max);
        }
    }

    /// Draw scrollbar track + thumb
    pub fn draw_scrollbar(&self) {
        let track_x = self.rect.x + self.rect.w - SCROLL_W;
        let (tr, tg, tb) = rgb(COLOR_SCROLLBAR_BG);
        fb::fill_rect(track_x, self.rect.y, SCROLL_W, self.rect.h, tr, tg, tb);
        // Thumb
        if self.content_h > self.rect.h {
            let thumb_h = (self.rect.h * self.rect.h / self.content_h).max(20);
            let thumb_y = self.rect.y + self.scroll_y * self.rect.h / self.content_h;
            let (hr, hg, hb) = rgb(if self.thumb_drag { COLOR_SCROLLBAR_HOVER } else { COLOR_SCROLLBAR_THUMB });
            fb::fill_rect_rounded(track_x+1, thumb_y, SCROLL_W-2, thumb_h, hr, hg, hb, 3);
        }
    }

    /// Content viewport rect (excluding scrollbar)
    pub fn viewport(&self) -> Rect {
        Rect { x: self.rect.x, y: self.rect.y, w: self.rect.w - SCROLL_W, h: self.rect.h }
    }
}

// ── Slider ────────────────────────────────────────────────────────────────────
pub struct Slider {
    pub rect:  Rect,
    pub value: f32,   // 0.0..1.0
    pub min:   f32,
    pub max:   f32,
    pub dragging: bool,
    pub color: u32,
}

impl Slider {
    pub fn new(x: usize, y: usize, w: usize, min: f32, max: f32) -> Self {
        Self { rect: Rect{x,y,w,h:20}, value:(min+max)/2.0, min, max,
               dragging: false, color: COLOR_ACCENT }
    }
    pub fn draw(&self) {
        let (tr, tg, tb) = rgb(0x0A1020);
        fb::fill_rect(self.rect.x, self.rect.y+7, self.rect.w, 6, tr, tg, tb);
        fb::draw_rect(self.rect.x, self.rect.y+7, self.rect.w, 6, 0x2A,0x3A,0x5A);
        // Filled portion
        let pct = (self.value - self.min) / (self.max - self.min).max(0.001);
        let filled = (self.rect.w as f32 * pct) as usize;
        if filled > 0 {
            let (r,g,b) = rgb(self.color);
            fb::fill_rect(self.rect.x, self.rect.y+7, filled, 6, r, g, b);
        }
        // Thumb
        let thumb_x = self.rect.x + filled;
        fb::fill_rect_rounded(
            thumb_x.saturating_sub(8), self.rect.y+2,
            16, 16, 0xCC,0xDD,0xFF, 8
        );
        // Value label
        let pct_int = (pct * 100.0) as u32;
        let lbl = alloc::format!("{}%", pct_int);
        let (lr,lg,lb) = rgb(COLOR_TEXT_SECONDARY);
        font::draw_string_rgb(&lbl, self.rect.x + self.rect.w + 8, self.rect.y + 2,
                               (lr,lg,lb), rgb(COLOR_WINDOW_BG));
    }
    pub fn on_mouse(&mut self, px: i32, _py: i32, pressed: bool) -> bool {
        if pressed && self.rect.contains(px, _py) {
            self.dragging = true;
        }
        if !pressed { self.dragging = false; }
        if self.dragging && self.rect.w > 0 {
            let rel = (px - self.rect.x as i32).clamp(0, self.rect.w as i32) as f32;
            self.value = self.min + (self.max - self.min) * rel / self.rect.w as f32;
            return true;
        }
        false
    }
    pub fn value_norm(&self) -> f32 {
        (self.value - self.min) / (self.max - self.min).max(0.001)
    }
}

// ── Tooltip ───────────────────────────────────────────────────────────────────
pub struct Tooltip {
    pub text:    alloc::string::String,
    pub visible: bool,
    pub x:       usize,
    pub y:       usize,
}

impl Tooltip {
    pub fn new(text: &str) -> Self {
        Self { text: text.into(), visible: false, x: 0, y: 0 }
    }
    pub fn show(&mut self, x: usize, y: usize) { self.visible = true; self.x=x; self.y=y; }
    pub fn hide(&mut self) { self.visible = false; }
    pub fn draw(&self) {
        if !self.visible { return; }
        let tw = self.text.len() * font::FONT_WIDTH + 12;
        let th = font::FONT_HEIGHT + 8;
        let (br,bg,bb) = rgb(0x1A2A4A);
        fb::fill_rect_rounded(self.x, self.y.saturating_sub(th+4), tw, th, br, bg, bb, 4);
        fb::draw_rect(self.x, self.y.saturating_sub(th+4), tw, th, 0x3A,0x4A,0x6A);
        let (tr,tg,tb) = rgb(COLOR_TEXT_PRIMARY);
        font::draw_string_rgb(&self.text, self.x+6,
            self.y.saturating_sub(th+4)+4, (tr,tg,tb), (br,bg,bb));
    }
}

// ── Dropdown ─────────────────────────────────────────────────────────────────
pub struct Dropdown {
    pub rect:    Rect,
    pub items:   Vec<alloc::string::String>,
    pub selected: usize,
    pub open:    bool,
}

impl Dropdown {
    pub fn new(x: usize, y: usize, w: usize, items: Vec<alloc::string::String>) -> Self {
        let h = font::FONT_HEIGHT + 8;
        Self { rect: Rect{x,y,w,h}, items, selected: 0, open: false }
    }
    pub fn draw(&self) {
        // Main button
        let (br,bg,bb) = rgb(COLOR_BTN_BG);
        fb::fill_rect_rounded(self.rect.x, self.rect.y, self.rect.w, self.rect.h, br,bg,bb, 5);
        fb::draw_rect(self.rect.x, self.rect.y, self.rect.w, self.rect.h, 0x2A,0x3A,0x5A);
        // Selected text
        if let Some(sel) = self.items.get(self.selected) {
            let (tr,tg,tb) = rgb(COLOR_TEXT_PRIMARY);
            font::draw_string_rgb(sel, self.rect.x+8, self.rect.y+4, (tr,tg,tb), rgb(COLOR_BTN_BG));
        }
        // Arrow ▼
        let ax = self.rect.x + self.rect.w - 20;
        let ay = self.rect.y + self.rect.h/2;
        let (ar,ag,ab) = rgb(COLOR_TEXT_SECONDARY);
        fb::fill_rect(ax, ay-1, 8, 2, ar, ag, ab);
        fb::fill_rect(ax+2, ay+1, 4, 2, ar, ag, ab);
        fb::fill_rect(ax+4, ay+3, 0, 0, ar, ag, ab);

        // Dropdown list
        if self.open {
            let list_y = self.rect.y + self.rect.h;
            let item_h = font::FONT_HEIGHT + 6;
            let list_h = self.items.len() * item_h + 4;
            let (lr,lg,lb) = rgb(0x0D1626);
            fb::fill_rect_rounded(self.rect.x, list_y, self.rect.w, list_h, lr,lg,lb, 5);
            fb::draw_rect(self.rect.x, list_y, self.rect.w, list_h, 0x2A,0x3A,0x5A);
            for (i, item) in self.items.iter().enumerate() {
                let iy = list_y + 2 + i * item_h;
                if i == self.selected {
                    fb::fill_rect(self.rect.x+2, iy, self.rect.w-4, item_h-1, 0x1A,0x3A,0x7A);
                }
                let (tr,tg,tb) = rgb(if i==self.selected {COLOR_TEXT_PRIMARY} else {COLOR_TEXT_SECONDARY});
                font::draw_string_rgb(item, self.rect.x+8, iy+3, (tr,tg,tb), rgb(if i==self.selected {0x1A3A7A} else {0x0D1626}));
            }
        }
    }
    pub fn on_click(&mut self, px: i32, py: i32) -> Option<usize> {
        if self.rect.contains(px, py) {
            self.open = !self.open;
            return None;
        }
        if self.open {
            let list_y = self.rect.y + self.rect.h;
            let item_h = font::FONT_HEIGHT + 6;
            for (i, _) in self.items.iter().enumerate() {
                let iy = list_y + 2 + i * item_h;
                let r = Rect { x: self.rect.x, y: iy, w: self.rect.w, h: item_h };
                if r.contains(px, py) {
                    self.selected = i;
                    self.open = false;
                    return Some(i);
                }
            }
            self.open = false;
        }
        None
    }
}

// ── MenuBar ───────────────────────────────────────────────────────────────────
pub struct MenuItem {
    pub label: alloc::string::String,
    pub items: Vec<alloc::string::String>,
}

pub struct MenuBar {
    pub rect:   Rect,
    pub menus:  Vec<MenuItem>,
    pub active: Option<usize>,  // open menu index
}

impl MenuBar {
    pub fn new(x: usize, y: usize, w: usize) -> Self {
        Self { rect: Rect{x,y,w,h:24}, menus: Vec::new(), active: None }
    }
    pub fn add_menu(&mut self, label: &str, items: Vec<&str>) {
        self.menus.push(MenuItem {
            label: label.into(),
            items: items.into_iter().map(|s| s.into()).collect(),
        });
    }
    pub fn draw(&self) {
        // Bar background
        let (br,bg,bb) = rgb(0x0A1020);
        fb::fill_rect(self.rect.x, self.rect.y, self.rect.w, self.rect.h, br,bg,bb);
        fb::hline(self.rect.x, self.rect.y+self.rect.h-1, self.rect.w, 0x1A,0x2A,0x4A);
        // Menu labels
        let mut lx = self.rect.x + 8;
        for (i, menu) in self.menus.iter().enumerate() {
            let lw = menu.label.len() * font::FONT_WIDTH + 16;
            let is_active = self.active == Some(i);
            if is_active {
                fb::fill_rect(lx-4, self.rect.y+1, lw, self.rect.h-2, 0x1A,0x3A,0x7A);
            }
            let (tr,tg,tb) = rgb(if is_active {COLOR_TEXT_PRIMARY} else {COLOR_TEXT_SECONDARY});
            font::draw_string_rgb(&menu.label, lx+4, self.rect.y+4, (tr,tg,tb),
                                   rgb(if is_active {0x1A3A7A} else {0x0A1020}));
            // Dropdown
            if is_active {
                let item_h = font::FONT_HEIGHT + 6;
                let list_h = menu.items.len() * item_h + 4;
                let (dr,dg,db) = rgb(0x0D1626);
                fb::fill_rect_rounded(lx-4, self.rect.y+self.rect.h,
                    lw.max(160), list_h, dr,dg,db, 5);
                fb::draw_rect(lx-4, self.rect.y+self.rect.h, lw.max(160), list_h, 0x2A,0x3A,0x5A);
                for (j, item) in menu.items.iter().enumerate() {
                    let iy = self.rect.y + self.rect.h + 2 + j * item_h;
                    if item == "---" {
                        fb::hline(lx, iy + item_h/2, lw.max(160)-8, 0x2A,0x3A,0x5A);
                    } else {
                        let (ir,ig,ib) = rgb(COLOR_TEXT_SECONDARY);
                        font::draw_string_rgb(item, lx+4, iy+3, (ir,ig,ib), rgb(0x0D1626));
                    }
                }
            }
            lx += lw;
        }
    }
    pub fn on_click(&mut self, px: i32, py: i32) -> Option<(usize, usize)> {
        // Check menu bar labels
        let mut lx = self.rect.x + 8;
        for (i, menu) in self.menus.iter().enumerate() {
            let lw = menu.label.len() * font::FONT_WIDTH + 16;
            let br = Rect { x: lx-4, y: self.rect.y, w: lw, h: self.rect.h };
            if br.contains(px, py) {
                self.active = if self.active == Some(i) { None } else { Some(i) };
                return None;
            }
            // Check dropdown items
            if self.active == Some(i) {
                let item_h = font::FONT_HEIGHT + 6;
                for (j, item) in menu.items.iter().enumerate() {
                    if item == "---" { lx += lw; continue; }
                    let iy = self.rect.y + self.rect.h + 2 + j * item_h;
                    let ir = Rect { x: lx-4, y: iy, w: lw.max(160), h: item_h };
                    if ir.contains(px, py) {
                        self.active = None;
                        return Some((i, j));
                    }
                }
            }
            lx += lw;
        }
        if self.active.is_some() { self.active = None; }
        None
    }
}

// ── Modal / Dialog ────────────────────────────────────────────────────────────
pub struct Modal {
    pub title:   alloc::string::String,
    pub message: alloc::string::String,
    pub buttons: Vec<alloc::string::String>,
    pub visible: bool,
    pub result:  Option<usize>,  // which button was clicked
    rect:        Rect,
    btns:        Vec<Button>,
}

impl Modal {
    pub fn new(title: &str, message: &str, buttons: Vec<&str>) -> Self {
        let w = 360usize; let h = 160usize;
        let (sw, sh) = fb::size();
        let x = sw.saturating_sub(w) / 2;
        let y = sh.saturating_sub(h) / 2;

        let btn_w = 90; let btn_h = 30;
        let n = buttons.len();
        let total_btn_w = n * btn_w + (n-1) * 8;
        let btn_start_x = x + (w - total_btn_w) / 2;
        let btn_y = y + h - btn_h - 16;

        let btns: Vec<Button> = buttons.iter().enumerate().map(|(i, lbl)| {
            Button::new(btn_start_x + i * (btn_w+8), btn_y, btn_w, btn_h, lbl)
        }).collect();

        Self {
            title: title.into(), message: message.into(),
            buttons: buttons.into_iter().map(|s| s.into()).collect(),
            visible: false, result: None,
            rect: Rect{x,y,w,h}, btns,
        }
    }
    pub fn show(&mut self) { self.visible = true; self.result = None; }
    pub fn hide(&mut self) { self.visible = false; }

    pub fn draw(&self) {
        if !self.visible { return; }
        // Dimmed backdrop
        for y in 0..fb::height() {
            for x in 0..fb::width() {
                fb::blend_pixel(x, y, 0, 0, 0, 160);
            }
        }
        // Dialog box
        let (dr,dg,db) = rgb(0x0D1626);
        fb::fill_rect_rounded(self.rect.x, self.rect.y, self.rect.w, self.rect.h, dr,dg,db, 10);
        fb::draw_rect(self.rect.x, self.rect.y, self.rect.w, self.rect.h, 0x3A,0x4A,0x7A);
        // Title
        let (tr,tg,tb) = rgb(COLOR_TEXT_PRIMARY);
        font::draw_string_rgb(&self.title, self.rect.x+16, self.rect.y+16, (tr,tg,tb), rgb(0x0D1626));
        // Divider
        fb::hline(self.rect.x+8, self.rect.y+36, self.rect.w-16, 0x2A,0x3A,0x5A);
        // Message
        let (mr,mg,mb) = rgb(COLOR_TEXT_SECONDARY);
        font::draw_string_rgb(&self.message, self.rect.x+16, self.rect.y+50, (mr,mg,mb), rgb(0x0D1626));
        // Buttons
        for btn in &self.btns { btn.draw(); }
    }

    pub fn on_click(&mut self, px: i32, py: i32) -> Option<usize> {
        if !self.visible { return None; }
        for (i, btn) in self.btns.iter_mut().enumerate() {
            if btn.on_mouse(px, py, true) || btn.rect.contains(px, py) {
                self.result = Some(i);
                self.visible = false;
                return Some(i);
            }
        }
        None
    }
}

// ── TabBar ─────────────────────────────────────────────────────────────────────
pub struct TabBar {
    pub rect:   Rect,
    pub tabs:   Vec<alloc::string::String>,
    pub active: usize,
}

impl TabBar {
    pub fn new(x: usize, y: usize, w: usize) -> Self {
        Self { rect: Rect{x,y,w,h:28}, tabs: Vec::new(), active: 0 }
    }
    pub fn add(&mut self, label: &str) { self.tabs.push(label.into()); }
    pub fn draw(&self) {
        let (br,bg,bb) = rgb(COLOR_WINDOW_BG);
        fb::fill_rect(self.rect.x, self.rect.y, self.rect.w, self.rect.h, br,bg,bb);
        fb::hline(self.rect.x, self.rect.y+self.rect.h-1, self.rect.w, 0x1A,0x2A,0x4A);
        let tab_w = if self.tabs.is_empty() { 80 }
                    else { (self.rect.w / self.tabs.len()).max(60) };
        for (i, tab) in self.tabs.iter().enumerate() {
            let tx = self.rect.x + i * tab_w;
            let is_active = i == self.active;
            let (tbr,tbg,tbb) = rgb(if is_active { COLOR_TITLEBAR_FOCUSED } else { COLOR_WINDOW_BG });
            fb::fill_rect(tx, self.rect.y, tab_w, self.rect.h, tbr, tbg, tbb);
            if is_active {
                let (ar,ag,ab) = rgb(COLOR_ACCENT);
                fb::hline(tx, self.rect.y+self.rect.h-2, tab_w, ar,ag,ab);
            }
            let tw = tab.len() * font::FONT_WIDTH;
            let tlx = tx + (tab_w.saturating_sub(tw)) / 2;
            let tly = self.rect.y + (self.rect.h - font::FONT_HEIGHT) / 2;
            let (tr,tg,tb) = rgb(if is_active {COLOR_TEXT_PRIMARY} else {COLOR_TEXT_SECONDARY});
            font::draw_string_rgb(tab, tlx, tly, (tr,tg,tb), rgb(if is_active {COLOR_TITLEBAR_FOCUSED} else {COLOR_WINDOW_BG}));
        }
    }
    pub fn on_click(&mut self, px: i32, py: i32) -> Option<usize> {
        if !self.rect.contains(px, py) { return None; }
        let tab_w = if self.tabs.is_empty() { 80 }
                    else { (self.rect.w / self.tabs.len()).max(60) };
        let idx = ((px - self.rect.x as i32) / tab_w as i32) as usize;
        if idx < self.tabs.len() { self.active = idx; Some(idx) } else { None }
    }
}
