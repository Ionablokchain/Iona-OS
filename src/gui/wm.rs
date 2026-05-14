//! IONA OS Window Manager
//!
//! Focus model:
//!   - KEYBOARD focus: fereastra care primește KeyDown/KeyUp events
//!     → se schimbă la MouseDown în orice zonă din frame-ul ferestrei
//!     → se schimbă la alt+tab (TODO: ciclic)
//!     → vizual: border albastru + titlebar luminat + titlu alb
//!   - MOUSE focus: fereastra topmost sub cursor (hover)
//!     → hover nu schimbă keyboard focus
//!     → MouseDown schimbă atât keyboard focus cât și z-order (bring-to-front)
//!   - Pierdere focus: click pe desktop → focused = None
//!
//! Hit testing — stratificat în ordine z:
//!   1. btn_close / btn_min / btn_max (12px circ, dreapta titlebar)
//!   2. resize_zone (6×6 colț dreapta-jos)
//!   3. titlebar (drag)
//!   4. client area (forward to app)
//!   5. niciun window → desktop
//!
//! Move/resize pipeline:
//!   MouseDown titlebar  → drag_start → DragState::Moving
//!   MouseDown resize    → drag_start → DragState::Resizing
//!   MouseMove           → update position/size, mark dirty old+new rect
//!   MouseUp             → DragState::None

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use spin::{Lazy, Mutex};
use crate::gui::events::{GuiEvent, MouseBtn, Key, Mods};
use crate::gui::theme::*;
use crate::io::{framebuffer as fb, font};

// ── Window ────────────────────────────────────────────────────────────────────
#[derive(Clone, Debug)]
pub struct Window {
    pub id:        u32,
    pub title:     String,
    pub x:         i32,
    pub y:         i32,
    pub w:         u32,
    pub h:         u32,
    pub z:         u32,
    pub visible:   bool,
    pub minimized: bool,
    pub maximized: bool,
    pub pre_max:   Option<(i32,i32,u32,u32)>,
    pub pixels:    Vec<u32>,
    pub dirty:     bool,
    pub owner_tid: crate::task::TaskId,
}

// Dimension constants — all pub so compositor can use them
pub const TITLEBAR_H:  u32 = 30;
pub const BORDER:      u32 = 1;
pub const BTN_SIZE:    u32 = 12;
pub const BTN_MARGIN:  u32 = 10;
pub const BTN_GAP:     u32 = 6;
pub const RESIZE_ZONE: u32 = 8;
pub const SHADOW_D:    u32 = 4;

impl Window {
    pub fn new(id: u32, title: String, x: i32, y: i32, w: u32, h: u32,
               owner_tid: crate::task::TaskId) -> Self {
        Self {
            id, title, x, y, w, h, z: id,
            visible: true, minimized: false, maximized: false,
            pre_max: None,
            pixels: alloc::vec![COLOR_WINDOW_BG; (w * h) as usize],
            dirty: true,
            owner_tid,
        }
    }

    // ── Geometry helpers ──────────────────────────────────────────────────────
    pub fn frame_x(&self) -> i32 { self.x - BORDER as i32 }
    pub fn frame_y(&self) -> i32 { self.y - TITLEBAR_H as i32 - BORDER as i32 }
    pub fn frame_w(&self) -> u32 { self.w + 2*BORDER }
    pub fn frame_h(&self) -> u32 { self.h + TITLEBAR_H + 2*BORDER }

    pub fn titlebar_rect(&self) -> (i32,i32,u32,u32) {
        (self.frame_x(), self.frame_y(), self.frame_w(), TITLEBAR_H)
    }

    // Buttons: close (rightmost) → min → max  (macOS style, left side)
    pub fn btn_close(&self) -> (i32,i32) {
        (self.frame_x() + BTN_MARGIN as i32,
         self.frame_y() + (TITLEBAR_H/2 - BTN_SIZE/2) as i32)
    }
    pub fn btn_min(&self) -> (i32,i32) {
        let (bx,by) = self.btn_close();
        (bx + (BTN_SIZE+BTN_GAP) as i32, by)
    }
    pub fn btn_max(&self) -> (i32,i32) {
        let (bx,by) = self.btn_min();
        (bx + (BTN_SIZE+BTN_GAP) as i32, by)
    }

    pub fn resize_rect(&self) -> (i32,i32,u32,u32) {
        (self.x + self.w as i32 - RESIZE_ZONE as i32,
         self.y + self.h as i32 - RESIZE_ZONE as i32,
         RESIZE_ZONE + BORDER, RESIZE_ZONE + BORDER)
    }

    // ── Hit testing ───────────────────────────────────────────────────────────
    fn btn_hit(bx: i32, by: i32, px: i32, py: i32) -> bool {
        let r = BTN_SIZE as i32;
        // Circle hit test: cheaper than sqrt, use (dx²+dy²) ≤ r²
        let dx = px - (bx + r/2);
        let dy = py - (by + r/2);
        dx*dx + dy*dy <= (r/2)*(r/2) + 4  // +4 forgiveness
    }

    pub fn hit_close (&self, px: i32, py: i32) -> bool { let (x,y)=self.btn_close(); Self::btn_hit(x,y,px,py) }
    pub fn hit_min   (&self, px: i32, py: i32) -> bool { let (x,y)=self.btn_min();   Self::btn_hit(x,y,px,py) }
    pub fn hit_max   (&self, px: i32, py: i32) -> bool { let (x,y)=self.btn_max();   Self::btn_hit(x,y,px,py) }

    pub fn hit_resize(&self, px: i32, py: i32) -> bool {
        let (rx,ry,rw,rh) = self.resize_rect();
        px >= rx && px < rx+rw as i32 && py >= ry && py < ry+rh as i32
    }
    pub fn hit_titlebar(&self, px: i32, py: i32) -> bool {
        let (tx,ty,tw,th) = self.titlebar_rect();
        px >= tx && px < tx+tw as i32 && py >= ty && py < ty+th as i32
    }
    pub fn hit_client(&self, px: i32, py: i32) -> bool {
        px >= self.x && px < self.x+self.w as i32 &&
        py >= self.y && py < self.y+self.h as i32
    }
    pub fn hit_frame(&self, px: i32, py: i32) -> bool {
        px >= self.frame_x() && px < self.frame_x()+self.frame_w() as i32 &&
        py >= self.frame_y() && py < self.frame_y()+self.frame_h() as i32
    }

    /// Detailed hit — returns what was hit inside this window
    pub fn hit_detail(&self, px: i32, py: i32) -> HitResult {
        if !self.visible || self.minimized { return HitResult::None; }
        if !self.hit_frame(px, py)         { return HitResult::None; }
        if self.hit_close(px, py)          { return HitResult::BtnClose; }
        if self.hit_min(px, py)            { return HitResult::BtnMin;   }
        if self.hit_max(px, py)            { return HitResult::BtnMax;   }
        if self.hit_resize(px, py)         { return HitResult::Resize;   }
        if self.hit_titlebar(px, py)       { return HitResult::Titlebar; }
        if self.hit_client(px, py)         { return HitResult::Client;   }
        HitResult::Border
    }

    pub fn frame_dirty_rect(&self) -> (usize,usize,usize,usize) {
        let fx = (self.frame_x() - SHADOW_D as i32).max(0) as usize;
        let fy = (self.frame_y() - SHADOW_D as i32).max(0) as usize;
        let fw = self.frame_w() as usize + SHADOW_D as usize * 2;
        let fh = self.frame_h() as usize + SHADOW_D as usize * 2;
        (fx, fy, fw, fh)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HitResult {
    None, BtnClose, BtnMin, BtnMax, Titlebar, Resize, Client, Border,
}

// ── Drag state ────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq)]
enum DragState {
    None,
    Moving  { wid: u32, off_x: i32, off_y: i32 },
    Resizing{ wid: u32, orig_w: u32, orig_h: u32, start_x: i32, start_y: i32 },
}

// ── WM State ──────────────────────────────────────────────────────────────────
pub struct WmState {
    pub windows:  BTreeMap<u32, Window>,
    pub z_order:  Vec<u32>,          // z_order[0] = topmost
    pub focused:  Option<u32>,       // keyboard focus
    pub hovered:  Option<u32>,       // mouse hover (no keyboard)
    pub next_id:  u32,
    drag:         DragState,
    // last cursor for dirty rect erasure
    last_cursor:  (i32, i32),
}

impl WmState {
    fn new() -> Self {
        Self {
            windows: BTreeMap::new(), z_order: Vec::new(),
            focused: None, hovered: None, next_id: 1,
            drag: DragState::None,
            last_cursor: (400, 300),
        }
    }

    /// Top window (z_order[0]) that contains (px,py)
    fn top_at(&self, px: i32, py: i32) -> Option<u32> {
        for &wid in &self.z_order {
            if let Some(w) = self.windows.get(&wid) {
                if w.visible && !w.minimized && w.hit_frame(px, py) {
                    return Some(wid);
                }
            }
        }
        None
    }

    pub fn bring_to_front(&mut self, wid: u32) {
        self.z_order.retain(|&id| id != wid);
        self.z_order.insert(0, wid);
        let n = self.z_order.len();
        for (i, &id) in self.z_order.iter().enumerate() {
            if let Some(w) = self.windows.get_mut(&id) { w.z = (n-i) as u32; }
        }
    }

    /// Set keyboard focus — marks both old and new window dirty
    pub fn set_focus(&mut self, new_focus: Option<u32>) {
        if self.focused == new_focus { return; }
        // Mark old focused window dirty (needs redraw without focus highlight)
        if let Some(old) = self.focused {
            if let Some(w) = self.windows.get_mut(&old) { w.dirty = true; }
        }
        // Mark new focused window dirty
        if let Some(nw) = new_focus {
            if let Some(w) = self.windows.get_mut(&nw) { w.dirty = true; }
        }
        self.focused = new_focus;
    }
}

pub static WM: Lazy<Mutex<WmState>> = Lazy::new(|| Mutex::new(WmState::new()));

pub fn init() {
    crate::serial_println!("  [GUI/WM] window manager initialized");
    crate::serial_println!("  [GUI/WM] focus: click-to-focus | keyboard → focused window");
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn create_window(title: &str, x: i32, y: i32, w: u32, h: u32,
                     owner_tid: crate::task::TaskId) -> u32 {
    let mut wm = WM.lock();
    let id = wm.next_id; wm.next_id += 1;
    let win = Window::new(id, title.into(), x, y, w, h, owner_tid);
    wm.z_order.insert(0, id);
    wm.windows.insert(id, win);
    wm.focused = Some(id);
    // Mark region dirty
    let w_ref = match wm.windows.get(&id) { Some(w) => w, None => return id };
    let (fx,fy,fw,fh) = w_ref.frame_dirty_rect();
    drop(wm);
    fb::mark_dirty(fx, fy, fw, fh);
    crate::serial_println!("  [GUI/WM] window {} '{}' created {}×{}", id, title, w, h);
    id
}

pub fn close_window(wid: u32) {
    crate::serial_println!("[WM] close_window wid={}", wid);
    let mut wm = WM.lock();
    // Clear the window's frame area in the framebuffer so no stale pixels remain
    if let Some(w) = wm.windows.get(&wid) {
        let fx = w.frame_x().max(0) as usize;
        let fy = w.frame_y().max(0) as usize;
        let fw = w.frame_w() as usize;
        let fh = w.frame_h() as usize;
        // Paint over with a dark background color to clear stale pixels
        fb::fill_rect(fx, fy, fw, fh, 0x08, 0x0C, 0x18);
        fb::mark_dirty(fx, fy, fw, fh);
    }
    wm.windows.remove(&wid);
    wm.z_order.retain(|&id| id != wid);
    if wm.focused == Some(wid) { wm.focused = wm.z_order.first().copied(); }
    if wm.hovered == Some(wid) { wm.hovered = None; }
    fb::mark_all_dirty();
    // Force full shell layer redraw (including wallpaper) so background fills the vacated area
    drop(wm);
    {
        let mut st = crate::gui::SHELL_STATE.lock();
        st.dirty = true;
        st.regions = crate::gui::state::desktop::DirtyRegions::all_dirty();
    }
}

pub fn update_pixels(wid: u32, x: u16, y: u16, w: u16, h: u16, pixels: &[u32]) {
    let mut wm = WM.lock();
    if let Some(win) = wm.windows.get_mut(&wid) {
        let stride = win.w as usize;
        for row in 0..h as usize {
            let dst_y = y as usize + row;
            if dst_y >= win.h as usize { break; }
            let src_off = row * w as usize;
            let dst_off = dst_y * stride + x as usize;
            let copy = (w as usize).min(stride.saturating_sub(x as usize));
            if src_off + copy <= pixels.len() && dst_off + copy <= win.pixels.len() {
                win.pixels[dst_off..dst_off+copy].copy_from_slice(&pixels[src_off..src_off+copy]);
            }
        }
        win.dirty = true;
        // Mark client area dirty
        let wx = win.x as usize; let wy = win.y as usize;
        let ww = win.w as usize; let wh = win.h as usize;
        drop(wm);
        fb::mark_dirty(wx, wy, ww, wh);
    }
}

pub fn set_title(wid: u32, title: String) {
    let mut wm = WM.lock();
    if let Some(w) = wm.windows.get_mut(&wid) {
        w.title = title; w.dirty = true;
        let (fx,fy,fw,_) = w.titlebar_rect();
        let th = TITLEBAR_H as usize;
        drop(wm);
        fb::mark_dirty(fx.max(0) as usize, fy.max(0) as usize, fw as usize, th);
    }
}

pub fn focused_window() -> Option<u32> { WM.lock().focused }

// ── Event dispatch ────────────────────────────────────────────────────────────
pub fn dispatch_event(ev: GuiEvent) {
    match ev {
        GuiEvent::MouseDown { x, y, button: MouseBtn::Left }  => on_ldown(x, y),
        GuiEvent::MouseUp   { x, y, button: MouseBtn::Left }  => on_lup(x, y),
        GuiEvent::MouseMove { x, y, dx, dy }                   => on_move(x, y, dx, dy),
        GuiEvent::MouseDown { x, y, button: MouseBtn::Right }  => on_rdown(x, y),
        GuiEvent::KeyDown   { key, ch, mods }                  => on_key(key, ch, mods),
        GuiEvent::AppDraw   { wid, x, y, w, h, pixels }        => update_pixels(wid, x, y, w, h, &pixels),
        GuiEvent::AppTitle  { wid, title }                      => set_title(wid, title),
        GuiEvent::AppClose  { wid }                             => close_window(wid),
        _ => {}
    }
}

// ── Mouse handlers ────────────────────────────────────────────────────────────
fn on_ldown(px: i32, py: i32) {
    let mut wm = WM.lock();
    let hit_wid = wm.top_at(px, py);

    match hit_wid {
        None => {
            // Click on desktop → lose focus
            wm.set_focus(None);
            wm.drag = DragState::None;
            return;
        }
        Some(wid) => {
            // Bring to front + focus
            let prev_focused = wm.focused;
            wm.bring_to_front(wid);
            wm.set_focus(Some(wid));

            // Mark old+new position dirty if z-order changed
            if prev_focused != Some(wid) { fb::mark_all_dirty(); }

            let win = match wm.windows.get(&wid) { Some(w) => w.clone(), None => return };

            // Hit detail on the now-topmost window
            match win.hit_detail(px, py) {
                HitResult::BtnClose => {
                    drop(wm);
                    // Notify app
                    crate::gui::ipc::push_window_event(wid, crate::gui::ipc::encode_close(wid));
                    close_window(wid);
                }
                HitResult::BtnMin => {
                    if let Some(w) = wm.windows.get_mut(&wid) {
                        w.minimized = !w.minimized; w.dirty = true;
                    }
                    fb::mark_all_dirty();
                }
                HitResult::BtnMax => {
                    let (sw, sh) = fb::size();
                    if let Some(w) = wm.windows.get_mut(&wid) {
                        if !w.maximized {
                            w.pre_max = Some((w.x, w.y, w.w, w.h));
                            w.x = 0; w.y = TITLEBAR_H as i32;
                            w.w = sw as u32; w.h = sh as u32 - TITLEBAR_H - 32;
                            w.maximized = true;
                        } else {
                            if let Some((ox,oy,ow,oh)) = w.pre_max.take() {
                                w.x=ox; w.y=oy; w.w=ow; w.h=oh; w.maximized=false;
                            }
                        }
                        w.pixels.resize((w.w*w.h) as usize, COLOR_WINDOW_BG);
                        w.dirty = true;
                    }
                    fb::mark_all_dirty();
                }
                HitResult::Resize => {
                    let orig = (win.w, win.h);
                    wm.drag = DragState::Resizing { wid, orig_w: orig.0, orig_h: orig.1, start_x: px, start_y: py };
                }
                HitResult::Titlebar => {
                    // Drag starts from frame_y (titlebar top), offset within titlebar
                    let off_x = px - win.x;
                    let off_y = py - win.frame_y();
                    wm.drag = DragState::Moving { wid, off_x, off_y };
                }
                HitResult::Client => {
                    // Forward click to app via IPC
                    let rel_x = (px - win.x).max(0) as u16;
                    let rel_y = (py - win.y).max(0) as u16;
                    let ev = crate::gui::ipc::encode_mouse_btn(wid, px, py, 0, true);
                    crate::gui::ipc::push_window_event(wid, ev);
                }
                _ => {}
            }
        }
    }
}

fn on_lup(px: i32, py: i32) {
    let mut wm = WM.lock();
    // If was dragging/resizing, release
    if wm.drag != DragState::None {
        wm.drag = DragState::None;
    }
    // Forward mouse up to focused window app
    if let Some(wid) = wm.focused {
        let ev = crate::gui::ipc::encode_mouse_btn(wid, px, py, 0, false);
        crate::gui::ipc::push_window_event(wid, ev);
    }
}

fn on_move(px: i32, py: i32, _dx: i16, _dy: i16) {
    let mut wm = WM.lock();

    match wm.drag {
        DragState::Moving { wid, off_x, off_y } => {
            if let Some(win) = wm.windows.get_mut(&wid) {
                if !win.maximized {
                    // Mark old position dirty
                    let (fx,fy,fw,fh) = win.frame_dirty_rect();
                    fb::mark_dirty(fx, fy, fw, fh);

                    // New position: constrain so titlebar always visible
                    let (sw, sh) = fb::size();
                    let new_x = px - off_x;
                    let new_y = py - off_y + TITLEBAR_H as i32;
                    win.x = new_x.clamp(-(win.w as i32 - 60), sw as i32 - 60);
                    win.y = new_y.clamp(TITLEBAR_H as i32, sh as i32 - 32);

                    // Mark new position dirty
                    let (fx2,fy2,fw2,fh2) = win.frame_dirty_rect();
                    fb::mark_dirty(fx2, fy2, fw2, fh2);
                    win.dirty = true;
                }
            }
        }
        DragState::Resizing { wid, orig_w, orig_h, start_x, start_y } => {
            if let Some(win) = wm.windows.get_mut(&wid) {
                let (fx,fy,fw,fh) = win.frame_dirty_rect();
                fb::mark_dirty(fx, fy, fw, fh);

                let new_w = (orig_w as i32 + px - start_x).max(200) as u32;
                let new_h = (orig_h as i32 + py - start_y).max(100) as u32;
                win.w = new_w; win.h = new_h;
                win.pixels.resize((new_w*new_h) as usize, COLOR_WINDOW_BG);
                win.dirty = true;

                let (fx2,fy2,fw2,fh2) = win.frame_dirty_rect();
                fb::mark_dirty(fx2, fy2, fw2, fh2);
            }
        }
        DragState::None => {
            // Update hover — no focus change
            let hovered = wm.top_at(px, py);
            if wm.hovered != hovered {
                wm.hovered = hovered;
                // Send mouse move to focused window if in its client area
            }
            // Forward move event to focused window
            if let Some(wid) = wm.focused {
                if let Some(win) = wm.windows.get(&wid) {
                    if win.hit_client(px, py) {
                        let ev = crate::gui::ipc::encode_mouse_move(wid, px, py, _dx, _dy);
                        crate::gui::ipc::push_window_event(wid, ev);
                    }
                }
            }
        }
    }
}

fn on_rdown(px: i32, py: i32) {
    // Right-click on window: forward to app (context menu)
    let wm = WM.lock();
    if let Some(wid) = wm.top_at(px, py) {
        let ev = crate::gui::ipc::encode_mouse_btn(wid, px, py, 1, true);
        crate::gui::ipc::push_window_event(wid, ev);
    }
}

fn on_key(key: Key, ch: Option<char>, mods: Mods) {
    let wm = WM.lock();
    // Keyboard events go ONLY to the focused window
    if let Some(wid) = wm.focused {
        let ascii = ch.map(|c| c as u8).unwrap_or(0);
        let keycode = match key {
            Key::Char(c) => c as u32,
            Key::Enter   => 0x0D,
            Key::Backspace => 0x08,
            Key::Escape  => 0x1B,
            Key::Tab     => 0x09,
            Key::Left    => 0x25, Key::Right => 0x27,
            Key::Up      => 0x26, Key::Down  => 0x28,
            Key::Home    => 0x24, Key::End   => 0x23,
            Key::Delete  => 0x2E,
            Key::F1      => 0x70, Key::F2 => 0x71,
            Key::F3      => 0x72, Key::F4 => 0x73,
            Key::F5      => 0x74, Key::F11=> 0x7A,
            _            => 0,
        };
        let ev = crate::gui::ipc::encode_key(wid, keycode, ascii, true);
        crate::gui::ipc::push_window_event(wid, ev);
    }
}

// ── Legacy draw functions (kept for compatibility with older callers) ──────────
pub fn redraw_dirty() {}  // now handled by compositor
pub fn repaint_region(_x: usize, _y: usize, _w: usize, _h: usize) {}

// ── Window snapping ───────────────────────────────────────────────────────────
const SNAP_THRESHOLD: i32 = 24; // pixels from edge to trigger snap

/// Check if window should snap to edge and apply snap geometry.
/// Call from MouseUp after a move drag.
pub fn snap_to_edge(wid: u32) {
    let (sw, sh) = crate::io::framebuffer::size();
    let sw = sw as i32; let sh = sh as i32;
    let mut wm = WM.lock();
    let win = match wm.windows.get_mut(&wid) { Some(w) => w, None => return };
    let fx = win.frame_x();
    let fy = win.frame_y();
    let fw = win.frame_w() as i32;
    let fh = win.frame_h() as i32;
    use crate::gui::layout::constants::{TOPBAR_H, SIDEBAR_W, TASKBAR_H};
    let cx0 = SIDEBAR_W as i32; let cy0 = TOPBAR_H as i32;
    let cx1 = sw; let cy1 = sh - TASKBAR_H as i32;
    let cw = cx1 - cx0; let ch = cy1 - cy0;

    // Left half snap
    if fx <= cx0 + SNAP_THRESHOLD {
        win.x = cx0 + crate::gui::wm::BORDER as i32;
        win.y = cy0 + crate::gui::wm::TITLEBAR_H as i32 + crate::gui::wm::BORDER as i32;
        win.w = (cw / 2) as u32;
        win.h = (ch - crate::gui::wm::TITLEBAR_H as i32 - crate::gui::wm::BORDER as i32 * 2).max(100) as u32;
        crate::serial_println!("[WM] snap left: wid={}", wid);
        return;
    }
    // Right half snap
    if fx + fw >= cx1 - SNAP_THRESHOLD {
        win.x = cx0 + cw / 2 + crate::gui::wm::BORDER as i32;
        win.y = cy0 + crate::gui::wm::TITLEBAR_H as i32 + crate::gui::wm::BORDER as i32;
        win.w = (cw / 2) as u32;
        win.h = (ch - crate::gui::wm::TITLEBAR_H as i32 - crate::gui::wm::BORDER as i32 * 2).max(100) as u32;
        crate::serial_println!("[WM] snap right: wid={}", wid);
        return;
    }
    // Top maximize snap
    if fy <= cy0 + SNAP_THRESHOLD {
        win.x = cx0 + crate::gui::wm::BORDER as i32;
        win.y = cy0 + crate::gui::wm::TITLEBAR_H as i32 + crate::gui::wm::BORDER as i32;
        win.w = (cw - crate::gui::wm::BORDER as i32 * 2).max(200) as u32;
        win.h = (ch - crate::gui::wm::TITLEBAR_H as i32 - crate::gui::wm::BORDER as i32 * 2).max(100) as u32;
        crate::serial_println!("[WM] snap maximize: wid={}", wid);
    }
}

/// Check snap zones during drag (for visual preview indicator)
pub fn snap_zone(fx: i32, fy: i32) -> Option<&'static str> {
    let (sw, sh) = crate::io::framebuffer::size();
    let sw = sw as i32;
    use crate::gui::layout::constants::{SIDEBAR_W, TOPBAR_H, TASKBAR_H};
    let cx0 = SIDEBAR_W as i32;
    if fx <= cx0 + SNAP_THRESHOLD { return Some("left"); }
    if fx + 400 >= sw - SNAP_THRESHOLD { return Some("right"); }
    if fy <= TOPBAR_H as i32 + SNAP_THRESHOLD { return Some("maximize"); }
    None
}

/// Minimize a window — hide it, mark it in taskbar state
pub fn minimize_window(wid: u32) {
    let mut wm = WM.lock();
    if let Some(win) = wm.windows.get_mut(&wid) {
        win.minimized = true;
        win.visible   = false;
        crate::serial_println!("[WM] minimized wid={}", wid);
    }
}

/// Restore a minimized window
pub fn restore_window(wid: u32) {
    let mut wm = WM.lock();
    if let Some(win) = wm.windows.get_mut(&wid) {
        win.minimized = false;
        win.visible   = true;
    }
    wm.bring_to_front(wid);
    wm.set_focus(Some(wid));
    crate::serial_println!("[WM] restored wid={}", wid);
}

/// Route keyboard input to focused window via IPC
pub fn route_to_focused(key_event: &crate::gui::events::GuiEvent) {
    // Delegate to ipc::route_to_focused which encodes the event properly
    crate::gui::ipc::route_to_focused(key_event);
}

/// Focus the window under cursor (call on mouse click)
pub fn focus_under_cursor(mx: i32, my: i32) {
    let mut wm = WM.lock();
    // Find topmost window under cursor
    let mut target: Option<u32> = None;
    for win in wm.windows.values().rev() {
        if win.hit_frame(mx, my) { target = Some(win.id); break; }
    }
    if let Some(wid) = target {
        let prev = wm.focused;
        if prev != Some(wid) {
            wm.focused = Some(wid);
            // Mark both old and new window dirty
            if let Some(p) = prev { wm.windows.get_mut(&p).map(|w| w.dirty = true); }
            wm.windows.get_mut(&wid).map(|w| w.dirty = true);
        }
    }
}

/// Tab cycling through windows
pub fn focus_next_window() {
    let mut wm = WM.lock();
    if wm.windows.is_empty() { return; }
    let ids: alloc::vec::Vec<u32> = wm.windows.keys().copied().collect();
    let cur_idx = wm.focused.and_then(|f| ids.iter().position(|&id| id == f)).unwrap_or(0);
    let next_idx = (cur_idx + 1) % ids.len();
    wm.focused = Some(ids[next_idx]);
}
