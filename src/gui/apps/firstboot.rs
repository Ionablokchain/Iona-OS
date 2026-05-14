//! First-boot wizard — ghid de configurare la prima pornire
//!
//! Pași:
//!   1. Welcome — prezentare IONA OS
//!   2. Language — selectare limbă (EN/RO)
//!   3. Network — DHCP sau IP static
//!   4. Node setup — configurare IONA Node (validator ID, peers)
//!   5. Keystore — creare passphrase pentru secure keystore
//!   6. Done — summary + reboot
//!
//! Afișat dacă /etc/iona-node.json.first_boot == true

use alloc::{vec, string::{String, ToString}, vec::Vec, format};
use crate::gui::{wm, ipc, theme::*, widgets::*};
use crate::io::font;

const WIN_W: u32 = 520;
const WIN_H: u32 = 400;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WizardStep {
    Welcome = 0,
    Language = 1,
    Network = 2,
    NodeSetup = 3,
    Keystore = 4,
    Done = 5,
}

pub struct FirstBootWizard {
    pub wid:   u32,
    step:      WizardStep,
    finished:  bool,
    // Collected config
    language:  usize,      // 0=EN, 1=RO
    use_dhcp:  bool,
    static_ip: String,
    validator_id: u32,
    peers:     String,
    passphrase: String,
    passphrase2: String,
    // Widgets
    next_btn:  Button,
    back_btn:  Button,
    tab_bar:   TabBar,
    input1:    TextInput,
    input2:    TextInput,
    checkbox1: Checkbox,
    dirty:     bool,
}

impl FirstBootWizard {
    pub fn new(x: i32, y: i32) -> Self {
        let tid = crate::arch::x86_64::percpu::current_tid();
        let wid = wm::create_window("IONA OS — Configurare inițială", x, y, WIN_W, WIN_H, tid);
        ipc::register_window(wid);

        let ww = WIN_W as usize;
        let wh = WIN_H as usize;
        let btn_y = wh - 54;

        let mut wizard = FirstBootWizard {
            wid, step: WizardStep::Welcome,
            language: 1, use_dhcp: true,
            static_ip: String::new(),
            validator_id: 0,
            peers: String::new(),
            passphrase: String::new(),
            passphrase2: String::new(),
            next_btn: Button::new(ww-130, btn_y, 110, 36, "Continuare →"),
            back_btn: Button::new(20, btn_y, 90, 36, "← Înapoi"),
            tab_bar:  { let mut t = TabBar::new(0, 0, ww); for s in &["1","2","3","4","5","6"] { t.add(s); } t },
            input1:   TextInput::new(20, 180, ww-40, ""),
            input2:   TextInput::new(20, 240, ww-40, ""),
            checkbox1: Checkbox::new(20, 180, "Utilizare DHCP (recomandat)"),
            dirty: true,
            finished: false,
        };
        wizard.tab_bar.active = 0;
        wizard.checkbox1.checked = true;
        wizard
    }

    pub fn on_click(&mut self, px: i32, py: i32) {
        // Simulate press then release so Button::on_mouse detects a click
        self.next_btn.on_mouse(px, py, true);
        if self.next_btn.on_mouse(px, py, false) {
            self.next_step();
        }
        self.back_btn.on_mouse(px, py, true);
        if self.back_btn.on_mouse(px, py, false) && self.step != WizardStep::Welcome {
            self.prev_step();
        }
        self.checkbox1.on_click(px, py);
        self.input1.on_click(px, py);
        self.input2.on_click(px, py);
        self.dirty = true;
    }

    fn next_step(&mut self) {
        self.step = match self.step {
            WizardStep::Welcome  => { self.apply_language();   WizardStep::Language  }
            WizardStep::Language => { WizardStep::Network  }
            WizardStep::Network  => { self.apply_network();    WizardStep::NodeSetup }
            WizardStep::NodeSetup=> { self.apply_node();       WizardStep::Keystore  }
            WizardStep::Keystore => { self.apply_keystore();   WizardStep::Done      }
            WizardStep::Done     => { self.finish();           WizardStep::Done      }
        };
        if !self.finished {
            self.tab_bar.active = self.step as usize;
            self.dirty = true;
        }
    }

    fn prev_step(&mut self) {
        self.step = match self.step {
            WizardStep::Language  => WizardStep::Welcome,
            WizardStep::Network   => WizardStep::Language,
            WizardStep::NodeSetup => WizardStep::Network,
            WizardStep::Keystore  => WizardStep::NodeSetup,
            WizardStep::Done      => WizardStep::Keystore,
            _                     => WizardStep::Welcome,
        };
        self.tab_bar.active = self.step as usize;
        self.dirty = true;
    }

    fn apply_language(&mut self) { /* save language preference */ }
    fn apply_network(&mut self) {
        self.use_dhcp = self.checkbox1.checked;
        if !self.use_dhcp { self.static_ip = self.input1.value.clone(); }
    }
    fn apply_node(&mut self) {
        self.peers = self.input1.value.clone();
    }
    fn apply_keystore(&mut self) {
        let pass = self.input1.value.clone();
        if !pass.is_empty() && pass == self.input2.value {
            crate::security::keystore::init(&pass);
            crate::serial_println!("[FIRSTBOOT] keystore created");
        }
    }
    fn finish(&mut self) {
        // Guard against re-entry (finish can be called multiple times if
        // multiple Enter keys are queued for the Done step)
        if self.finished { return; }
        self.finished = true;
        // Mark first_boot as complete
        let config = br#"{"first_boot": false}"#;
        crate::fs::ionafs::write("/etc/iona-os-firstboot.done", config);
        crate::serial_println!("[FIRSTBOOT] wizard complete — closing window {}", self.wid);
        // Unregister IPC queue so no more events arrive
        ipc::unregister_window(self.wid);
        // Close the wizard window
        wm::close_window(self.wid);
        // Launch default desktop apps
        super::terminal::launch(140, 80);
        super::monitor::launch(540, 90);
    }

    pub fn draw(&mut self) {
        if !self.dirty { return; }
        self.dirty = false;

        let ww = WIN_W as usize;
        let wh = WIN_H as usize;
        let fd = font::raw_font_data();
        let mut px = vec![COLOR_WINDOW_BG; ww * wh];

        // Tab bar background
        self.tab_bar.draw();

        // Step content
        let content_y = 40;
        match self.step {
            WizardStep::Welcome => {
                draw_title(&mut px, ww, fd, "Bun venit la IONA OS", 20, content_y);
                draw_text(&mut px, ww, fd, "IONA OS este un sistem de operare", 20, content_y+40, COLOR_TEXT_SECONDARY);
                draw_text(&mut px, ww, fd, "bare-metal x86_64 cu nod blockchain integrat.", 20, content_y+58, COLOR_TEXT_SECONDARY);
                draw_text(&mut px, ww, fd, "Acest wizard va configura sistemul in 5 pasi.", 20, content_y+90, COLOR_TEXT_PRIMARY);
            }
            WizardStep::Language => {
                draw_title(&mut px, ww, fd, "Selectare limba", 20, content_y);
                draw_text(&mut px, ww, fd, "[ ] English", 20, content_y+50, COLOR_TEXT_PRIMARY);
                draw_text(&mut px, ww, fd, "[*] Romana", 20, content_y+74, COLOR_ACCENT);
            }
            WizardStep::Network => {
                draw_title(&mut px, ww, fd, "Configurare retea", 20, content_y);
                self.checkbox1.draw();
            }
            WizardStep::NodeSetup => {
                draw_title(&mut px, ww, fd, "Configurare IONA Node", 20, content_y);
                draw_text(&mut px, ww, fd, "Peers (IP:port, separat prin virgula):", 20, content_y+50, COLOR_TEXT_SECONDARY);
                self.input1.draw();
            }
            WizardStep::Keystore => {
                draw_title(&mut px, ww, fd, "Securitate — Keystore", 20, content_y);
                draw_text(&mut px, ww, fd, "Passphrase pentru chei private:", 20, content_y+50, COLOR_TEXT_SECONDARY);
                self.input1.draw();
                draw_text(&mut px, ww, fd, "Confirmare passphrase:", 20, content_y+140, COLOR_TEXT_SECONDARY);
                self.input2.draw();
            }
            WizardStep::Done => {
                draw_title(&mut px, ww, fd, "Configurare completa!", 20, content_y);
                draw_text(&mut px, ww, fd, "IONA OS este gata de utilizare.", 20, content_y+50, COLOR_SUCCESS);
                draw_text(&mut px, ww, fd, "Apasati 'Finalizare' pentru a intra in desktop.", 20, content_y+74, COLOR_TEXT_PRIMARY);
                self.next_btn = Button::new(ww-130, wh-54, 110, 36, "Finalizare");
            }
        }

        // Buttons — draw into pixel buffer (not framebuffer)
        draw_btn_buf(&mut px, ww, fd, &self.next_btn);
        if self.step != WizardStep::Welcome { draw_btn_buf(&mut px, ww, fd, &self.back_btn); }

        // Tab bar — draw into pixel buffer
        {
            let tab_y = 0usize;
            let tab_count = 6usize;
            let tab_w = ww / tab_count;
            for i in 0..tab_count {
                let tx = i * tab_w;
                let bg = if i == self.tab_bar.active { COLOR_ACCENT } else { COLOR_BTN_BG };
                fill_rect_buf(&mut px, ww, tx, tab_y, tab_w, 24, bg);
                let label = match i { 0=>"1", 1=>"2", 2=>"3", 3=>"4", 4=>"5", _=>"6" };
                let lx = tx + (tab_w - label.len() * font::FONT_WIDTH) / 2;
                let ly = tab_y + (24 - font::FONT_HEIGHT) / 2;
                draw_str_buf(&mut px, ww, fd, label, lx, ly, 0xFFFFFF, bg);
            }
        }

        // Checkbox — draw into pixel buffer (Network step)
        if self.step == WizardStep::Network {
            let cb = &self.checkbox1;
            let sz = cb.rect.w;
            fill_rect_buf(&mut px, ww, cb.rect.x, cb.rect.y, sz, sz, COLOR_INPUT_BG);
            draw_rect_buf(&mut px, ww, cb.rect.x, cb.rect.y, sz, sz,
                if cb.checked { COLOR_ACCENT } else { COLOR_INPUT_BORDER });
            if cb.checked {
                // Simple checkmark
                let cx = cb.rect.x + 2;
                let cy = cb.rect.y + sz / 2;
                for dx in 0..sz.saturating_sub(4) {
                    if cy * ww + cx + dx < px.len() { px[cy * ww + cx + dx] = COLOR_ACCENT; }
                }
                let cvx = cb.rect.x + sz / 2;
                for dy in 2..sz.saturating_sub(2) {
                    let iy = cb.rect.y + dy;
                    if iy * ww + cvx < px.len() { px[iy * ww + cvx] = COLOR_ACCENT; }
                }
            }
            let tx = cb.rect.x + sz + 6;
            let ty = cb.rect.y + (sz - font::FONT_HEIGHT) / 2;
            draw_str_buf(&mut px, ww, fd, &cb.label, tx, ty, COLOR_TEXT_PRIMARY, COLOR_WINDOW_BG);
        }

        // TextInput — draw into pixel buffer
        if self.step == WizardStep::NodeSetup || self.step == WizardStep::Keystore {
            draw_input_buf(&mut px, ww, fd, &self.input1);
            if self.step == WizardStep::Keystore {
                draw_input_buf(&mut px, ww, fd, &self.input2);
            }
        }

        wm::update_pixels(self.wid, 0, 0, ww as u16, wh as u16, &px);
    }
}

fn draw_title(px: &mut Vec<u32>, stride: usize, fd: &[u8], s: &str, x: usize, y: usize) {
    draw_str_buf(px, stride, fd, s, x, y, 0xFFFFFF, COLOR_WINDOW_BG);
}
fn draw_text(px: &mut Vec<u32>, stride: usize, fd: &[u8], s: &str, x: usize, y: usize, col: u32) {
    draw_str_buf(px, stride, fd, s, x, y, col, COLOR_WINDOW_BG);
}
fn draw_str_buf(px: &mut Vec<u32>, stride: usize, fd: &[u8], s: &str, mut x: usize, y: usize, fg: u32, bg: u32) {
    for b in s.bytes() {
        let goff = 32 + b as usize * 16;
        if goff + 16 > fd.len() { x += font::FONT_WIDTH; continue; }
        for r in 0..font::FONT_HEIGHT {
            let byte = fd[goff + r];
            for c in 0..font::FONT_WIDTH {
                let sx = x+c; let sy = y+r;
                if sy * stride + sx < px.len() {
                    px[sy*stride+sx] = if byte & (0x80>>c) != 0 { fg } else { bg };
                }
            }
        }
        x += font::FONT_WIDTH;
    }
}

/// Fill a rectangle in the pixel buffer
fn fill_rect_buf(px: &mut Vec<u32>, stride: usize, x: usize, y: usize, w: usize, h: usize, color: u32) {
    for row in y..y+h {
        for col in x..x+w {
            let idx = row * stride + col;
            if idx < px.len() { px[idx] = color; }
        }
    }
}

/// Draw a 1px rectangle outline in the pixel buffer
fn draw_rect_buf(px: &mut Vec<u32>, stride: usize, x: usize, y: usize, w: usize, h: usize, color: u32) {
    for col in x..x+w {
        let top = y * stride + col;
        let bot = (y+h.saturating_sub(1)) * stride + col;
        if top < px.len() { px[top] = color; }
        if bot < px.len() { px[bot] = color; }
    }
    for row in y..y+h {
        let left = row * stride + x;
        let right = row * stride + x + w.saturating_sub(1);
        if left < px.len() { px[left] = color; }
        if right < px.len() { px[right] = color; }
    }
}

/// Draw a button into the pixel buffer
fn draw_btn_buf(px: &mut Vec<u32>, stride: usize, fd: &[u8], btn: &Button) {
    let bg_color = match btn.state {
        BtnState::Normal  => COLOR_BTN_BG,
        BtnState::Hover   => COLOR_BTN_BG_HOVER,
        BtnState::Pressed => COLOR_BTN_BG_PRESS,
        BtnState::Disabled => 0x0A1020,
    };
    fill_rect_buf(px, stride, btn.rect.x, btn.rect.y, btn.rect.w, btn.rect.h, bg_color);
    draw_rect_buf(px, stride, btn.rect.x, btn.rect.y, btn.rect.w, btn.rect.h, COLOR_BTN_BORDER);
    // Center label
    let tw = btn.label.len() * font::FONT_WIDTH;
    let tx = btn.rect.x + btn.rect.w.saturating_sub(tw) / 2;
    let ty = btn.rect.y + btn.rect.h.saturating_sub(font::FONT_HEIGHT) / 2;
    let fg = if btn.state == BtnState::Pressed { COLOR_BTN_TEXT_PRESS } else { COLOR_BTN_TEXT };
    draw_str_buf(px, stride, fd, &btn.label, tx, ty, fg, bg_color);
}

/// Draw a text input into the pixel buffer
fn draw_input_buf(px: &mut Vec<u32>, stride: usize, fd: &[u8], input: &TextInput) {
    fill_rect_buf(px, stride, input.rect.x, input.rect.y, input.rect.w, input.rect.h, COLOR_INPUT_BG);
    let border = if input.focused { COLOR_INPUT_BORDER_FOCUS } else { COLOR_INPUT_BORDER };
    draw_rect_buf(px, stride, input.rect.x, input.rect.y, input.rect.w, input.rect.h, border);
    let tx = input.rect.x + 6;
    let ty = input.rect.y + 4;
    if input.value.is_empty() && !input.focused {
        draw_str_buf(px, stride, fd, &input.placeholder, tx, ty, COLOR_TEXT_MUTED, COLOR_INPUT_BG);
    } else {
        let max_chars = input.rect.w.saturating_sub(12) / font::FONT_WIDTH;
        let visible_start = input.cursor.saturating_sub(max_chars);
        let s = &input.value[visible_start.min(input.value.len())..];
        let s = &s[..s.len().min(max_chars)];
        draw_str_buf(px, stride, fd, s, tx, ty, COLOR_INPUT_TEXT, COLOR_INPUT_BG);
        if input.focused {
            let cur_col = input.cursor.saturating_sub(visible_start);
            let cx = tx + cur_col * font::FONT_WIDTH;
            // Draw cursor line
            for dy in 0..font::FONT_HEIGHT {
                let idx = (ty + dy) * stride + cx;
                if idx < px.len() { px[idx] = COLOR_INPUT_CURSOR; }
            }
        }
    }
}

static mut FIRSTBOOT_APP: Option<FirstBootWizard> = None;

/// Check if first-boot wizard should run
pub fn should_run() -> bool {
    // Check for firstboot done marker
    crate::fs::ionafs::read("/etc/iona-os-firstboot.done").is_none()
}

pub fn launch(x: i32, y: i32) {
    unsafe { FIRSTBOOT_APP = Some(FirstBootWizard::new(x, y)); }
}

pub fn tick() -> bool {
    unsafe {
        if let Some(ref mut app) = FIRSTBOOT_APP {
            if app.finished {
                FIRSTBOOT_APP = None;
                return false;
            }
            if let Some(buf) = ipc::poll_window_event(app.wid) {
                if buf.len() >= 6 {
                    match buf[0] {
                        2 => { // MouseDown — format: [type:1][wid:4][x:4][y:4][btn:1]
                            if buf.len() >= 13 {
                                let screen_x = i32::from_le_bytes(buf[5..9].try_into().unwrap_or([0;4]));
                                let screen_y = i32::from_le_bytes(buf[9..13].try_into().unwrap_or([0;4]));
                                // Convert screen coords to window-local coords
                                let win_pos = {
                                    let wm_lock = wm::WM.lock();
                                    wm_lock.windows.get(&app.wid).map(|w| (w.x, w.y))
                                };
                                if let Some((wx, wy)) = win_pos {
                                    let local_x = screen_x - wx;
                                    let local_y = screen_y - wy;
                                    app.on_click(local_x, local_y);
                                }
                            }
                        }
                        4 => { // KeyDown — format: [type:1][wid:4][keycode:4][ascii:1]
                            if buf.len() >= 10 {
                                let keycode = u32::from_le_bytes(buf[5..9].try_into().unwrap_or([0;4]));
                                let ascii = buf[9];
                                let key = match ascii {
                                    b'\n'|b'\r' | 0x0D => crate::gui::events::Key::Enter,
                                    0x08|0x7F => crate::gui::events::Key::Backspace,
                                    0x1B => crate::gui::events::Key::Escape,
                                    0x09 => crate::gui::events::Key::Tab,
                                    c if c != 0 => crate::gui::events::Key::Char(c as char),
                                    _ => match keycode {
                                        0x0D => crate::gui::events::Key::Enter,
                                        0x08 => crate::gui::events::Key::Backspace,
                                        0x1B => crate::gui::events::Key::Escape,
                                        _ => crate::gui::events::Key::Char('\0'),
                                    },
                                };
                                // Enter = advance wizard, Escape/Backspace = go back
                                match &key {
                                    crate::gui::events::Key::Enter => {
                                        if !app.input1.focused && !app.input2.focused {
                                            app.next_step();
                                        } else {
                                            // In text input, Enter moves to next field or advances
                                            if app.input1.focused { app.input1.on_key(&key, Some(ascii as char)); }
                                            if app.input2.focused { app.input2.on_key(&key, Some(ascii as char)); }
                                        }
                                    }
                                    crate::gui::events::Key::Escape => {
                                        if app.step != WizardStep::Welcome {
                                            app.prev_step();
                                        }
                                    }
                                    _ => {
                                        if app.input1.focused { app.input1.on_key(&key, Some(ascii as char)); }
                                        if app.input2.focused { app.input2.on_key(&key, Some(ascii as char)); }
                                    }
                                }
                                app.dirty = true;
                            }
                        }
                        _ => {}
                    }
                }
            }
            if app.dirty && !app.finished {
                app.draw();
                return true;
            }
        }
        false
    }
}
