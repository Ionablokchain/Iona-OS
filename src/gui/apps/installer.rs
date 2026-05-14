//! IONA OS Installer — mediu de instalare ușor (easy install wizard)
//!
//! Pași:
//!   1. Welcome    — selectare limbă (EN/RO/DE)
//!   2. License    — acceptare licență IONA OS
//!   3. Disk       — selectare disc + partiționare automată
//!   4. System     — hostname, timezone, cont utilizator
//!   5. Network    — DHCP sau IP static
//!   6. Node       — configurare IONA Node (opțional)
//!   7. Installing — progress bar cu pașii instalării
//!   8. Done       — summary + reboot
//!
//! Lansat de gui_loop_task dacă /etc/iona-installed nu există.

use alloc::{vec, string::{String, ToString}, vec::Vec, format};
use crate::gui::{wm, ipc, theme::*, widgets::*};
use crate::io::font;

const WIN_W: u32 = 640;
const WIN_H: u32 = 480;
const PAD: usize = 24;
const LINE_H: usize = 20;

// ── Installer steps ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InstallStep {
    Welcome    = 0,
    License    = 1,
    Disk       = 2,
    System     = 3,
    Network    = 4,
    Node       = 5,
    Installing = 6,
    Done       = 7,
}

const STEP_COUNT: usize = 8;
const STEP_LABELS: [&str; STEP_COUNT] = [
    "Bun venit", "Licenta", "Disc", "Sistem",
    "Retea", "Nod", "Instalare", "Gata",
];

// ── Detected disk info ───────────────────────────────────────────────────────

#[derive(Clone)]
struct DiskInfo {
    name:     String,
    size_mb:  u64,
    selected: bool,
}

// ── Installer state ──────────────────────────────────────────────────────────

pub struct InstallerApp {
    pub wid:       u32,
    step:          InstallStep,
    finished:      bool,
    dirty:         bool,

    // Step 1: Welcome
    language:      usize,           // 0=RO, 1=EN, 2=DE

    // Step 2: License
    license_accepted: bool,

    // Step 3: Disk
    disks:         Vec<DiskInfo>,
    selected_disk: usize,
    format_disk:   bool,

    // Step 4: System
    hostname:      String,
    timezone:      String,
    username:      String,
    password:      String,
    password2:     String,

    // Step 5: Network
    use_dhcp:      bool,
    static_ip:     String,
    gateway:       String,
    dns:           String,

    // Step 6: Node
    enable_node:   bool,
    validator_id:  String,
    peers:         String,

    // Step 7: Installing
    install_progress: f32,      // 0.0..1.0
    install_step_msg: String,
    install_done:     bool,
    install_tick:     u64,      // internal timer

    // Widgets
    next_btn:      Button,
    back_btn:      Button,
    // Text inputs (reused across steps)
    input1:        TextInput,
    input2:        TextInput,
    input3:        TextInput,
    input4:        TextInput,
    input5:        TextInput,
    checkbox1:     Checkbox,
    checkbox2:     Checkbox,
    progress:      ProgressBar,
}

impl InstallerApp {
    pub fn new(x: i32, y: i32) -> Self {
        let tid = crate::arch::x86_64::percpu::current_tid();
        let wid = wm::create_window("IONA OS — Installer", x, y, WIN_W, WIN_H, tid);
        ipc::register_window(wid);

        let ww = WIN_W as usize;
        let wh = WIN_H as usize;
        let btn_y = wh - 54;

        // Detect available disks
        let disks = detect_disks();

        InstallerApp {
            wid,
            step: InstallStep::Welcome,
            finished: false,
            dirty: true,

            language: 0,     // default RO
            license_accepted: false,

            disks,
            selected_disk: 0,
            format_disk: true,

            hostname: String::from("iona-node-01"),
            timezone: String::from("Europe/Bucharest"),
            username: String::from("iona"),
            password: String::new(),
            password2: String::new(),

            use_dhcp: true,
            static_ip: String::new(),
            gateway: String::new(),
            dns: String::from("1.1.1.1"),

            enable_node: true,
            validator_id: String::new(),
            peers: String::from("10.0.2.2:9000"),

            install_progress: 0.0,
            install_step_msg: String::from("Se pregateste instalarea..."),
            install_done: false,
            install_tick: 0,

            next_btn: Button::new(ww - 150, btn_y, 126, 38, "Continuare →"),
            back_btn: Button::new(PAD, btn_y, 100, 38, "← Inapoi"),
            input1: TextInput::new(PAD, 220, ww - PAD * 2, ""),
            input2: TextInput::new(PAD, 270, ww - PAD * 2, ""),
            input3: TextInput::new(PAD, 320, ww - PAD * 2, ""),
            input4: TextInput::new(PAD, 370, ww - PAD * 2, ""),
            input5: TextInput::new(PAD, 220, ww - PAD * 2, ""),
            checkbox1: Checkbox::new(PAD, 220, "DHCP (recomandat)"),
            checkbox2: Checkbox::new(PAD, 220, "Activeaza IONA Node"),
            progress: ProgressBar::new(PAD, 280, ww - PAD * 2, 24),
        }
    }

    // ── Event handling ───────────────────────────────────────────────────────

    pub fn on_click(&mut self, px: i32, py: i32) {
        // Navigation buttons
        self.next_btn.on_mouse(px, py, true);
        if self.next_btn.on_mouse(px, py, false) {
            self.next_step();
        }
        self.back_btn.on_mouse(px, py, true);
        if self.back_btn.on_mouse(px, py, false) && self.step != InstallStep::Welcome {
            self.prev_step();
        }

        // Step-specific click handling
        match self.step {
            InstallStep::Welcome => {
                // Language selection — detect click on language rows
                let lang_y_base = 200usize;
                for i in 0..3 {
                    let ry = lang_y_base + i * 36;
                    if py >= ry as i32 && py < (ry + 30) as i32
                       && px >= PAD as i32 && px < (WIN_W as i32 - PAD as i32) {
                        self.language = i;
                    }
                }
            }
            InstallStep::License => {
                // Accept checkbox
                let old = self.license_accepted;
                // Click area for the accept checkbox
                let cb_y = 380;
                if py >= cb_y && py < cb_y + 20
                   && px >= PAD as i32 && px < (PAD + 300) as i32 {
                    self.license_accepted = !self.license_accepted;
                }
            }
            InstallStep::Disk => {
                // Disk selection
                let disk_y_base = 180usize;
                for i in 0..self.disks.len() {
                    let ry = disk_y_base + i * 40;
                    if py >= ry as i32 && py < (ry + 34) as i32
                       && px >= PAD as i32 && px < (WIN_W as i32 - PAD as i32) {
                        self.selected_disk = i;
                        for d in &mut self.disks { d.selected = false; }
                        if let Some(d) = self.disks.get_mut(i) { d.selected = true; }
                    }
                }
                // Format checkbox
                let cb_y = 180 + self.disks.len() * 40 + 10;
                if py >= cb_y as i32 && py < (cb_y + 20) as i32
                   && px >= PAD as i32 && px < (PAD + 300) as i32 {
                    self.format_disk = !self.format_disk;
                }
            }
            InstallStep::System => {
                self.input1.on_click(px, py);
                self.input2.on_click(px, py);
                self.input3.on_click(px, py);
                self.input4.on_click(px, py);
            }
            InstallStep::Network => {
                // DHCP checkbox
                let cb_y = 190;
                if py >= cb_y && py < cb_y + 20
                   && px >= PAD as i32 && px < (PAD + 300) as i32 {
                    self.use_dhcp = !self.use_dhcp;
                }
                if !self.use_dhcp {
                    self.input1.on_click(px, py);
                    self.input2.on_click(px, py);
                    self.input3.on_click(px, py);
                }
            }
            InstallStep::Node => {
                // Enable node checkbox
                let cb_y = 190;
                if py >= cb_y && py < cb_y + 20
                   && px >= PAD as i32 && px < (PAD + 300) as i32 {
                    self.enable_node = !self.enable_node;
                }
                if self.enable_node {
                    self.input1.on_click(px, py);
                    self.input2.on_click(px, py);
                }
            }
            _ => {}
        }
        self.dirty = true;
    }

    pub fn on_key(&mut self, key: &crate::gui::events::Key, ch: Option<char>) {
        match self.step {
            InstallStep::System => {
                if self.input1.focused { self.input1.on_key(key, ch); }
                if self.input2.focused { self.input2.on_key(key, ch); }
                if self.input3.focused { self.input3.on_key(key, ch); }
                if self.input4.focused { self.input4.on_key(key, ch); }
            }
            InstallStep::Network => {
                if !self.use_dhcp {
                    if self.input1.focused { self.input1.on_key(key, ch); }
                    if self.input2.focused { self.input2.on_key(key, ch); }
                    if self.input3.focused { self.input3.on_key(key, ch); }
                }
            }
            InstallStep::Node => {
                if self.enable_node {
                    if self.input1.focused { self.input1.on_key(key, ch); }
                    if self.input2.focused { self.input2.on_key(key, ch); }
                }
            }
            _ => {
                // Enter = advance, Escape = go back
                use crate::gui::events::Key;
                match key {
                    Key::Enter => self.next_step(),
                    Key::Escape => {
                        if self.step != InstallStep::Welcome { self.prev_step(); }
                    }
                    _ => {}
                }
            }
        }
        self.dirty = true;
    }

    // ── Step navigation ──────────────────────────────────────────────────────

    fn next_step(&mut self) {
        self.step = match self.step {
            InstallStep::Welcome => InstallStep::License,
            InstallStep::License => {
                if !self.license_accepted { return; }
                InstallStep::Disk
            }
            InstallStep::Disk => {
                self.collect_system_defaults();
                InstallStep::System
            }
            InstallStep::System => {
                self.collect_system();
                InstallStep::Network
            }
            InstallStep::Network => {
                self.collect_network();
                InstallStep::Node
            }
            InstallStep::Node => {
                self.collect_node();
                self.start_install();
                InstallStep::Installing
            }
            InstallStep::Installing => {
                if !self.install_done { return; }
                InstallStep::Done
            }
            InstallStep::Done => {
                self.finish();
                InstallStep::Done
            }
        };
        // Reset input fields for new step
        self.reset_inputs_for_step();
        self.dirty = true;
    }

    fn prev_step(&mut self) {
        self.step = match self.step {
            InstallStep::License    => InstallStep::Welcome,
            InstallStep::Disk       => InstallStep::License,
            InstallStep::System     => InstallStep::Disk,
            InstallStep::Network    => InstallStep::System,
            InstallStep::Node       => InstallStep::Network,
            InstallStep::Installing => return,  // can't go back during install
            InstallStep::Done       => return,  // can't go back after done
            _                       => InstallStep::Welcome,
        };
        self.reset_inputs_for_step();
        self.dirty = true;
    }

    fn reset_inputs_for_step(&mut self) {
        let ww = WIN_W as usize;
        // Unfocus all
        self.input1.focused = false;
        self.input2.focused = false;
        self.input3.focused = false;
        self.input4.focused = false;

        match self.step {
            InstallStep::System => {
                self.input1 = TextInput::new(PAD + 160, 200, ww - PAD * 2 - 160, "iona-node-01");
                self.input1.value = self.hostname.clone();
                self.input2 = TextInput::new(PAD + 160, 246, ww - PAD * 2 - 160, "iona");
                self.input2.value = self.username.clone();
                self.input3 = TextInput::new(PAD + 160, 292, ww - PAD * 2 - 160, "Parola");
                self.input3.value = self.password.clone();
                self.input4 = TextInput::new(PAD + 160, 338, ww - PAD * 2 - 160, "Confirmare parola");
                self.input4.value = self.password2.clone();
            }
            InstallStep::Network => {
                self.input1 = TextInput::new(PAD + 120, 240, ww - PAD * 2 - 120, "192.168.1.100");
                self.input1.value = self.static_ip.clone();
                self.input2 = TextInput::new(PAD + 120, 286, ww - PAD * 2 - 120, "192.168.1.1");
                self.input2.value = self.gateway.clone();
                self.input3 = TextInput::new(PAD + 120, 332, ww - PAD * 2 - 120, "1.1.1.1");
                self.input3.value = self.dns.clone();
            }
            InstallStep::Node => {
                self.input1 = TextInput::new(PAD + 120, 240, ww - PAD * 2 - 120, "auto-generated");
                self.input1.value = self.validator_id.clone();
                self.input2 = TextInput::new(PAD + 120, 286, ww - PAD * 2 - 120, "10.0.2.2:9000");
                self.input2.value = self.peers.clone();
            }
            _ => {}
        }
    }

    // ── Data collection ──────────────────────────────────────────────────────

    fn collect_system_defaults(&mut self) {
        // Set up input defaults before entering System step
    }

    fn collect_system(&mut self) {
        self.hostname = if self.input1.value.is_empty() {
            "iona-node-01".into()
        } else {
            self.input1.value.clone()
        };
        self.username = if self.input2.value.is_empty() {
            "iona".into()
        } else {
            self.input2.value.clone()
        };
        self.password = self.input3.value.clone();
        self.password2 = self.input4.value.clone();
    }

    fn collect_network(&mut self) {
        if !self.use_dhcp {
            self.static_ip = self.input1.value.clone();
            self.gateway = self.input2.value.clone();
            self.dns = self.input3.value.clone();
        }
    }

    fn collect_node(&mut self) {
        if self.enable_node {
            self.validator_id = self.input1.value.clone();
            self.peers = self.input2.value.clone();
        }
    }

    // ── Installation process ─────────────────────────────────────────────────

    fn start_install(&mut self) {
        self.install_progress = 0.0;
        self.install_done = false;
        self.install_step_msg = String::from("Se pregateste instalarea...");
        self.install_tick = crate::arch::x86_64::timer::uptime_ms();
    }

    /// Called each tick during the Installing step — advances the progress
    fn advance_install(&mut self) {
        if self.install_done { return; }

        let now = crate::arch::x86_64::timer::uptime_ms();
        let elapsed = now.saturating_sub(self.install_tick);

        // Simulate installation phases (each ~500ms)
        let phase = (elapsed / 500) as usize;
        let (progress, msg) = match phase {
            0 => (0.05, "Verificare disc..."),
            1 => (0.10, "Creare tabel de partitii..."),
            2 => (0.15, "Formatare IONAFS..."),
            3 => (0.20, "Scriere superblock..."),
            4 => (0.25, "Copiere kernel..."),
            5 => (0.35, "Copiere module sistem..."),
            6 => (0.45, "Instalare drivere hardware..."),
            7 => (0.50, "Configurare bootloader (GRUB)..."),
            8 => (0.55, "Scriere /etc/iona-os.conf..."),
            9 => (0.60, "Configurare retea..."),
            10 => (0.65, "Creare cont utilizator..."),
            11 => (0.70, "Configurare securitate (keystore)..."),
            12 => (0.75, "Configurare IONA Node..."),
            13 => (0.80, "Instalare aplicatii desktop..."),
            14 => (0.85, "Generare chei criptografice..."),
            15 => (0.90, "Configurare firstboot..."),
            16 => (0.95, "Verificare integritate..."),
            _ => {
                self.install_done = true;
                self.next_btn = Button::new(
                    WIN_W as usize - 150, WIN_H as usize - 54, 126, 38, "Continuare →");
                (1.0, "Instalare completa!")
            }
        };
        self.install_progress = progress;
        self.install_step_msg = String::from(msg);

        // Actually write config files during install
        if phase == 8 && elapsed >= 4000 && elapsed < 4500 {
            self.write_system_config();
        }
        if phase == 9 && elapsed >= 4500 && elapsed < 5000 {
            self.write_network_config();
        }
        if phase == 10 && elapsed >= 5000 && elapsed < 5500 {
            self.write_user_config();
        }
        if phase == 12 && elapsed >= 6000 && elapsed < 6500 {
            self.write_node_config();
        }

        self.progress.set(self.install_progress);
        self.dirty = true;
    }

    fn write_system_config(&self) {
        let config = format!(
            "{{\"hostname\":\"{}\",\"timezone\":\"{}\",\"language\":{},\"version\":\"0.6.0\"}}",
            self.hostname, self.timezone, self.language
        );
        crate::fs::ionafs::write("/etc/iona-os.conf", config.as_bytes());
        crate::serial_println!("[INSTALLER] wrote /etc/iona-os.conf");
    }

    fn write_network_config(&self) {
        let config = if self.use_dhcp {
            String::from("{\"mode\":\"dhcp\"}")
        } else {
            format!(
                "{{\"mode\":\"static\",\"ip\":\"{}\",\"gateway\":\"{}\",\"dns\":\"{}\"}}",
                self.static_ip, self.gateway, self.dns
            )
        };
        crate::fs::ionafs::write("/etc/network.conf", config.as_bytes());
        crate::serial_println!("[INSTALLER] wrote /etc/network.conf");
    }

    fn write_user_config(&self) {
        let config = format!(
            "{{\"username\":\"{}\",\"home\":\"/home/{}\",\"shell\":\"/bin/ionash\"}}",
            self.username, self.username
        );
        crate::fs::ionafs::write("/etc/users.conf", config.as_bytes());
        // Create home directory marker
        let home = format!("/home/{}/.profile", self.username);
        crate::fs::ionafs::write(&home, b"# IONA OS user profile\n");
        crate::serial_println!("[INSTALLER] created user '{}'", self.username);
    }

    fn write_node_config(&self) {
        if self.enable_node {
            let config = format!(
                "{{\"enabled\":true,\"validator_id\":\"{}\",\"peers\":\"{}\",\
                \"reconcile_interval_ms\":30000,\"attest_interval_ms\":60000,\
                \"gossip_interval_ms\":1000,\"admin_port\":7777,\"gossip_port\":9000}}",
                self.validator_id, self.peers
            );
            crate::fs::ionafs::write("/etc/iona-node.json", config.as_bytes());
            crate::serial_println!("[INSTALLER] wrote /etc/iona-node.json");
        }
    }

    // ── Finish ───────────────────────────────────────────────────────────────

    fn finish(&mut self) {
        if self.finished { return; }
        self.finished = true;

        // Mark OS as installed
        crate::fs::ionafs::write("/etc/iona-installed", b"true");
        // Mark firstboot as done too
        crate::fs::ionafs::write("/etc/iona-os-firstboot.done", b"{\"first_boot\": false}");

        crate::serial_println!("[INSTALLER] installation complete — closing window {}", self.wid);

        ipc::unregister_window(self.wid);
        wm::close_window(self.wid);

        // Launch desktop apps
        super::terminal::launch(140, 80);
        super::monitor::launch(540, 90);
    }

    // ── Tick ─────────────────────────────────────────────────────────────────

    pub fn tick(&mut self) -> bool {
        let mut redraw = self.dirty;

        // Advance installation progress if in Installing step
        if self.step == InstallStep::Installing && !self.install_done {
            self.advance_install();
            redraw = true;
        }

        // Process IPC events
        while let Some(buf) = ipc::poll_window_event(self.wid) {
            if buf.len() >= 6 {
                match buf[0] {
                    2 => { // MouseDown
                        if buf.len() >= 13 {
                            let screen_x = i32::from_le_bytes(
                                buf[5..9].try_into().unwrap_or([0; 4]));
                            let screen_y = i32::from_le_bytes(
                                buf[9..13].try_into().unwrap_or([0; 4]));
                            let win_pos = {
                                let wm_lock = wm::WM.lock();
                                wm_lock.windows.get(&self.wid).map(|w| (w.x, w.y))
                            };
                            if let Some((wx, wy)) = win_pos {
                                let local_x = screen_x - wx;
                                let local_y = screen_y - wy;
                                self.on_click(local_x, local_y);
                            }
                        }
                    }
                    4 => { // KeyDown
                        if buf.len() >= 10 {
                            let keycode = u32::from_le_bytes(
                                buf[5..9].try_into().unwrap_or([0; 4]));
                            let ascii = buf[9];
                            let key = match ascii {
                                b'\n' | b'\r' | 0x0D => crate::gui::events::Key::Enter,
                                0x08 | 0x7F => crate::gui::events::Key::Backspace,
                                0x1B => crate::gui::events::Key::Escape,
                                0x09 => crate::gui::events::Key::Tab,
                                c if c != 0 => crate::gui::events::Key::Char(c as char),
                                _ => match keycode {
                                    0x0D => crate::gui::events::Key::Enter,
                                    0x08 => crate::gui::events::Key::Backspace,
                                    0x1B => crate::gui::events::Key::Escape,
                                    0x25 => crate::gui::events::Key::Left,
                                    0x27 => crate::gui::events::Key::Right,
                                    0x24 => crate::gui::events::Key::Home,
                                    0x23 => crate::gui::events::Key::End,
                                    0x2E => crate::gui::events::Key::Delete,
                                    _    => crate::gui::events::Key::Char('\0'),
                                },
                            };
                            self.on_key(&key, Some(ascii as char));
                            redraw = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        if redraw && !self.finished {
            self.draw();
            self.dirty = false;
        }
        redraw
    }

    // ── Drawing ──────────────────────────────────────────────────────────────

    fn draw(&mut self) {
        let ww = WIN_W as usize;
        let wh = WIN_H as usize;
        let fd = font::raw_font_data();
        let mut px = vec![COLOR_WINDOW_BG; ww * wh];

        // ── Step indicator bar (top) ─────────────────────────────────────────
        let bar_h = 28usize;
        let step_w = ww / STEP_COUNT;
        let current = self.step as usize;
        for i in 0..STEP_COUNT {
            let sx = i * step_w;
            let bg = if i < current {
                COLOR_SUCCESS        // completed steps = green
            } else if i == current {
                COLOR_ACCENT         // current step = blue
            } else {
                0x0A1628             // future steps = dark
            };
            fill_rect_buf(&mut px, ww, sx, 0, step_w, bar_h, bg);
            // Step label
            let label = STEP_LABELS[i];
            let lw = label.len() * font::FONT_WIDTH;
            let lx = sx + step_w.saturating_sub(lw) / 2;
            let ly = (bar_h - font::FONT_HEIGHT) / 2;
            let fg = if i <= current { 0xFFFFFF } else { COLOR_TEXT_MUTED };
            draw_str_buf(&mut px, ww, fd, label, lx, ly, fg, bg);
            // Separator
            if i < STEP_COUNT - 1 {
                for row in 0..bar_h {
                    let idx = row * ww + sx + step_w - 1;
                    if idx < px.len() { px[idx] = 0x1A2A40; }
                }
            }
        }

        // ── Step content ─────────────────────────────────────────────────────
        let content_y = bar_h + 16;

        match self.step {
            InstallStep::Welcome => {
                self.draw_welcome(&mut px, ww, fd, content_y);
            }
            InstallStep::License => {
                self.draw_license(&mut px, ww, fd, content_y);
            }
            InstallStep::Disk => {
                self.draw_disk(&mut px, ww, fd, content_y);
            }
            InstallStep::System => {
                self.draw_system(&mut px, ww, fd, content_y);
            }
            InstallStep::Network => {
                self.draw_network(&mut px, ww, fd, content_y);
            }
            InstallStep::Node => {
                self.draw_node(&mut px, ww, fd, content_y);
            }
            InstallStep::Installing => {
                self.draw_installing(&mut px, ww, fd, content_y);
            }
            InstallStep::Done => {
                self.draw_done(&mut px, ww, fd, content_y);
            }
        }

        // ── Navigation buttons ───────────────────────────────────────────────
        if self.step != InstallStep::Installing || self.install_done {
            draw_btn_buf(&mut px, ww, fd, &self.next_btn);
        }
        if self.step != InstallStep::Welcome
           && self.step != InstallStep::Installing
           && self.step != InstallStep::Done {
            draw_btn_buf(&mut px, ww, fd, &self.back_btn);
        }

        wm::update_pixels(self.wid, 0, 0, ww as u16, wh as u16, &px);
    }

    // ── Per-step draw functions ──────────────────────────────────────────────

    fn draw_welcome(&self, px: &mut Vec<u32>, ww: usize, fd: &[u8], y0: usize) {
        draw_str_buf(px, ww, fd, "Bun venit la IONA OS!", PAD, y0,
                     0xFFFFFF, COLOR_WINDOW_BG);
        draw_str_buf(px, ww, fd, "IONA OS v0.6.0 — sistem de operare bare-metal",
                     PAD, y0 + 30, COLOR_TEXT_SECONDARY, COLOR_WINDOW_BG);
        draw_str_buf(px, ww, fd, "cu nod blockchain integrat, TLS 1.3, GUI complet.",
                     PAD, y0 + 50, COLOR_TEXT_SECONDARY, COLOR_WINDOW_BG);

        draw_str_buf(px, ww, fd, "Selectati limba de instalare:",
                     PAD, y0 + 90, COLOR_TEXT_PRIMARY, COLOR_WINDOW_BG);

        let langs = ["  Romana  (RO)", "  English (EN)", "  Deutsch (DE)"];
        for (i, lang) in langs.iter().enumerate() {
            let ry = y0 + 120 + i * 36;
            let selected = i == self.language;
            let bg = if selected { COLOR_ACCENT } else { 0x0A1628 };
            let fg = if selected { 0xFFFFFF } else { COLOR_TEXT_SECONDARY };
            fill_rect_buf(px, ww, PAD, ry, ww - PAD * 2, 30, bg);
            draw_rect_buf(px, ww, PAD, ry, ww - PAD * 2, 30,
                          if selected { COLOR_ACCENT } else { 0x1E3050 });
            // Radio indicator
            let radio = if selected { "(*)" } else { "( )" };
            draw_str_buf(px, ww, fd, radio, PAD + 8, ry + 8, fg, bg);
            draw_str_buf(px, ww, fd, lang, PAD + 40, ry + 8, fg, bg);
        }
    }

    fn draw_license(&self, px: &mut Vec<u32>, ww: usize, fd: &[u8], y0: usize) {
        draw_str_buf(px, ww, fd, "Licenta IONA OS", PAD, y0,
                     0xFFFFFF, COLOR_WINDOW_BG);

        // License text area
        let text_y = y0 + 30;
        let text_h = 250;
        fill_rect_buf(px, ww, PAD, text_y, ww - PAD * 2, text_h, 0x060C18);
        draw_rect_buf(px, ww, PAD, text_y, ww - PAD * 2, text_h, 0x1E3050);

        let license_lines = [
            "IONA OS — Open Source License",
            "",
            "Copyright (c) 2024-2026 IONA Project",
            "",
            "Permission is hereby granted, free of charge,",
            "to any person obtaining a copy of this software",
            "and associated documentation files, to deal in",
            "the Software without restriction, including",
            "without limitation the rights to use, copy,",
            "modify, merge, publish, distribute, sublicense,",
            "and/or sell copies of the Software.",
            "",
            "THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT",
            "WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.",
        ];
        for (i, line) in license_lines.iter().enumerate() {
            let ly = text_y + 8 + i * (font::FONT_HEIGHT + 2);
            if ly + font::FONT_HEIGHT < text_y + text_h {
                draw_str_buf(px, ww, fd, line, PAD + 12, ly,
                             COLOR_TEXT_SECONDARY, 0x060C18);
            }
        }

        // Accept checkbox
        let cb_y = text_y + text_h + 16;
        let checked = self.license_accepted;
        let cb_bg = if checked { COLOR_ACCENT } else { 0x0A1628 };
        fill_rect_buf(px, ww, PAD, cb_y, 16, 16, cb_bg);
        draw_rect_buf(px, ww, PAD, cb_y, 16, 16,
                      if checked { COLOR_ACCENT } else { 0x1E3050 });
        if checked {
            // Simple checkmark
            for dx in 2..14 {
                let idx = (cb_y + 8) * ww + PAD + dx;
                if idx < px.len() { px[idx] = 0xFFFFFF; }
            }
        }
        draw_str_buf(px, ww, fd, "Accept termenii licentei IONA OS",
                     PAD + 24, cb_y + 2, COLOR_TEXT_PRIMARY, COLOR_WINDOW_BG);
        if !checked {
            draw_str_buf(px, ww, fd, "(trebuie sa acceptati pentru a continua)",
                         PAD + 24, cb_y + 20, COLOR_WARNING, COLOR_WINDOW_BG);
        }
    }

    fn draw_disk(&self, px: &mut Vec<u32>, ww: usize, fd: &[u8], y0: usize) {
        draw_str_buf(px, ww, fd, "Selectare disc pentru instalare", PAD, y0,
                     0xFFFFFF, COLOR_WINDOW_BG);
        draw_str_buf(px, ww, fd, "IONA OS va fi instalat pe discul selectat:",
                     PAD, y0 + 26, COLOR_TEXT_SECONDARY, COLOR_WINDOW_BG);

        let disk_y = y0 + 60;
        if self.disks.is_empty() {
            draw_str_buf(px, ww, fd, "Nu s-au detectat discuri disponibile.",
                         PAD, disk_y, COLOR_ERROR, COLOR_WINDOW_BG);
            draw_str_buf(px, ww, fd, "Verificati conexiunile hardware.",
                         PAD, disk_y + 22, COLOR_TEXT_SECONDARY, COLOR_WINDOW_BG);
        } else {
            for (i, disk) in self.disks.iter().enumerate() {
                let ry = disk_y + i * 44;
                let selected = i == self.selected_disk;
                let bg = if selected { 0x1A2A50 } else { 0x0A1628 };
                fill_rect_buf(px, ww, PAD, ry, ww - PAD * 2, 38, bg);
                draw_rect_buf(px, ww, PAD, ry, ww - PAD * 2, 38,
                              if selected { COLOR_ACCENT } else { 0x1E3050 });

                // Radio
                let radio = if selected { "(*)" } else { "( )" };
                draw_str_buf(px, ww, fd, radio, PAD + 8, ry + 4, COLOR_TEXT_PRIMARY, bg);

                // Disk name
                draw_str_buf(px, ww, fd, &disk.name, PAD + 44, ry + 4,
                             COLOR_TEXT_PRIMARY, bg);

                // Size
                let size_str = format!("{} MB", disk.size_mb);
                draw_str_buf(px, ww, fd, &size_str, PAD + 44, ry + 20,
                             COLOR_TEXT_SECONDARY, bg);

                // Capacity bar
                let bar_x = ww - PAD - 200;
                let bar_w = 180;
                let filled = (bar_w as f64 * disk.size_mb as f64 / 65536.0).min(bar_w as f64) as usize;
                fill_rect_buf(px, ww, bar_x, ry + 14, bar_w, 10, 0x0A1628);
                if filled > 0 {
                    fill_rect_buf(px, ww, bar_x, ry + 14, filled, 10, COLOR_ACCENT);
                }
            }
        }

        // Format checkbox
        let cb_y = disk_y + self.disks.len() * 44 + 16;
        let cb_bg = if self.format_disk { COLOR_ACCENT } else { 0x0A1628 };
        fill_rect_buf(px, ww, PAD, cb_y, 16, 16, cb_bg);
        draw_rect_buf(px, ww, PAD, cb_y, 16, 16,
                      if self.format_disk { COLOR_ACCENT } else { 0x1E3050 });
        if self.format_disk {
            for dx in 2..14 {
                let idx = (cb_y + 8) * ww + PAD + dx;
                if idx < px.len() { px[idx] = 0xFFFFFF; }
            }
        }
        draw_str_buf(px, ww, fd, "Formateaza disc cu IONAFS (recomandat)",
                     PAD + 24, cb_y + 2, COLOR_TEXT_PRIMARY, COLOR_WINDOW_BG);

        // Partition info
        if !self.disks.is_empty() {
            let info_y = cb_y + 34;
            draw_str_buf(px, ww, fd, "Partitii create automat:",
                         PAD, info_y, COLOR_TEXT_SECONDARY, COLOR_WINDOW_BG);
            let parts = [
                "/boot     256 MB   FAT32   (bootloader)",
                "/         restul   IONAFS  (sistem + date)",
                "swap      512 MB   swap    (memorie virtuala)",
            ];
            for (i, p) in parts.iter().enumerate() {
                draw_str_buf(px, ww, fd, p, PAD + 16, info_y + 22 + i * 18,
                             COLOR_TEXT_MUTED, COLOR_WINDOW_BG);
            }
        }
    }

    fn draw_system(&self, px: &mut Vec<u32>, ww: usize, fd: &[u8], y0: usize) {
        draw_str_buf(px, ww, fd, "Configurare sistem", PAD, y0,
                     0xFFFFFF, COLOR_WINDOW_BG);
        draw_str_buf(px, ww, fd, "Completati datele de sistem:",
                     PAD, y0 + 26, COLOR_TEXT_SECONDARY, COLOR_WINDOW_BG);

        // Labels + inputs
        let fields = [
            ("Hostname:", 200),
            ("Utilizator:", 246),
            ("Parola:", 292),
            ("Confirmare:", 338),
        ];
        for (label, y) in &fields {
            draw_str_buf(px, ww, fd, label, PAD, *y,
                         COLOR_TEXT_PRIMARY, COLOR_WINDOW_BG);
        }

        // Draw text inputs
        draw_input_buf(px, ww, fd, &self.input1);
        draw_input_buf(px, ww, fd, &self.input2);
        draw_input_buf(px, ww, fd, &self.input3);
        draw_input_buf(px, ww, fd, &self.input4);

        // Password match indicator
        if !self.input3.value.is_empty() && !self.input4.value.is_empty() {
            let match_msg = if self.input3.value == self.input4.value {
                ("Parolele coincid", COLOR_SUCCESS)
            } else {
                ("Parolele nu coincid!", COLOR_ERROR)
            };
            draw_str_buf(px, ww, fd, match_msg.0, PAD + 160, 370,
                         match_msg.1, COLOR_WINDOW_BG);
        }
    }

    fn draw_network(&self, px: &mut Vec<u32>, ww: usize, fd: &[u8], y0: usize) {
        draw_str_buf(px, ww, fd, "Configurare retea", PAD, y0,
                     0xFFFFFF, COLOR_WINDOW_BG);
        draw_str_buf(px, ww, fd, "Selectati modul de conectare la retea:",
                     PAD, y0 + 26, COLOR_TEXT_SECONDARY, COLOR_WINDOW_BG);

        // DHCP checkbox
        let cb_y = y0 + 60;
        let cb_bg = if self.use_dhcp { COLOR_ACCENT } else { 0x0A1628 };
        fill_rect_buf(px, ww, PAD, cb_y, 16, 16, cb_bg);
        draw_rect_buf(px, ww, PAD, cb_y, 16, 16,
                      if self.use_dhcp { COLOR_ACCENT } else { 0x1E3050 });
        if self.use_dhcp {
            for dx in 2..14 {
                let idx = (cb_y + 8) * ww + PAD + dx;
                if idx < px.len() { px[idx] = 0xFFFFFF; }
            }
        }
        draw_str_buf(px, ww, fd, "Utilizare DHCP (recomandat)",
                     PAD + 24, cb_y + 2, COLOR_TEXT_PRIMARY, COLOR_WINDOW_BG);

        if self.use_dhcp {
            draw_str_buf(px, ww, fd, "Adresa IP va fi obtinuta automat de la server.",
                         PAD, cb_y + 34, COLOR_TEXT_SECONDARY, COLOR_WINDOW_BG);
            // Show current lease if available
            let lease = crate::net::dhcp::get_lease();
            if lease.ip != [0, 0, 0, 0] {
                let ip_str = format!("IP curent: {}.{}.{}.{}",
                    lease.ip[0], lease.ip[1], lease.ip[2], lease.ip[3]);
                draw_str_buf(px, ww, fd, &ip_str,
                             PAD, cb_y + 56, COLOR_SUCCESS, COLOR_WINDOW_BG);
            }
        } else {
            // Static IP fields
            let fields = [
                ("Adresa IP:", 240 - y0 + y0),
                ("Gateway:", 286 - y0 + y0),
                ("DNS:", 332 - y0 + y0),
            ];
            for (label, y) in &fields {
                draw_str_buf(px, ww, fd, label, PAD, *y,
                             COLOR_TEXT_PRIMARY, COLOR_WINDOW_BG);
            }
            draw_input_buf(px, ww, fd, &self.input1);
            draw_input_buf(px, ww, fd, &self.input2);
            draw_input_buf(px, ww, fd, &self.input3);
        }
    }

    fn draw_node(&self, px: &mut Vec<u32>, ww: usize, fd: &[u8], y0: usize) {
        draw_str_buf(px, ww, fd, "Configurare IONA Node", PAD, y0,
                     0xFFFFFF, COLOR_WINDOW_BG);
        draw_str_buf(px, ww, fd, "IONA OS include un nod blockchain integrat.",
                     PAD, y0 + 26, COLOR_TEXT_SECONDARY, COLOR_WINDOW_BG);

        // Enable node checkbox
        let cb_y = y0 + 60;
        let cb_bg = if self.enable_node { COLOR_ACCENT } else { 0x0A1628 };
        fill_rect_buf(px, ww, PAD, cb_y, 16, 16, cb_bg);
        draw_rect_buf(px, ww, PAD, cb_y, 16, 16,
                      if self.enable_node { COLOR_ACCENT } else { 0x1E3050 });
        if self.enable_node {
            for dx in 2..14 {
                let idx = (cb_y + 8) * ww + PAD + dx;
                if idx < px.len() { px[idx] = 0xFFFFFF; }
            }
        }
        draw_str_buf(px, ww, fd, "Activeaza IONA Node (validator)",
                     PAD + 24, cb_y + 2, COLOR_TEXT_PRIMARY, COLOR_WINDOW_BG);

        if self.enable_node {
            let fields_y = cb_y + 40;
            draw_str_buf(px, ww, fd, "Validator ID:", PAD, fields_y,
                         COLOR_TEXT_PRIMARY, COLOR_WINDOW_BG);
            draw_str_buf(px, ww, fd, "Peers:", PAD, fields_y + 46,
                         COLOR_TEXT_PRIMARY, COLOR_WINDOW_BG);
            draw_input_buf(px, ww, fd, &self.input1);
            draw_input_buf(px, ww, fd, &self.input2);

            // Info box
            let info_y = fields_y + 100;
            fill_rect_buf(px, ww, PAD, info_y, ww - PAD * 2, 70, 0x0A1628);
            draw_rect_buf(px, ww, PAD, info_y, ww - PAD * 2, 70, 0x1E3050);
            draw_str_buf(px, ww, fd, "Nodul va sincroniza automat cu reteaua",
                         PAD + 12, info_y + 8, COLOR_TEXT_SECONDARY, 0x0A1628);
            draw_str_buf(px, ww, fd, "IONA dupa instalare. Cheile criptografice",
                         PAD + 12, info_y + 26, COLOR_TEXT_SECONDARY, 0x0A1628);
            draw_str_buf(px, ww, fd, "vor fi generate automat la primul start.",
                         PAD + 12, info_y + 44, COLOR_TEXT_SECONDARY, 0x0A1628);
        } else {
            draw_str_buf(px, ww, fd, "Nodul poate fi activat ulterior din Settings.",
                         PAD, cb_y + 34, COLOR_TEXT_MUTED, COLOR_WINDOW_BG);
        }
    }

    fn draw_installing(&mut self, px: &mut Vec<u32>, ww: usize, fd: &[u8], y0: usize) {
        draw_str_buf(px, ww, fd, "Se instaleaza IONA OS...", PAD, y0,
                     0xFFFFFF, COLOR_WINDOW_BG);

        // Progress percentage
        let pct = (self.install_progress * 100.0) as u32;
        let pct_str = format!("{}%", pct);
        let pct_x = ww - PAD - pct_str.len() * font::FONT_WIDTH;
        draw_str_buf(px, ww, fd, &pct_str, pct_x, y0,
                     COLOR_ACCENT, COLOR_WINDOW_BG);

        // Progress bar
        let bar_y = y0 + 40;
        let bar_w = ww - PAD * 2;
        let bar_h = 28;
        fill_rect_buf(px, ww, PAD, bar_y, bar_w, bar_h, 0x0A1628);
        draw_rect_buf(px, ww, PAD, bar_y, bar_w, bar_h, 0x1E3050);
        let filled = (bar_w as f32 * self.install_progress) as usize;
        if filled > 2 {
            // Gradient-like fill for progress bar
            for row in 1..bar_h - 1 {
                for col in 1..filled.min(bar_w - 1) {
                    let t = col as f32 / filled as f32;
                    let r = (0x1E as f32 + (0x3D - 0x1E) as f32 * t) as u32;
                    let g = (0x4A as f32 + (0x8E - 0x4A) as f32 * t) as u32;
                    let b = (0x80 as f32 + (0xF0 - 0x80) as f32 * t) as u32;
                    let color = (r << 16) | (g << 8) | b;
                    let idx = (bar_y + row) * ww + PAD + col;
                    if idx < px.len() { px[idx] = color; }
                }
            }
        }

        // Current step message
        draw_str_buf(px, ww, fd, &self.install_step_msg, PAD, bar_y + bar_h + 16,
                     COLOR_TEXT_PRIMARY, COLOR_WINDOW_BG);

        // Installation log
        let log_y = bar_y + bar_h + 50;
        let log_h = 200;
        fill_rect_buf(px, ww, PAD, log_y, ww - PAD * 2, log_h, 0x060C18);
        draw_rect_buf(px, ww, PAD, log_y, ww - PAD * 2, log_h, 0x1E3050);

        // Show completed steps
        let steps_done = [
            (0.05, "Verificare disc"),
            (0.10, "Creare tabel de partitii"),
            (0.15, "Formatare IONAFS"),
            (0.20, "Scriere superblock"),
            (0.25, "Copiere kernel"),
            (0.35, "Copiere module sistem"),
            (0.45, "Instalare drivere hardware"),
            (0.50, "Configurare bootloader"),
            (0.55, "Scriere configuratie sistem"),
            (0.60, "Configurare retea"),
            (0.65, "Creare cont utilizator"),
            (0.70, "Configurare securitate"),
            (0.75, "Configurare IONA Node"),
            (0.80, "Instalare aplicatii desktop"),
            (0.85, "Generare chei criptografice"),
            (0.90, "Configurare firstboot"),
            (0.95, "Verificare integritate"),
        ];

        let max_visible = log_h / (font::FONT_HEIGHT + 4);
        let mut shown = 0;
        for (threshold, label) in &steps_done {
            if self.install_progress >= *threshold && shown < max_visible {
                let ly = log_y + 6 + shown * (font::FONT_HEIGHT + 4);
                let status = if self.install_progress > *threshold + 0.05 {
                    ("[OK]", COLOR_SUCCESS)
                } else {
                    ("[..]", COLOR_ACCENT)
                };
                draw_str_buf(px, ww, fd, status.0, PAD + 8, ly, status.1, 0x060C18);
                draw_str_buf(px, ww, fd, label, PAD + 48, ly,
                             COLOR_TEXT_SECONDARY, 0x060C18);
                shown += 1;
            }
        }

        if self.install_done {
            draw_str_buf(px, ww, fd, "Instalare completa!", PAD, bar_y + bar_h + 16,
                         COLOR_SUCCESS, COLOR_WINDOW_BG);
        }
    }

    fn draw_done(&self, px: &mut Vec<u32>, ww: usize, fd: &[u8], y0: usize) {
        draw_str_buf(px, ww, fd, "Instalare completa!", PAD, y0,
                     COLOR_SUCCESS, COLOR_WINDOW_BG);

        let mut y = y0 + 40;
        draw_str_buf(px, ww, fd, "IONA OS a fost instalat cu succes.",
                     PAD, y, COLOR_TEXT_PRIMARY, COLOR_WINDOW_BG);
        y += 30;

        // Summary box
        fill_rect_buf(px, ww, PAD, y, ww - PAD * 2, 200, 0x0A1628);
        draw_rect_buf(px, ww, PAD, y, ww - PAD * 2, 200, 0x1E3050);

        let mut sy = y + 12;
        let summary = [
            format!("Limba:       {}", match self.language { 0 => "Romana", 1 => "English", _ => "Deutsch" }),
            format!("Disc:        {}", self.disks.get(self.selected_disk).map(|d| d.name.as_str()).unwrap_or("N/A")),
            format!("Hostname:    {}", self.hostname),
            format!("Utilizator:  {}", self.username),
            format!("Retea:       {}", if self.use_dhcp { "DHCP" } else { "Static" }),
            format!("IONA Node:   {}", if self.enable_node { "Activ" } else { "Dezactivat" }),
        ];
        for line in &summary {
            draw_str_buf(px, ww, fd, line, PAD + 16, sy,
                         COLOR_TEXT_SECONDARY, 0x0A1628);
            sy += 22;
        }

        // Additional info
        sy = y + 216;
        draw_str_buf(px, ww, fd, "Apasati 'Finalizare' pentru a intra in desktop.",
                     PAD, sy, COLOR_TEXT_PRIMARY, COLOR_WINDOW_BG);
        draw_str_buf(px, ww, fd, "Puteti modifica setarile oricand din Settings.",
                     PAD, sy + 22, COLOR_TEXT_MUTED, COLOR_WINDOW_BG);
    }
}

// ── Disk detection ───────────────────────────────────────────────────────────

fn detect_disks() -> Vec<DiskInfo> {
    let mut disks = Vec::new();

    // Check NVMe
    if crate::drivers::nvme::is_available() {
        disks.push(DiskInfo {
            name: String::from("nvme0n1 — NVMe SSD"),
            size_mb: crate::drivers::nvme::capacity_mb().unwrap_or(32768),
            selected: true,
        });
    }

    // Check virtio-blk
    if crate::drivers::virtio::blk::is_available() {
        disks.push(DiskInfo {
            name: String::from("vda — VirtIO Block"),
            size_mb: crate::drivers::virtio::blk::capacity_mb().unwrap_or(16384),
            selected: disks.is_empty(),
        });
    }

    // Check AHCI/SATA
    if crate::drivers::ahci::is_available() {
        disks.push(DiskInfo {
            name: String::from("sda — SATA HDD/SSD"),
            size_mb: crate::drivers::ahci::capacity_mb().unwrap_or(65536),
            selected: disks.is_empty(),
        });
    }

    // Fallback: if no real disks detected, show in-memory option
    if disks.is_empty() {
        disks.push(DiskInfo {
            name: String::from("ram0 — RAM Disk (in-memory)"),
            size_mb: 256,
            selected: true,
        });
    }

    disks
}

// ── Drawing helpers (same pattern as firstboot.rs) ───────────────────────────

fn draw_str_buf(px: &mut Vec<u32>, stride: usize, fd: &[u8], s: &str,
                mut x: usize, y: usize, fg: u32, bg: u32) {
    for b in s.bytes() {
        let goff = 32 + b as usize * 16;
        if goff + 16 > fd.len() { x += font::FONT_WIDTH; continue; }
        for r in 0..font::FONT_HEIGHT {
            let byte = fd[goff + r];
            for c in 0..font::FONT_WIDTH {
                let sx = x + c;
                let sy = y + r;
                let idx = sy * stride + sx;
                if idx < px.len() {
                    px[idx] = if byte & (0x80 >> c) != 0 { fg } else { bg };
                }
            }
        }
        x += font::FONT_WIDTH;
    }
}

fn fill_rect_buf(px: &mut Vec<u32>, stride: usize, x: usize, y: usize,
                  w: usize, h: usize, color: u32) {
    for row in y..y + h {
        for col in x..x + w {
            let idx = row * stride + col;
            if idx < px.len() { px[idx] = color; }
        }
    }
}

fn draw_rect_buf(px: &mut Vec<u32>, stride: usize, x: usize, y: usize,
                  w: usize, h: usize, color: u32) {
    for col in x..x + w {
        let top = y * stride + col;
        let bot = (y + h.saturating_sub(1)) * stride + col;
        if top < px.len() { px[top] = color; }
        if bot < px.len() { px[bot] = color; }
    }
    for row in y..y + h {
        let left = row * stride + x;
        let right = row * stride + x + w.saturating_sub(1);
        if left < px.len() { px[left] = color; }
        if right < px.len() { px[right] = color; }
    }
}

fn draw_btn_buf(px: &mut Vec<u32>, stride: usize, fd: &[u8], btn: &Button) {
    let bg_color = match btn.state {
        BtnState::Normal   => COLOR_BTN_BG,
        BtnState::Hover    => COLOR_BTN_BG_HOVER,
        BtnState::Pressed  => COLOR_BTN_BG_PRESS,
        BtnState::Disabled => 0x0A1020,
    };
    fill_rect_buf(px, stride, btn.rect.x, btn.rect.y, btn.rect.w, btn.rect.h, bg_color);
    draw_rect_buf(px, stride, btn.rect.x, btn.rect.y, btn.rect.w, btn.rect.h, COLOR_BTN_BORDER);
    let tw = btn.label.len() * font::FONT_WIDTH;
    let tx = btn.rect.x + btn.rect.w.saturating_sub(tw) / 2;
    let ty = btn.rect.y + btn.rect.h.saturating_sub(font::FONT_HEIGHT) / 2;
    let fg = if btn.state == BtnState::Pressed { COLOR_BTN_TEXT_PRESS } else { COLOR_BTN_TEXT };
    draw_str_buf(px, stride, fd, &btn.label, tx, ty, fg, bg_color);
}

fn draw_input_buf(px: &mut Vec<u32>, stride: usize, fd: &[u8], input: &TextInput) {
    fill_rect_buf(px, stride, input.rect.x, input.rect.y,
                  input.rect.w, input.rect.h, COLOR_INPUT_BG);
    let border = if input.focused { COLOR_INPUT_BORDER_FOCUS } else { COLOR_INPUT_BORDER };
    draw_rect_buf(px, stride, input.rect.x, input.rect.y,
                  input.rect.w, input.rect.h, border);
    let tx = input.rect.x + 6;
    let ty = input.rect.y + 4;
    if input.value.is_empty() && !input.focused {
        draw_str_buf(px, stride, fd, &input.placeholder, tx, ty,
                     COLOR_TEXT_MUTED, COLOR_INPUT_BG);
    } else {
        let max_chars = input.rect.w.saturating_sub(12) / font::FONT_WIDTH;
        let visible_start = input.cursor.saturating_sub(max_chars);
        let s = &input.value[visible_start.min(input.value.len())..];
        let s = &s[..s.len().min(max_chars)];
        draw_str_buf(px, stride, fd, s, tx, ty, COLOR_INPUT_TEXT, COLOR_INPUT_BG);
        if input.focused {
            let cur_col = input.cursor.saturating_sub(visible_start);
            let cx = tx + cur_col * font::FONT_WIDTH;
            for dy in 0..font::FONT_HEIGHT {
                let idx = (ty + dy) * stride + cx;
                if idx < px.len() { px[idx] = COLOR_INPUT_CURSOR; }
            }
        }
    }
}

// ── Public API (same pattern as other apps) ──────────────────────────────────

static mut INSTALLER_APP: Option<InstallerApp> = None;

/// Check if installer should run (OS not yet installed)
pub fn should_run() -> bool {
    crate::fs::ionafs::read("/etc/iona-installed").is_none()
}

pub fn launch(x: i32, y: i32) {
    crate::serial_println!("[INSTALLER] launching at ({}, {})", x, y);
    unsafe { INSTALLER_APP = Some(InstallerApp::new(x, y)); }
}

pub fn get_wid() -> Option<u32> {
    unsafe { INSTALLER_APP.as_ref().map(|a| a.wid) }
}

pub fn tick() -> bool {
    unsafe {
        if let Some(ref mut app) = INSTALLER_APP {
            if app.finished {
                INSTALLER_APP = None;
                return false;
            }
            app.tick()
        } else {
            false
        }
    }
}

pub fn is_running() -> bool {
    unsafe { INSTALLER_APP.is_some() }
}
