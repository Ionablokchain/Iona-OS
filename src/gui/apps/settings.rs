//! Settings app — system configuration GUI
use alloc::{vec::Vec, format, string::{String, ToString}};
use crate::gui::{wm, ipc, theme::*, text, primitives::draw as prim};
use crate::io::{font, framebuffer as fb};
use crate::gui::icons::{Icon, draw_icon};

const WIN_W: u32 = 580; const WIN_H: u32 = 440;
const PAD: usize = 14;

#[derive(Clone, Copy, PartialEq)]
enum Tab { Display, Network, Node, Security, About }

pub struct SettingsApp {
    pub wid: u32,
    tab: Tab,
    dirty: bool,
}
impl SettingsApp {
    pub fn new(x: i32, y: i32) -> Self {
        let tid = crate::arch::x86_64::percpu::current_tid();
        let wid = wm::create_window("Settings", x, y, WIN_W, WIN_H, tid);
        ipc::register_window(wid);
        Self { wid, tab: Tab::Display, dirty: true }
    }
    pub fn tick(&mut self, _now: u64) -> bool {
        let mut redraw = self.dirty;
        while let Some(buf) = ipc::poll_window_event(self.wid) {
            if buf.len() >= 9 && buf[0] == 2 {
                let x = i32::from_le_bytes([buf[1],buf[2],buf[3],buf[4]]);
                let y = i32::from_le_bytes([buf[5],buf[6],buf[7],buf[8]]);
                self.on_click(x, y); redraw = true;
            }
        }
        if redraw { self.draw(); self.dirty = false; }
        redraw
    }
    fn on_click(&mut self, x: i32, y: i32) {
        // Tab clicks (top row)
        let tabs = [(Tab::Display,"Display"),(Tab::Network,"Network"),
                    (Tab::Node,"Node"),(Tab::Security,"Security"),(Tab::About,"About")];
        for (i,(t,_)) in tabs.iter().enumerate() {
            let tx = PAD + i * 110;
            if x >= tx as i32 && x < (tx+108) as i32 && y >= PAD as i32 && y < (PAD+32) as i32 {
                self.tab = *t; self.dirty = true;
            }
        }
        // Content area actions
        match self.tab {
            Tab::Node => {
                // "Apply" button at y=380
                if y >= 380 && y < 412 && x >= PAD as i32 && x < (PAD+100) as i32 {
                    self.apply_node_config();
                }
            }
            Tab::Security => {
                if y >= 380 && y < 412 && x >= PAD as i32 && x < (PAD+120) as i32 {
                    crate::gui::modal::confirm("Rotate keystore key?",
                        "This will re-encrypt all stored keys.", &["Rotate","Cancel"]);
                }
            }
            _ => {}
        }
    }
    fn apply_node_config(&self) {
        crate::serial_println!("[SETTINGS] node config applied");
        // Push notification via the state module
        {
            let mut shell = crate::gui::SHELL_STATE.lock();
            shell.notifications.push("Settings", "Node config applied", crate::gui::state::notifications::NotifKind::Success, 5000);
        }
    }
    fn draw(&self) {
        let ww=WIN_W as usize; let wh=WIN_H as usize;
        let mut px=alloc::vec![COLOR_WINDOW_BG; ww*wh];
        let fd=font::raw_font_data();
        let tabs=[("Display",Tab::Display),("Network",Tab::Network),
                  ("Node",Tab::Node),("Security",Tab::Security),("About",Tab::About)];
        // Tab bar
        for (i,(lbl,t)) in tabs.iter().enumerate() {
            let tx=PAD+i*110; let is_active=self.tab==*t;
            let bg=if is_active{COLOR_BTN_BG_PRESS}else{COLOR_BTN_BG};
            fill_px(&mut px,ww,tx,PAD,108,30,bg);
            draw_str(&mut px,ww,fd,lbl,tx+8,PAD+7,if is_active{0xFFFFFF}else{COLOR_TEXT_SECONDARY as u32},bg);
        }
        // Separator
        fill_px(&mut px,ww,0,PAD+32,ww,1,COLOR_TASKBAR_BORDER);
        let cy=PAD+44;
        match self.tab {
            Tab::Display => {
                draw_str(&mut px,ww,fd,"Resolution:",PAD,cy,COLOR_TEXT_SECONDARY,COLOR_WINDOW_BG);
                draw_str(&mut px,ww,fd,"1920 × 1080 (current)",PAD+120,cy,COLOR_TEXT_PRIMARY,COLOR_WINDOW_BG);
                draw_str(&mut px,ww,fd,"Theme:",PAD,cy+30,COLOR_TEXT_SECONDARY,COLOR_WINDOW_BG);
                draw_str(&mut px,ww,fd,"Dark (IONA Blue)",PAD+120,cy+30,COLOR_TEXT_PRIMARY,COLOR_WINDOW_BG);
                draw_str(&mut px,ww,fd,"Brightness:",PAD,cy+60,COLOR_TEXT_SECONDARY,COLOR_WINDOW_BG);
                fill_px(&mut px,ww,PAD+120,cy+64,200,8,COLOR_BTN_BG);
                fill_px(&mut px,ww,PAD+120,cy+64,160,8,COLOR_BTN_BG_PRESS);
                draw_str(&mut px,ww,fd,"Wallpaper:",PAD,cy+90,COLOR_TEXT_SECONDARY,COLOR_WINDOW_BG);
                draw_str(&mut px,ww,fd,"IONA Mountains (procedural)",PAD+120,cy+90,COLOR_TEXT_PRIMARY,COLOR_WINDOW_BG);
            }
            Tab::Network => {
                let net_ok=crate::net::is_ready();
                draw_str(&mut px,ww,fd,"Status:",PAD,cy,COLOR_TEXT_SECONDARY,COLOR_WINDOW_BG);
                draw_str(&mut px,ww,fd,if net_ok{"Connected"}else{"Disconnected"},PAD+120,cy,if net_ok{COLOR_SUCCESS}else{COLOR_ERROR},COLOR_WINDOW_BG);
                draw_str(&mut px,ww,fd,"IP Address:",PAD,cy+30,COLOR_TEXT_SECONDARY,COLOR_WINDOW_BG);
                draw_str(&mut px,ww,fd,"10.0.2.15 (DHCP)",PAD+120,cy+30,COLOR_TEXT_PRIMARY,COLOR_WINDOW_BG);
                draw_str(&mut px,ww,fd,"DNS:",PAD,cy+60,COLOR_TEXT_SECONDARY,COLOR_WINDOW_BG);
                draw_str(&mut px,ww,fd,"8.8.8.8 (Google)",PAD+120,cy+60,COLOR_TEXT_PRIMARY,COLOR_WINDOW_BG);
                draw_str(&mut px,ww,fd,"Gossip Port:",PAD,cy+90,COLOR_TEXT_SECONDARY,COLOR_WINDOW_BG);
                draw_str(&mut px,ww,fd,"9000",PAD+120,cy+90,COLOR_TEXT_PRIMARY,COLOR_WINDOW_BG);
            }
            Tab::Node => {
                let h={let e=crate::consensus::engine::CONSENSUS_ENGINE.lock();e.as_ref().map(|e|e.height).unwrap_or(0)};
                let h_str=format!("Height: {}",h);
                draw_str(&mut px,ww,fd,"Consensus:",PAD,cy,COLOR_TEXT_SECONDARY,COLOR_WINDOW_BG);
                draw_str(&mut px,ww,fd,&h_str,PAD+120,cy,COLOR_ACCENT,COLOR_WINDOW_BG);
                draw_str(&mut px,ww,fd,"Validator ID:",PAD,cy+30,COLOR_TEXT_SECONDARY,COLOR_WINDOW_BG);
                draw_str(&mut px,ww,fd,"0",PAD+120,cy+30,COLOR_TEXT_PRIMARY,COLOR_WINDOW_BG);
                draw_str(&mut px,ww,fd,"Peers:",PAD,cy+60,COLOR_TEXT_SECONDARY,COLOR_WINDOW_BG);
                draw_str(&mut px,ww,fd,"3 connected",PAD+120,cy+60,COLOR_SUCCESS,COLOR_WINDOW_BG);
                draw_str(&mut px,ww,fd,"Admin Port:",PAD,cy+90,COLOR_TEXT_SECONDARY,COLOR_WINDOW_BG);
                draw_str(&mut px,ww,fd,"7777",PAD+120,cy+90,COLOR_TEXT_PRIMARY,COLOR_WINDOW_BG);
                // Apply button
                fill_px(&mut px,ww,PAD,380,100,32,COLOR_BTN_BG_PRESS);
                draw_str(&mut px,ww,fd,"Apply",PAD+20,387,0xFFFFFF,COLOR_BTN_BG_PRESS);
            }
            Tab::Security => {
                draw_str(&mut px,ww,fd,"Keystore:",PAD,cy,COLOR_TEXT_SECONDARY,COLOR_WINDOW_BG);
                let ks_str=if crate::security::keystore::is_unlocked(){"Unlocked"}else{"Locked"};
                draw_str(&mut px,ww,fd,ks_str,PAD+120,cy,if crate::security::keystore::is_unlocked(){COLOR_SUCCESS}else{COLOR_WARNING},COLOR_WINDOW_BG);
                draw_str(&mut px,ww,fd,"Canary:",PAD,cy+30,COLOR_TEXT_SECONDARY,COLOR_WINDOW_BG);
                draw_str(&mut px,ww,fd,"Active (randomized at boot)",PAD+120,cy+30,COLOR_SUCCESS,COLOR_WINDOW_BG);
                draw_str(&mut px,ww,fd,"TLS:",PAD,cy+60,COLOR_TEXT_SECONDARY,COLOR_WINDOW_BG);
                draw_str(&mut px,ww,fd,"ChaCha20-Poly1305",PAD+120,cy+60,COLOR_SUCCESS,COLOR_WINDOW_BG);
                fill_px(&mut px,ww,PAD,380,120,32,COLOR_BTN_BG);
                draw_str(&mut px,ww,fd,"Rotate Key...",PAD+8,387,COLOR_TEXT_PRIMARY as u32,COLOR_BTN_BG);
            }
            Tab::About => {
                draw_str(&mut px,ww,fd,"IONA OS",PAD,cy,COLOR_ACCENT,COLOR_WINDOW_BG);
                draw_str(&mut px,ww,fd,"Version: 0.6.0",PAD,cy+30,COLOR_TEXT_PRIMARY,COLOR_WINDOW_BG);
                draw_str(&mut px,ww,fd,"Kernel: x86_64 bare-metal Rust",PAD,cy+60,COLOR_TEXT_SECONDARY,COLOR_WINDOW_BG);
                draw_str(&mut px,ww,fd,"Consensus: Tendermint BFT",PAD,cy+90,COLOR_TEXT_SECONDARY,COLOR_WINDOW_BG);
                draw_str(&mut px,ww,fd,"Crypto: ChaCha20-Poly1305, BN254 Groth16",PAD,cy+120,COLOR_TEXT_SECONDARY,COLOR_WINDOW_BG);
                draw_str(&mut px,ww,fd,"Build: 2026-03-31",PAD,cy+150,COLOR_TEXT_MUTED,COLOR_WINDOW_BG);
            }
        }
        wm::update_pixels(self.wid,0,0,WIN_W as u16,WIN_H as u16,&px);
    }
}
fn fill_px(px:&mut Vec<u32>,stride:usize,x:usize,y:usize,w:usize,h:usize,c:u32){
    for row in y..y+h{for col in x..x+w{let i=row*stride+col;if i<px.len(){px[i]=c;}}}
}
fn draw_str(px:&mut Vec<u32>,stride:usize,fd:&[u8],s:&str,mut x:usize,y:usize,fg:u32,bg:u32){
    for b in s.bytes(){let go=32+b as usize*16;if go+16>fd.len(){x+=8;continue;}
        for r in 0..16{let byte=fd[go+r];for c in 0..8{let sx=x+c;let sy=y+r;let i=sy*stride+sx;
            if i<px.len(){px[i]=if byte&(0x80>>c)!=0{fg}else{bg};}}}x+=8;}
}
static mut SETTINGS_APP: Option<SettingsApp> = None;
pub fn launch(x: i32, y: i32) { unsafe { SETTINGS_APP = Some(SettingsApp::new(x, y)); } }
pub fn get_wid() -> Option<u32> { unsafe { SETTINGS_APP.as_ref().map(|a| a.wid) } }
pub fn tick(now_ms: u64) -> bool { unsafe { if let Some(ref mut a)=SETTINGS_APP {a.tick(now_ms)} else {false} } }
