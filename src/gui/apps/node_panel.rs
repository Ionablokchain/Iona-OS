//! IONA Node Control Panel — start/stop node, peer management, consensus status
use alloc::{vec::Vec, format, string::{String, ToString}};
use crate::gui::{wm, ipc, theme::*};
use crate::io::font;

const WIN_W: u32 = 500; const WIN_H: u32 = 420; const PAD: usize = 14;

pub struct NodePanelApp {
    pub wid:         u32,
    dirty:           bool,
    node_running:    bool,
    log_lines:       alloc::vec::Vec<alloc::string::String>,
    last_height:     u64,
}

impl NodePanelApp {
    pub fn new(x: i32, y: i32) -> Self {
        let tid = crate::arch::x86_64::percpu::current_tid();
        let wid = wm::create_window("IONA Node Control", x, y, WIN_W, WIN_H, tid);
        ipc::register_window(wid);
        Self {
            wid, dirty: true,
            node_running: true,
            log_lines: alloc::vec![
                "  [NODE] IONA Node v0.6.0 starting...".into(),
                "  [BFT] Tendermint engine initialized".into(),
                "  [NET] Gossipsub P2P connected".into(),
            ],
            last_height: 0,
        }
    }
    pub fn tick(&mut self, now: u64) -> bool {
        // Check modal result for stop confirmation
        if let Some(0) = crate::gui::modal::take_result() {
            self.node_running = false;
            self.log_lines.push("  [NODE] Node stopped by user".into());
            if self.log_lines.len() > 12 { self.log_lines.remove(0); }
            self.dirty = true;
        }
        // Update height from real consensus engine
        let h = {
            let e = crate::consensus::engine::CONSENSUS_ENGINE.lock();
            e.as_ref().map(|e| e.height).unwrap_or(0)
        };
        if h != self.last_height {
            self.last_height = h;
            let msg = alloc::format!("  [BFT] Block {} committed", h);
            self.log_lines.push(msg);
            if self.log_lines.len() > 12 { self.log_lines.remove(0); }
            self.dirty = true;
        }
    
        let mut redraw = self.dirty;
        while let Some(buf) = ipc::poll_window_event(self.wid) {
            if buf.len()>=9 && buf[0]==2 {
                let x=i32::from_le_bytes([buf[1],buf[2],buf[3],buf[4]]);
                let y=i32::from_le_bytes([buf[5],buf[6],buf[7],buf[8]]);
                self.on_click(x,y); redraw=true;
            }
        }
        if redraw { self.draw(); self.dirty=false; }
        redraw
    }
    fn on_click(&mut self, x: i32, y: i32) {
        let pad = 14i32;
        // Start button
        if x >= pad && x < pad+120 && y >= 60 && y < 92 && !self.node_running {
            self.node_running = true;
            self.log_lines.push("  [NODE] Start command sent (syscall 400)".into());
            if self.log_lines.len() > 12 { self.log_lines.remove(0); }
            // Syscall 400 = consensus tick — triggers engine start
            let _ = unsafe { core::arch::asm!("syscall",
                in("rax") 400u64, in("rdi") 0u64, in("rsi") 0u64,
                options(nostack)); };
            crate::serial_println!("[NODE_PANEL] node started");
            self.dirty = true;
        }
        // Stop button
        if x >= pad+130 && x < pad+250 && y >= 60 && y < 92 && self.node_running {
            crate::gui::modal::confirm("Stop Node?","This will halt consensus.",&["Stop","Cancel"]);
            // Modal result checked next tick
            self.dirty = true;
        }
    }
    fn draw(&self) {
        let ww=WIN_W as usize; let wh=WIN_H as usize;
        let mut px=alloc::vec![COLOR_WINDOW_BG; ww*wh];
        let fd=font::raw_font_data();
        let _pad=14usize;
        // Header
        draw_str(&mut px,ww,fd,"IONA Node Control Panel",PAD,PAD,COLOR_ACCENT,COLOR_WINDOW_BG);
        fill_px(&mut px,ww,0,PAD+20,ww,1,COLOR_TASKBAR_BORDER);

        // Buttons
        fill_px(&mut px,ww,PAD,60,120,32,COLOR_SUCCESS);
        draw_str(&mut px,ww,fd,"Start Node",PAD+12,69,0xFFFFFF,COLOR_SUCCESS);
        fill_px(&mut px,ww,PAD+130,60,120,32,COLOR_ERROR);
        draw_str(&mut px,ww,fd,"Stop Node",PAD+142,69,0xFFFFFF,COLOR_ERROR);

        // Consensus status
        let h = {let e=crate::consensus::engine::CONSENSUS_ENGINE.lock();e.as_ref().map(|e|e.height).unwrap_or(0)};
        let status_rows: &[(&str, &str)] = &[
            ("Status","Running"),("Height",&format!("{}",h)),
            ("Round","0"),("Step","COMMIT"),
            ("Validators","3/3 online"),("Fast quorum","enabled"),
        ];
        let mut cy=110usize;
        for (k,v) in status_rows {
            draw_str(&mut px,ww,fd,k,PAD,cy,COLOR_TEXT_SECONDARY,COLOR_WINDOW_BG);
            draw_str(&mut px,ww,fd,v,PAD+140,cy,COLOR_TEXT_PRIMARY,COLOR_WINDOW_BG);
            cy+=22;
        }
        fill_px(&mut px,ww,0,cy+4,ww,1,COLOR_TASKBAR_BORDER);
        cy+=14;
        draw_str(&mut px,ww,fd,"Connected peers:",PAD,cy,COLOR_TEXT_SECONDARY,COLOR_WINDOW_BG);
        cy+=22;
        for (i,peer) in ["10.0.2.2:9000","10.0.2.3:9000","10.0.2.4:9000"].iter().enumerate() {
            fill_px(&mut px,ww,PAD,cy+4,6,6,COLOR_SUCCESS);
            draw_str(&mut px,ww,fd,peer,PAD+14,cy,COLOR_TEXT_PRIMARY,COLOR_WINDOW_BG);
            cy+=20;
        }
        wm::update_pixels(self.wid,0,0,WIN_W as u16,WIN_H as u16,&px);
    }
}

fn fill_px(px:&mut Vec<u32>,s:usize,x:usize,y:usize,w:usize,h:usize,c:u32){
    for row in y..y+h{for col in x..x+w{let i=row*s+col;if i<px.len(){px[i]=c;}}}}
fn draw_str(px:&mut Vec<u32>,s:usize,fd:&[u8],t:&str,mut x:usize,y:usize,fg:u32,bg:u32){
    for b in t.bytes(){let go=32+b as usize*16;if go+16>fd.len(){x+=8;continue;}
        for r in 0..16{let byte=fd[go+r];for c in 0..8{let sx=x+c;let sy=y+r;let i=sy*s+sx;
            if i<px.len(){px[i]=if byte&(0x80>>c)!=0{fg}else{bg};}}}x+=8;}}
fn str_to_px(px:&mut Vec<u32>,s:usize,fd:&[u8],t:&str,x:usize,y:usize,fg:u32,bg:u32){
    draw_str(px,s,fd,t,x,y,fg,bg);}

static mut NODE_PANEL: Option<NodePanelApp> = None;
pub fn launch(x:i32,y:i32){unsafe{NODE_PANEL=Some(NodePanelApp::new(x,y));}}
pub fn get_wid()->Option<u32>{unsafe{NODE_PANEL.as_ref().map(|a|a.wid)}}
pub fn tick(now:u64)->bool{unsafe{if let Some(ref mut a)=NODE_PANEL{a.tick(now)}else{false}}}
