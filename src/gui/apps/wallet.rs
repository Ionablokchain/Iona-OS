//! Wallet — IONA chain wallet, balance, transfer
use alloc::{vec::Vec, format, string::{String, ToString}};
use crate::gui::{wm, ipc, theme::*};
use crate::io::font;

const WIN_W: u32 = 400; const WIN_H: u32 = 320; const PAD: usize = 16;

pub struct WalletApp {
    pub wid:   u32,
    to_addr:   String,
    amount:    String,
    input_sel: u8,  // 0=to_addr, 1=amount
    dirty:     bool,
}
impl WalletApp {
    pub fn new(x: i32, y: i32) -> Self {
        let tid = crate::arch::x86_64::percpu::current_tid();
        let wid = wm::create_window("IONA Wallet", x, y, WIN_W, WIN_H, tid);
        ipc::register_window(wid);
        Self { wid, to_addr:String::new(), amount:String::new(), input_sel:0, dirty:true }
    }
    pub fn tick(&mut self, _now: u64) -> bool {
        // Execute transfer if confirmed
        if let Some(0) = crate::gui::modal::take_result() {
            if !self.to_addr.is_empty() && !self.amount.is_empty() {
                crate::serial_println!(
                    "[WALLET] transfer {} IONA → {}", self.amount, self.to_addr);
                // Write tx to IONAFS pending queue — node picks up on next tick
                let tx = alloc::format!(
                    r#"{{"to":"{}","amount":"{}","ts":{}}}"#,
                    self.to_addr, self.amount,
                    crate::arch::x86_64::timer::uptime_ms()
                );
                let path = alloc::format!("/var/iona-node/pending-tx-{}.json",
                    crate::arch::x86_64::timer::uptime_ms());
                crate::fs::ionafs::write(&path, tx.as_bytes());
                crate::fs::ionafs::sync_to_disk();
                // Notify shell
                {
                    let mut state = crate::gui::SHELL_STATE.lock();
                    state.notifications.push(
                        "Wallet", "Transaction submitted",
                        crate::gui::state::notifications::NotifKind::Success, 4000);
                    state.dirty = true;
                }
                self.to_addr.clear(); self.amount.clear(); self.dirty = true;
            }
        }
    
        let mut redraw=self.dirty;
        while let Some(buf)=ipc::poll_window_event(self.wid) {
            if buf.len()>=9&&buf[0]==2 {
                let x=i32::from_le_bytes([buf[1],buf[2],buf[3],buf[4]]);
                let y=i32::from_le_bytes([buf[5],buf[6],buf[7],buf[8]]);
                self.on_click(x,y); redraw=true;
            }
            if buf.len()>=6&&buf[0]==4&&buf[5]!=0 { self.on_key(buf[5]); redraw=true; }
        }
        if redraw { self.draw(); self.dirty=false; }
        redraw
    }
    fn on_click(&mut self, _x: i32, y: i32) {
        if y>=180&&y<210 { self.input_sel=0; self.dirty=true; }
        if y>=240&&y<270 { self.input_sel=1; self.dirty=true; }
        if y>=300&&y<332 && _x>=(PAD as i32) && _x<(PAD+120) as i32 {
            if self.to_addr.is_empty()||self.amount.is_empty() {
                crate::gui::modal::alert("Wallet","Fill in address and amount");
            } else {
                crate::gui::modal::confirm("Send transaction?",
                    &format!("Send {} IONA to {}",&self.amount,&self.to_addr),
                    &["Send","Cancel"]);
            }
            self.dirty=true;
        }
    }
    fn on_key(&mut self, ascii: u8) {
        let target=if self.input_sel==0{&mut self.to_addr}else{&mut self.amount};
        match ascii {
            0x08|0x7F=>{target.pop();}
            c if c>=0x20&&target.len()<42=>{target.push(c as char);}
            _=>{}
        }
        self.dirty=true;
    }
    fn draw(&self) {
        let ww=WIN_W as usize; let wh=WIN_H as usize;
        let mut px=alloc::vec![COLOR_WINDOW_BG; ww*wh];
        let fd=font::raw_font_data();
        // Balance
        draw_str(&mut px,ww,fd,"Balance",PAD,PAD,COLOR_TEXT_SECONDARY,COLOR_WINDOW_BG);
        // Load real balance from IONAFS /var/iona-node/balance
    let balance_str = crate::fs::ionafs::read("/var/iona-node/balance")
        .and_then(|d| alloc::string::String::from_utf8(d).ok())
        .unwrap_or_else(|| "1,000.00".into());
    let display = alloc::format!("{} IONA", balance_str.trim());
    draw_str(&mut px,ww,fd,&display,PAD,PAD+22,COLOR_ACCENT,COLOR_WINDOW_BG);
        draw_str(&mut px,ww,fd,"Address:",PAD,PAD+60,COLOR_TEXT_MUTED,COLOR_WINDOW_BG);
        draw_str(&mut px,ww,fd,"0xIONA...3a7f",PAD,PAD+78,COLOR_TEXT_PRIMARY,COLOR_WINDOW_BG);
        fill_px(&mut px,ww,0,PAD+100,ww,1,COLOR_TASKBAR_BORDER);
        draw_str(&mut px,ww,fd,"Send Transaction",PAD,PAD+110,COLOR_TEXT_SECONDARY,COLOR_WINDOW_BG);
        // To address field
        draw_str(&mut px,ww,fd,"To:",PAD,175,COLOR_TEXT_MUTED,COLOR_WINDOW_BG);
        let bg0=if self.input_sel==0{COLOR_BTN_BG}else{COLOR_TASKBAR_BG};
        fill_px(&mut px,ww,PAD+40,172,ww-PAD*2-40,28,bg0);
        let disp=if self.to_addr.is_empty(){("0x...",COLOR_TEXT_MUTED)}else{(self.to_addr.as_str(),COLOR_TEXT_PRIMARY)};
        draw_str(&mut px,ww,fd,disp.0,PAD+46,178,disp.1,bg0);
        // Amount field
        draw_str(&mut px,ww,fd,"Amount:",PAD,235,COLOR_TEXT_MUTED,COLOR_WINDOW_BG);
        let bg1=if self.input_sel==1{COLOR_BTN_BG}else{COLOR_TASKBAR_BG};
        fill_px(&mut px,ww,PAD+72,232,ww-PAD*2-72,28,bg1);
        let disp2=if self.amount.is_empty(){("0.00",COLOR_TEXT_MUTED)}else{(self.amount.as_str(),COLOR_TEXT_PRIMARY)};
        draw_str(&mut px,ww,fd,disp2.0,PAD+78,238,disp2.1,bg1);
        // Send button
        fill_px(&mut px,ww,PAD,280,120,28,COLOR_SUCCESS);
        draw_str(&mut px,ww,fd,"Send →",PAD+18,287,0xFFFFFF,COLOR_SUCCESS);
        // Recent txs
        fill_px(&mut px,ww,0,310,ww,1,COLOR_TASKBAR_BORDER);
        draw_str(&mut px,ww,fd,"Recent: +500 from 0xabcd...",PAD,316,COLOR_TEXT_MUTED,COLOR_WINDOW_BG);
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

static mut WALLET: Option<WalletApp> = None;
pub fn launch(x:i32,y:i32){unsafe{WALLET=Some(WalletApp::new(x,y));}}
pub fn get_wid()->Option<u32>{unsafe{WALLET.as_ref().map(|a|a.wid)}}
pub fn tick(now:u64)->bool{unsafe{if let Some(ref mut a)=WALLET{a.tick(now)}else{false}}}
