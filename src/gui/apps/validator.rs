//! Validator Dashboard — uptime, missed blocks, rewards
use alloc::{vec::Vec, format, string::{String, ToString}};
use crate::gui::{wm, ipc, theme::*};
use crate::io::font;

const WIN_W: u32 = 520; const WIN_H: u32 = 380;

pub struct ValidatorApp { pub wid: u32, dirty: bool }
impl ValidatorApp {
    pub fn new(x: i32, y: i32) -> Self {
        let tid = crate::arch::x86_64::percpu::current_tid();
        let wid = wm::create_window("Validator Dashboard", x, y, WIN_W, WIN_H, tid);
        ipc::register_window(wid);
        Self { wid, dirty: true }
    }
    pub fn tick(&mut self, _now: u64) -> bool {
        while let Some(_)=ipc::poll_window_event(self.wid) {}
        if self.dirty { self.draw(); self.dirty=false; true } else { false }
    }
    fn draw(&self) {
        let ww=WIN_W as usize; let wh=WIN_H as usize;
        let mut px=alloc::vec![COLOR_WINDOW_BG; ww*wh];
        let fd=font::raw_font_data();
        let h={let e=crate::consensus::engine::CONSENSUS_ENGINE.lock();e.as_ref().map(|e|e.height).unwrap_or(0)};
        let up_s=crate::arch::x86_64::timer::uptime_ms()/1000;
        draw_str(&mut px,ww,fd,"Validator Dashboard",14,14,COLOR_ACCENT,COLOR_WINDOW_BG);
        fill_px(&mut px,ww,0,34,ww,1,COLOR_TASKBAR_BORDER);
        let rows: &[(&str, String)] = &[
            ("Validator ID", "0".into()),
            ("Status",       "Active".into()),
            ("Height",       format!("{}", h)),
            ("Uptime",       format!("{}h {}m", up_s/3600, (up_s%3600)/60)),
            ("Missed blocks","0".into()),
            ("Total votes",  format!("{}", h*3)),
            ("Block reward", format!("{:.2} IONA/block", 1.25)),
            ("Pending reward",format!("{:.2} IONA", h as f32 * 1.25)),
        ];
        let mut cy = 48usize;
        for (k, v) in rows {
            draw_str(&mut px,ww,fd,k, 14, cy, COLOR_TEXT_SECONDARY, COLOR_WINDOW_BG);
            let col = if v=="Active"||v=="0" { COLOR_SUCCESS } else { COLOR_TEXT_PRIMARY };
            draw_str(&mut px,ww,fd,v,200, cy, col, COLOR_WINDOW_BG);
            cy+=26;
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
static mut VALIDATOR: Option<ValidatorApp> = None;
pub fn launch(x:i32,y:i32){unsafe{VALIDATOR=Some(ValidatorApp::new(x,y));}}
pub fn get_wid()->Option<u32>{unsafe{VALIDATOR.as_ref().map(|a|a.wid)}}
pub fn tick(now:u64)->bool{unsafe{if let Some(ref mut a)=VALIDATOR{a.tick(now)}else{false}}}
