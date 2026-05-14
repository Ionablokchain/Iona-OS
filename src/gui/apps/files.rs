//! File Manager — IONAFS navigator with open/delete/rename
use alloc::{vec::Vec, format, string::{String, ToString}};
use crate::gui::{wm, ipc, theme::*};
use crate::io::font;

const WIN_W: u32 = 520; const WIN_H: u32 = 400; const PAD: usize = 12;

pub struct FilesApp {
    pub wid:      u32,
    path:         String,
    entries:      Vec<String>,
    selected:     Option<usize>,
    scroll:       usize,
    dirty:        bool,
}
impl FilesApp {
    pub fn new(x: i32, y: i32) -> Self {
        let tid = crate::arch::x86_64::percpu::current_tid();
        let wid = wm::create_window("Files — /", x, y, WIN_W, WIN_H, tid);
        ipc::register_window(wid);
        let entries = crate::fs::ionafs::list();
        Self { wid, path:"/".into(), entries, selected:None, scroll:0, dirty:true }
    }
    pub fn tick(&mut self, _now: u64) -> bool {
        let mut redraw = self.dirty;
        while let Some(buf) = ipc::poll_window_event(self.wid) {
            if buf.len()>=9 && buf[0]==2 {
                let _x=i32::from_le_bytes([buf[1],buf[2],buf[3],buf[4]]);
                let y=i32::from_le_bytes([buf[5],buf[6],buf[7],buf[8]]);
                self.on_click(_x,y); redraw=true;
            }
            if buf.len()>=6 && buf[0]==4 { self.on_key(buf[5]); redraw=true; }
        }
        if redraw { self.draw(); self.dirty=false; }
        redraw
    }
    fn on_click(&mut self, _x: i32, y: i32) {
        let list_top = 44usize;
        let row_h = 22usize;
        if y >= list_top as i32 {
            let idx = (y as usize - list_top) / row_h + self.scroll;
            if idx < self.entries.len() {
                self.selected = Some(idx);
                self.dirty = true;
            }
        }
    }
    fn on_key(&mut self, ascii: u8) {
        match ascii {
            0x7F | 0x08 => { // Delete selected
                if let Some(idx) = self.selected {
                    if idx < self.entries.len() {
                        let path = self.entries[idx].clone();
                        crate::gui::modal::confirm(
                            "Delete file?", &path, &["Delete","Cancel"]);
                        self.dirty = true;
                    }
                }
            }
            _ => {}
        }
    }
    fn draw(&self) {
        let ww=WIN_W as usize; let wh=WIN_H as usize;
        let mut px=alloc::vec![COLOR_WINDOW_BG; ww*wh];
        let fd=font::raw_font_data();
        // Path bar
        fill_px(&mut px,ww,0,0,ww,36,COLOR_TASKBAR_BG);
        draw_str(&mut px,ww,fd,"/  (IONAFS root)",PAD,10,COLOR_TEXT_SECONDARY,COLOR_TASKBAR_BG);
        fill_px(&mut px,ww,0,36,ww,1,COLOR_TASKBAR_BORDER);
        // Column headers
        draw_str(&mut px,ww,fd,"Name",PAD,40,COLOR_TEXT_MUTED,COLOR_WINDOW_BG);
        draw_str(&mut px,ww,fd,"Size",300,40,COLOR_TEXT_MUTED,COLOR_WINDOW_BG);
        fill_px(&mut px,ww,0,56,ww,1,COLOR_TASKBAR_BORDER);
        // File list
        let row_h=22usize; let list_top=60usize;
        let visible=(wh.saturating_sub(list_top+36))/row_h;
        for i in 0..visible {
            let idx=i+self.scroll;
            if idx>=self.entries.len(){break;}
            let entry=&self.entries[idx];
            let ry=list_top+i*row_h;
            if self.selected==Some(idx) {
                fill_px(&mut px,ww,0,ry-2,ww,row_h,COLOR_BTN_BG);
            }
            // Icon — folder or file
            let is_dir=!entry.contains('.');
            fill_px(&mut px,ww,PAD,ry+3,10,12,if is_dir{COLOR_ACCENT}else{COLOR_TEXT_MUTED});
            let name=entry.rsplit('/').next().unwrap_or(entry);
            draw_str(&mut px,ww,fd,name,PAD+14,ry+3,COLOR_TEXT_PRIMARY,if self.selected==Some(idx){COLOR_BTN_BG}else{COLOR_WINDOW_BG});
            // Size
            if let Some(stat)=crate::fs::ionafs::stat(entry) {
                let size_str=format!("{} B",stat.size);
                draw_str(&mut px,ww,fd,&size_str,300,ry+3,COLOR_TEXT_MUTED,if self.selected==Some(idx){COLOR_BTN_BG}else{COLOR_WINDOW_BG});
            }
        }
        // Status bar
        let sb_y=wh-28;
        fill_px(&mut px,ww,0,sb_y,ww,28,COLOR_TASKBAR_BG);
        let count_str=format!("{} items  |  Del=delete  |  selected: {}",
            self.entries.len(), self.selected.map(|i|self.entries.get(i).map(|s|s.as_str()).unwrap_or("none")).unwrap_or("none"));
        draw_str(&mut px,ww,fd,&count_str,PAD,sb_y+7,COLOR_TEXT_MUTED,COLOR_TASKBAR_BG);
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

static mut FILES_APP: Option<FilesApp> = None;
pub fn launch(x:i32,y:i32){unsafe{FILES_APP=Some(FilesApp::new(x,y));}}
pub fn get_wid()->Option<u32>{unsafe{FILES_APP.as_ref().map(|a|a.wid)}}
pub fn tick(now:u64)->bool{unsafe{if let Some(ref mut a)=FILES_APP{a.tick(now)}else{false}}}
