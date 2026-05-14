//! Text Editor — simple IONAFS file editor
use alloc::{vec::Vec, format, string::{String, ToString}};
use crate::gui::{wm, ipc, theme::*};
use crate::io::font;

const WIN_W: u32 = 560; const WIN_H: u32 = 420;

pub struct EditorApp {
    pub wid:   u32,
    path:      String,
    lines:     Vec<String>,
    cursor_row:usize, cursor_col:usize,
    scroll:    usize,
    dirty:     bool, modified: bool,
}
impl EditorApp {
    pub fn new(x: i32, y: i32) -> Self {
        let tid = crate::arch::x86_64::percpu::current_tid();
        let wid = wm::create_window("Editor — untitled", x, y, WIN_W, WIN_H, tid);
        ipc::register_window(wid);
        Self { wid, path:String::new(), lines:alloc::vec![String::new()],
               cursor_row:0, cursor_col:0, scroll:0, dirty:true, modified:false }
    }
    pub fn open(&mut self, path: &str) {
        self.path=path.into();
        if let Some(data)=crate::fs::ionafs::read(path) {
            let text=alloc::string::String::from_utf8_lossy(&data).into_owned();
            self.lines=text.split('\n').map(|l|l.into()).collect();
            if self.lines.is_empty(){self.lines.push(String::new());}
        }
        self.modified=false; self.dirty=true;
    }
    pub fn tick(&mut self, _now: u64) -> bool {
        let mut redraw=self.dirty;
        while let Some(buf)=ipc::poll_window_event(self.wid) {
            if buf.len()>=6&&buf[0]==4&&buf[5]!=0 { self.on_key(buf[5]); redraw=true; }
        }
        if redraw { self.draw(); self.dirty=false; }
        redraw
    }
    fn on_key(&mut self, ascii: u8) {
        match ascii {
            b'\r'|b'\n' => {
                let rest=self.lines[self.cursor_row].split_off(self.cursor_col);
                self.cursor_row+=1;
                self.lines.insert(self.cursor_row,rest);
                self.cursor_col=0; self.modified=true;
            }
            0x08|0x7F => {
                if self.cursor_col>0 {
                    self.lines[self.cursor_row].remove(self.cursor_col-1);
                    self.cursor_col-=1;
                } else if self.cursor_row>0 {
                    let line=self.lines.remove(self.cursor_row);
                    self.cursor_row-=1;
                    self.cursor_col=self.lines[self.cursor_row].len();
                    self.lines[self.cursor_row].push_str(&line);
                }
                self.modified=true;
            }
            c if c>=0x20 => {
                self.lines[self.cursor_row].insert(self.cursor_col,c as char);
                self.cursor_col+=1; self.modified=true;
            }
            _ => {}
        }
        self.dirty=true;
    }
    fn draw(&self) {
        let ww=WIN_W as usize; let wh=WIN_H as usize;
        let mut px=alloc::vec![COLOR_WINDOW_BG; ww*wh];
        let fd=font::raw_font_data();
        let header=if self.modified{format!("Editor — {}*",&self.path)}else{format!("Editor — {}",&self.path)};
        fill_px(&mut px,ww,0,0,ww,28,COLOR_TASKBAR_BG);
        draw_str(&mut px,ww,fd,&header,12,6,COLOR_TEXT_PRIMARY,COLOR_TASKBAR_BG);
        // Line numbers + content
        let line_h=18usize; let content_top=32usize; let line_num_w=36usize;
        let visible=(wh-content_top-20)/line_h;
        fill_px(&mut px,ww,0,content_top,line_num_w,wh-content_top,COLOR_TASKBAR_BG);
        for i in 0..visible {
            let row=i+self.scroll;
            if row>=self.lines.len(){break;}
            let ry=content_top+i*line_h;
            let num_str=format!("{:3}",row+1);
            draw_str(&mut px,ww,fd,&num_str,4,ry+1,COLOR_TEXT_MUTED,COLOR_TASKBAR_BG);
            draw_str(&mut px,ww,fd,&self.lines[row],line_num_w+6,ry+1,COLOR_TEXT_PRIMARY,COLOR_WINDOW_BG);
            // Cursor
            if row==self.cursor_row {
                let cx=line_num_w+6+self.cursor_col*8;
                fill_px(&mut px,ww,cx,ry,2,line_h,COLOR_ACCENT);
            }
        }
        // Status bar
        fill_px(&mut px,ww,0,wh-20,ww,20,COLOR_TASKBAR_BG);
        let st=format!("Ln {}  Col {}  {}",self.cursor_row+1,self.cursor_col+1,if self.modified{"modified"}else{"saved"});
        draw_str(&mut px,ww,fd,&st,8,wh-14,COLOR_TEXT_MUTED,COLOR_TASKBAR_BG);
        wm::update_pixels(self.wid,0,0,WIN_W as u16,WIN_H as u16,&px);
    }
}
fn fill_px(px:&mut Vec<u32>,s:usize,x:usize,y:usize,w:usize,h:usize,c:u32){
    for row in y..y+h{for col in x..x+w{let i=row*s+col;if i<px.len(){px[i]=c;}}}}
fn draw_str(px:&mut Vec<u32>,s:usize,fd:&[u8],t:&str,mut x:usize,y:usize,fg:u32,bg:u32){
    for b in t.bytes(){let go=32+b as usize*16;if go+16>fd.len(){x+=8;continue;}
        for r in 0..16{let byte=fd[go+r];for c in 0..8{let sx=x+c;let sy=y+r;let i=sy*s+sx;
            if i<px.len(){px[i]=if byte&(0x80>>c)!=0{fg}else{bg};}}}x+=8;}}
static mut EDITOR: Option<EditorApp> = None;
pub fn launch(x:i32,y:i32){unsafe{EDITOR=Some(EditorApp::new(x,y));}}
pub fn launch_file(x:i32,y:i32,path:&str){unsafe{EDITOR=Some(EditorApp::new(x,y));if let Some(ref mut e)=EDITOR{e.open(path);}}}
pub fn get_wid()->Option<u32>{unsafe{EDITOR.as_ref().map(|a|a.wid)}}
pub fn tick(now:u64)->bool{unsafe{if let Some(ref mut a)=EDITOR{a.tick(now)}else{false}}}
