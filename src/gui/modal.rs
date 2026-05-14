//! Modal dialog system — blocking overlay for confirmations, alerts, inputs
use alloc::{string::String, vec::Vec};
use spin::{Lazy, Mutex};
use crate::io::{framebuffer as fb, font};
use crate::gui::{theme::{palette::*, rgb, spacing::*}, primitives::draw as prim, text};

pub enum ModalKind { Confirm, Alert, Input }

pub struct ModalState {
    pub visible:    bool,
    pub title:      String,
    pub message:    String,
    pub buttons:    Vec<String>,
    pub input:      String,
    pub focused:    usize,
    pub kind:       ModalKind,
    pub result:     Option<usize>,
    pub input_done: Option<String>,
    pub dirty:      bool,
}
impl Default for ModalState {
    fn default() -> Self { Self {
        visible:false, title:String::new(), message:String::new(),
        buttons:alloc::vec![], input:String::new(), focused:0,
        kind:ModalKind::Confirm, result:None, input_done:None, dirty:false,
    }}
}

static MODAL: Lazy<Mutex<ModalState>> = Lazy::new(|| Mutex::new(ModalState::default()));

pub fn confirm(title: &str, msg: &str, btns: &[&str]) {
    let mut m = MODAL.lock();
    m.visible=true; m.dirty=true; m.result=None; m.input_done=None;
    m.title=title.into(); m.message=msg.into(); m.focused=0;
    m.buttons=btns.iter().map(|&s| s.into()).collect();
    m.kind=ModalKind::Confirm;
}
pub fn alert(title: &str, msg: &str) { confirm(title, msg, &["OK"]); }
pub fn input_dialog(title: &str, placeholder: &str) {
    confirm(title, placeholder, &["OK","Anulare"]);
    MODAL.lock().kind = ModalKind::Input;
}
pub fn dismiss() { let mut m = MODAL.lock(); m.visible=false; m.dirty=true; }
pub fn is_visible() -> bool { MODAL.lock().visible }
pub fn take_result() -> Option<usize> { MODAL.lock().result.take() }
pub fn take_input()  -> Option<String> { MODAL.lock().input_done.take() }

/// Returns true = event consumed by modal
pub fn on_key(ascii: u8) -> bool {
    let mut m = MODAL.lock();
    if !m.visible { return false; }
    match ascii {
        b'\t' => { let n=m.buttons.len().max(1); m.focused=(m.focused+1)%n; m.dirty=true; }
        b'\r'|b'\n' => {
            if matches!(m.kind, ModalKind::Input) { m.input_done=Some(m.input.clone()); }
            m.result=Some(m.focused); m.visible=false; m.dirty=true;
        }
        0x1B => { m.result=Some(m.buttons.len().saturating_sub(1)); m.visible=false; m.dirty=true; }
        0x08|0x7F => { if matches!(m.kind,ModalKind::Input){m.input.pop();m.dirty=true;} }
        c if c>=0x20 => { if matches!(m.kind,ModalKind::Input)&&m.input.len()<64{m.input.push(c as char);m.dirty=true;} }
        _ => {}
    }
    true
}

pub fn on_click(px: i32, py: i32) -> bool {
    let (sw,sh) = fb::size();
    let mw=360usize; let mh=140usize;
    let mx=sw/2-mw/2; let my=sh/2-mh/2;
    let mut m = MODAL.lock();
    if !m.visible { return false; }
    let btn_y = my+mh-44; let btn_w=90usize; let btn_gap=12usize;
    let n=m.buttons.len(); let tbw=n*btn_w+n.saturating_sub(1)*btn_gap;
    let bsx=mx+mw/2-tbw/2;
    for i in 0..n {
        let bx=bsx+i*(btn_w+btn_gap);
        if px>=bx as i32&&px<(bx+btn_w) as i32&&py>=btn_y as i32&&py<(btn_y+32) as i32 {
            if matches!(m.kind,ModalKind::Input){m.input_done=Some(m.input.clone());}
            m.result=Some(i); m.visible=false; m.dirty=true; return true;
        }
    }
    true
}

pub fn draw() {
    let (sw,sh)=fb::size();
    let m=MODAL.lock();
    if !m.visible { return; }
    // Dim overlay
    for y in 0..sh { for x in 0..sw { fb::blend_pixel(x,y,0,0,0,130); } }
    let mw=360usize;
    let input_h=if matches!(m.kind,ModalKind::Input){38}else{0};
    let mh=140+input_h;
    let mx=sw/2-mw/2; let my=sh/2-mh/2;
    prim::fill_card(mx,my,mw,mh,GLASS,GLASS_BORDER,14,90);
    // Title bar
    let (tbr,tbg,tbb)=rgb(GLASS_DARK);
    fb::fill_rect(mx,my,mw,32,tbr,tbg,tbb);
    let (er,eg,eb)=rgb(GLASS_BORDER); fb::hline(mx,my+32,mw,er,eg,eb);
    text::draw_text_centered(mx,my+8,mw,font::FONT_HEIGHT+8,&m.title,TEXT_PRIMARY,GLASS_DARK);
    // Message
    text::draw_text_centered(mx,my+44,mw,font::FONT_HEIGHT+8,&m.message,TEXT_SECONDARY,GLASS);
    // Input field
    if matches!(m.kind,ModalKind::Input) {
        let iy=my+mh-82;
        prim::fill_card(mx+MD,iy,mw-MD*2,28,0x0A1520,GLASS_BORDER,6,0);
        let (disp,col)=if m.input.is_empty(){(m.message.as_str(),TEXT_MUTED)}else{(m.input.as_str(),TEXT_PRIMARY)};
        text::draw_text_clipped(mx+MD+8,iy+6,mw-MD*2-16,28,disp,col,0x0A1520);
    }
    // Buttons
    let btn_y=my+mh-44; let btn_w=90usize; let btn_gap=12usize;
    let n=m.buttons.len(); let tbw=n*btn_w+n.saturating_sub(1)*btn_gap;
    let bsx=mx+mw/2-tbw/2;
    for (i,lbl) in m.buttons.iter().enumerate() {
        let bx=bsx+i*(btn_w+btn_gap);
        let focused=i==m.focused;
        let (bg,fg)=if focused{(ACCENT,0xFFFFFFu32)}else{(GLASS_DARK,TEXT_SECONDARY)};
        prim::fill_card(bx,btn_y,btn_w,32,bg,if focused{ACCENT}else{GLASS_BORDER},8,0);
        text::draw_text_centered(bx,btn_y,btn_w,32,lbl,fg,bg);
    }
}
