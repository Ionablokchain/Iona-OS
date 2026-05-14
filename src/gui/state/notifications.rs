//! Notification queue — real push/dismiss/history system
use alloc::{string::String, collections::VecDeque, vec::Vec};

#[derive(Clone, Debug)]
pub enum NotifKind { Info, Success, Warning, Error }

#[derive(Clone, Debug)]
pub struct Notif {
    pub id:       u32,
    pub title:    String,
    pub body:     String,
    pub kind:     NotifKind,
    pub ts_ms:    u64,
    pub duration: u64,  // 0 = permanent
    pub read:     bool,
}

pub struct NotifState {
    pub active:     VecDeque<Notif>,
    pub history:    Vec<Notif>,
    pub panel_open: bool,
    next_id:        u32,
}
impl Default for NotifState {
    fn default() -> Self { Self { active: VecDeque::new(), history: Vec::new(), panel_open: false, next_id: 1 } }
}
impl NotifState {
    pub fn push(&mut self, title: &str, body: &str, kind: NotifKind, duration: u64) -> u32 {
        let id=self.next_id; self.next_id+=1;
        let ts=crate::arch::x86_64::timer::uptime_ms();
        let n=Notif{id,title:title.into(),body:body.into(),kind,ts_ms:ts,duration,read:false};
        self.active.push_back(n.clone()); self.history.push(n); id
    }
    pub fn dismiss(&mut self, id: u32) {
        self.active.retain(|n| n.id != id);
        if let Some(n)=self.history.iter_mut().find(|n|n.id==id){n.read=true;}
    }
    pub fn tick(&mut self) {
        let now=crate::arch::x86_64::timer::uptime_ms();
        self.active.retain(|n| n.duration==0 || now-n.ts_ms < n.duration);
    }
    pub fn unread(&self) -> u32 { self.history.iter().filter(|n|!n.read).count() as u32 }
    pub fn current(&self) -> Option<&Notif> { self.active.front() }
}
