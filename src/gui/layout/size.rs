#[derive(Clone, Copy, Debug)]
pub struct Rect { pub x: i32, pub y: i32, pub w: i32, pub h: i32 }
impl Rect {
    pub fn new(x: i32, y: i32, w: i32, h: i32) -> Self { Self{x,y,w,h} }
    pub fn contains(&self, px: i32, py: i32) -> bool {
        px >= self.x && px < self.x+self.w && py >= self.y && py < self.y+self.h
    }
    pub fn inset(&self, n: i32) -> Self { Self{x:self.x+n,y:self.y+n,w:self.w-n*2,h:self.h-n*2} }
    pub fn ux(&self) -> usize { self.x.max(0) as usize }
    pub fn uy(&self) -> usize { self.y.max(0) as usize }
    pub fn uw(&self) -> usize { self.w.max(0) as usize }
    pub fn uh(&self) -> usize { self.h.max(0) as usize }
}
