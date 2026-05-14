use super::size::Rect;
pub fn center_in(container: Rect, w: i32, h: i32) -> Rect {
    Rect::new(container.x+(container.w-w)/2, container.y+(container.h-h)/2, w, h)
}
pub fn align_right(container: Rect, w: i32, h: i32) -> Rect {
    Rect::new(container.x+container.w-w, container.y+(container.h-h)/2, w, h)
}
pub fn align_bottom(container: Rect, w: i32, h: i32) -> Rect {
    Rect::new(container.x+(container.w-w)/2, container.y+container.h-h, w, h)
}
