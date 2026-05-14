use super::size::Rect;
pub fn layout_column(bounds: Rect, gap: i32, n: usize) -> alloc::vec::Vec<Rect> {
    if n == 0 { return alloc::vec![]; }
    let total_gap = gap * (n as i32 - 1);
    let child_h = (bounds.h - total_gap) / n as i32;
    (0..n).map(|i| Rect::new(bounds.x, bounds.y + i as i32*(child_h+gap), bounds.w, child_h)).collect()
}
