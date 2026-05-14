use super::size::Rect;
pub fn layout_row(bounds: Rect, gap: i32, n: usize) -> alloc::vec::Vec<Rect> {
    if n == 0 { return alloc::vec![]; }
    let total_gap = gap * (n as i32 - 1);
    let child_w = (bounds.w - total_gap) / n as i32;
    (0..n).map(|i| Rect::new(bounds.x + i as i32*(child_w+gap), bounds.y, child_w, bounds.h)).collect()
}
pub fn layout_row_weights(bounds: Rect, gap: i32, weights: &[i32]) -> alloc::vec::Vec<Rect> {
    let total_w: i32 = weights.iter().sum();
    let total_gap = gap * (weights.len() as i32 - 1);
    let avail = bounds.w - total_gap;
    let mut x = bounds.x;
    weights.iter().map(|&w| {
        let cw = avail * w / total_w.max(1);
        let r = Rect::new(x, bounds.y, cw, bounds.h);
        x += cw + gap; r
    }).collect()
}
