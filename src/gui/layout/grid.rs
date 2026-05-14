use super::size::Rect;
/// Fixed-column grid
pub fn layout_grid(bounds: Rect, cols: usize, gap: i32, n: usize) -> alloc::vec::Vec<Rect> {
    if cols == 0 { return alloc::vec![]; }
    let total_hgap = gap * (cols as i32 - 1);
    let cell_w = (bounds.w - total_hgap) / cols as i32;
    let rows = (n + cols - 1) / cols;
    let total_vgap = gap * (rows as i32 - 1);
    let cell_h = if rows > 0 { (bounds.h - total_vgap) / rows as i32 } else { 0 };
    (0..n).map(|i| {
        let col = i % cols;
        let row = i / cols;
        Rect::new(
            bounds.x + col as i32 * (cell_w + gap),
            bounds.y + row as i32 * (cell_h + gap),
            cell_w, cell_h,
        )
    }).collect()
}
