//! Icon renderer — 16×16 pixel icons drawn via fb primitives
use crate::io::framebuffer as fb;
use super::ids::Icon;
use crate::gui::theme::rgb;

/// Draw a 16×16 icon at pixel position (x, y) in color `col`
pub fn draw_icon(x: usize, y: usize, icon: Icon, col: u32, bg: u32) {
    let (r, g, b) = rgb(col);
    let (br, bg_, bb) = rgb(bg);
    match icon {
        Icon::Search     => draw_search(x, y, r, g, b, br, bg_, bb),
        Icon::Terminal   => draw_terminal(x, y, r, g, b, br, bg_, bb),
        Icon::Monitor    => draw_monitor(x, y, r, g, b, br, bg_, bb),
        Icon::Folder     => draw_folder(x, y, r, g, b, br, bg_, bb),
        Icon::Settings   => draw_settings(x, y, r, g, b, br, bg_, bb),
        Icon::Bell | Icon::BellDot => draw_bell(x, y, r, g, b, br, bg_, bb),
        Icon::Calendar   => draw_calendar(x, y, r, g, b, br, bg_, bb),
        Icon::Music      => draw_music(x, y, r, g, b, br, bg_, bb),
        Icon::Play       => draw_play(x, y, r, g, b, br, bg_, bb),
        Icon::Pause      => draw_pause(x, y, r, g, b, br, bg_, bb),
        Icon::Prev       => draw_prev(x, y, r, g, b, br, bg_, bb),
        Icon::Next       => draw_next(x, y, r, g, b, br, bg_, bb),
        Icon::Node       => draw_node(x, y, r, g, b, br, bg_, bb),
        Icon::Wallet     => draw_wallet(x, y, r, g, b, br, bg_, bb),
        Icon::Files      => draw_files(x, y, r, g, b, br, bg_, bb),
        Icon::Plus       => draw_plus(x, y, r, g, b, br, bg_, bb),
        Icon::Check      => draw_check(x, y, r, g, b, br, bg_, bb),
        Icon::Close      => draw_close_icon(x, y, r, g, b, br, bg_, bb),
        Icon::Wifi       => draw_wifi(x, y, r, g, b, br, bg_, bb),
        Icon::Weather    => draw_weather(x, y, r, g, b, br, bg_, bb),
        _                => draw_dot(x, y, r, g, b),
    }
    // Notification dot for BellDot
    if icon == Icon::BellDot {
        fb::fill_rect_rounded(x+10, y, 5, 5, 0xFF, 0x47, 0x57, 3);
    }
}

fn px(x0: usize, y0: usize, cols: &[&str], r: u8, g: u8, b: u8, br: u8, bg: u8, bb: u8) {
    for (row, &line) in cols.iter().enumerate() {
        for (col, ch) in line.chars().enumerate() {
            if ch == '#' { fb::set_pixel(x0+col, y0+row, r, g, b); }
            else          { fb::set_pixel(x0+col, y0+row, br, bg, bb); }
        }
    }
}

fn draw_search(x: usize, y: usize, r: u8, g: u8, b: u8, br: u8, bg: u8, bb: u8) {
    px(x, y, &[
        "  ####  .....",
        " #    # .....",
        "#      #.....",
        "#      #.....",
        " #    # .....",
        "  ####  .....",
        ".....##......",
        "......##.....",
    ], r, g, b, br, bg, bb);
}
fn draw_terminal(x: usize, y: usize, r: u8, g: u8, b: u8, br: u8, bg: u8, bb: u8) {
    let rows = &[
        "################",
        "#..............#",
        "#.>..#.........#",
        "#....######....#",
        "#..............#",
        "#..............#",
        "################",
    ];
    for (row, &l) in rows.iter().enumerate() {
        for (col, ch) in l.chars().enumerate() {
            if ch == '#' || ch == '>' { fb::set_pixel(x+col, y+row+1, r, g, b); }
            else                      { fb::set_pixel(x+col, y+row+1, br, bg, bb); }
        }
    }
}
fn draw_monitor(x: usize, y: usize, r: u8, g: u8, b: u8, br: u8, bg: u8, bb: u8) {
    fb::draw_rect(x, y+1, 16, 11, r, g, b);
    fb::hline(x+6, y+12, 4, r, g, b);
    fb::hline(x+3, y+13, 10, r, g, b);
    fb::fill_rect_rounded(x+5, y+4, 6, 4, r, g, b, 1);
}
fn draw_folder(x: usize, y: usize, r: u8, g: u8, b: u8, br: u8, bg: u8, bb: u8) {
    fb::fill_rect(x, y+3, 16, 10, r, g, b);
    fb::fill_rect(x, y+1, 7, 3, r, g, b);
}
fn draw_settings(x: usize, y: usize, r: u8, g: u8, b: u8, br: u8, bg: u8, bb: u8) {
    fb::fill_rect_rounded(x+5, y+5, 6, 6, r, g, b, 3);
    for i in 0..4 {
        let angle = i * 4;
        fb::set_pixel(x + 8, y + angle, r, g, b);
        fb::set_pixel(x + angle, y + 8, r, g, b);
    }
}
fn draw_bell(x: usize, y: usize, r: u8, g: u8, b: u8, br: u8, bg: u8, bb: u8) {
    fb::fill_rect_rounded(x+2, y+2, 12, 9, r, g, b, 3);
    fb::fill_rect(x+5, y+11, 6, 2, r, g, b);
    fb::set_pixel(x+8, y, r, g, b);
}
fn draw_calendar(x: usize, y: usize, r: u8, g: u8, b: u8, br: u8, bg: u8, bb: u8) {
    fb::draw_rect(x+1, y+2, 14, 12, r, g, b);
    fb::hline(x+1, y+5, 14, r, g, b);
    fb::set_pixel(x+4, y+1, r, g, b); fb::set_pixel(x+4, y, r, g, b);
    fb::set_pixel(x+11, y+1, r, g, b); fb::set_pixel(x+11, y, r, g, b);
    for row in [7usize,10] { for col in [3usize,6,9,12] { fb::set_pixel(x+col,y+row,r,g,b); } }
}
fn draw_music(x: usize, y: usize, r: u8, g: u8, b: u8, br: u8, bg: u8, bb: u8) {
    fb::hline(x+3, y+3, 10, r, g, b);
    fb::hline(x+3, y+5, 10, r, g, b);
    fb::vline(x+12, y+3, 8, r, g, b);
    fb::fill_rect_rounded(x+2, y+10, 4, 3, r, g, b, 2);
    fb::fill_rect_rounded(x+10, y+10, 4, 3, r, g, b, 2);
}
fn draw_play(x: usize, y: usize, r: u8, g: u8, b: u8, br: u8, bg: u8, bb: u8) {
    for i in 0..8usize { fb::fill_rect(x+3, y+1+i, i+1, 1, r, g, b); }
    for i in (0..8usize).rev() { fb::fill_rect(x+3, y+9+i, 8-i, 1, r, g, b); }
}
fn draw_pause(x: usize, y: usize, r: u8, g: u8, b: u8, br: u8, bg: u8, bb: u8) {
    fb::fill_rect(x+3, y+2, 3, 12, r, g, b);
    fb::fill_rect(x+10, y+2, 3, 12, r, g, b);
}
fn draw_prev(x: usize, y: usize, r: u8, g: u8, b: u8, br: u8, bg: u8, bb: u8) {
    fb::fill_rect(x+2, y+2, 2, 12, r, g, b);
    for i in 0..8usize { fb::fill_rect(x+6, y+2+i, 8-i, 1, r, g, b); }
    for i in (0..8usize).rev() { fb::fill_rect(x+6, y+10+i, i+1, 1, r, g, b); }
}
fn draw_next(x: usize, y: usize, r: u8, g: u8, b: u8, br: u8, bg: u8, bb: u8) {
    fb::fill_rect(x+12, y+2, 2, 12, r, g, b);
    for i in 0..8usize { fb::fill_rect(x+2, y+2+i, i+1, 1, r, g, b); }
    for i in (0..8usize).rev() { fb::fill_rect(x+2, y+10+i, 8-i, 1, r, g, b); }
}
fn draw_node(x: usize, y: usize, r: u8, g: u8, b: u8, br: u8, bg: u8, bb: u8) {
    fb::fill_rect_rounded(x+5, y+5, 6, 6, r, g, b, 3);
    fb::fill_rect_rounded(x+1, y+1, 4, 4, r, g, b, 2);
    fb::fill_rect_rounded(x+11, y+1, 4, 4, r, g, b, 2);
    fb::fill_rect_rounded(x+6, y+11, 4, 4, r, g, b, 2);
    fb::hline(x+4, y+3, 4, r, g, b);
    fb::hline(x+9, y+3, 3, r, g, b);
    fb::vline(x+8, y+9, 3, r, g, b);
}
fn draw_wallet(x: usize, y: usize, r: u8, g: u8, b: u8, br: u8, bg: u8, bb: u8) {
    fb::draw_rect(x+1, y+3, 14, 10, r, g, b);
    fb::fill_rect(x+1, y+1, 10, 3, r, g, b);
    fb::fill_rect_rounded(x+9, y+6, 5, 4, r, g, b, 2);
    fb::set_pixel(x+11, y+8, br, bg, bb);
}
fn draw_files(x: usize, y: usize, r: u8, g: u8, b: u8, br: u8, bg: u8, bb: u8) {
    fb::fill_rect(x+1, y+3, 10, 11, r, g, b);
    fb::fill_rect(x+5, y+1, 10, 11, r, g, b);
    fb::fill_rect(x+6, y+2, 8, 9, br, bg, bb);
}
fn draw_plus(x: usize, y: usize, r: u8, g: u8, b: u8, _: u8, _: u8, _: u8) {
    fb::fill_rect(x+7, y+2, 2, 12, r, g, b);
    fb::fill_rect(x+2, y+7, 12, 2, r, g, b);
}
fn draw_check(x: usize, y: usize, r: u8, g: u8, b: u8, _: u8, _: u8, _: u8) {
    for i in 0..5usize { fb::set_pixel(x+2+i, y+8+i, r, g, b); }
    for i in 0..8usize { fb::set_pixel(x+6+i, y+12-i, r, g, b); }
}
fn draw_close_icon(x: usize, y: usize, r: u8, g: u8, b: u8, _: u8, _: u8, _: u8) {
    for i in 0..12usize { fb::set_pixel(x+2+i, y+2+i, r, g, b); fb::set_pixel(x+13-i, y+2+i, r, g, b); }
}
fn draw_wifi(x: usize, y: usize, r: u8, g: u8, b: u8, _: u8, _: u8, _: u8) {
    fb::fill_rect_rounded(x+6, y+11, 4, 4, r, g, b, 2);
    for arc in 1..4usize {
        let rx_ = x + 8 - arc*2;
        let ry_ = y + 10 - arc*2;
        let rw_ = arc*4;
        fb::hline(rx_, ry_, rw_.min(16), r, g, b);
    }
}
fn draw_weather(x: usize, y: usize, r: u8, g: u8, b: u8, _: u8, _: u8, _: u8) {
    fb::fill_rect_rounded(x+2, y+6, 12, 7, r, g, b, 4);
    fb::fill_rect_rounded(x+5, y+3, 7, 6, r, g, b, 4);
    fb::fill_rect_rounded(x+8, y+1, 5, 5, r, g, b, 3);
    fb::hline(x+7, y+13, 1, 0x88, 0xAA, 0xFF);
    fb::hline(x+10, y+13, 1, 0x88, 0xAA, 0xFF);
}
fn draw_dot(x: usize, y: usize, r: u8, g: u8, b: u8) {
    fb::fill_rect_rounded(x+5, y+5, 6, 6, r, g, b, 3);
}
