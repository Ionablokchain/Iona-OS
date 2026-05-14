//! Text metrics — approximate width/height for PSF2 8×16
use crate::io::font::{FONT_WIDTH, FONT_HEIGHT};

pub fn text_width(s: &str) -> usize { s.len() * FONT_WIDTH }
pub fn text_height(_s: &str) -> usize { FONT_HEIGHT }
pub fn text_cols(s: &str) -> usize { s.len() }
pub fn truncate_to_width(s: &str, max_px: usize) -> &str {
    let max_chars = max_px / FONT_WIDTH;
    if s.len() <= max_chars { s } else { &s[..max_chars] }
}
pub fn ellipsis_to_width(s: &str, max_px: usize) -> alloc::string::String {
    let max_chars = max_px / FONT_WIDTH;
    if s.len() <= max_chars {
        s.into()
    } else if max_chars > 3 {
        let mut out: alloc::string::String = s[..max_chars-3].into();
        out.push_str("...");
        out
    } else {
        s[..max_chars.min(s.len())].into()
    }
}
