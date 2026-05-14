//! Typography — text size/weight constants for PSF2 8×16 font

use crate::io::font::{FONT_WIDTH, FONT_HEIGHT};

// In pixel units (font is 8×16 fixed)
pub const SIZE_TITLE:    usize = 16; // 1× scale
pub const SIZE_SUBTITLE: usize = 16;
pub const SIZE_BODY:     usize = 16;
pub const SIZE_SMALL:    usize = 16; // PSF2 has no scaling, all same
pub const SIZE_CAPTION:  usize = 16;
pub const SIZE_MONO:     usize = 16;

pub const CHAR_W: usize = FONT_WIDTH;   // 8
pub const CHAR_H: usize = FONT_HEIGHT;  // 16
pub const LINE_H: usize = 20;           // 16px glyph + 4px gap
