pub mod draw;
pub use draw::*;

/// Helpers matching palette rgb
#[inline]
pub fn rgb3(c: u32) -> (u8,u8,u8) {
    (((c>>16)&0xFF) as u8, ((c>>8)&0xFF) as u8, (c&0xFF) as u8)
}
