//! Shadow parameters for draw::soft_shadow
// Shadow = draw X layers of blended dark at offsets

pub const SHADOW_CARD_DX: usize = 4;
pub const SHADOW_CARD_DY: usize = 6;
pub const SHADOW_CARD_SPREAD: usize = 4;
pub const SHADOW_CARD_ALPHA_START: u8 = 90;

pub const SHADOW_SM_DX: usize = 2;
pub const SHADOW_SM_DY: usize = 3;
pub const SHADOW_SM_SPREAD: usize = 2;
pub const SHADOW_SM_ALPHA_START: u8 = 60;
