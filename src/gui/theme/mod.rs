//! IONA OS GUI Theme — tokens, palette, typography, spacing

pub mod tokens;
pub mod palette;
pub mod typography;
pub mod spacing;
pub mod shadows;

pub use tokens::*;
pub use palette::*;
pub use typography::*;
pub use spacing::*;
pub use shadows::*;

/// Resolve a ColorToken to a packed 0xRRGGBB value
pub fn color(tok: ColorToken) -> u32 {
    match tok {
        ColorToken::Glass            => GLASS,
        ColorToken::GlassBorder      => GLASS_BORDER,
        ColorToken::GlassDark        => GLASS_DARK,
        ColorToken::GlassHover       => GLASS_HOVER,
        ColorToken::AccentBlue       => ACCENT,
        ColorToken::AccentBlueSoft   => ACCENT_SOFT,
        ColorToken::AccentGlow       => ACCENT_GLOW,
        ColorToken::TextPrimary      => TEXT_PRIMARY,
        ColorToken::TextSecondary    => TEXT_SECONDARY,
        ColorToken::TextMuted        => TEXT_MUTED,
        ColorToken::TextAccent       => TEXT_ACCENT,
        ColorToken::StatusOk         => STATUS_OK,
        ColorToken::StatusWarn       => STATUS_WARN,
        ColorToken::StatusErr        => STATUS_ERR,
        ColorToken::ShellBar         => SHELL_BAR,
        ColorToken::ShellBorder      => SHELL_BORDER,
        ColorToken::DockBg           => DOCK_BG,
        ColorToken::DockItemHover    => DOCK_ITEM_HOVER,
        ColorToken::DockItemActive   => DOCK_ITEM_ACTIVE,
        ColorToken::TaskbarItem      => TASKBAR_ITEM,
        ColorToken::TaskbarItemActive=> TASKBAR_ITEM_ACTIVE,
        ColorToken::TaskbarItemHover => TASKBAR_ITEM_HOVER,
        ColorToken::ProgressBg       => PROGRESS_BG,
        ColorToken::ProgressFg       => PROGRESS_FG,
    }
}

pub fn radius(tok: RadiusToken) -> usize {
    match tok {
        RadiusToken::Card      => 16,
        RadiusToken::CardSmall => 10,
        RadiusToken::CardXs    => 6,
        RadiusToken::Pill      => 999,
        RadiusToken::Dock      => 14,
        RadiusToken::Button    => 8,
    }
}

/// Decompose packed color to (r,g,b)
#[inline] pub fn rgb(c: u32) -> (u8,u8,u8) {
    (((c>>16)&0xFF) as u8, ((c>>8)&0xFF) as u8, (c&0xFF) as u8)
}


pub fn init() { crate::serial_println!("  [GUI/THEME] IONA theme loaded"); }


// Legacy aliases kept for older GUI/WM code paths
pub const COLOR_DESKTOP_BG:         u32 = BG_SKY_BOT;
pub const COLOR_TASKBAR_BG:         u32 = SHELL_BAR;
pub const COLOR_TASKBAR_BORDER:     u32 = SHELL_BORDER;
pub const COLOR_TITLEBAR_FOCUSED:   u32 = GLASS;
pub const COLOR_TITLEBAR_UNFOCUSED: u32 = GLASS_DARK;
pub const COLOR_BORDER_FOCUSED:     u32 = ACCENT;
pub const COLOR_BORDER_UNFOCUSED:   u32 = GLASS_BORDER;
pub const COLOR_TITLE_FOCUSED:      u32 = TEXT_PRIMARY;
pub const COLOR_TITLE_UNFOCUSED:    u32 = TEXT_SECONDARY;
pub const COLOR_WINDOW_BG:          u32 = GLASS_DARK;
pub const COLOR_SHADOW:             u32 = 0x020408;
pub const COLOR_RESIZE_HANDLE:      u32 = GLASS_BORDER;
pub const COLOR_BTN_BG:             u32 = GLASS;
pub const COLOR_BTN_BG_HOVER:       u32 = GLASS_HOVER;
pub const COLOR_BTN_BG_PRESS:       u32 = ACCENT;
pub const COLOR_BTN_BORDER:         u32 = GLASS_BORDER;
pub const COLOR_BTN_TEXT:           u32 = TEXT_PRIMARY;
pub const COLOR_BTN_TEXT_PRESS:     u32 = 0xFFFFFF;
pub const COLOR_INPUT_BG:           u32 = GLASS_DARK;
pub const COLOR_INPUT_BORDER:       u32 = GLASS_BORDER;
pub const COLOR_INPUT_BORDER_FOCUS: u32 = ACCENT;
pub const COLOR_INPUT_TEXT:         u32 = TEXT_PRIMARY;
pub const COLOR_INPUT_CURSOR:       u32 = ACCENT;
pub const COLOR_INPUT_SELECT:       u32 = ACCENT_SOFT;
pub const COLOR_SCROLLBAR_BG:       u32 = GLASS_DARK;
pub const COLOR_SCROLLBAR_THUMB:    u32 = GLASS_BORDER;
pub const COLOR_SCROLLBAR_HOVER:    u32 = GLASS_HOVER;
pub const COLOR_TEXT_PRIMARY:       u32 = TEXT_PRIMARY;
pub const COLOR_TEXT_SECONDARY:     u32 = TEXT_SECONDARY;
pub const COLOR_TEXT_MUTED:         u32 = TEXT_MUTED;
pub const COLOR_ACCENT:             u32 = ACCENT;
pub const COLOR_SUCCESS:            u32 = STATUS_OK;
pub const COLOR_WARNING:            u32 = STATUS_WARN;
pub const COLOR_ERROR:              u32 = STATUS_ERR;
pub const COLOR_DOCK_BG:            u32 = DOCK_BG;
pub const COLOR_DOCK_ITEM_HOVER:    u32 = DOCK_ITEM_HOVER;
pub const COLOR_DOCK_ITEM_ACTIVE:   u32 = DOCK_ITEM_ACTIVE;
