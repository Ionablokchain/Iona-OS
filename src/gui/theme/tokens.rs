//! Design tokens — semantic enums for theme lookups

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ColorToken {
    Glass, GlassBorder, GlassDark, GlassHover,
    AccentBlue, AccentBlueSoft, AccentGlow,
    TextPrimary, TextSecondary, TextMuted, TextAccent,
    StatusOk, StatusWarn, StatusErr,
    ShellBar, ShellBorder,
    DockBg, DockItemHover, DockItemActive,
    TaskbarItem, TaskbarItemActive, TaskbarItemHover,
    ProgressBg, ProgressFg,
}

#[derive(Clone, Copy, Debug)]
pub enum RadiusToken {
    Card,      // 16
    CardSmall, // 10
    CardXs,    // 6
    Pill,      // 999
    Dock,      // 14
    Button,    // 8
}

#[derive(Clone, Copy, Debug)]
pub enum TextToken {
    Title, Subtitle, Body, Small, Caption, Mono,
}

#[derive(Clone, Copy, Debug)]
pub enum SpacingToken {
    Xs = 4, Sm = 8, Md = 12, Lg = 16, Xl = 24, Xxl = 32,
}
