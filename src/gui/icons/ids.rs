//! Icon ID enum — every icon used in the shell
//!
//! ME-04: Icon MUST remain Copy — all variants must be unit variants (no fields).
//! Adding a variant with a String or Vec will break Copy and cause compile errors
//! in APPS slice and anywhere Icon is stored by value.
//! If you need a labeled icon, add a separate IconLabel struct.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Icon {
    Search = 0, Wifi, Signal, Bell, BellDot,
    Folder, Browser, Mail, Settings,
    Calendar, Weather, Monitor, Music,
    Play, Pause, Prev, Next, Heart,
    Terminal, Node, Wallet, Files,
    Dot, Check, Close, Minimize, Maximize,
    Up, Down, Left, Right,
    Plus, Minus,
}
