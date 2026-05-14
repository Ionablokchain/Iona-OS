//! IONA OS Built-in GUI Applications
pub mod terminal;
pub mod monitor;
pub mod firstboot;
pub mod settings;
pub mod node_panel;
pub mod files;
pub mod wallet;
pub mod editor;
pub mod lock_screen;
pub mod tx_log;
pub mod validator;
pub mod installer;

use crate::arch::x86_64::timer;

/// Tick all running apps — returns number of apps that redrawn
pub fn tick_all() -> usize {
    // Return early if locked — lock screen handles all input
    if lock_screen::is_locked() {
        lock_screen::draw();
        return 1;
    }
    let now = timer::uptime_ms();
    let mut drawn = 0usize;
    if terminal::tick()         { drawn += 1; }
    if monitor::tick(now)       { drawn += 1; }
    if firstboot::tick()        { drawn += 1; }
    if installer::tick()        { drawn += 1; }
    if settings::tick(now)      { drawn += 1; }
    if node_panel::tick(now)    { drawn += 1; }
    if files::tick(now)         { drawn += 1; }
    if wallet::tick(now)        { drawn += 1; }
    if editor::tick(now)        { drawn += 1; }
    if tx_log::tick(now)        { drawn += 1; }
    if validator::tick(now)     { drawn += 1; }
    // Modal overlay (drawn on top of everything)
    if crate::gui::modal::is_visible() {
        crate::gui::modal::draw();
        drawn += 1;
    }
    drawn
}
