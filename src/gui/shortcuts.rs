//! Keyboard shortcut system — Alt+Tab, Super, Ctrl+C/V/W/Z, etc.
use crate::gui::events::{GuiEvent, Key, Mods};
use crate::gui::state::desktop::DesktopShellState;

/// Process a KeyDown event for global shortcuts.
/// Returns true if consumed — caller must not forward to focused app.
pub fn handle(ev: &GuiEvent, state: &mut DesktopShellState) -> bool {
    let (key, mods) = match ev {
        GuiEvent::KeyDown { key, mods, .. } => (key, mods),
        _ => return false,
    };

    // ── Super+L — lock screen ────────────────
    if mods.ctrl && mods.alt && matches!(key, Key::Char('l')|Key::Char('L')) {
        crate::gui::apps::lock_screen::lock(); state.dirty=true; return true;
    }
    // ── Super / Win key ────────────────────────────────────
    if matches!(key, Key::Super) {
        state.topbar.search_focused = !state.topbar.search_focused;
        if state.topbar.search_focused { state.topbar.search_text.clear(); }
        state.regions.topbar = true;
        state.dirty = true;
        return true;
    }

    // ── Alt+Tab — cycle window focus ──────────────────────────────────────
    if mods.alt && matches!(key, Key::Tab) {
        let mut wm = crate::gui::wm::WM.lock();
        let windows: alloc::vec::Vec<u32> = wm.z_order.clone();
        if windows.len() < 2 { return true; }
        let current = wm.focused;
        let next = match current {
            Some(wid) => {
                let pos = windows.iter().position(|&w| w == wid).unwrap_or(0);
                windows[(pos + 1) % windows.len()]
            }
            None => windows[0],
        };
        wm.set_focus(Some(next));
        wm.bring_to_front(next);
        state.regions.taskbar = true;
        state.dirty = true;
        return true;
    }

    // ── Ctrl shortcuts ────────────────────────────────────────────────────
    if mods.ctrl {
        match key {
            // Ctrl+C — copy selected text from focused app
            Key::Char('c') | Key::Char('C') => {
                // Signal focused app to copy — app reads its own selection
                // For terminal: copy last output line
                if let Some(text) = crate::gui::apps::terminal::get_selected_text() {
                    crate::gui::clipboard::set_text(&text);
                    crate::serial_println!("[SHORTCUT] Ctrl+C: copied {} chars", text.len());
                }
                return true;
            }
            // Ctrl+V — paste from clipboard into focused app
            Key::Char('v') | Key::Char('V') => {
                if let Some(text) = crate::gui::clipboard::get_text() {
                    // Inject paste as individual KeyDown events
                    for ch in text.chars().take(256) {
                        let paste_ev = GuiEvent::KeyDown {
                            key: Key::Char(ch), mods: Mods::default(), ch: Some(ch),
                        };
                        crate::gui::ipc::route_to_focused(&paste_ev);
                    }
                    crate::serial_println!("[SHORTCUT] Ctrl+V: pasted {} chars", text.len());
                }
                return true;
            }
            // Ctrl+W — close focused window
            Key::Char('w') | Key::Char('W') => {
                let focused = crate::gui::wm::WM.lock().focused;
                if let Some(wid) = focused {
                    crate::gui::wm::close_window(wid);
                    state.regions.taskbar = true;
                    state.dirty = true;
                }
                return true;
            }
            // Ctrl+Z — undo (forwarded to focused app via IPC)
            Key::Char('z') | Key::Char('Z') => { return false; } // let app handle
            // Ctrl+F — focus search bar
            Key::Char('f') | Key::Char('F') => {
                state.topbar.search_focused = true;
                state.topbar.search_text.clear();
                state.regions.topbar = true;
                state.dirty = true;
                return true;
            }
            _ => {}
        }
    }

    // ── Escape — dismiss overlays ─────────────────────────────────────────
    if matches!(key, Key::Escape) {
        if crate::gui::modal::is_visible() {
            crate::gui::modal::on_key(0x1B);
            state.dirty = true;
            return true;
        }
        if state.show_context_menu {
            state.show_context_menu = false;
            state.regions.overlay = true;
            state.dirty = true;
            return true;
        }
        if state.topbar.search_focused {
            state.topbar.search_focused = false;
            state.topbar.search_text.clear();
            state.regions.topbar = true;
            state.dirty = true;
            return true;
        }
    }

    // ── Search bar typing ─────────────────────────────────────────────────
    if state.topbar.search_focused {
        match key {
            Key::Backspace => {
                state.topbar.search_text.pop();
                state.regions.topbar = true;
                state.dirty = true;
                return true;
            }
            Key::Enter => {
                // Launch first search result
                let results = crate::gui::integration::search::query(&state.topbar.search_text);
                if let Some(r) = results.first() {
                    crate::serial_println!("[SEARCH] launch: {}", r.label);
                }
                state.topbar.search_focused = false;
                state.topbar.search_text.clear();
                state.regions.topbar = true;
                state.dirty = true;
                return true;
            }
            Key::Char(c) => {
                if state.topbar.search_text.len() < 48 {
                    state.topbar.search_text.push(*c);
                    state.regions.topbar = true;
                    state.dirty = true;
                }
                return true;
            }
            _ => {}
        }
    }

    false
}
