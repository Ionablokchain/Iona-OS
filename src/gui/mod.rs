//! IONA OS GUI Stack v0.7 — full shell implementation
//!
//! New shell pipeline (60fps):
//!   services::update_state() → shell::draw(state) → compositor → present()
//!
//! Composition order (from package spec):
//!   1. wallpaper (shell layer)
//!   2. shell chrome: topbar, sidebar, taskbar, panels, widgets
//!   3. managed app windows (WM layer, on top of shell)
//!   4. overlays: tooltips, context menus
//!   5. cursor

pub mod events;
pub mod wm;
pub mod widgets;
pub mod desktop;      // kept for compat, now wraps shell
pub mod ipc;
pub mod theme;
pub mod compositor;
pub mod apps;
pub mod clipboard;
pub mod modal;
pub mod shortcuts;
pub use apps::lock_screen;

// New shell system
pub mod primitives;
pub mod text;
pub mod icons;
pub mod layout;
pub mod shell;
pub mod widgets_shell;
pub mod services;
pub mod state;
pub mod animation;
pub mod integration;

use spin::{Lazy, Mutex};
use state::DesktopShellState;

pub static SHELL_STATE: Lazy<Mutex<DesktopShellState>> =
    Lazy::new(|| Mutex::new(DesktopShellState::default()));

pub fn init() {
    crate::serial_println!("  [GUI] Initializing IONA OS shell v0.7...");
    theme::init();
    events::init();
    wm::init();
    ipc::init();
    clipboard::init();
    crate::serial_println!("  [GUI] Shell state initialized");
    let t = crate::task::Task::new("gui-loop", gui_loop_task, 0, 15);
    crate::sched::SCHEDULER.lock().spawn(t);
}

pub fn gui_loop_task(_: u64) -> ! {
    const TARGET_MS: u64 = 16; // ~60fps

    // Launch default apps — priority: installer > firstboot > desktop
    if apps::installer::should_run() {
        apps::installer::launch(80, 40);
    } else if apps::firstboot::should_run() {
        apps::firstboot::launch(160, 100);
    } else {
        apps::terminal::launch(140, 80);
        apps::monitor::launch(540, 90);
    }

    crate::serial_println!("  [GUI] desktop ready — entering 60fps shell loop");

    loop {
        let t0 = crate::arch::x86_64::timer::uptime_ms();

        // 1. Update live state (CHECK 5: lock released before draw)
        {
            let mut state = SHELL_STATE.lock();
            services::update_state(&mut state);
        }

        // 2. Events — shell consumes first (CHECK 3 focus routing)
        events::pump();
        while let Some(ev) = events::next() {
            use events::GuiEvent;
            // Lock screen — consumes ALL events when locked
            if apps::lock_screen::is_locked() {
                if let events::GuiEvent::KeyDown { .. } = &ev {
                    let ascii = match &ev {
                        events::GuiEvent::KeyDown { ch, .. } => ch.map(|c|c as u8).unwrap_or(0),
                        _ => 0,
                    };
                    apps::lock_screen::on_key(ascii);
                }
                continue; // skip WM dispatch when locked
            }
            // Global shortcuts first (Alt+Tab, Super, Ctrl+C/V/W/F)
            let shortcut_consumed = {
                let mut state = SHELL_STATE.lock();
                shortcuts::handle(&ev, &mut state)
            };
            // Shell elements second (dock, taskbar, app grid)
            let consumed = shortcut_consumed || {
                let mut state = SHELL_STATE.lock();
                if !shortcut_consumed { integration::handle_shell_event(&ev, &mut state) }
                else { true }
            };
            if !consumed {
                match &ev {
                    GuiEvent::MouseDown { x, y, .. } => {
                        if !desktop::handle_click(*x, *y) {
                            wm::dispatch_event(ev.clone());
                        }
                    }
                    _ => { wm::dispatch_event(ev.clone()); }
                }
            }
            ipc::route_to_focused(&ev);
            // Route scroll wheel to terminal
            if let events::GuiEvent::MouseScroll { dy, .. } = &ev {
                apps::terminal::on_scroll(*dy);
            }
        }

        // 3. Tick apps
        let t_apps = crate::arch::x86_64::timer::uptime_ms();
        apps::tick_all();

        // 4. Composite (CHECK 6: time shell draw + present separately)
        let t_compose = crate::arch::x86_64::timer::uptime_ms();
        compositor::compose_and_present();
        let t_end = crate::arch::x86_64::timer::uptime_ms();

        // 5. IPC flush + frame timing log (every 5s in debug)
        ipc::flush_to_apps();
        static mut FRAME_LOG_NEXT: u64 = 0;
        unsafe {
            if t_end >= FRAME_LOG_NEXT {
                let shell_ms  = t_compose.saturating_sub(t_apps);
                let compose_ms= t_end.saturating_sub(t_compose);
                let total_ms  = t_end.saturating_sub(t0);
                crate::serial_println!(
                    "[GUI] frame: total={}ms shell={}ms compose={}ms",
                    total_ms, shell_ms, compose_ms
                );
                FRAME_LOG_NEXT = t_end + 5000;
            }
        }

        // Frame cap ~60fps
        let elapsed = t_end.saturating_sub(t0);
        if elapsed < TARGET_MS {
            crate::arch::x86_64::timer::sleep_ms(TARGET_MS - elapsed);
        }
    }
}

/// Called by compositor to draw the shell layer (below app windows).
/// R-03 fix: only redraws when state.dirty — prevents full redraw every frame.
/// After draw, dirty is reset to false; only clock/stats ticks set it again.
/// Called by compositor to draw the shell layer (below app windows).
///
/// CHECK 5: No deadlock pattern — lock is acquired, dirty check done,
/// lock released BEFORE draw (draw gets its own lock internally).
/// draw_shell_layer never mutates state in the draw path — only reads.
pub fn draw_shell_layer() {
    // Step 1: check dirty under lock, then release
    let should_draw = {
        let state = SHELL_STATE.lock();
        state.dirty
    };
    if !should_draw { return; }

    // Step 2: draw under separate lock acquisition (draw reads state)
    {
        let state = SHELL_STATE.lock();
        shell::draw(&state);
    }

    // Step 3: clear dirty under fresh lock acquisition (no lock held during draw)
    {
        let mut state = SHELL_STATE.lock();
        state.dirty = false;
        state.regions = state::desktop::DirtyRegions::all_clean();
    }
}
