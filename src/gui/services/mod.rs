//! Services — live data providers for shell state
//! Check 1: per-region dirty flags — clock tick → topbar dirty only,
//!           stats tick → right_panel dirty only, hover → sidebar dirty only.

pub mod clock;
pub mod stats;

pub fn update_state(state: &mut super::state::DesktopShellState) {
    let now = crate::arch::x86_64::timer::uptime_ms();
    if state.last_tick_ms != 0 && now - state.last_tick_ms < 1000 { return; }
    state.last_tick_ms = now;

    // Clock — only topbar dirty
    let new_time = clock::current_time_str();
    if new_time != state.topbar.time_str {
        state.topbar.time_str = new_time;
        state.regions.topbar = true;
        state.dirty = true;
    }
    let new_date = clock::current_date_str();
    if new_date != state.topbar.date_str {
        state.topbar.date_str = new_date;
        state.regions.topbar = true;
        state.dirty = true;
    }

    // Net status
    let net_ok = crate::net::is_ready();
    if net_ok != state.topbar.net_ok {
        state.topbar.net_ok = net_ok;
        state.regions.topbar = true;
        state.dirty = true;
    }

    // Stats — only right_panel dirty
    let new_cpu = stats::cpu_pct();
    let new_ram = stats::ram_pct();
    if (new_cpu as i32 - state.monitor.cpu_pct as i32).abs() > 2 ||
       (new_ram as i32 - state.monitor.ram_pct as i32).abs() > 2 {
        state.monitor.cpu_pct  = new_cpu;
        state.monitor.ram_pct  = new_ram;
        state.monitor.disk_pct = stats::disk_pct();
        state.monitor.tx_mb    = stats::tx_mb();
        state.monitor.rx_mb    = stats::rx_mb();
        state.monitor.node_h   = 2847 + now / 500;
        state.regions.right_panel = true;
        state.dirty = true;
    }

    // Media progress — only right_panel dirty
    state.media.advance(1000);
    if state.media.dirty {
        state.regions.right_panel = true;
        state.dirty = true;
        state.media.dirty = false;
    }

    // Hover animation advance (smooth sidebar icon scale)
    let speed = 0.18f32;
    for (i, anim) in state.sidebar.hover_anim.iter_mut().enumerate() {
        let target = if state.sidebar.hovered == Some(i) { 1.0f32 } else { 0.0f32 };
        *anim += (target - *anim) * speed;
        if (*anim - target).abs() > 0.02 { state.regions.sidebar = true; state.dirty = true; }
    }
    // Tick notification auto-dismiss
    state.notifications.tick();
    state.topbar.notif_count = state.notifications.unread();
    // Tasks dirty propagation
    if state.tasks.dirty {
        state.regions.tasks = true;
        state.dirty = true;
        state.tasks.dirty = false;
    }
}
