//! Map dock/taskbar/app-grid clicks to app launches
//!
//! I-03 fix: wid-ul real este capturat de la wm::create_window() sau
//! din apps::terminal/monitor prin wid() accessor — nu mai e hardcodat 1/2.

use crate::gui::shell::app_grid::APPS;
use crate::gui::state::taskbar::{TaskbarItem, TaskbarState};
use crate::gui::icons::Icon;

/// Launch app by index in APPS list, add to taskbar with real wid
pub fn launch_app(index: usize, taskbar: &mut TaskbarState) {
    if index >= APPS.len() { return; }
    let app = &APPS[index];
    let tid = crate::arch::x86_64::percpu::current_tid();

    // I-03 fix: capture real wid from each launch path
    let wid: u32 = match app.label {
        "Terminal" => {
            crate::gui::apps::terminal::launch(120, 80);
            // Get the actual wid that terminal stored
            crate::gui::apps::terminal::get_wid().unwrap_or(0)
        }
        "Monitor" => {
            crate::gui::apps::monitor::launch(400, 80);
            crate::gui::apps::monitor::get_wid().unwrap_or(0)
        }
        _ => {
            // Generic window — wm::create_window returns the real wid
            crate::gui::wm::create_window(app.label, 200, 120, 480, 360, tid)
        }
    };

    if wid == 0 {
        crate::serial_println!("[LAUNCHER] warning: wid=0 for '{}'", app.label);
    }

    // Add to taskbar only if not already present (match by label)
    if !taskbar.items.iter().any(|i| i.label == app.label) {
        taskbar.items.push(TaskbarItem {
            label: app.label.into(),
            icon:  app.icon,
            wid,
        });
    } else {
        // Update wid if window was re-launched
        if let Some(item) = taskbar.items.iter_mut().find(|i| i.label == app.label) {
            item.wid = wid;
        }
    }

    taskbar.active = taskbar.items.iter().position(|i| i.label == app.label);
    crate::serial_println!("[LAUNCHER] launched: {} wid={}", app.label, wid);
}

pub fn focus_taskbar_item(index: usize, taskbar: &TaskbarState) {
    if let Some(item) = taskbar.items.get(index) {
        if item.wid > 0 {
            let mut wm = crate::gui::wm::WM.lock();
            wm.bring_to_front(item.wid);
            wm.set_focus(Some(item.wid));
        }
    }
}
