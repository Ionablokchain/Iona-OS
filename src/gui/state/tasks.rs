//! TasksState — standalone task list owned by shell widget
//!
//! S-02 design decision:
//!   TasksState este izolat în SHELL_STATE — nu e sincronizat cu alte app-uri.
//!   Aceasta e intenționat: tasks widget e o agendă a shell-ului, nu un task
//!   manager de sistem. App-urile nu pot citi/scrie tasks din kernel.
//!
//!   Dacă în viitor vrei sync cu o app externă:
//!   → Adaugă syscall 500: task_add/toggle/remove
//!   → Shell cere update via IPC la fiecare tick

use alloc::string::String;

#[derive(Clone)]
pub struct Task {
    pub label: String,
    pub done:  bool,
    pub color: u32,
}

pub struct TasksState {
    pub items:   alloc::vec::Vec<Task>,
    pub dirty:   bool,  // mark true when tasks change — triggers widget redraw
}

impl Default for TasksState {
    fn default() -> Self {
        Self {
            dirty: true,
            items: alloc::vec![
                Task { label: "Deploy validator v2".into(),    done: false, color: 0x3D8EF0 },
                Task { label: "Review consensus PR".into(),    done: true,  color: 0x2ED573 },
                Task { label: "Update TLS certs".into(),       done: false, color: 0xFFA502 },
                Task { label: "Write integration tests".into(),done: false, color: 0x3D8EF0 },
            ],
        }
    }
}

impl TasksState {
    pub fn toggle(&mut self, index: usize) {
        if let Some(t) = self.items.get_mut(index) {
            t.done = !t.done;
            self.dirty = true;
        }
    }

    pub fn add(&mut self, label: &str, color: u32) {
        self.items.push(Task { label: label.into(), done: false, color });
        self.dirty = true;
    }

    pub fn remove(&mut self, index: usize) {
        if index < self.items.len() {
            self.items.remove(index);
            self.dirty = true;
        }
    }
}
