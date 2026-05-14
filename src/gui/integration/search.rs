//! Search — filtrează apps, IONAFS files, comenzi
use alloc::{vec::Vec, string::String};

pub struct SearchResult {
    pub label: String,
    pub kind:  SearchKind,
    pub data:  String,
}
pub enum SearchKind { App, File, Command }

pub fn query(text: &str) -> Vec<SearchResult> {
    if text.is_empty() { return alloc::vec![]; }
    let q = text.to_lowercase();
    let mut res: Vec<SearchResult> = Vec::new();
    // Apps
    for app in crate::gui::shell::app_grid::APPS {
        if app.label.to_lowercase().contains(&q) {
            res.push(SearchResult{label:app.label.into(),kind:SearchKind::App,data:app.label.into()});
        }
    }
    // IONAFS files
    for path in crate::fs::ionafs::list() {
        let name = path.rsplit('/').next().unwrap_or(&path);
        if name.to_lowercase().contains(&q) {
            res.push(SearchResult{label:name.into(),kind:SearchKind::File,data:path.clone()});
            if res.len()>=6 { break; }
        }
    }
    // Commands
    for (cmd, lbl) in &[("shutdown","Shutdown"),("reboot","Reboot"),
                         ("terminal","Terminal"),("settings","Settings"),
                         ("node","IONA Node"),("lock","Lock screen")] {
        if cmd.contains(&q.as_str()) || lbl.to_lowercase().contains(&q) {
            res.push(SearchResult{label:(*lbl).into(),kind:SearchKind::Command,data:(*cmd).into()});
        }
    }
    res.truncate(8); res
}
