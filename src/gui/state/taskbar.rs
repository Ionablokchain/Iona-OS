use crate::gui::icons::Icon;
pub struct TaskbarItem { pub label: alloc::string::String, pub icon: Icon, pub wid: u32 }
pub struct TaskbarState {
    pub items:   alloc::vec::Vec<TaskbarItem>,
    pub active:  Option<usize>,
    pub hovered: Option<usize>,
}
impl Default for TaskbarState { fn default() -> Self { Self { items: alloc::vec![], active: None, hovered: None } } }
