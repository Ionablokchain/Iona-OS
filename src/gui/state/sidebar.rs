use crate::gui::icons::Icon;
pub struct DockItem { pub label: &'static str, pub icon: Icon }
pub struct SidebarState {
    pub items:      alloc::vec::Vec<DockItem>,
    pub active:     usize,
    pub hovered:    Option<usize>,
    pub hover_anim: [f32; 8],  // 0.0..1.0 per slot, animated toward hovered=1.0
}
impl Default for SidebarState {
    fn default() -> Self { Self {
        items: alloc::vec![
            DockItem { label: "Term",     icon: Icon::Terminal },
            DockItem { label: "Files",    icon: Icon::Files    },
            DockItem { label: "Monitor",  icon: Icon::Monitor  },
            DockItem { label: "Node",     icon: Icon::Node     },
            DockItem { label: "Wallet",   icon: Icon::Wallet   },
            DockItem { label: "Settings", icon: Icon::Settings },
        ],
        active: 0, hovered: None, hover_anim: [0.0; 8],
    }}
}
