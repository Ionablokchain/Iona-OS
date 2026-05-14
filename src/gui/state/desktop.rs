use super::{topbar::TopbarState, sidebar::SidebarState, taskbar::TaskbarState,
            calendar::CalendarState, weather::WeatherState, tasks::TasksState,
            media::MediaState, monitor::MonitorState,
            notifications::{NotifState, NotifKind}};
use alloc::string::String;

pub struct TooltipState { pub x: usize, pub y: usize, pub text: String }

/// Per-region dirty flags — only repaint what changed
pub struct DirtyRegions {
    pub wallpaper:  bool,  // full repaint (boot or resolution change)
    pub topbar:     bool,  // clock tick, net status
    pub sidebar:    bool,  // hover/active change
    pub taskbar:    bool,  // app open/close/focus
    pub app_grid:   bool,  // hover change
    pub right_panel:bool,  // stats tick
    pub weather:    bool,  // weather update
    pub tasks:      bool,  // task toggle/add/remove
    pub overlay:    bool,  // tooltip / context menu
}

impl DirtyRegions {
    pub fn all_clean() -> Self {
        Self { wallpaper:false, topbar:false, sidebar:false, taskbar:false,
               app_grid:false, right_panel:false, weather:false,
               tasks:false, overlay:false }
    }
    pub fn all_dirty() -> Self {
        Self { wallpaper:true, topbar:true, sidebar:true, taskbar:true,
               app_grid:true, right_panel:true, weather:true,
               tasks:true, overlay:true }
    }
    pub fn any(&self) -> bool {
        self.wallpaper || self.topbar || self.sidebar || self.taskbar ||
        self.app_grid  || self.right_panel || self.weather ||
        self.tasks     || self.overlay
    }
}

pub struct DesktopShellState {
    pub topbar:       TopbarState,
    pub sidebar:      SidebarState,
    pub taskbar:      TaskbarState,
    pub calendar:     CalendarState,
    pub weather:      WeatherState,
    pub tasks:        TasksState,
    pub media:        MediaState,
    pub monitor:      MonitorState,
    pub notifications: NotifState,
    pub search_results: alloc::vec::Vec<alloc::string::String>,
    pub hovered_app:  Option<usize>,
    pub tooltip:      Option<TooltipState>,
    pub show_context_menu: bool,
    pub context_x:    usize,
    pub context_y:    usize,
    pub dirty:        bool,           // full shell redraw needed
    pub regions:      DirtyRegions,   // per-region flags
    pub last_tick_ms: u64,
}

impl Default for DesktopShellState {
    fn default() -> Self { Self {
        topbar: TopbarState::default(), sidebar: SidebarState::default(),
        taskbar: TaskbarState::default(), calendar: CalendarState::default(),
        weather: WeatherState::default(), tasks: TasksState::default(),
        media: MediaState::default(), monitor: MonitorState::default(),
        hovered_app: None, tooltip: None,
        show_context_menu: false, context_x: 0, context_y: 0,
        notifications: NotifState::default(),
        search_results: alloc::vec![],
        dirty: true,
        regions: DirtyRegions::all_dirty(),
        last_tick_ms: 0,
    }}
}
