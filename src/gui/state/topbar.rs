use alloc::string::String;
pub struct TopbarState {
    pub time_str:    String,
    pub date_str:    String,
    pub weather_str: String,
    pub net_ok:      bool,
    pub notif_count: u32,
    pub search_text: String,
    pub search_focused: bool,
}
impl Default for TopbarState {
    fn default() -> Self { Self {
        time_str: "00:00:00".into(), date_str: "Mon 01 Jan".into(),
        weather_str: "18°C".into(), net_ok: true,
        notif_count: 0, search_text: String::new(), search_focused: false,
    }}
}
