use alloc::string::String;
pub struct CalEvent { pub time: String, pub label: String, pub color: u32 }
pub struct CalendarState {
    pub month_label: String,
    pub day:         u8,
    pub events:      alloc::vec::Vec<CalEvent>,
}
impl Default for CalendarState {
    fn default() -> Self { Self {
        month_label: "March 2026".into(), day: 31,
        events: alloc::vec![
            CalEvent { time: "09:00".into(), label: "Validator meeting".into(), color: 0x3D8EF0 },
            CalEvent { time: "14:00".into(), label: "Chain audit".into(),       color: 0x2ED573 },
            CalEvent { time: "17:30".into(), label: "Code review".into(),       color: 0xFFA502 },
        ],
    }}
}
