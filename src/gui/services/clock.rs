use alloc::{format, string::String};
pub fn current_time_str() -> String {
    let ms = crate::arch::x86_64::timer::uptime_ms();
    let s  = ms / 1000;
    let h  = s / 3600 % 24;
    let m  = s / 60 % 60;
    let sec= s % 60;
    format!("{:02}:{:02}:{:02}", h, m, sec)
}
pub fn current_date_str() -> String {
    let ms = crate::arch::x86_64::timer::uptime_ms();
    let days = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"];
    let months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
    let day_idx = (ms / 86_400_000) as usize % 7;
    let month_idx = (ms / 2_592_000_000) as usize % 12;
    let day_num = 1 + (ms / 86_400_000) as u8 % 30;
    format!("{} {:02} {}", days[day_idx], day_num, months[month_idx])
}
