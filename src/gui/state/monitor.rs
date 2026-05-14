pub struct MonitorState {
    pub cpu_pct:  u8,
    pub ram_pct:  u8,
    pub disk_pct: u8,
    pub tx_mb:    f32,
    pub rx_mb:    f32,
    pub node_h:   u64,
    pub peers:    u8,
}
impl Default for MonitorState {
    fn default() -> Self { Self { cpu_pct:30, ram_pct:55, disk_pct:55, tx_mb:2.4, rx_mb:1.1, node_h:2847, peers:3 } }
}
