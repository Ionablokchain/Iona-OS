use alloc::string::String;
pub struct ForecastDay { pub label: String, pub temp: i8, pub icon_label: String }
pub struct WeatherState {
    pub city:        String,
    pub temp:        i8,
    pub description: String,
    pub forecast:    alloc::vec::Vec<ForecastDay>,
}
impl Default for WeatherState {
    fn default() -> Self { Self {
        city: "Nurnberg".into(), temp: 14, description: "Partly cloudy".into(),
        forecast: alloc::vec![
            ForecastDay { label: "Tue".into(), temp: 14, icon_label: "~".into() },
            ForecastDay { label: "Wed".into(), temp: 11, icon_label: "~".into() },
            ForecastDay { label: "Thu".into(), temp: 16, icon_label: "+".into() },
            ForecastDay { label: "Fri".into(), temp: 18, icon_label: "+".into() },
        ],
    }}
}
