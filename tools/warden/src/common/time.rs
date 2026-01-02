use std::time::SystemTime;

/// Time catch for displays
pub fn get_time() -> (u32, u32, u32) { // Return Hours, Minutes, Seconds 
    let duration = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    let secs = duration.as_secs();
    let seconds = (secs % 60) as u32;
    let minutes = ((secs / 60) % 60) as u32;
    let hours = ((secs / 3600) % 24) as u32;

    (hours, minutes, seconds)
}