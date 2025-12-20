pub mod antivirus;
pub mod updates;

pub use antivirus::scanner::{antivirus_check, antivirus_detailed_check};
pub use updates::windows_update_scanner::updates_check;