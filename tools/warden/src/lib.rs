pub mod antivirus;
pub mod updates;

pub use antivirus::scanner::antivirus_wmi_api;
pub use updates::scanner::update_com_api;