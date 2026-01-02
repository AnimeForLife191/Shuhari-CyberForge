mod antivirus;
mod updates;
mod firewall;

mod common;

pub use antivirus::scanner::scan_antivirus;
pub use updates::scanner::scan_updates;
pub use firewall::scanner::scan_firewall;