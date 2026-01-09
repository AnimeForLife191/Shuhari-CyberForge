mod antivirus;
mod updates;
mod firewall;
mod uac;
mod common;

pub use antivirus::{
    scanner::scan_antivirus,
    display::display_antivirus
};
pub use updates::{
    scanner::scan_updates,
    display::display_updates
};
pub use firewall::{
    scanner::scan_firewall,
    display::display_firewalls
};
pub use uac::{
    scanner::scan_uac,
    display::display_uac
};