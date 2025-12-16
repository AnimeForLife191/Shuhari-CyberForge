pub mod old_defender;
pub mod updates;



pub use old_defender::{
    DefenderError,
    DefenderStatus,
    is_defender_installed,
    get_defender_status,
    is_defender_enabled,
    get_signature_version,
    get_signature_last_update,
    is_real_time_protection_enabled
};