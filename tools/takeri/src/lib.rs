pub mod hashing;
pub mod common;
pub mod scanner;

pub use hashing::directory::hash_directory;
pub use scanner::scanner::init_scanner;
pub use scanner::cvd::json_handler::update_if_needed;