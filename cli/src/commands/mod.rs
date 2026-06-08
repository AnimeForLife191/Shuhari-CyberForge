#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::ShugoCommand;
#[cfg(target_os = "windows")]
pub fn handle_shugo(cmd: ShugoCommand, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {

}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::ShugoCommand;
#[cfg(target_os = "linux")]
pub fn handle_shugo(cmd: ShugoCommand, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    linux::handle(cmd, verbose)
}

mod takeri;
pub use takeri::TakeriCommand;
pub fn handle_takeri(cmd: TakeriCommand, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    takeri::handle(cmd, verbose)
}