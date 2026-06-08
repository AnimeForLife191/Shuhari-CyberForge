use clap::Subcommand;
use std::path::PathBuf;
use takeri::scanner::display_malware_scan;

#[derive(Subcommand)]
pub enum TakeriCommand {
    /// Scans files and directories for signature malware
    Scan {
        path: PathBuf,
        #[arg(short, long)]
        recursive: bool
    },
}

pub fn handle(cmd: TakeriCommand, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        TakeriCommand::Scan { path, recursive } => display_malware_scan(&path, recursive)?
    }
    Ok(())
}