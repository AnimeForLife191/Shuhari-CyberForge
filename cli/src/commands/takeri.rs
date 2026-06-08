use clap::Subcommand;
use std::path::PathBuf;
use takeri::scanner::display_malware_scan;

use takeri::hash::{
    hash_files,
    display::show
};

#[derive(Subcommand)]
pub enum TakeriCommand {
    /// Scans files and directories for signature malware
    Scan {
        path: PathBuf,
        #[arg(short, long)]
        recursive: bool
    },
    /// Calculates MD5 and SHA256 hashes for one or more files
    Hash {
        paths: Vec<PathBuf>
    }
}

pub fn handle(cmd: TakeriCommand, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        TakeriCommand::Scan { path, recursive } => display_malware_scan(&path, recursive)?,
        TakeriCommand::Hash { paths } => {
            let hashes = hash_files(paths)?;
            show(hashes)?;
        }
    }
    Ok(())
}