use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[cfg(target_os = "windows")]
use shugo::{
    scan_antivirus, 
    scan_updates, 
    scan_firewall,
    scan_uac,
    scan_uas,
    display_antivirus, 
    display_updates,
    display_firewalls,
    display_uac,
    display_uas
};

use takeri::{
    scanner::display_malware_scan
};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Gives a more detailed output
    #[arg(short, long, global = true)]
    verbose: bool
}

#[derive(Subcommand)]
enum Command {
    #[cfg(target_os = "windows")]
    #[command(subcommand)]
    /// The Windows Security Audit and Educator
    Shugo(ShugoCommand),

    #[command(subcommand)]
    Takeri(TakeriCommand)
}

#[cfg(target_os = "windows")]
#[derive(Subcommand)]
enum ShugoCommand {
    /// Shows current and third-party antivirus's and their states
    Antivirus,
    /// Shows pending updates, sizes, product, classification, and description
    Updates,
    /// Shows Windows Defender profiles, third-party firewalls, and their states
    Firewall,
    /// Shows UAC (User Access Control) settings
    Uac,
    /// Shows UAS (User Access Security) settings
    Uas
}


#[derive(Subcommand)]
enum TakeriCommand {
    Scan {
        path: PathBuf,

        #[arg(short, long)]
        recursive: bool
    },
}


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli: Cli = Cli::parse();

    match cli.command {
        #[cfg(target_os = "windows")]
        Command::Shugo(scmd) => match scmd {
            ShugoCommand::Antivirus => display_antivirus(&scan_antivirus()?, cli.verbose),
            ShugoCommand::Updates => display_updates(scan_updates()?, cli.verbose),
            ShugoCommand::Firewall => display_firewalls(scan_firewall()?, cli.verbose),
            ShugoCommand::Uac => display_uac(scan_uac()?, cli.verbose),
            ShugoCommand::Uas => display_uas(scan_uas()?, cli.verbose),
        }
        Command::Takeri(tcmd) => match tcmd {
            TakeriCommand::Scan { path, recursive } => display_malware_scan(&path, recursive)?,
        }
    }
    Ok(())
}