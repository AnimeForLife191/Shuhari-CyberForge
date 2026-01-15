use clap::{Parser, Subcommand};

use shugo::{
    scan_antivirus, 
    scan_updates, 
    scan_firewall,
    scan_uac,
    scan_uas
};
use shugo::{
    display_antivirus, 
    display_updates,
    display_firewalls,
    display_uac,
    display_uas
};

/// Shuhari-CyberForge: Experimental security tools for educational purposes
#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Gives a more detailed output
    #[arg(short, long, global = true)]
    verbose: bool
}

// This is where tools can be added to the CLI and be given subcommands
#[derive(Subcommand)]
enum Command {
    #[command(subcommand)]
    /// The Windows Security Audit and Educator
    Shugo(ShugoCommand)
}

// This is the subcommands for Shugo
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli: Cli = Cli::parse();

    match cli.command {
        Command::Shugo(wcmd) => match wcmd {
            ShugoCommand::Antivirus => display_antivirus(&scan_antivirus()?, cli.verbose),
            ShugoCommand::Updates => display_updates(scan_updates()?, cli.verbose),
            ShugoCommand::Firewall => display_firewalls(scan_firewall()?, cli.verbose),
            ShugoCommand::Uac => display_uac(scan_uac()?, cli.verbose),
            ShugoCommand::Uas => display_uas(scan_uas()?, cli.verbose),
        }
    }
    Ok(())
}