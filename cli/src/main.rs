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

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    #[arg(short, long, global = true)]
    verbose: bool
}

// This is where tools can be added to the CLI and be given subcommands
#[derive(Subcommand)]
enum Command {
    #[command(subcommand)]
    Shugo(ShugoCommand) // Shugo tool
}

// This is the subcommands for Shugo
#[derive(Subcommand)]
enum ShugoCommand {
    Antivirus, // Shugo antivirus subcommand
    Updates, // Shugo updates subcommand
    Firewall, // Shugo firewall subcommand
    Uac, // Shugo uac (User Account Control) subcommand
    Uas // Shugo uas (User Account Security) subcommand
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

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