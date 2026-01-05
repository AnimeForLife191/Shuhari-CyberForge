use clap::{Parser, Subcommand};

use warden::{
    scan_antivirus, 
    scan_updates, 
    scan_firewall
};
use warden::{
    display_antivirus, 
    display_updates,
    display_firewalls
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
    Warden(WardenCommand) // WARDEN tool
}

// This is the subcommands for WARDEN
#[derive(Subcommand)]
enum WardenCommand {
    Antivirus, // WARDEN antivirus subcommand
    Updates, // WARDEN updates subcommand
    Firewall // WARDEN firewall subcommand
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Warden(wcmd) => match wcmd {
            WardenCommand::Antivirus => display_antivirus(&scan_antivirus()?, cli.verbose),
            WardenCommand::Updates => display_updates(scan_updates()?, cli.verbose),
            WardenCommand::Firewall => display_firewalls(scan_firewall()?, cli.verbose),
        }
    }
    Ok(())
}