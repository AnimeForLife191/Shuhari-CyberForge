use clap::{Parser, Subcommand};

use warden::{scan_antivirus, scan_updates, scan_firewall};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command
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
            WardenCommand::Antivirus => scan_antivirus()?,
            WardenCommand::Updates => scan_updates()?,
            WardenCommand::Firewall => scan_firewall()?
        }
    }
    Ok(())
}