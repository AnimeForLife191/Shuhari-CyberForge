mod commands;
use clap::{Parser, Subcommand};
use commands::{ShugoCommand, TakeriCommand};

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
    #[command(subcommand)]
    /// Security Audit and Educator
    Shugo(ShugoCommand),
    #[command(subcommand)]
    /// Malware Scanner
    Takeri(TakeriCommand)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Shugo(scmd) => commands::handle_shugo(scmd, cli.verbose)?,
        Command::Takeri(tcmd) => commands::handle_takeri(tcmd, cli.verbose)?
    }
    Ok(())
}