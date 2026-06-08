#![cfg(target_os = "linux")]

use clap::Subcommand;

use shugo::linux;

#[derive(Subcommand)]
pub enum ShugoCommand {
    Updates,
}

pub fn handle(cmd: ShugoCommand, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        ShugoCommand::Updates => {linux::updates::check_updates()}
    }
}