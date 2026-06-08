#![cfg(target_os = "windows")]

use clap::Subcommand;

use shugo::windows;

#[derive(Subcommand)]
pub enum ShugoCommand {
    Antivirus,
    Updates,
    Firewall,
    Uac,
    Uas
}

pub fn handle(cmd: ShugoCommand, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        ShugoCommand::Antivirus => display_antivirus(&scan_antivirus()?, verbose),
        ShugoCommand::Updates => display_updates(scan_updates()?, verbose),
        ShugoCommand::Firewall => display_firewalls(scan_firewall()?, verbose),
        ShugoCommand::Uac => display_uac(scan_uac()?, verbose),
        ShugoCommand::Uas => display_uas(scan_uas()?, verbose),
    }
}