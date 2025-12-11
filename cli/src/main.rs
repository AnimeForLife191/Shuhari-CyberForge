use clap::{Parser, Subcommand};
use warden;

#[derive(Parser)]
#[command(name = "sysdefense")]
#[command(version = "0.1.0")]
#[command(about = "Community-dreiven security suite")]
struct Cli {
    #[command(subcommand)]
    command: Commands
}

#[derive(Subcommand)]
enum Commands {
    Warden
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Warden => run_warden(),
    }
}

fn run_warden() {
    println!("WARDEN - System Auditing and Educator");

    match warden::get_defender_status() {
        Ok(status) => {
            // Installation
            if status.installed {
                println!("Installed: Yes");
            } else {
                println!("Installed: No");
                println!("Windows Defender is NOT installed!\n");
                return;
            }
            // Enabled
            if status.enabled {
                println!("Enabled: Yes");
            } else {
                println!(" Enabled: No");
            }

            // Signature Version
            if let Some(version) = &status.signature_last_updated {
                println!("Signature Version: {}", version);
            } else {
                println!("Signature Version: Unknown");
            }

            // Last Signature Update
            if let Some(updated) = &status.signature_last_updated {
                println!("Last Updated: {}", updated);
            } else {
                println!("Last Updated: Unknown");
            }

            // Real-Time Protection
            if status.real_time_protection {
                println!("Real-Time Protection: Active");
            } else {
                println!("Real-Time Protection: Inactive");
            }

            // Overall Status
            println!("\n=========================================");
            if status.installed && status.enabled && status.real_time_protection {
                println!("Status: PROTECTED");
            } else {
                println!("Status: AT RISK");
            }
            println!("\n==========================================");
            
        }
        Err(e) => {
            println!("Error: {}\n", e);

            if e.to_string().contains("only available on Windows") {
                println!("This tool requires Windows. \n");
            }
        }
    }
}