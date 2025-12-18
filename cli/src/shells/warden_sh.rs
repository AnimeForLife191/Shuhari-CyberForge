use colored::Colorize;
use rustyline::{DefaultEditor, error::ReadlineError};

use warden::antivirus::scanner::{antivirus_check, antivirus_detailed_check};

use crate::banners::warden_banners::warden_home_banner;

pub fn warden_shell(rl: &mut DefaultEditor) {
    warden_home_banner();

    loop {
        let readline = rl.readline(&format!("[WARDEN]> "));

        match readline {
            Ok(line) => {
                let _ = rl.add_history_entry(line.as_str());
                let input = line.trim();

                if input.is_empty() {
                    continue;
                }

                let parts: Vec<&str> = input.split_whitespace().collect();
                let command = parts[0].to_lowercase();
                let args = &parts[1..];

                match command.as_str() {
                    "antivirus" => {
                        handle_antivirus_command(args);
                    }

                    _ => {
                        println!("{}", format!("Unknown command: '{}'. Type 'help' for available commands.", command).red());
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("{}", "Use 'exit' to return to main menu".yellow());
            }
            Err(ReadlineError::Eof) => {
                break;
            }
            Err(err) => {
                println!("{}", format!("Error: {:?}", err).red());
                break;
            }
        }
    }
}

fn handle_antivirus_command(args: &[&str]) {
    if args.is_empty() {
        println!("{}", "Usage: antivirus <check>".yellow());
        return;
    }

    match args[0].to_lowercase().as_str() {
        "check" => {
            println!("{}", "Running Antivirus Check".green());
            if let Err(e) = antivirus_check() {
                println!("{}", format!("Error: {}", e).red());
            }
        }

        "detail" => {
            println!("{}", "Running Detailed Antivirus Check".green());
            if let Err(e) = antivirus_detailed_check() {
                println!("{}", format!("Error: {}", e).red());
            }
        }
        _ => {
            println!("{}", format!("Unkonwn antivirus command: '{}'", args[0]).red());
        }
    }
}