use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use colored::*;

mod banners;
mod shells;

use crate::banners::general_banners::home_banner;
use crate::shells::warden_sh::warden_shell;


fn main() {
    home_banner();

    // Readline editor for input
    let mut rl = DefaultEditor::new().expect("Failed to create readline editor");

    // Shell loop
    loop {
        // readline for home
        let readline = rl.readline("sysdefense> ");

        match readline {
            Ok(line) => {

                // Add line to history to recall it
                let _ = rl.add_history_entry(line.as_str());
                // Trims the whitespace and converts to lowercase
                let input = line.trim();

                if input.is_empty() {
                    continue;
                }

                match input.to_lowercase().as_str() {

                    // Transfers to WARDEN's shell
                    "warden" => {
                        println!("{}", "Entering WARDEN tool...".green());
                        warden_shell(&mut rl);
                    }
                    
                    // Exits the software
                    "exit" | "quit" => {
                        println!("{}", "Goodbye!".cyan());
                    }

                    // Shows commands
                    "help" => {
                        //print_main_help();
                    }

                    // Error handling for when theirs no responding command
                    _ => {
                        println!("{}", format!("Unknown tool: '{}'. Type 'help' for available tools", input).red());
                    }                    
                }
            }
            Err(ReadlineError::Interrupted) => {
                // When pressing Ctrl+C
                println!("{}", "Use 'exit' to quit".yellow());
            }
            Err(ReadlineError::Eof) => {
                // Ctrl+D
                println!("{}", "Goodbye!".cyan());
                break;
            }
            Err(err) => {
                println!("{}", format!("Error: {:?}", err).red());
                break;
            }
        }

    }
}