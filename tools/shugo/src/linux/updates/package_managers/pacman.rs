use crate::common::commands::run_command;

use super::PendingUpdate;

pub fn pacman_check_updates(command: &str, args: &[&str]) -> Vec<PendingUpdate> {
    let output = match run_command(command, &[]) {
        Some(output) => output,
        None => {
            println!("Error: {} failed to run", command);
            return vec![];
        }
    };

    match output.status.code() {
        Some(0) => {},
        Some(2) => {
            println!("Up to Date");
            return vec![];
        },
        Some(1) => {
            println!("Error encountered: {}", String::from_utf8_lossy(&output.stderr));
            return vec![];
        },
        Some(_) => {
            println!("Unknown error encountered");
            return vec![];
        },
        None => {
            println!("Process terminated by signal");
            return vec![];
        }
    }

    let mut updates = Vec::new();

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let update: Vec<&str> = line.split_whitespace().collect();
        
        if update.len() < 4 {
            continue;
        }
        let name = update[0];
        let current_version = update[1];
        let new_version = update[3];

        updates.push(PendingUpdate {
            name: name.to_string(),
            current_version: current_version.to_string(),
            new_version: new_version.to_string(),
            classification: None,
            min_mb: None,
            max_mb: None,
            description: None
        });
    }

    updates
}