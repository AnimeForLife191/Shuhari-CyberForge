use crate::common::commands::run_command;

use super::PendingUpdate;

pub fn dnf_check_updates(command: &str, args: &[&str]) -> Vec<PendingUpdate> {
    let output = match run_command(command, args) {
        Some(output) => {
            output
        },
        None => {
            println!("Error: {} failed to run", command);
            return vec![];
        }
    };

    match output.status.code() {
        Some(0) => {
            println!("Up to Date");
            return vec![]
        },
        Some(100) => {},
        Some(1) => {
            println!("Error encountered: {}", String::from_utf8_lossy(&output.stderr));
            return vec![];
        }
        Some(_) => {
            println!("Unknown Error encountered");
        },
        None => {}
    }

    let mut updates = Vec::new();

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.trim().is_empty() {
            continue;
        }
        
        let update: Vec<&str> = line.split_whitespace().collect();
        
        if update.len() != 3 {
            continue;
        }

        let mut parts = update[0].splitn(2, '.');
        let name = parts.next().unwrap_or("").to_string();
    
        let classification = if update[2].contains("security") {
            Some("Security".to_string())
        } else if update[2].contains("updates") {
            Some("Regular".to_string())
        } else if update[2].contains("testing") {
            Some("Testing".to_string())
        } else {
            None
        };
        let new_version = update[1].to_string();

        updates.push(PendingUpdate {
            name,
            current_version: String::new(),
            new_version,
            classification,
            min_mb: None,
            max_mb: None,
            description: None
        });
    }

    updates
}