use crate::common::commands::run_command;

use super::PendingUpdate;

pub fn zypper_check_updates(command: &str, args: &[&str]) -> Vec<PendingUpdate> {
    let output = match run_command(command, args) {
        Some(output) => output,
        None => {
            println!("Error: {} failed to run", command);
            return vec![];
        }
    };

    match output.status.code() {
        Some(0) => {},
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
        if line.trim().is_empty()
            || line.starts_with("Loading")
            || line.starts_with("Reading")
            || line.starts_with("S |")
            || line.starts_with("--") {
            continue;
        }

        let fields: Vec<&str> = line.split('|').collect();
        if fields.len() != 6 {
            continue;
        }

        let name = fields[2].trim().to_string();
        let current_version = fields[3].trim().to_string();
        let new_version = fields[4].trim().to_string();
        let repo = fields[1].trim();

        let classification = if repo.contains("security") {
            Some("Security".to_string())
        } else if repo.contains("update") {
            Some("Regular".to_string())
        } else if repo.contains("backport") {
            Some("Backport".to_string())
        } else {
            None
        };

        updates.push(PendingUpdate {
            name,
            current_version,
            new_version,
            classification,
            min_mb: None,
            max_mb: None,
            description: None
        });
    }
    updates
}