use crate::common::commands::run_command;

use super::PendingUpdate;

pub fn apt_check_updates(command: &str, args: &[&str]) -> Vec<PendingUpdate> {
    let output = match run_command(command, args) {
        Some(output) => output,
        None => {
            println!("Error: {} failed to run", command);
            return vec![];
        }
    };

    let mut updates = Vec::new();

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.starts_with("Listing") {
            continue;
        }

        let update: Vec<&str> = line.split_whitespace().collect();
        
        if update.len() < 4 {
            continue;
        }

        let mut parts = update[0].splitn(2, '/');
        let name = parts.next().unwrap_or("").to_string();
        let repo = parts.next().unwrap_or("").to_string();
        let classification = if repo.contains("security") {
            Some("Security".to_string())
        } else if repo.contains("updates") {
            Some("Regular".to_string())
        } else if repo.contains("backports") {
            Some("Backport".to_string())
        } else {
            None
        };
        let current_version = line
            .find("[upgradable from: ")
            .map(|start| {
                let rest = &line[start + "[upgradable from: ".len()..];
                rest.find(']')
                    .map(|end| rest[..end].to_string())
            })
            .flatten()
            .unwrap_or_default();
        let new_version = update[1].to_string();
        
        

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