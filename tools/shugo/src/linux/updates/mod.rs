mod package_managers;

use crate::common::commands::run_command;

use super::updates::package_managers::{PackageManager, Pacman, Apt, Dnf, Zypper};

fn detect_package_managers() -> Vec<Box<dyn PackageManager>> {
    let mut managers: Vec<Box<dyn PackageManager>> = Vec::new();

    if run_command("checkupdates", &[]).is_some() {
        managers.push(Box::new(Pacman));
    }
    if run_command("apt", &["--version"]).is_some() {
        managers.push(Box::new(Apt));
    }
    if run_command("dnf", &["--version"]).is_some() {
        managers.push(Box::new(Dnf));
    }
    if run_command("zypper", &["--version"]).is_some() {
        managers.push(Box::new(Zypper));
    }

    managers
}

fn run_update_audit(manager: &dyn PackageManager) {
    let updates = manager.pending_updates();

    println!("Package Manager: {}", manager.name());
    println!("Pending Updates: {}", updates.len());

    for update in updates {
        println!(" - {}", update.name);
    }
}

pub fn check_updates() -> Result<(), Box<dyn std::error::Error>> {
    let managers = detect_package_managers();

    if managers.is_empty() {
        println!("No supported package manager found");
        return Ok(());
    }

    for manager in &managers {
        run_update_audit(manager.as_ref());
    }

    Ok(())
}