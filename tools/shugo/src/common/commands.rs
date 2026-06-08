use std::process::{Command, Output};

pub fn run_command(command: &str, args: &[&str]) -> Option<Output> {
    Command::new(command)
        .args(args)
        .output()
        .ok()
}

pub fn command_exists(command: &str, args: &[&str]) -> bool {
    run_command(command, &args).is_some()
}