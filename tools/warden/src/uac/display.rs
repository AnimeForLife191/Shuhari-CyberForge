use super::scanner::UacInfo;
use crate::common::time::get_time;

pub fn display_uac(info: UacInfo, verbose: bool) {
    println!("USER ACCOUNT CONTROL STATUS");
    println!("{}", "=".repeat(30));

    if verbose {display_scan_details();}

    display_summary(&info);
    
}

fn display_scan_details() {
    println!("Scan Details:"); 
    let (h, m, s) = get_time();
    println!(" - Scan Started: {:02}:{:02}:{:02} UTC", h, m, s);
    println!(" - Registry Key Path: SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
    println!(" - Query: EnableLUA & ConsentPromptBehaviorAdmin");
    println!();
}

fn display_summary(info: &UacInfo) {
    println!("Summary:");
    println!("Status: {}", if info.enabled {"Enabled"} else {"Disabled"});
    println!("Notification Level: {}", decode_prompt_level(info.prompt_level));
}

fn decode_prompt_level(level: u32) -> &'static str {
    match level {
        0 => "Never notify (Least Secure)",
        1 => "Prompt for credentials on secure desktop",
        2 => "Prompt for consent on secure desktop",
        5 => "Prompt for consent (Default)",
        _ => "Unknown configuration"
    }
}