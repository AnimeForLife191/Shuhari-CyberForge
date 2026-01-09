use super::scanner::UacInfo;
use crate::common::time::get_time;

pub fn display_uac(info: UacInfo, verbose: bool) {
    println!("USER ACCOUNT CONTROL STATUS");
    println!("{}", "=".repeat(30));

    if verbose {display_scan_details();}

    display_summary(&info);

    if verbose {display_technical(&info);}

    display_assessment(&info);
    
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
    println!(" - Status: {}", if info.enabled {"Enabled"} else {"Disabled"});
    println!(" - Notification Level: {}", decode_prompt_level(info.prompt_level));
    println!();
}

fn display_technical(info: &UacInfo) {
    println!("Technical Information:");
    println!(" - EnableLUA Value: {}", info.lua_value);
    println!(" - ConsentPromptBehaviorAdmin Value: {}", info.prompt_level);
    println!(" - Registry Access: 'HKEY_LOCAL_MACHINE' with 'KEY_READ' permissions");
    println!();
}

fn display_assessment(info: &UacInfo) {
    println!("Security Assessment:");

    if info.enabled {
        println!(" - UAC is enabled (Recommended)");
    } else {
        println!(" - UAC is disabled (Not Recommended)");
    }

    if info.prompt_level == 0 {
        println!(" - Using 'Never Notify' notification level (Not Secure)");
    } else if info.prompt_level == 1 {
        println!(" - Using 'Credentials on secure desktop' notification level (Secure)");
    } else if info.prompt_level == 2 {
        println!(" - Using 'Consent on secure desktop' notification level (Secure)");
    } else if info.prompt_level == 5 {
        println!(" - Using 'Consent' notification level (Default Secure)");
    } else {
        println!(" - Unknown notification level");
    }
    println!()
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