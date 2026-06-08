use super::scanner::UacInfo;
use crate::common::time::get_time;

pub fn display_uac(info: UacInfo, verbose: bool) {
    println!();
    println!("USER ACCOUNT CONTROL STATUS");
    println!("{}", "=".repeat(30));

    if verbose {display_scan_details(&info);}

    display_summary(&info, verbose);
    
    display_settings(&info, verbose);

    display_assessment(&info);

    if verbose {display_technical();}
    
}

fn display_scan_details(info: &UacInfo) {
    println!("Scan Details:");
    let (h, m, s) = get_time();
    println!(" - Scan Started: {:02}:{:02}:{:02} UTC", h, m, s);
    println!(" - Registry Key: {}", info.module_info.registry_key);
    println!(" - Query:");
    for query in info.module_info.queries.iter() {
        println!("   - {}", query);
    }

    println!();
}

fn display_summary(info: &UacInfo, verbose: bool) {
    println!("Summary:");
    println!(" - UAC Status: {}", uac_decode(info.lua_value));
    if verbose {println!("   - Value: {}", info.lua_value);}
    println!(" - Prompt Level: {}", decode_prompt_level(info.prompt_level_value));
    if verbose {println!("   - Value: {}", info.prompt_level_value);}
    println!();
}

fn display_settings(info: &UacInfo, verbose: bool) {
    println!("UAC Settings:");
    println!(" - Secure Desktop: {}", uac_decode(info.prompt_on_secure_desktop_value));
    if verbose {println!("   - Value: {}", info.prompt_on_secure_desktop_value);}
    println!(" - Installer Detection: {}", uac_decode(info.installer_detection_value));
    if verbose {println!("   - Value: {}", info.installer_detection_value);}
    println!(" - Code Signature Validation: {}", uac_decode(info.validate_admin_code_signatures_value));
    if verbose {println!("   - Value: {}", info.validate_admin_code_signatures_value);}
    println!(" - Virtualization: {}", uac_decode(info.enable_virtualization_value));
    if verbose {println!("   - Value: {}", info.enable_virtualization_value);}
    println!(" - Administrator Token: {}", uac_decode(info.filter_admin_token_value));
    if verbose {println!("   - Value: {}", info.filter_admin_token_value);}
    println!();
}

fn display_assessment(info: &UacInfo) {
    println!("Security Assessment:");
    println!(" - UAC Protection:");

    if info.lua_value == 0 {
        println!("   - UAC is DISABLED - Critical security risk!");
        println!("   - All programs run with full administrator privileges");
    } else if info.prompt_level_value == 0 {
        println!("   - UAC is enabled but set to 'Never notify' - Ineffective!");
    } else {
        println!("   - UAC is enabled");
    }
    println!();

    println!("- Security Weaknesses:");
    let mut weakness = Vec::new();

    if info.prompt_on_secure_desktop_value == 0 {
        weakness.push("Secure Desktop is disabled - UAC prompts vulnerable to malware");
    } if info.installer_detection_value == 0 {
        weakness.push("Installer Detection is disabled - Silent installations possible");
    } if info.validate_admin_code_signatures_value == 0 {
        weakness.push("Code Signature Validation is disabled - Unsigned apps can elevate");
    } if info.enable_virtualization_value == 0 {
        weakness.push("Virtualization is disabled - Legacy app compatibility may suffer");
    }

    if weakness.is_empty() {
        println!("   - No significant weaknesses detected");
    } else {
        for (i, weakness) in weakness.iter().enumerate() {
            println!("   {}. {}", i + 1, weakness);
            println!();
        }
    }
}

fn display_technical() {
    println!("Technical Information:");
    println!(" - Access Rights: KEY_READ");
    println!(" - Registry Hive: HKEY_LOCAL_MACHINE");
    println!();
}

fn uac_decode(state: u32) -> String {
    match state {
        0 => "Disabled".to_string(),
        1 => "Enabled".to_string(),
        _ => "Unknown".to_string()
    }
}

fn decode_prompt_level(level: u32) -> &'static str {
    match level {
        0 => "Never notify (Least Secure)",
        1 => "Prompt for credentials on secure desktop",
        2 => "Prompt for consent on secure desktop",
        3 => "Prompt for credentials",
        4 => "Prompt for consent",
        5 => "Prompt for consent for non-Windows binaries (Most Secure, Default)",
        _ => "Unknown configuration"
    }
}