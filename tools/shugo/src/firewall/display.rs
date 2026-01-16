use super::scanner::{WindowsFirewallProfile, FirewallProfileDetails, FirewallProductInfo, ModuleInfo};
use crate::common::time::get_time;

pub fn display_firewalls(firewall: (WindowsFirewallProfile, Vec<FirewallProductInfo>, ModuleInfo), verbose: bool) {
    let (profile, products, module) = (firewall.0, firewall.1, firewall.2);

    println!();
    println!("FIREWALL PROTECTION AUDIT");
    println!("{}", "=".repeat(30));

    if verbose {display_scan_details(module);}

    display_summary(&profile, &products, verbose);

    display_products(&products, verbose);

    display_assessment(&profile, &products);

    if verbose {display_technical();}
}

fn display_scan_details(module: ModuleInfo) {
    println!("Scan Details:"); 
    let (h, m, s) = get_time();
    println!(" - Scan Started: {:02}:{:02}:{:02} UTC", h, m, s);
    println!(" - WMI Namespace: {}", module.namespace);
    println!(" - COM Context: CLSCTX_INPROC_SERVER");
    println!(" - Query: {}", module.query);
    println!();
}

fn display_summary(profile: &WindowsFirewallProfile, products: &Vec<FirewallProductInfo> ,verbose: bool) {
    println!("Summary:");
    println!(" - Windows Firewall Status:");
    if verbose {println!("   (Blocked = secure, default, Allowed = permissive)");}
    println!("   - Public Profile: {}", firewall_enabled(&profile.public));
    if verbose {
        println!("     - Inbound Traffic: {}", firewall_inbound(&profile.public));
        println!("     - Outbound Traffic: {}", firewall_outbound(&profile.public));
        println!("     - Notifications: {}", firewall_notifications(&profile.public));
    }
    println!("   - Private Profile: {}", firewall_enabled(&profile.private));
    if verbose {
        println!("     - Inbound Traffic: {}", firewall_inbound(&profile.private));
        println!("     - Outbound Traffic: {}", firewall_outbound(&profile.private));
        println!("     - Notifications: {}", firewall_notifications(&profile.private));
    }
    println!("   - Domain Profile: {}", firewall_enabled(&profile.domain));
    if verbose {
        println!("     - Inbound Traffic: {}", firewall_inbound(&profile.domain));
        println!("     - Outbound Traffic: {}", firewall_outbound(&profile.domain));
        println!("     - Notifications: {}", firewall_notifications(&profile.domain));
    }
    println!();
    println!(" - Third-Party Firewalls: {}", products.len());
    println!();
}

fn display_products(products: &Vec<FirewallProductInfo>, verbose: bool) {
    println!("Third-Party Firewalls:");
    if products.is_empty() {
        println!(" - No Third-Party Firewalls Detected");
        println!();
        return;
    }
    for (i, prod) in products.iter().enumerate() {
        println!("{}. {}", i + 1, prod.name);
        println!("   - Status: {}", third_party_state(prod.state));
        if verbose {
            println!("   - Product State: {}", prod.state);
            println!("   - Hexadecimal State: 0x{:X}", prod.state);
        }
        println!();
    }
}

fn display_assessment(profile: &WindowsFirewallProfile, products: &Vec<FirewallProductInfo>) {
    println!("Security Assessment:");
    println!(" - Windows Defender Firewall:");
    let all_disabled: bool = {
        !profile.public.profile_enabled &&
        !profile.private.profile_enabled &&
        !profile.domain.profile_enabled
    };

    if all_disabled {
        println!("   - All profiles are DISABLED - Critical security risk!");
    } else if !profile.public.profile_enabled {
        println!("   - Public profile is DISABLED - Risk on untrusted networks!");
    } else {
        println!("   - At least one profile is Enabled");
    }

    if profile.public.profile_enabled && !profile.public.inbound_blocked {
        println!("   - Public profile allows inbound traffic - Risky!");
    }

    println!();
    println!(" - Third-Party Firewalls:");
    let active_third_party = products
        .iter()
        .filter(
            |p| {
                let fw_active: bool = ((p.state >> 12) & 0xF) != 0;
                fw_active
            }
        )
        .count();
    
    if active_third_party == 0 && all_disabled {
        println!("   - No active firewall protection detected!");
    } else if active_third_party > 0 {
        println!("   - {} active third-party firewall(s)", active_third_party);
        for prod in products {
            if ((prod.state >> 12) & 0xF) != 0 {
                println!("     - {}", prod.name);
            }
        }
    } else if active_third_party == 0 && !all_disabled {
        println!("   - Windows Defender is the active firewall");
    }
    println!();

}

fn display_technical() {
    println!("Technical Information:");
    println!(" - COM Apartment: MTA (Multi-threaded)");
    println!(" - API: INetFwPolicy2");
    println!(" - COM Context: CLSCTX_ALL");
    println!();
}

fn firewall_enabled(info: &FirewallProfileDetails) -> String {
    if info.profile_enabled {
        "Enabled".to_string()
    } else {
        "Disabled".to_string()
    }
}

fn firewall_inbound(info: &FirewallProfileDetails) -> String {
    if info.inbound_blocked {
        "Blocked".to_string()
    } else {
        "Allowed".to_string()
    }
}

fn firewall_outbound(info: &FirewallProfileDetails) -> String {
    if info.outbound_blocked {
        "Blocked".to_string()
    } else {
        "Allowed".to_string()
    }
}

fn firewall_notifications(info: &FirewallProfileDetails) -> String {
    if info.notifications_disabled {
        "Off".to_string()
    } else {
        "On".to_string()
    }
}

fn third_party_state(state: i32) -> String {
    // Extract bits 12-15 to check if firewall is active
    let fw_active: bool = ((state >> 12) & 0xF) != 0;

    if fw_active {
        "Active".to_string()
    } else {
        "Inactive".to_string()
    }
}