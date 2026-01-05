use super::scanner::{WindowsFirewallProfile, FirewallProductInfo};
use crate::common::time::get_time;

pub fn display_firewalls(firewall: (WindowsFirewallProfile, Vec<FirewallProductInfo>), verbose: bool) {

    let profile = firewall.0;
    let product = firewall.1;

    println!("FIREWALL PROTECTION AUDIT");
    println!("{}", "=".repeat(30));

    if verbose {display_scan_details();}
    
    display_summary(&profile, &product, verbose);

    if verbose {display_technical();}

}

fn display_scan_details() {
    println!("Scan Details:"); 
    let (h, m, s) = get_time();
    println!(" - Scan Started: {:02}:{:02}:{:02} UTC", h, m, s);
    println!(" - WMI Namespace: ROOT\\SecurityCenter2");
    println!(" - Query: Select displayName, productState FROM FirewallProduct");
    println!();
}

fn display_summary(profiles: &WindowsFirewallProfile, products: &Vec<FirewallProductInfo>, verbose: bool) {

    let windows_active = profiles.public || profiles.private || profiles.domain;
    // let windows_fully_active = profiles.public && profiles.private && profiles.domain;
    let active_products = products.iter().filter(|prod| prod.is_active).count();
    let total_active = if windows_active {1} else {0} + active_products;

    println!("Summary:");
    println!(" - Windows Firewall Status:");
    println!("   - Public: {}", if profiles.public {"Enabled"} else {"Disabled"});
    if !profiles.public {println!("     - Public Networks UNPROTECTED");}
    println!("   - Private: {}", if profiles.private {"Enabled"} else {"Disabled"});
    if !profiles.private {println!("     - Private Networks UNPROTECTED");}
    println!("   - Domain: {}", if profiles.domain {"Enabled"} else {"Disabled"});
    if !profiles.domain {println!("     - Domain Networks UNPROTECTED")}
    println!(" - Third-Party Firewalls Detected: {}", products.len());

    println!(" - Active Firewalls: {}", total_active);
    println!();

    if products.len() > 0 {
        product_details(products, verbose);
    }
    
    if windows_active || active_products > 0 {
        println!("System Firewall Protection Is Active\n");
    } else {
        println!("System Firewall Protection Is Inactive\n")
    }
}


fn product_details(products: &Vec<FirewallProductInfo>, verbose: bool) {
    println!("Third-Party Firewall Details:");
    println!();
    for (i, prod) in products.iter().enumerate() {
        println!("{}. {}", i + 1, prod.name);
        println!(" - Status: {}", if prod.is_active {"Active"} else {"Inactive"});
        println!();
        if verbose {
            println!(" - Product Hexadecimal State: 0x{:X}", prod.state);
            println!(" - Product Raw State: {}", prod.state);
            println!();
        }
    }
}

fn display_technical() {
    println!("Technical Information:");
    println!(" - Firewall API: INetFwPolicy2");
    println!(" - COM Context: CLSCTX_ALL");
}