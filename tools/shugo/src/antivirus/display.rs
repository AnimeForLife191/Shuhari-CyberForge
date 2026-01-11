use super::scanner::ProductInfo;
use crate::common::time::get_time;

/// Display for Antivirus Module
pub fn display_antivirus(products: &[ProductInfo], verbose: bool) {
    println!();
    println!("ANTIVIRUS PROTECTION AUDIT");
    println!("{}", "=".repeat(30));

    if verbose {display_scan_details();}

    if products.is_empty() {
        println!(" - No Antivirus Products Found!")
    } else {
        display_summary(&products, verbose);

        product_display(&products, verbose);
    }

    display_assessment(&products);

    if verbose {display_technical();}
}

fn display_scan_details() {
    let (h, m, s) = get_time();

    println!("Scan Details:"); 
    println!(" - Scan Started: {:02}:{:02}:{:02} UTC", h, m, s);
    println!(" - WMI Namespace: ROOT\\SecurityCenter2");
    println!(" - Query: Select displayName, productState FROM AntiVirusProduct");
    println!();
}

fn display_summary(products: &[ProductInfo], verbose: bool) {
    println!("Summary:");
    println!(" - Products Found: {}", products.len());

    let inactive_count = products.iter().filter(|p| p.product_status == 0).count();
    println!("   - Products Inactive: {}", inactive_count);

    let active_count = products.iter().filter(|p| p.product_status == 1).count();
    println!("   - Products Active: {}", active_count);

    if verbose {
        let snoozed_count = products.iter().filter(|p| p.product_status == 2).count();
        println!("   - Products Snoozed: {}", snoozed_count);

        let expired_count = products.iter().filter(|p| p.product_status == 3).count();
        println!("   - Products Expired: {}", expired_count);
    }

    println!();
}

fn product_display(products: &[ProductInfo], verbose: bool) {
    println!("Product Details:");

    for (i, prod) in products.iter().enumerate() {
        println!("{}. {}", i+1, prod.name);

        println!(" - Status: {}", state_status_decode(prod.product_status));
        if verbose {println!("   - Hex Value (0x0F000): {}", prod.product_status);}

        println!(" - Third-Party: {}", state_owner_decode(prod.product_owner));
        if verbose {println!("   - Hex Value (0x00F00): {}", prod.product_owner);}

        println!(" - Definitions: {}", state_definition_decode(prod.definition_status));
        if verbose {println!("   - Hex Value (0x000F0): {}", prod.definition_status);}

        if verbose {
            println!(" - Product State: {}", prod.state);
            println!(" - Hexadecimal State: 0x{:X}", prod.state);
        }
        println!()
    }
}

fn display_assessment(products: &[ProductInfo]) {
    println!("Security Assessment:");

    println!(" - Antivirus Protection:");
    let active_count = products.iter().filter(|p| p.product_status == 1).count();
    if active_count == 0 {
        println!("   - Antivirus Protection Not Found!");
    }
    if active_count == 1 {
        println!("   - Antivirus Protection Is Active");
    }
    if active_count > 1 {
        println!("   - More than one antivirus product is active.");
        println!("   - It's recommend having only one antivirus active at a time.");
    }
    println!();

    println!(" - Active Products:");
    if active_count == 0 {
        println!("   - No active products");
        println!();
    } else {
        for prod in products {
            if prod.product_status == 1 {
                println!("   - {}", prod.name);
                if prod.definition_status == 1 {
                    println!("     - Definitions: Out-of-date");
                } else {
                    println!("     - Definitions: Up-to-date");
                }
            }
            println!();
        }
    }
}

fn display_technical() {
    println!("Technical Information:");
    println!(" - COM Apartment: MTA (Multi-threaded)");
    println!(" - WMI Context: CLSCTX_INPROC_SERVER");
    println!();
}

fn state_status_decode(state: i32) -> String{
    match state {
        0 => "Off".to_string(),
        1 => "On".to_string(),
        2 => "Snoozed".to_string(),
        3 => "Expired".to_string(),
        _ => "Unknown".to_string()
    }
}

fn state_definition_decode(state: i32) -> String {
    match state {
        0 => "Up-to-date".to_string(),
        1 => "Out-of-date".to_string(),
        _ => "Unknown".to_string()
    }
}

fn state_owner_decode(state: i32) -> String {
    match state {
        0 => "Yes".to_string(),
        1 => "No".to_string(),
        _ => "Unknown".to_string()
    }
}