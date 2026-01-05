use super::scanner::ProductInfo;
use crate::common::time::get_time;

/// Display for Antivirus Module
pub fn display_antivirus(products: &[ProductInfo], verbose: bool) {
    println!("ANTIVIRUS PROTECTION AUDIT");
    println!("{}", "=".repeat(30));

    if verbose {display_scan_details();}

    if products.is_empty() {
        println!("No Antivirus Products Found");
        return;
    }

    display_summary(products);

    product_details(products, verbose);

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

fn display_summary(products: &[ProductInfo]) {
    println!("Summary:");
    println!(" - Products Found: {}", products.len());
    let active_count = products.iter().filter(|prod| prod.is_active).count();
    println!(" - Active: {}/{}", active_count, products.len());
    let real_time_count = products.iter().filter(|prod| prod.is_realtime).count();
    println!(" - Real-time Protection: {}/{}", real_time_count, products.len());
    let definitions_count = products.iter().filter(|prod| prod.definitions_new).count();
    println!(" - Definitions Updated: {}/{}", definitions_count, products.len());
    println!();
}

fn product_details(products: &[ProductInfo], verbose: bool) {
    println!("Product Details:"); // For loop to iterate through products
    println!();
    for (i, prod) in products.iter().enumerate() {
        println!("{}. {}", i + 1, prod.name); // Name of product
        println!(" - Status: {}", if prod.is_active {"Active"} else {"Inactive"}); // Product is Active or Inactive
        println!(" - Real-time: {}", if prod.is_realtime {"Enabled"} else {"Disabled"}); // Real-time On or Off
        println!(" - Definitions: {}", if prod.definitions_new {"Up-to-date"} else {"Out-of-date"}); // Definitions are up-to-date
        if verbose {
            println!(" - Product Hexadecimal State: 0x{:X}", prod.state); // Hexadecimal of product
            println!(" - Product Raw State: {}", prod.state); // Raw state of product
        }
        println!();
    }
}

fn display_technical() {
    println!("Technical Information:");
    println!(" - COM Apartment: MTA (Multi-threaded)");
    println!(" - WMI Context: CLSCTX_INPROC_SERVER");
    println!();
}