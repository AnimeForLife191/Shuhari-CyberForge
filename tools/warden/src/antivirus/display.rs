use super::scanner::ProductInfo;
use crate::common::time::get_time;

/// Display for Antivirus Module
pub fn display_antivirus(products: &[ProductInfo], verbose: bool) {
    println!("ANTIVIRUS PROTECTION AUDIT"); // Title for display
    println!("{}", "=".repeat(30));

    if products.is_empty() {
        println!("No Antivirus Products Found");
        return;
    }

    // If verbose is NOT used
    if !verbose {
        println!("Summary:");
        println!(" - Products Found: {}", products.len()); // We use the length of the vec to get our count
        let active_count = products.iter().filter(|prod| prod.is_active).count(); // Filtering out the none active products
        println!(" - Active: {}/{}", active_count, products.len()); // Verifying how many products are active
        let real_time_count = products.iter().filter(|prod| prod.is_realtime).count(); // Filtering out real-time protection
        println!(" - Real-time Protection: {}/{}", real_time_count, products.len()); // Verifying how many products have real-time on
        let definitions_count = products.iter().filter(|prod| prod.definitions_new).count(); // Filtering out non updated definitions
        println!(" - Definitions Updated: {}/{}\n", definitions_count, products.len()); // Verifying how many products definitions are current

        println!("Product Details:\n"); // For loop to iterate through products
        for (i, prod) in products.iter().enumerate() {
            println!("{}. {}", i + 1, prod.name); // Name of product
            println!("  - Status: {}", if prod.is_active {"Active"} else {"Inactive"}); // Product is Active or Inactive
            println!("  - Real-time: {}", if prod.is_realtime {"Enabled"} else {"Disabled"}); // Real-time On or Off
            println!("  - Definitions: {}\n", if prod.definitions_new {"Up-to-date"} else {"Out-of-date"}); // Diffinitions are up-to-date
        }
    } else { 
        // Verbose Scan
        println!("Scan Details:"); 
        println!(" - Scan Started: {:02}:{:02}:{:02} UTC", get_time().0, get_time().1, get_time().2); // NOTE: 0 is hours, 1 is minutes, 2 is seconds
        println!(" - WMI Namespace: ROOT\\SecurityCenter2"); // Namespaced used
        println!(" - Query: SELECT displayName, productState FROM AntiVirusProduct\n"); // Query used

        println!("Summary:");
        println!(" - Products Found: {}", products.len());
        let active_count = products.iter().filter(|prod| prod.is_active).count();
        println!(" - Active: {}/{}", active_count, products.len());
        let real_time_count = products.iter().filter(|prod| prod.is_realtime).count();
        println!(" - Real-time Protection: {}/{}", real_time_count, products.len());
        let definitions_count = products.iter().filter(|prod| prod.definitions_new).count();
        println!(" - Definitions Updated: {}/{}\n", definitions_count, products.len());

        println!("Product Details:\n");
        for (i, prod) in products.iter().enumerate() {
            println!("{}. {}", i + 1, prod.name);
            println!(" - Status: {}", if prod.is_active {"Active"} else {"Inactive"});
            println!(" - Real-time: {}", if prod.is_realtime {"Enabled"} else {"Disabled"});
            println!(" - Definitions: {}", if prod.definitions_new {"Up-to-date"} else {"Out-of-date"});
            println!(" - Raw State: {}", prod.state); // Raw state of product
            println!(" - Hexadecimal State: 0x{:X}\n", prod.state); // Hexadecimal of product
        }

        println!("Technical Information:");
        println!(" - COM Apartment: MTA (Multi-threaded)");
        println!(" - WMI Context: CLSCTX_INPROC_SERVER");
        println!();
    }
}