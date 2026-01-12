use super::scanner::UpdateSummary;
use crate::common::time::get_time;

/// Display for Update Module
pub fn display_updates(update: UpdateSummary, verbose: bool) {
    println!();
    println!("UPDATES PENDING AUDIT");
    println!("{}", "=".repeat(30));

    if verbose {display_scan_details(&update);}
    
    display_summary(&update, verbose);

    update_display(
        &update, 
        verbose, 
        update.critical_count, 
        "Critical Updates", 
        "Critical Updates Needing Installed:"
    );

        update_display(
        &update, 
        verbose, 
        update.security_count, 
        "Security Updates", 
        "Security Updates Needing Installed:"
    );

    update_display(
        &update, 
        verbose, 
        update.definition_count, 
        "Definition Updates", 
        "Definition Updates Needing Installed:"
    );

    update_display(&update, 
        verbose, 
        update.feature_count, 
        "Feature Packs", 
        "Feature Updates Needing Installed:"
    );

    update_display(
        &update, 
        verbose,  
        update.driver_count, 
        "Drivers", 
        "Driver Updates Needing Installed:"
    );

    other_updates(
        &update, 
        verbose, 
        update.other_count, 
        "Other Updates Needing Installed:"
    );

    if verbose {display_technical();}
}

fn display_scan_details(update: &UpdateSummary) {
    let (h, m, s) = get_time();

    println!("Scan Details:"); 
    println!(" - Scan Started: {:02}:{:02}:{:02} UTC", h, m, s);
    println!(" - Update Service: Windows Update Agent");
    println!(" - Query: {}", update.query);
    println!();
}

fn display_summary(update: &UpdateSummary, verbose: bool) {
    println!("Summary:");
    if update.total_count == 0 {
        println!(" - No Updates Available");
        println!();
        return;
    }
    println!(" - Updates Available: {}", update.total_count);
    println!("   - Critical Updates: {}", update.critical_count);
    println!("   - Security Updates: {}", update.security_count);
    if verbose {
        println!("   - Definition Updates: {}", update.definition_count);
        println!("   - Feature Updates: {}", update.feature_count);
        println!("   - Driver Updates: {}", update.driver_count);
        println!("   - Other Updates: {}", update.other_count);
        println!();
    }
    println!();
}

fn update_display(update: &UpdateSummary, verbose: bool, count: i32, class: &str, header: &str) {
    if count == 0 {
        return;
    }
    println!("{}", header);
    let mut display_counter = 0;
    for info in &update.update_list {
        if info.classification == class {
            println!("{}. {}", display_counter+1, info.title);
            display_counter += 1;
            println!("   - Size: {:.2} - {:.2} MB", info.min_mb, info.max_mb);
            if verbose {
                println!("   - Product: {}", info.product);
                println!("   - Classification: {}", info.classification);
                println!("   - Description: {}", info.description);
            }
            println!();
        }
    }
}

fn other_updates(update: &UpdateSummary, verbose: bool, count: i32, header: &str) {
    if count == 0 {
        return;
    }

    println!("{}", header);
    let mut display_counter = 0;
    let classes = [
        "Critical Updates",
        "Security Updates",
        "Definition Updates",
        "Feature Packs",
        "Drivers"
    ];
    for info in &update.update_list {
        if classes.contains(&info.classification.as_str()) {
            continue;
        }

        println!("{}. {}", display_counter+1, info.title);
        display_counter += 1;
        println!("   - Size: {:.2} - {:.2} MB", info.min_mb, info.max_mb);
            if verbose {
                println!("   - Product: {}", info.product);
                println!("   - Classification: {}", info.classification);
                println!("   - Description: {}", info.description);
            }
            println!();
    }
}

fn display_technical() {
    println!("Technical Information:");
    println!(" - COM Apartment: MTA (Multi-threaded)");
    println!(" - COM Context: CLSCTX_ALL");
    println!(" - API: Windows Update Agent (WUA)");
    println!();
}