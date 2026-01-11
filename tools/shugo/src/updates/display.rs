use super::scanner::UpdateSummary;
use crate::common::time::get_time;

pub fn display_updates(summary: UpdateSummary, verbose: bool) {

    println!("UPDATES PENDING AUDIT"); // Title for display
    println!("{}", "=".repeat(30)); // Seperator

    if summary.total_count == 0 {
        println!("No Updates Available");
        println!("Awesome, you're all up-to-date");
        return;
    }

    if verbose {
        display_scan_details();
    }

    display_summary(&summary);
    updates_summary(&summary, summary.critical_count, "Critical Updates", "Critical Updates Needing Installed:");
    updates_summary(&summary, summary.security_count, "Security Updates", "Security Updates Needing Installed:");

    if verbose {
        updates_summary(&summary, summary.definition_count, "Definition Updates", "Definition Updates Needing Installed:");
        updates_summary(&summary, summary.feature_count, "Feature Packs", "Feature Updates Needing Installed:");
        updates_summary(&summary, summary.driver_count, "Drivers", "Driver Updates Needing Installed:");
        other_updates(&summary, summary.other_count, "Other Updates Needing Installed:");
    }
}

fn display_scan_details() {
    println!("Scan Details:"); 
    let (h, m, s) = get_time();
    println!(" - Scan Started: {:02}:{:02}:{:02} UTC", h, m, s);
    println!(" - Update Service: Windows Update Agent");
    println!(" - Search Criteria: IsInstalled=0");
    println!();
}

fn display_summary(summary: &UpdateSummary) {
    println!("Summary:");
    println!(" - Updates Available: {}", summary.total_count);
    println!(" - Critical Updates: {}", summary.critical_count);
    println!(" - Security Updates: {}", summary.security_count);
    println!(" - Definition Updates: {}", summary.definition_count);
    println!(" - Feature Updates: {}", summary.feature_count);
    println!(" - Driver Updates: {}", summary.driver_count);
    println!(" - Other Updates: {}", summary.other_count);
    println!();
}

fn updates_summary(summary: &UpdateSummary, count: i32 ,class: &str, header: &str) {
    if count == 0 {
        return;
    }
    println!("{}", header);
    let mut i = 0;
    for info in &summary.update_list {
        if info.classification == class {
            println!("{}. {}", i+1, info.title);
            i += 1;
            println!(" - Type: {}", info.classification);
            println!(" - Size: {:.2} MB", info.min_mb);
            println!();
        }
    }
}

fn other_updates(summary: &UpdateSummary, count: i32, header: &str) {
    if count == 0 {
        return;
    }
    println!("{}", header);
    let mut display_count = 0;
    let classes = [
        "Critical Updates",
        "Security Updates",
        "Definition Updates",
        "Feature Packs",
        "Drivers"
    ];
    for info in &summary.update_list {
        if classes.contains(&info.classification.as_str()) {
            continue;
        }
        println!("{}. {}", display_count+1, info.title);
        display_count += 1;
        println!(" - Type: {}", info.classification);
        println!(" - Size: {:.2} MB", info.min_mb);
        println!();
    }
}