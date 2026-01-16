use super::scanner::UserAccountSummary;
use crate::common::time::get_time;

pub fn display_uas(info: UserAccountSummary, verbose: bool) {
    println!();
    println!("USER ACCOUNT SECURITY AUDIT");
    println!("{}", "=".repeat(30));

    if verbose {display_scan_details();}

    display_summary(&info);

    if verbose {account_display(&info);}

    display_assessment(&info);
}

fn display_scan_details() {
    println!("Scan Details:"); 
    let (h, m, s) = get_time();
    println!(" - Scan Started: {:02}:{:02}:{:02} UTC", h, m, s);
    println!(" - API: NetUserEnum (Level 1)");
    println!(" - Scope: Local Computer Accounts");
    println!();
}

fn display_summary(info: &UserAccountSummary) {
    println!("Summary:");
    println!(" - Total Accounts: {}", info.total_users);
    println!(" - Enabled Accounts: {}", info.enabled_users);
    println!(" - Administrator Accounts: {}", info.admin_count);
    println!(" - Guest Account: {}", if info.guest_enabled {"Enabled (Not Recommended)"} else {"Disabled (Recommended)"});
    println!();
}

fn account_display(info: &UserAccountSummary) {
    println!("Account Details:");
    println!();
    for (i, account) in info.accounts.iter().enumerate() {
        println!("{}. {} ({})", i + 1, account.username, account.account_type);
        println!("   - Administrator: {}", if account.is_admin {"Yes"} else {"No"});
        println!("   - Status: {}", if account.is_enabled {"Enabled"} else {"Disabled"});
        println!();
    }
}

fn display_assessment(info: &UserAccountSummary) {
    println!("Security Assessment:");

    if !info.guest_enabled {
        println!(" - Guest account is disabled (Recommended)");
    } else {
        println!(" - Guest account is enabled (Not Recommended)");
    }

    if info.admin_count > 1 {
        println!(" - {} administrator acounts detected", info.admin_count);
    } else if info.admin_count == 1 {
        println!(" - Single administrator account (Recommended)");
    }

    println!(" - {} of {} accounts currently enabled", info.enabled_users, info.total_users);
    println!()
}