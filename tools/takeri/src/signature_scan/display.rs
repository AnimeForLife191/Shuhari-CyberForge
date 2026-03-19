use std::path::Path;

use crate::scanner::cvd::cvd_reader::SignatureDb;
use crate::scanner::scanner::{ScanResult, DirectoryScanResult, init_scanner};


pub fn init_scan(path: &Path, recursive: bool, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    println!("Malware Scan");
    println!("{}", "=".repeat(30));

    if verbose {
        scan_details_display(&path, recursive);
    }

    let scanner = init_scanner()?;

    if path.is_file() {
        let result = scanner.scan_file(path)?;
        display_file_scan(result, verbose);
    } else {
        let result = scanner.scan_dir(path, recursive)?;
        display_dir_scan(result, verbose);
    }

    Ok(())
}

fn scan_details_display (path: &Path, recursive: bool) {
    println!("Scan Details:");
    println!(" - Target: {}", path.display());
    println!(" - Recursive: {}", recursive);
    println!(" - Method: Signature-based (MD5 hash)");
    println!();
}

fn signature_db_display (db: &SignatureDb) {
    println!("Signature Database:");
    println!(" - MD5 Signatures Loaded: {}", db.md5_signatures.len());
    println!(" - MD5 Sizes: {}", db.md5_sizes.len());
    println!(" - Sha256 Signatures Loaded: {}", db.sha256_signatures.len());
    println!(" - Sha256 Sizes: {}", db.sha256_sizes.len());
    println!(" - Unique File Sizes: {}", db.all_sizes.len());
} 

fn display_file_scan(result: ScanResult, verbose: bool) {
    println!("File Scan Result:");
    println!();

    match result {
        ScanResult::Clean => {
            println!("File is clean");
            println!();
        }
        ScanResult::Infected { malware_path, malware_name, malware_size, hash } => {
            println!("THREAT DETECTED!");
            println!();
            println!(" - File: {}", malware_path.display());
            println!(" - Malware: {}", malware_name);
            println!(" - Size: {}", match malware_size {
                Some(size) => format!("{} bytes", size),
                None => "* (any size)".to_string()
            });

            if verbose {
                println!(" - MD5: {}", hash);
            }
            println!();
        }
    }
    println!()
}

fn display_dir_scan(result: DirectoryScanResult, verbose: bool) {

    println!("Scan Summary:");
    println!(" - Files Scanned: {}", result.clean + result.infected.len() as usize);
    println!(" - Clean: {}", result.clean);
    println!(" - Skipped: {}", result.skipped);
    println!(" - Infected: {}", result.infected.len());
    println!(" - Failed: {}", result.failed.len());
    println!();

    if !result.failed.is_empty() {
        println!("Failed Files:");
        for (path, error) in result.failed.iter().take(5) {
            println!(" - {}: {}", path.display(), error);
        }
        if result.failed.len() > 5 {
            println!(" ... and {} more failures", result.failed.len() - 5);
        }
        println!();
    }

    if !result.infected.is_empty() {
        println!("INFECTED FILES DETECTED:");
        println!();

        let display_count = if result.infected.len() > 10 {
            10
        } else {
            result.infected.len()
        };

        for (i, file) in result.infected.iter().take(display_count).enumerate() {
            println!("{}. {}", i + 1, file.path);
            println!("   Malware: {}", file.malware_name);
            println!("   Size: {}", match file.malware_size {
                Some(size) => format!("{} bytes", size),
                None => "* (any size)".to_string()
            });

            if verbose {
                println!("   MD5: {}", file.hash);
            }
            println!();
        }

        if result.infected.len() > 10 {
            println!("... and {} more infected files", result.infected.len() - 10);
            println!("Recommendation: Full system scan and malware removal required.");
            println!();
        }
    } else {
        println!("No threats detected");
        println!();
    }

    if !result.infected.is_empty() {
        println!("Security Assessment:");
        println!(" - CRITICAL: Malware detected on this system");
        println!(" - Action Required:");
        println!("   1. Quarantine or delete infected files");
        println!("   2. Run a full system scan");
        println!("   3. Check for persistence mechanisms");
        println!("   4. Update all software and signatures");
        
        if verbose {
            println!();
            println!("Educational Note:");
            println!("  Signature-based detection only catches KNOWN malware.");
            println!("  Consider running heuristic/behavioral scans for");
            println!("  comprehensive protection against new threats.");
        }
        println!();
    }
    
}