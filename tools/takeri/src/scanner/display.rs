use std::path::Path;

use crate::scanner::scanner::{ScanResult, DirectoryScanResult, init_scanner};

pub fn display_malware_scan(path: &Path, recursive: bool) -> Result<(), Box<dyn std::error::Error>>{
    println!();
    let scanner = init_scanner()?;
    if path.is_file() {
        let result = scanner.scan_file(path)?;
        display_file_scan(result);
    } else {
        let result = scanner.scan_dir(path, recursive)?;
        display_dir_scan(result);
    }
    Ok(())
}

fn display_file_scan(result: ScanResult) {
    println!("-------Scan Result-------");
    match result {
        ScanResult::Clean {file}=> {
            println!("File: {}", file);
            println!("Status: Clean");
            println!("-------------------------")
        }
        ScanResult::Infected { file } => {
            println!("File: {}", file.path);
            println!("Size: {}", match file.malware_size {
                Some(size) => format!("{} bytes", size),
                None => "* (any size)".to_string()
            });
            println!("Status: INFECTED");
            println!("Malware: {}", file.malware_name);
            println!("Hash: {}", file.hash);
            println!("-------------------------")
        }
        ScanResult::Suspicious { file } => {
            println!("File: {}", file.path);
            println!("Status: SUSPICIOUS");
            println!("Claims to be: .{}", file.extension);
            println!("Actually is: {}", file.actual_format);
            println!("-------------------------")
        }
    }
}

fn display_dir_scan(result: DirectoryScanResult) {
    println!("-------Scan Summary-------");
    println!("Scanned files: {}", result.clean + result.infected.len() as usize);
    println!("Infected files: {}", result.infected.len());
    println!("Suspicious files: {}", result.suspicious.len());
    println!("Skipped files: {}", result.skipped);  
    println!("Failed files: {}", result.failed.len());
    println!("--------------------------");
    println!();

    if !result.failed.is_empty() {
        println!("FAILED FILES:");
        println!();
        for (path, error) in result.failed.iter().take(5) {
            println!(" - {}: {}", path.display(), error);
        }
        if result.failed.len() > 5 {
            println!(" ... and {} more", result.failed.len() - 5);
        }
        println!();
    }

    if !result.suspicious.is_empty() {
        println!("SUSPICIOUS FILES:");
        println!();
        for (i, file) in result.suspicious.iter().take(10).enumerate() {
            println!("{}. {}", i + 1, file.path);
            println!("   Claims to be: .{}", file.extension);
            println!("   Actually is: {}", file.actual_format);
            println!();
        }
        if result.suspicious.len() > 10 {
            println!("... and {} more suspcious files", result.suspicious.len() - 10);
            println!();
        }
    }

    if !result.infected.is_empty() {
        println!("INFECTED FILES DETECTED:");
        println!();
        for (i, file) in result.infected.iter().take(10).enumerate() {
            println!("{}. {}", i + 1, file.path);
            println!("   Malware: {}", file.malware_name);
            println!("   Size: {}", match file.malware_size {
                Some(size) => format!("{} bytes", size),
                None => "* (any size)".to_string()
            });
            println!();
        }
        if result.infected.len() > 10 {
            println!("... and {} more suspicious files", result.infected.len() - 10);
            println!();
        }
        println!(" CRITICAL: Malware detected. Quarantine or delete infected files immediately.");
        println!();
    } else {
        println!("No threats detected.");
        println!();
    }
}