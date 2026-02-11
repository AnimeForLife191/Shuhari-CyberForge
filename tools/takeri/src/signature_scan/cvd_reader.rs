//! # Signature Management
//! 
//! This file handles ClamAV signature database operations for Takeri:
//! - Downloading signature files (.cvd) from ClamAV servers
//! - Parsing .cvd files and extracting .hdb signatures
//! - Version checking to determine if updates are needed
//! - Building in-memory signature database for fast scanning
//! 
//! # ClamAV Database Format
//!
//! ClamAV uses .cvd (ClamAV Virus Database) files which contain:
//! - 512-byte header (metadata: version, signature count, build time)
//! - Gzipped tarball containing various signature files (.hdb, .hsb, .ndb, etc.)
//!
//! Takeri currently supports .hdb files (hash-based signatures).

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read};
use reqwest::blocking::Client;
use flate2::read::GzDecoder;
use std::fs::{File, write};
use std::ffi::OsStr;
use std::path::Path;
use tar::Archive;
use uuid::Uuid;
use hex;

pub struct SignatureInfo {
    pub size: SignatureSize,
    pub name: String,
}
pub struct SignatureDb {
    pub signatures: HashMap<[u8;16], SignatureInfo>,
    pub all_sizes: HashSet<u64>
}

pub enum SignatureSize {
    Specific { size: HashSet<u64> },
    Wildcard
}

/// Getting main.cvd
pub fn download_main_cvd(output_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let url = "https://database.clamav.net/main.cvd";

    let uuid = Uuid::new_v4();
    let user_agent = format!("CVDUPDATE/1.0 ({})", uuid);

    let client = Client::builder()
        .user_agent(&user_agent)
        .build()?;

    println!("Downloading with User-Agent: {}", user_agent);

    let response = client.get(url).send()?;

    let bytes = response.bytes()?;

    write(output_path, &bytes)?;

    println!("Downloaded main.cvd ({} bytes)", bytes.len());

    Ok(())
}

pub fn cvd_file_reader(path: &Path) -> Result<SignatureDb, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?; // Open .cvd file

    let mut buffer = [0u8; 512]; // Buffer for header of .cvd

    file.read_exact(&mut buffer)?;

    let decoder = GzDecoder::new(file);

    let mut archive = Archive::new(decoder);

    let mut signatures: HashMap<[u8;16], SignatureInfo> = HashMap::new();
    let mut all_sizes: HashSet<u64> = HashSet::new();

    for entry in archive.entries()? {
        let entry = entry?;
        if let Some(ext) = entry.path()?.extension() {
            if ext == OsStr::new("hdb") {
                let reader: BufReader<tar::Entry<'_, GzDecoder<File>>> = BufReader::new(entry);

                for line in reader.lines() {
                    let line = line?;

                    if line.trim().is_empty() {
                        continue;
                    }

                    let parts: Vec<&str> = line.split(':').collect();

                    if parts.len() >= 3 {
                        let hash: [u8;16] = hex::decode(parts[0])?.try_into().unwrap();

                        let name = parts[2].to_string();

                        let size_str = parts[1];
                        let size = if size_str == "*" {
                            SignatureSize::Wildcard
                        } else {
                            match size_str.parse::<u64>() {
                                Ok(size_parsed) => SignatureSize::Specific { 
                                    size: {
                                        let mut signature_size: HashSet<u64> = HashSet::new();
                                        signature_size.insert(size_parsed);
                                        signature_size
                                    } 
                                },
                                Err(_) => {
                                    continue;
                                }
                            }
                        };

                        if let SignatureSize::Specific { size: size_set } = &size {
                            for &size in size_set {
                                all_sizes.insert(size);
                            }
                        }

                        let signature_info = SignatureInfo {
                            size,
                            name
                        };

                        if signatures.contains_key(&hash) {
                            if let Some(existing) = signatures.get_mut(&hash) {
                                match &mut existing.size {
                                    SignatureSize::Specific { size: existing_set } => {
                                        match &signature_info.size {
                                            SignatureSize::Specific { size: new_set } => {
                                                for &new_size in new_set {
                                                    existing_set.insert(new_size);
                                                    all_sizes.insert(new_size);
                                                }
                                            }
                                            SignatureSize::Wildcard => {
                                                existing.size = SignatureSize::Wildcard;
                                            }
                                        }
                                    }
                                    SignatureSize::Wildcard => {
                                    }
                                }
                            }
                        } else {
                            signatures.insert(hash, signature_info);
                        }
                    } 
                }
            }
        }
    }

    Ok(SignatureDb { signatures, all_sizes })
}

fn download_cvd_header_http(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let uuid = Uuid::new_v4();
    let user_agent = format!("CVDUPDATE/1.0 ({})", uuid);

    let client = Client::builder()
        .user_agent(&user_agent)
        .build()?;

    let resp = client
        .get(url)
        .header("Range", "bytes=0-511")
        .send()?;

    let bytes = resp.bytes()?;

    let header: [u8;512] = bytes[..].try_into()?;

    let null_pos = header.iter().position(|&b| b == 0);

    let actual_bytes = match null_pos {
        Some(pos) => {
            &header[..pos]
        }
        None => {
            &header[..]
        }
    };

    let header_string = String::from_utf8(actual_bytes.to_vec())?;
    Ok(header_string)
}

pub fn cvd_version(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?; // Opens .cvd file
    let mut header = [0u8;512]; // Header for .cvd file
    
    file.read_exact(&mut header)?;

    let null_pos = header.iter().position(|&b| b == 0);

    let actual_bytes = match null_pos {
        Some(pos) => {
            &header[..pos]
        }
        None => {
            &header[..]
        }
    };

    let header_string = String::from_utf8(actual_bytes.to_vec())?;
    let version = header_string.split(':').nth(2);
    match version {
        Some(version) => Ok(version.to_string()),
        None => Err("Invalid CVD Header: No Version Found".into())
    }
}

pub fn version_current(path: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    let url = "https://database.clamav.net/main.cvd";
    let cvd_header = download_cvd_header_http(url)?;
    let current_version = cvd_version(path)?;

    let version = cvd_header.split(':').nth(2);
    let new_version = match version {
        Some(version) => version.to_string(),
        None => "Invalid CVD Header: No Version Found".to_string()
    };

    if current_version == new_version {
        Ok(true)
    } else {
        Ok(false)
    }
    
}