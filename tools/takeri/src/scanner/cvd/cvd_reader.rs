//! Takeri CVD Reader
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
use std::collections::hash_map::Entry;
use std::io::{BufRead, BufReader, Read};
use flate2::read::GzDecoder;
use std::fs::File;
use std::ffi::OsStr;
use std::path::Path;
use tar::Archive;
use hex;

pub struct SignatureInfo {
    pub size: SignatureSize,
    pub name: String,
}

pub struct SignatureDb {
    pub md5_signatures: HashMap<[u8; 16], SignatureInfo>,
    pub sha256_signatures: HashMap<[u8; 32], SignatureInfo>,

    pub md5_sizes: HashSet<u64>,
    pub sha256_sizes: HashSet<u64>,

    pub all_sizes: HashSet<u64>
}

pub enum SignatureSize {
    Specific { size: HashSet<u64> },
    Wildcard
}

impl SignatureDb {
    pub fn new() -> Self {
        Self { 
            md5_signatures: HashMap::new(), 
            sha256_signatures: HashMap::new(), 
            md5_sizes: HashSet::new(), 
            sha256_sizes: HashSet::new(), 
            all_sizes: HashSet::new() }
    }

    pub fn load_cvd(&mut self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let mut file = File::open(path)?;

        let mut buffer = [0u8; 512]; // Skipping header of .cvd file
        file.read_exact(&mut buffer)?;

        let decoder = GzDecoder::new(file);
        let mut archive = Archive::new(decoder);

        for entry in archive.entries()? {
            let entry = entry?;
            let ext = entry.path()?.extension().map(|e| e.to_os_string());

            let reader = BufReader::new(entry);

            match ext.as_deref() {
                Some(ext) if ext == OsStr::new("hdb") => {
                    self.parse_hdb(reader)?;
                }
                Some(ext) if ext == OsStr::new("hsb") => {
                    self.parse_hsb(reader)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn parse_hdb<R: BufRead>(&mut self, reader: R) -> Result<(), Box<dyn std::error::Error>> {
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 3 {
                continue;
            }

            let hash_vec= hex::decode(parts[0])?;
            let hash: [u8; 16] = match hash_vec.try_into() {
                Ok(h) => h,
                Err(_) => continue
            };
            let signature_info = match parse_signature(&parts, &mut self.all_sizes) {
                Some(info) => info,
                None => continue
            };

            insert_signature(&mut self.md5_signatures, 
                hash, 
                signature_info, 
                &mut self.md5_sizes, 
                &mut self.all_sizes
            );
        }
        Ok(())
    }

    fn parse_hsb<R: BufRead>(&mut self, reader: R) -> Result<(), Box<dyn std::error::Error>> {
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 3 {
                continue;
            }

            let hash_vec= hex::decode(parts[0])?;
            let signature_info = match parse_signature(&parts, &mut self.all_sizes) {
                Some(info) => info,
                None => continue
            };

            match hash_vec.len() {
                16 => {
                    if let Ok(hash) = hash_vec.try_into() {
                        insert_signature(
                            &mut self.md5_signatures,
                            hash,
                            signature_info,
                            &mut self.md5_sizes,
                            &mut self.all_sizes
                        );
                    }
                }
                32 => {
                    if let Ok(hash) = hash_vec.try_into() {
                        insert_signature(
                            &mut self.sha256_signatures,
                            hash,
                            signature_info,
                            &mut self.sha256_sizes,
                            &mut self.all_sizes
                        )
                    }
                }
                _ => continue
            }
        }
        Ok(())
    }
}


fn parse_signature(parts: &[&str], all_sizes: &mut HashSet<u64>) -> Option<SignatureInfo> {
    let name = parts[2].to_string();
    let size_str = parts[1];

    let size = if size_str == "*" {
        SignatureSize::Wildcard
    } else {
        match size_str.parse::<u64>() {
            Ok(size_parsed) => {
                all_sizes.insert(size_parsed);

                let mut set = HashSet::new();
                set.insert(size_parsed);

                SignatureSize::Specific { size: set }
            }
            Err(_) => return None
        }
    };
    Some(SignatureInfo { size, name })
}

fn insert_signature<const N: usize>(
    map: &mut HashMap<[u8; N], SignatureInfo>,
    hash: [u8; N],
    signature_info: SignatureInfo,
    hash_sizes: &mut HashSet<u64>,
    all_sizes: &mut HashSet<u64>,
    
) {
    match map.entry(hash) {
        Entry::Occupied(mut entry) => {
            let existing = entry.get_mut();

            match &mut existing.size {
                SignatureSize::Specific { size: existing_set } => {
                    match &signature_info.size {
                        SignatureSize::Specific { size: new_set } => {
                            for &new_size in new_set {
                                existing_set.insert(new_size);
                                all_sizes.insert(new_size);
                                hash_sizes.insert(new_size);
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
        Entry::Vacant(entry) => {
            entry.insert(signature_info);
        }
    }
}