use rayon::iter::{ParallelBridge, ParallelIterator};
use std::sync::atomic::{AtomicUsize, Ordering};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};
use std::fs::metadata;
use std::sync::Mutex;
use std::io::Error;

use crate::common::helper::{
    calculate_entropy, 
    calculate_md5_bytes, 
    calculate_sha256_bytes, 
    walk_directory
};
use super::cvd::cvd_reader::{
    SignatureDb, 
    SignatureSize, 
    SignatureInfo
};
use super::cvd::json_handler::prepare_cvd;


pub enum ScanResult {
    Clean,
    Infected {
        malware_path: PathBuf,
        malware_name: String,
        malware_size: Option<u64>,
        hash: String
    },
    
}

pub struct DirectoryScanResult {
    pub clean: usize,
    pub skipped: usize,
    pub infected: Vec<InfectedFile>,
    pub failed: Vec<(PathBuf, Error)>
}

pub struct InfectedFile {
    pub path: String,
    pub malware_name: String,
    pub hash: String,
    pub malware_size: Option<u64>
}

pub struct MalwareScanner {
    db: SignatureDb
}

impl MalwareScanner {
    pub fn new(db: SignatureDb) -> Self {
        MalwareScanner {db}
    }
    
    /// Scan File
    pub fn scan_file(&self, path: &Path) -> Result<ScanResult, Error> {
        let file_size = path.metadata()?.len();

        let entropy = match calculate_entropy(path) {
            Ok(e) => e,
            Err(_) => 0.0
        };
        
        println!("Entropy is {}", entropy);
        
        // If file size doesn't match any in db, determine clean
        if !self.db.all_sizes.contains(&file_size) {
            return Ok(ScanResult::Clean);
        }
        
        let mut md5_hash = None;
        let mut sha256_hash = None;

        // Get hash from file
        if self.db.md5_sizes.contains(&file_size) {
            md5_hash = Some(calculate_md5_bytes(path)?);
        }

        if self.db.sha256_sizes.contains(&file_size) {
            sha256_hash = Some(calculate_sha256_bytes(path)?);
        }

        if let Some(hash) = md5_hash {
            if let Some(signature_info) = self.db.md5_signatures.get(&hash) {
                return Ok(self.build_result(path, file_size, signature_info, hex::encode(hash)));
            }
        }

        if let Some(hash) = sha256_hash {
            if let Some(signature_info) = self.db.sha256_signatures.get(&hash) {
                return Ok(self.build_result(path, file_size, signature_info, hex::encode(hash)));
            }
        }

        Ok(ScanResult::Clean)
    }

    pub fn scan_dir(&self, path: &Path, recursive: bool) -> Result<DirectoryScanResult, Error> {
        let files = walk_directory(path, recursive)?;

        let infected = Mutex::new(Vec::new());
        let failed = Mutex::new(Vec::new());
        let clean_count = AtomicUsize::new(0);
        let skipped_count = AtomicUsize::new(0);

        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} [{elapsed_precise} {pos} Files Scanned]")
                .unwrap()  
        );

        files.par_bridge().for_each(|file| {
            let metadata = match metadata(&file) {
                Ok(m) => m,
                Err(e) => {
                    failed.lock().unwrap().push((file, e));
                    pb.inc(1);
                    return;
                }
            };

            let file_size = metadata.len();

            if !self.db.all_sizes.contains(&file_size) {
                skipped_count.fetch_add(1, Ordering::Relaxed);
                pb.inc(1);
                return;
            }

            let needs_md5 = self.db.md5_sizes.contains(&file_size);
            let needs_sha256 = self.db.sha256_sizes.contains(&file_size);

            let md5_hash = if needs_md5 {
                match calculate_md5_bytes(&file) {
                    Ok(h) => Some(h),
                    Err(e) => {
                        failed.lock().unwrap().push((file, e));
                        pb.inc(1);
                        return;
                    }
                }
            } else {
                None
            };

            let sha256_hash = if needs_sha256 {
                match calculate_sha256_bytes(&file) {
                    Ok(h) => Some(h),
                    Err(e) => {
                        failed.lock().unwrap().push((file, e));
                        pb.inc(1);
                        return;
                    }
                }
            } else {
                None
            };

            let mut found = false;

            if let Some(hash) = md5_hash {
                if let Some(signature_info) = self.db.md5_signatures.get(&hash) {
                    let is_infected = match &signature_info.size {
                        SignatureSize::Specific { size } => size.contains(&file_size),
                        SignatureSize::Wildcard => true
                    };

                    if is_infected {
                        infected.lock().unwrap().push(InfectedFile { 
                            path: file.to_string_lossy().to_string(), 
                            malware_name: signature_info.name.clone(), 
                            hash: hex::encode(hash), 
                            malware_size: Some(file_size) 
                        });
                        found = true;
                    }
                }
            }

            if !found {
                if let Some(hash) = sha256_hash {
                    if let Some(signature_info) = self.db.sha256_signatures.get(&hash) {
                        let is_infected = match &signature_info.size {
                            SignatureSize::Specific { size } => size.contains(&file_size),
                            SignatureSize::Wildcard => true
                        };

                        if is_infected {
                            infected.lock().unwrap().push(InfectedFile { 
                                path: file.to_string_lossy().to_string(), 
                                malware_name: signature_info.name.clone(), 
                                hash: hex::encode(hash), 
                                malware_size: Some(file_size) 
                            });

                            found = true
                        }
                    }
                }
            }

            if !found {
                clean_count.fetch_add(1, Ordering::Relaxed);
            }
            pb.inc(1);
        });
        pb.finish_with_message("Scan Complete!");

        Ok(DirectoryScanResult { 
            clean: clean_count.into_inner(), 
            skipped: skipped_count.into_inner(),
            infected: infected.into_inner().unwrap(), 
            failed: failed.into_inner().unwrap() 
        })
    }

    fn build_result(&self, path: &Path, file_size: u64, signature_info: &SignatureInfo, hash: String) -> ScanResult {
        match &signature_info.size {
            SignatureSize::Specific { size } => {
                if size.contains(&file_size) {
                    ScanResult::Infected { 
                        malware_path: path.to_path_buf(), 
                        malware_name: signature_info.name.clone(), 
                        malware_size: Some(file_size), 
                        hash 
                    }
                } else {
                    ScanResult::Clean
                }
            }
            SignatureSize::Wildcard => ScanResult::Infected {
                malware_path: path.to_path_buf(), 
                malware_name: signature_info.name.clone(), 
                malware_size: None, 
                hash 
            }
        }
    }
}

pub fn init_scanner() -> Result<MalwareScanner, Box<dyn std::error::Error>> {
    let paths = prepare_cvd()?;

    let main_db = &paths.main;
    let daily_db = &paths.daily;

    let mut db = SignatureDb::new();
    let _ = db.load_cvd(main_db);
    let _ = db.load_cvd(daily_db);
    println!("Database MD5 Signatures: {}", db.md5_signatures.len());
    println!("Database SHA256 Signatures: {}", db.sha256_signatures.len());

    let scanner = MalwareScanner::new(db);

    Ok(scanner)
}