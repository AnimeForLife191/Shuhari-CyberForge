

use rayon::iter::{ParallelBridge, ParallelIterator};
use std::sync::atomic::{AtomicUsize, Ordering};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};
use std::fs::metadata;
use std::sync::Mutex;
use std::io::Error;

use crate::common::helper::{calculate_md5_bytes, walk_directory};
use super::cvd_reader::{SignatureDb, SignatureSize};

pub enum ScanResult {
    Clean,
    Infected {
        malware_path: PathBuf,
        malware_name: String,
        malware_size: Option<u64>,
        hash: String
    }
}

pub struct DirectoryScanResult {
    pub clean: usize,
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

        // If file size doesn't match any in db, determine clean
        if !self.db.all_sizes.contains(&file_size) {
            return Ok(ScanResult::Clean);
        }

        // Get hash from file
        let hash: [u8; 16] = calculate_md5_bytes(path)?;

        match self.db.signatures.get(&hash) {
            Some(signature_info) => {
                match &signature_info.size {
                    SignatureSize::Specific { size: size_set } => {
                        if size_set.contains(&file_size) {
                            Ok(ScanResult::Infected { 
                                malware_path: path.to_path_buf(),
                                malware_name: signature_info.name.clone(), 
                                malware_size: Some(file_size), 
                                hash: hex::encode(hash) 
                            })
                        } else {
                            Ok(ScanResult::Clean)
                        }
                    }
                    SignatureSize::Wildcard => {
                        Ok(ScanResult::Infected { 
                            malware_path: path.to_path_buf(),
                            malware_name: signature_info.name.clone(), 
                            malware_size: None, 
                            hash: hex::encode(hash) 
                        })
                    }
                }
            }
            None => Ok(ScanResult::Clean)
        }
    }

    pub fn scan_dir(&self, path: &Path, recursive: bool) -> Result<DirectoryScanResult, Error> {
        let files = walk_directory(path, recursive)?;

        let infected = Mutex::new(Vec::new());
        let failed = Mutex::new(Vec::new());
        let clean_count = AtomicUsize::new(0);

        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} [{elapsed_precise} {pos} files hashed]")
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
                clean_count.fetch_add(1, Ordering::Relaxed);
                pb.inc(1);
                return;
            }

            let hash = match calculate_md5_bytes(&file) {
                Ok(hash) => hash,
                Err(e) => {
                    failed.lock().unwrap().push((file, e));
                    pb.inc(1);
                    return;
                }
            };

            match self.db.signatures.get(&hash) {
                Some(signature_info) => {
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
                    } else {
                        clean_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
                None => {
                    clean_count.fetch_add(1, Ordering::Relaxed);
                }
            }
            pb.inc(1);
        });
        pb.finish_with_message("Scan Complete!");

        Ok(DirectoryScanResult { 
            clean: clean_count.into_inner(), 
            infected: infected.into_inner().unwrap(), 
            failed: failed.into_inner().unwrap() 
        })
    }
}