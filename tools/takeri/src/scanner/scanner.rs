//! Takeri Scanner Module 

use rayon::iter::{ParallelBridge, ParallelIterator};
use std::sync::atomic::{AtomicUsize, Ordering};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};
use std::fs::{File, metadata};
use std::sync::Mutex;
use std::io::{Error, Read};

use crate::common::helper::{
    calculate_md5_bytes, 
    calculate_sha256_bytes, 
    walk_directory
};
use super::magic_bytes::MagicBytes;
use super::cvd::cvd_reader::{
    SignatureDb, 
    SignatureSize, 
    SignatureInfo
};
use super::cvd::json_handler::prepare_cvd;


pub enum ScanResult {
    Clean {
        file: String
    }, 
    Infected {
        file: InfectedFile
    },
    Suspicious {
        file: SuspiciousFile
    }
    
}

pub struct DirectoryScanResult {
    pub clean: usize,
    pub skipped: usize,
    pub infected: Vec<InfectedFile>,
    pub failed: Vec<(PathBuf, Error)>,
    pub suspicious: Vec<SuspiciousFile>
}

pub struct InfectedFile {
    pub path: String,
    pub malware_name: String,
    pub hash: String,
    pub malware_size: Option<u64>
}

pub struct SuspiciousFile {
    pub path: String,
    pub extension: String,
    pub actual_format: String
}

pub struct MalwareScanner {
    db: SignatureDb,
    magic: MagicBytes
}

impl MalwareScanner {
    pub fn new(db: SignatureDb) -> Self {
        MalwareScanner {
            db,
            magic: MagicBytes::new()
        }
    }
    
    /// Scan File
    pub fn scan_file(&self, path: &Path) -> Result<ScanResult, Error> {
        let file_size = path.metadata()?.len();
        
        // If file size doesn't match any in db, determine clean
        if !self.db.all_sizes.contains(&file_size) {
            return Ok(ScanResult::Clean { 
                file: path.to_string_lossy().to_string() 
            });
        }

        // Magic Bytes
        let ext = path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        let magic_buf = &self.read_magic_bytes(&path);
        let actual_format = self.magic.identify(&magic_buf);
        if let Some(false) = self.magic.check(ext, magic_buf) {
            return Ok(ScanResult::Suspicious { file: SuspiciousFile { 
                path: path.to_string_lossy().to_string(), 
                extension: ext.to_string(), 
                actual_format: actual_format.to_string() 
            } })
        };
        
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

        Ok(ScanResult::Clean {
            file: path.to_string_lossy().to_string()
        })
    }

    /// Scan Directory
    pub fn scan_dir(&self, path: &Path, recursive: bool) -> Result<DirectoryScanResult, Error> {
        let files = walk_directory(path, recursive)?;

        let infected = Mutex::new(Vec::new());
        let failed = Mutex::new(Vec::new());
        let suspicious = Mutex::new(Vec::new());
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

            // Magic Bytes
            let ext = file.extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");
            let magic_buf = &self.read_magic_bytes(&file);
            let actual_format = self.magic.identify(&magic_buf);
            if let Some(false) = self.magic.check(ext, magic_buf) {
                suspicious.lock().unwrap().push(SuspiciousFile {
                    path: file.to_string_lossy().to_string(),
                    extension: ext.to_string(),
                    actual_format: actual_format.to_string()
                });
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
        pb.finish_and_clear();

        Ok(DirectoryScanResult { 
            clean: clean_count.into_inner(), 
            skipped: skipped_count.into_inner(),
            infected: infected.into_inner().unwrap(), 
            failed: failed.into_inner().unwrap(),
            suspicious: suspicious.into_inner().unwrap()
        })
    }

    fn build_result(&self, path: &Path, file_size: u64, signature_info: &SignatureInfo, hash: String) -> ScanResult {
        match &signature_info.size {
            SignatureSize::Specific { size } => {
                if size.contains(&file_size) {
                    ScanResult::Infected { file: InfectedFile { 
                        path: path.to_string_lossy().to_string(), 
                        malware_name: signature_info.name.clone(), 
                        hash, 
                        malware_size: Some(file_size) 
                    } }
                } else {
                    ScanResult::Clean {
                        file: path.to_string_lossy().to_string()
                    }
                }
            }
            SignatureSize::Wildcard => ScanResult::Infected { file: InfectedFile { 
                path: path.to_string_lossy().to_string(), 
                malware_name: signature_info.name.clone(), 
                hash, 
                malware_size: None
            } }
        }
    }

    fn read_magic_bytes(&self, path: &Path) -> Vec<u8> {
        let mut f = match File::open(path) {
            Ok(f) => f,
            Err(_) => return vec![]
        };
        let mut buf = vec![0u8; 16];
        let n = f.read(&mut buf).unwrap_or(0);
        buf.truncate(n);
        buf
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