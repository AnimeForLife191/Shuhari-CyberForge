pub mod display;

use std::path::PathBuf;
use super::common::helper::{calculate_md5_bytes, calculate_sha256_bytes};

pub struct Hashes {
    pub file: PathBuf,
    pub md5: String,
    pub sha256: String
}

pub fn hash_files(files: Vec<PathBuf>) -> Result<Vec<Hashes>, std::io::Error> {
    let mut hashes = Vec::new();
    for file in files {
        if !file.is_file() {
            hashes.push(Hashes { 
                file: file.clone(), 
                md5: "Not a file".to_string(), 
                sha256: "Not a file".to_string() 
            });
            continue;
        }

        let md5_bytes = calculate_md5_bytes(&file)?;
        let sha256_bytes = calculate_sha256_bytes(&file)?;

        let md5_hex: String = md5_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let sha256_hex: String = sha256_bytes.iter().map(|b| format!("{:02x}", b)).collect();

        hashes.push(Hashes{
            file,
            md5: md5_hex,
            sha256: sha256_hex
        });
    }
    Ok(hashes)
}