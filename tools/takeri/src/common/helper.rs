use std::io::{Error, ErrorKind, BufReader, Read};
use std::path::{Path, PathBuf};
use md5::{Md5, Digest};
use sha2::{Sha256};
use walkdir::WalkDir;
use std::fs::*;

pub fn calculate_md5_bytes(path: &Path) -> Result<[u8; 16], Error> {
    let mut hasher = Md5::new();
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut buffer = [0u8; 8192];
    
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    
    let hash: [u8; 16] = hasher.finalize().into();
    Ok(hash)
}

pub fn calculate_sha256_bytes(path: &Path) -> Result<[u8; 32], Error> {
    let mut hasher = Sha256::new();
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut buffer = [0u8; 8192];
    
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    
    let hash: [u8; 32] = hasher.finalize().into();
    Ok(hash)
}

pub fn walk_directory(dir: &Path, recursive: bool) -> Result<impl Iterator<Item = PathBuf>, Error> {
    if dir.is_file() {
        return Err(Error::new(
            ErrorKind::NotADirectory, 
            "Not a directory"
        ));
    }

    let walker = if recursive {
        WalkDir::new(dir)
            .follow_links(false)
    } else {
        WalkDir::new(dir).max_depth(1)
    };

    let files = walker
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|f| f.path().is_file())
        .map(|f| f.path().to_path_buf());

    Ok(files)
}

pub fn calculate_entropy(path: &Path) -> Result<f64, Error> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut buffer = [0u8; 8192];

    let mut freq = [0u64; 256];
    let mut total_bytes = 0u64;

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        for &byte in &buffer[..bytes_read] {
            freq[byte as usize] += 1;
        }
        total_bytes += bytes_read as u64;
    }

        let mut entropy = 0.0;
        for &count in &freq {
            if count == 0 {
                continue;
            }

            let p = count as f64 / total_bytes as f64;
            entropy -= p * p.log2();
        }
    Ok(entropy)
}