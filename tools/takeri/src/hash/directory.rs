use walkdir::WalkDir;
use std::path::{Path, PathBuf};
use std::io::{Error, ErrorKind};
use indicatif::ProgressBar;
use rayon::prelude::*;
use std::sync::Mutex;

use super::calculator::{hash_selector, Hash};

pub struct DirectoryHashResult {
    pub successful: Vec<Hash>,
    pub failed: Vec<(PathBuf, Error)>
}

fn walk_directory(dir: &Path, recursive: bool) -> Result<Vec<PathBuf>, Error> {
    if dir.is_file() {
        return Err(Error::new(
            ErrorKind::NotADirectory, 
            "Not a directory"
        ));
    }
    let walker = if recursive {
        WalkDir::new(dir)
    } else {
        WalkDir::new(dir).max_depth(1)
    };

    let files: Vec<PathBuf> = walker
        .into_iter() // Iterator for Result<DirEntry, Error>
        .filter_map(|e| e.ok()) // Converts Result to Option
        .filter(|f| f.path().is_file()) // Returns only files
        .map(|f| f.path().to_path_buf()) // Converts to PathBuf
        .collect();

    Ok(files)
}

pub fn hash_directory(path: &Path, algorithm: &str, recursive: bool) -> Result<DirectoryHashResult, Error> {
    let files = walk_directory(path, recursive)?;

    let pb = ProgressBar::new(files.len() as u64);

    let successful = Mutex::new(Vec::new());
    let failed = Mutex::new(Vec::new());

    files.par_iter().for_each(|file| {
        match hash_selector(algorithm, file) {
            Ok(hash) => {
                successful.lock().unwrap().push(hash);
            }
            Err(e) => {
                failed.lock().unwrap().push((file.clone(), e));
            }
        }
        pb.inc(1);
    });

    pb.finish_with_message("Hashed!");
    
    Ok(DirectoryHashResult {
        successful: successful.into_inner().unwrap(),
        failed: failed.into_inner().unwrap()
    })
}