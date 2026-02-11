use std::io::{Error, ErrorKind, BufReader, Read};
use std::path::{Path, PathBuf};
use md5::{Md5, Digest};
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

pub fn walk_directory(dir: &Path, recursive: bool) -> Result<impl Iterator<Item = PathBuf>, Error> {
    // Error handling: Make sure we're actually working with a directory
    if dir.is_file() {
        return Err(Error::new(
            ErrorKind::NotADirectory, 
            "Not a directory"
        ));
    }

    /*
        Takeri: Recursive vs Non-Recursive

        - Recursive (max_depth unlimited): Walks through all subdirectories
        Example: C:\Users\*\ - Includes: C:\Users\*\{Documents\, Downloads\}

        - Non-Recursive (max_depth = 1): Only files directly in the directory
        Example: C:\Users\*\Documents - Includes only files in \Documents, not subdirectories

        For more information:
        (https://docs.rs/walkdir/latest/walkdir/) - Crate
    */
    let walker = if recursive {
        WalkDir::new(dir)
            .follow_links(false) // Doesn't follow symlinks (prevents looping)
    } else {
        WalkDir::new(dir).max_depth(1)
    };

    /*
        Takeri: Iterator Chain Explained

        This is a "pipeline" - data flows through transformations:

        1. `.into_iter()` - Start iterating through directory entries
            Type: Iterator<Item = Result<DirEntry, Error>>
        
        2. `.filter_map(|e| e.ok())` - Remove errors, keep valid entries
            - e.ok() converts Result to Option (Ok -> Some, Err -> None)
            - filter_map automatically removes None values
            Type: Iterator<Item = DirEntry>

        3. `.filter(|f| f.path().is_file())` - Keep only files, skip directories
            Type: Iterator<Item = DirEntry>
        
        4. `.map(|f| f.path().to_path_buf())` - Convert to owned PathBuf
            - DirEntry.path() returns a borrowed &Path
            - to_path_buf() creates an owned PathBuf we can store
            Type: Iterator<Item = PathBuf>

        Nothing actually executes until this iterator is consumed
    */
    let files = walker
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|f| f.path().is_file())
        .map(|f| f.path().to_path_buf());

    Ok(files)
}