use super::calculator::Hash;
use super::directory::DirectoryHashResult;

pub fn display_file_hash(hash: Hash) {
    println!("Hash: {}", hash.hash);
    println!("Algorithm: {}", hash.algorithm.to_uppercase());
    println!("File Path: {}", hash.file_path);
    println!("File Size: {}", hash.file_size);
}

pub fn display_directory_hash(files: DirectoryHashResult) {
    for file in files.successful {
        println!("{}: {}", file.hash, file.file_path);
    }
}