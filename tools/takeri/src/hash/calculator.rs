//! This is the Hash Module for Takeri. This is mostly a helper module 
//! for the Malware Scanner in Takeri but we'll also be using it as a 
//! way to scan files individualy.
//! 
//! We are able to:
//! 
//! - Convert file data into the following algorithm's:
//!     - MD5 (128 bit)-(Cryptographically broken but is still widley used for signatures against malware)
//!     - SHA-224 (224 bit)
//!     - SHA-256 (256 bit)-(Industry standard)
//!     - SHA-384 (384 bit)
//!     - SHA-512 (512 bit)-(Most secure, used for password hashing)

use std::path::Path;
use std::io::{Error, ErrorKind, BufReader, Read};
use std::fs::*;
use md5::Md5;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use hex::*;

pub struct Hash {
    pub hash: String,
    pub algorithm: String,
    pub file_path: String,
    pub file_size: u64
}

/* 
    Takeri: Understanding Hashing

    Hashing is taking data inside a file and running it through an algorithm, which will output a certain 
    string of numbers and letters. This is typically referred to as a digital footprint. If the exact same 
    file contents are found in another file, it will produce the same hash. Hashes are used for:

    - Checking file integrity
    - Securing passwords
    - and more

    Most found malware will have a signature attached to it, and it will be stored in a signature database 
    (e.g., ClamAV). This allows us to hash and compare files to malware signatures, giving us an accurate
    scan. There are a couple of flaws to this detection method, for example:

    - A single change in the file can create a whole new signature.
    - New malware that's undiscovered won’t have a signature.

    This makes it so that we get zero false positives, but it is not a great method for finding new and 
    hidden malware.
*/
/// Calculates Hash
fn calculator<D: Digest>(path: &Path, algorithm: &str) -> Result<Hash, Error> {
    /*
        Takeri: Hashing

        To start hashing, we need a hasher. This allows us to insert file contents into it and use a specific 
        algorithm to give us a hash. 
        Note: Every time we hash a file, the CPU will be doing most of the work.
    */

    // `D` allows us to use multiple different algorithms in one function
    let mut hasher = D::new(); 

    // Attempt to open the file in read only mode
    let file = File::open(path)?; 

    // Grabbing file size for more information
    let file_size = file.metadata()?.len();

    // This will allow us to read larger files more quickly by buffering them in memory
    let mut reader = BufReader::new(file);

    // This sets a limit on the buffer size
    let mut buffer = [0u8; 8192];

    // We loop through the file, gathing its contents
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        // Feed data into the hasher
        hasher.update(&buffer[..bytes_read]);
    }

    // Now we consume the hasher and it returns us a hash
    let hash = encode(hasher.finalize()).to_string();
    

    Ok(Hash { 
        hash,
        algorithm: algorithm.to_string(),
        file_path: path.display().to_string(),
        file_size
    })
}

/// User Chooses Hash
pub fn hash_selector(algorithm: &str, path: &Path) -> Result<Hash, Error> {
    if path.is_dir() {
        return Err(Error::new(
            ErrorKind::IsADirectory, 
            "Can't hash a directory"
        ));
    } else {
        match algorithm.to_lowercase().as_str() {
            "md5" => calculator::<Md5>(path, algorithm),
            "sha224" => calculator::<Sha224>(path, algorithm),
            "sha256" => calculator::<Sha256>(path, algorithm),
            "sha384" => calculator::<Sha384>(path, algorithm),
            "sha512" => calculator::<Sha512>(path, algorithm),
            _ => Err(Error::new(
                ErrorKind::InvalidInput, 
                format!("Unsupported algorithm: '{}'. Supported: md5, sha224, sha256, sha384, sha512", algorithm)))
        }
    }
}