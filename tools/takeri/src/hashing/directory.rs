//! This is the Directory Module for Takeri. This module handles hashing
//! multiple files within directories, with support for recursive scanning
//! and parallel processing for performance.
//! 
//! Key Features:
//! - Recursive directory traversal
//! - Parallel hashing using Rayon (multi-threaded)
//! - Progress tracking with spinners
//! - Graceful error handling (continues on failures)

use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};
use rayon::prelude::*;
use std::sync::Mutex;
use std::io::Error;

use crate::common::helper::walk_directory;
use super::file_hash::{hash_selector, Hash};


/*
    Takeri: Result Structure

    When hashing directories, some files may fail (permissions, corrupt files, etc.)
    We don't want one failure to stop the entire scan, so we seperate results:

    - successful: Files that hashed correctly
    - failed: Files that couldn't be hashed, with their error messages

    This allows us to see what worked and what didn't.
*/
pub struct DirectoryHashResult {
    pub successful: Vec<Hash>,
    pub failed: Vec<(PathBuf, Error)>
}


/*
    Takeri: Parallel Directory Hashing

    This function demonstrates several advanced Rust concepts:
    1. Parallel processing with Rayon
    2. Thread-safe data structures (Mutex)
    3. Streaming iterators
    4. Progress indication
*/
/// Directory Hashing
pub fn hash_directory(path: &Path, algorithm: &str, recursive: bool) -> Result<DirectoryHashResult, Error> {
    let files = walk_directory(path, recursive)?;

    /*
        Takeri: Thread-Safe Collections

        When using parallel processing (.par_bridge()), multiple threads access these
        collections simultaneously. We need Mutex to prevent data races:

        - Without Mutex: Thread A and Thread B could both try to push() at the same
        time, corrupting the Vec
        - With Mutex: Only one thread can access the Vec at a time via .lock()

        The .lock().unwrap() pattern:
        1. Waits for exclusive access
        2. Modifies the data
        3. Automatically releases the lock when the statement ends
    */
    let successful = Mutex::new(Vec::new());
    let failed = Mutex::new(Vec::new());

    /*
        Takeri: Progress Indication

        We use a spinner instead of a progress bar because:
        - We don't know total file count upfront (lazy iterator)
        - Spinner shows activity and count of files processed
        - Less overhead than constantly updating a progress bar percentage

        The template shows:
        - Spinner animation
        - Elapsed time
        - Number of files hashed so far

        For more information:
        (https://docs.rs/indicatif/latest/indicatif/) - Crate
    */
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {pos} files hashed")
            .unwrap()
    );

    /*
        Takeri: Parallel Processing with Rayon

        .par_bridge() is the magic that makes this parallel:
        - Takes our sequential iterator
        - Distrubutes work across all CPU cores
        - Automatically handles thread pooling and work stealing

        On a 32-core CPU, this allows us to scan 293k files in ~30 seconds.

        Of course this could vary significantly for different people, but
        it's still pretty cool to watch the numbers go up.

        For more information:
        (https://docs.rs/rayon/latest/rayon/) - Crate
    */
    files.par_bridge().for_each(|file| {
        match hash_selector(algorithm, &file) {
            Ok(hash) => {
                // Successfully hashed - add to successful list
                successful.lock().unwrap().push(hash);
            }
            Err(e) => {
                // Failed to hash - record the error but continue with other files
                // Common errors: permission denied, file deleted mid-scan, etc.
                failed.lock().unwrap().push((file.clone(), e));
            }
        }
        // Increment the progress counter (thread-safe)
        pb.inc(1);
    });
    pb.finish_with_message("Hashed!");

    /*
        Takeri: Extracting Results from Mutex

        .into_inner().unwrap() extracts the Vec from the Mutex:
        - At this point, all threads are done (par_bridge finished)
        - No more concurrent access, so into_inner() is safe
        - We get back our Vecs with all the collected results
    */
    Ok(DirectoryHashResult {
        successful: successful.into_inner().unwrap(),
        failed: failed.into_inner().unwrap()
    })
}