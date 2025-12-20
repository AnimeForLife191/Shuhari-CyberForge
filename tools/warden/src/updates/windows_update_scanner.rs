// Windows crate types we need
use windows::core::{
    BSTR, // BSTR = "Basic String" - COM's String Type (UTF-16 with length prefix)
    Result // Result = Windows crates error-handling type
};

// COM (Component Object Model) functions and constants
use windows::Win32::System::Com::{
    CLSCTX_ALL, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize
};

// Windows update agent types
use windows::Win32::System::UpdateAgent::{
    IUpdateSession, // Interface for working with Windows updates
    UpdateSession // The actual COM class ID (CLSID) for creating update sessions
};


/// RAII guard for COM initialization. Calls 'CoUninitialize' only if we initialized.
pub struct ComGuard(bool);

impl Drop for ComGuard {
    fn drop(&mut self) {
        // Only uninitialize if WE initialized COM (self.0 == true)
        // This handles the S_FALSE case where COM was already initialized
        if self.0 {
            unsafe {
                CoUninitialize();
            }
        }
    }
}


/// Initialize COM for the current thread and return a guard.
pub fn init_com() -> Result<ComGuard> {
    unsafe {
        // CoInitializeEx returns HRESULT, not Result
        // S_OK (0) = we initialized COM -> we must uninitialize
        // S_FALSE (1) = COM already initialized -> someone else uninitializes
        let hr = CoInitializeEx(None, COINIT_MULTITHREADED);
        // This initializes COM in multi-threaded apartment mode
        // IF other code uses COINIT_APARTMENTTHREADED, This MAY fail

        if hr.is_ok() {
            // Only track true for S_OK (0), not S_FALSE (1)
            Ok(ComGuard(hr.0 == 0))
        } else {
            Err(hr)?
        }
    }
}


/// Create an 'IUpdateSession' instance.
pub fn create_update_session() -> Result<IUpdateSession> {
    unsafe {
        // Create a COM object using its class ID (CLSID)
        // &UpdateSession = reference to the CLSID for Windows Update Session
        // None no aggregation (advanced COM feature not needed)
        // CLSCTX_ALL = try to create in any available context
        CoCreateInstance(&UpdateSession, None, CLSCTX_ALL)
    }
}


/// Search updates matching 'criteria' and return a vector of titles.
pub fn search_updates(session: &IUpdateSession, criteria: &str) -> Result<Vec<String>> {
    unsafe {
        // Step 1: Get a searcher object from the session
        // CreateUpdateSearcher() is a COM method on IUpdateSession interface
        let searcher = session.CreateUpdateSearcher()?;

        // Step 2: Convert Rust string to COM string
        // criteria: &str (Rust UTF-8) -> BSTR (COM UTF-16)
        let b = BSTR::from(criteria);

        // Step 3: Search for updates matching criteria
        // "IsInstalled=0" means "find updates that aren't installed yet"
        let result = searcher.Search(&b)?;
        // Returns ISearchResult interface

        // Step 4: Get the collection of updates from search results
        let updates = result.Updates()?;
        // Return IUpdateCollection interface

        // Step 5: Get count of updates in collection
        let count = updates.Count()? as i32;
        // Count() returns i32, we store it as i32 for the loop

        // Step 6: Pre-allocate vector with exact capacity (performance reasons)
        let mut titles = Vec::with_capacity(count as usize);
        // with_capacity allocates memory once, avoiding reallocations

        // Step 7: Loop through each update
        for i in 0..count {
            // Get update index i (COM collections are usually 0-indexed)
            let update = updates.get_Item(i)?;
            // Returns IUpdate interface for this specific update

            // Get the title of this update
            let title = update.Title()?;
            // Returns BSTR (COM string)

            // Convert COM BSTR to Rust String and add to vector
            titles.push(title.to_string());
            // to_string() converts UTF-16 BSTR to UTF-8 String
        }

        // Step 8: Return the vector of titles
        Ok(titles)
    }
}

pub fn updates_check() -> Result<()> {
    let _com_guard = init_com()?;
    let session = create_update_session()?;
    let titles = search_updates(&session, "IsInstalled=0")?;

    for (i, title) in titles.iter().enumerate() {
        println!(" {}. {}", i + 1, title);
    }

    if titles.is_empty() {
        println!("\nSystem is up to date!");
    } else {
        println!("\nUpdates are pending. Consider installing them.");
    }

    Ok(())
}