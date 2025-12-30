use windows::Win32::System::Com::*;
use windows::Win32::System::UpdateAgent::*;
use windows::core::*;

struct UpdateInfo {
    title: String,
    is_security: bool
}

struct UpdateSummary {
    total_count: i32,
    update_list: Vec<UpdateInfo>
}

/// Grabing updates for Windows
pub fn update_com_api() -> Result<()> {
    unsafe { // We use windows unsafe block here because were using foreign functions that are unsafe with Rust
        /*
            WARDEN: COM Aparments

            As you see we are using 'CoInitializeEx(None, COINIT_MULTITHREADED)'. This initializes:
            - MTA (Multi-Threaded Apartment): Objects can move between threads
            - Alternative: STA (Single-Threaded) with 'CoInitialize(None)'

            Why use MTA for WARDEN, well why not....WARDEN might use threads later so trying to learn it now is better.
            Its also more flexible for system tools.

            The trade off of using MTA is the cleanup
        */
        let _com: HRESULT = CoInitializeEx(None, COINIT_MULTITHREADED); // initializing COM thread
        if _com.is_err() { 
            println!("COM failed to initialize");
            return Err(_com.into()); // Error Check    
        }

        {
            /*
            WARDEN: Understanding COM Objects Lifetimes

            This scope is meant to be a controlled enviroment for COM objects:

            1. Problem: COM objects have self-destruct logic when dropped, now this isn't bad....BUT

            2. Issue: When Rust drops these objects, it creates a problem later when we try to close the COM thread as 
                we can't leave the COM thread initialized. This is a memory leak.
                When we call 'CoUninitialize()' to close the thread, Windows will destroy the COM objects....then Rust 
                will try to destroy them again.

            3. Solution: This scope will create the objects inside, then will be destroyed at the end of scope by Rust.
                This way, CoUninitialize() safely cleans the emptey COM state.

            4. Test: Uncomment the CoUninitialize() inside the end of this scope and see for yourself   
            */

            // Connect to Windows Update Service
            let session: IUpdateSession = CoCreateInstance(&UpdateSession, None, CLSCTX_ALL)?;

            // Get search interface to search updates
            let searcher = session.CreateUpdateSearcher()?;

            // The search criteria: "IsInstalled=0" tells the search to find pending updates
            let search_criteria = BSTR::from("IsInstalled=0");

            // Executing the search and getting a collection
            let data = searcher.Search(&search_criteria)?;
            let updates = data.Updates()?;

            // Counting the updates pending
            let count = updates.Count()?;

            // Process each update in the collection
            let mut update_list: Vec<UpdateInfo> = Vec::new();
            for i in 0..count {

                // Get updates at index i (COM collections are 0-indexed like Rust) 
                let update = updates.get_Item(i)?;

                // Extract title from BSTR to Rust String
                let title = update.Title()?.to_string();

                // See if a title has security in it
                let is_security = title.to_lowercase().contains("security");
            
                update_list.push(UpdateInfo { 
                    title, 
                    is_security 
                });    
            }

            let summary = UpdateSummary {
                total_count: count,
                update_list
            };
            display_updates(&summary);
            
            // Remove the '//' below to see what happens
            // CoUninitialize();
        } // End of Scope
        CoUninitialize();
    }// End of unsafe block
    Ok(())
}

fn display_updates(summary: &UpdateSummary) {
    println!("\n{} Window Updates Available", summary.total_count);
    println!("{}", "=".repeat(30));

    if summary.total_count == 0 {
        println!("Your up-to-date");
        return;
    } else {
        println!("You have {} Update(s) pending", summary.total_count);
    }

    let security_updates = summary.update_list
        .iter()
        .filter(|info| info.is_security)
        .count();

    if security_updates == 0 {
        println!("  - No Security Updates available");
    } else {
        println!("  - {} Security Updates available", security_updates);
    }

    println!("\nUpdate List: ");
    for (i, info) in summary.update_list.iter().enumerate() {
        println!("{}. {}\n", i + 1, info.title);
    }
}