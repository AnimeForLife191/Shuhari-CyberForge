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
pub fn scan_updates() -> Result<()> {
    /*
        WARDEN: If you haven't already, please go look at the Antivirus module then come back here

        Even though this module is more lighter then the Antivirus module, it's still holds key information about COM clean up
    */
    unsafe {

        let _com: HRESULT = CoInitializeEx(None, COINIT_MULTITHREADED);
        if _com.is_err() { 
            println!("Error with COM initilaization in Update module");
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

            println!("\nConnecting to Windows Update Service..."); // This shows us that were connecting to the Windows Update Service
            // Connect to Windows Update Service
            // for more info on IUpdateSession: https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-iupdatesession
            let session: IUpdateSession = CoCreateInstance(&UpdateSession, None, CLSCTX_ALL)?;
            // Why do we use 'CLSCTX_ALL' here?

            // To search for updates we need to create an instance for our search
            // for more info on 'IUpdateSearcher': https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-iupdatesearcher
            // for more info on 'CreateUpdateSearcher': https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdatesession-createupdatesearcher
            let searcher: IUpdateSearcher = session.CreateUpdateSearcher()?;

            println!("Checking for updates (This may take 10-30 seconds)..."); // Gives the user an estimate on how long it might take...because looking at nothing is boring
            // Our search criteria for this is: "IsInstalled=0". This tells the search to find pending updates
            let search_criteria = BSTR::from("IsInstalled=0");

            // We then use the 'Search' method with our criteria. This allows us to search for updates...if that wasn't obvious
            // for more info on 'Search': https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdatesearcher-search
            let data = searcher.Search(&search_criteria)?;

            // Now we can get our updates from the search
            // for more info on 'Updates': https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-isearchresult-get_updates
            // NOTE: There is not a lot on this page, but I wanted to add it just in case
            let updates = data.Updates()?;

            // We will be able to count how many updates we have in our collection using the 'Count' method
            // Their are multiple different methods to use with 'IUpdateCollection'
            // for more info on 'IUpdateCollection': https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-iupdatecollection
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

        // Here is the the cleaning part of COM, when we use COM objects like 'IUpdateSession', 'IUpdateSearcher', 'ISearchResult' or 'IUpdateCollection'
        // we need to clean them up so we can uninitialize the thread. Now Rust will do this on its own but theirs a slight problem with that.
        // If Rust destroys them after being used, Windows will also want to destroy them before closing the thread. This cuases issues and we can't
        // close the thread properly. There are two ways I have found to deal with this:
        //     1. You can use a method called 'drop()', this will drop the specified object but if you have multiple objects it can become messy        
        //     2. The option we're using is a scope. The COM objects will be dropped instead of destroyed after going out of scope.
        // If you want to try yourself, comment the 'CoUninitialize()' below and uncomment the one in the scope
        CoUninitialize();
    }// End of unsafe block
    Ok(())
}

fn display_updates(summary: &UpdateSummary) {
    println!("\n{} Window Updates Available", summary.total_count);
    println!("{}", "=".repeat(30));

    if summary.total_count == 0 {
        println!("You're up-to-date");
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