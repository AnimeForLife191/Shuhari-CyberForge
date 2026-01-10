use windows::Win32::System::Com::*;
use windows::Win32::System::UpdateAgent::*;
use windows::core::*;

use crate::common::wmi_helpers::decimal_to_u128;

pub struct UpdateInfo {
    pub title: String,
    pub classification: String,
    pub max_mb: f64
}

pub struct UpdateSummary {
    pub total_count: i32,
    pub critical_count: i32,
    pub security_count: i32,
    pub definition_count: i32,
    pub feature_count: i32,
    pub driver_count: i32,
    pub other_count: i32,
    pub update_list: Vec<UpdateInfo>
}

/// Constants for GUID classification
const CRITICAL_UPDATES_GUID: &str = "e6cf1350-c01b-414d-a61f-263d14d133b4";
const SECURITY_UPDATES_GUID: &str = "0fa1201d-4330-4fa8-8ae9-b877473b6441";
const DEFINITION_UPDATES_GUID: &str = "e0789628-ce08-4437-be74-2495b842f43b";
const FEATURE_UPDATES_GUID: &str = "b54e7d24-7add-428f-8b75-90a396fa584f";
const DRIVER_UPDATES_GUID: &str = "ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0";

/// Grabing updates for Windows
pub fn scan_updates() -> Result<UpdateSummary> {
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

        let summary;

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
            // for more info on IUpdateSession: https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-iupdatesession
            let session: IUpdateSession = CoCreateInstance(&UpdateSession, None, CLSCTX_ALL)?;
            // Why do we use 'CLSCTX_ALL' here?

            // To search for updates we need to create an instance for our search
            // for more info on 'IUpdateSearcher': https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-iupdatesearcher
            // for more info on 'CreateUpdateSearcher': https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdatesession-createupdatesearcher
            let searcher: IUpdateSearcher = session.CreateUpdateSearcher()?;

            // Our search criteria for this is: "IsInstalled=0". This tells the search to find pending updates
            let search_criteria = BSTR::from("IsInstalled=0");

            println!("Grabbing Updates, this may take 5-30 seconds...");
            // We then use the 'Search' method with our criteria. This allows us to search for updates...if that wasn't obvious
            // for more info on 'Search': https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdatesearcher-search
            // This is what takes so long to complete as we are grabbing information from Windows Update Services
            let data = searcher.Search(&search_criteria)?;

            // Now we can get our updates from the search
            // for more info on 'Updates': https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-isearchresult-get_updates
            // NOTE: There is not a lot on this page, but I wanted to add it just in case
            let updates = data.Updates()?;

            // We will be able to count how many updates we have in our collection using the 'Count' method
            // Their are multiple different methods to use with 'IUpdateCollection'
            // for more info on 'IUpdateCollection': https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-iupdatecollection
            let update_count = updates.Count()?;

            // We will process each update in the collection
            let mut update_list: Vec<UpdateInfo> = Vec::new();

            // We will then setup variables for counting our classifications
            let mut critical_count = 0;
            let mut security_count = 0;
            let mut definition_count = 0;
            let mut feature_count = 0;
            let mut driver_count = 0;
            let mut other_count = 0;
            
            // This for loop will be used to grab information on our updates
            for i in 0..update_count { // We get updates at index i (COM collections are 0-indexed like Rust)

                // We need to access the properties of our updates by getting into the right interface, we start with 'IUpdate'
                // for more info on 'IUpdate': https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-iupdate
                let update = updates.get_Item(i)?;
                
                // We then head to 'IUpdate2' using the 'cast' method
                // for more info on 'IUpdate2': https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-iupdate2
                let update2: IUpdate2 = update.cast()?;

                // Lets grab the title of our update first
                let title = update.Title()?.to_string();

                // Then the size
                let max_size = update.MaxDownloadSize()?;
                let max_bytes = decimal_to_u128(max_size);
                let max_mb = max_bytes as f64 / 1024.0 / 1024.0;

                // Now lets get our collection of categories
                let categories = update2.Categories()?;

                // Next well make our classification variable
                let mut classification: Option<String> = None;

                // This for loop will be for getting the category name and id of our update
                for j in 0..categories.Count()? { 
                    let category = categories.get_Item(j)?;

                    // NOTE: We will get two types of categories for each update.
                    // 1. The update classification (UpdateClassification)
                    // 2. The product thats recieving the update (Product)
                    // For now we want the classification
                    
                    if category.Type()? == "UpdateClassification" {
                        // We grab the classification Name
                        classification = Some(category.Name()?.to_string());

                        // Then the ID of the classification
                        let id = category.CategoryID()?;

                        // Now we can grab a total count of each classification we have for our updates
                        // Each classification has an ID number attached to it so its easy to grab our counts like this
                        if id == CRITICAL_UPDATES_GUID {
                            critical_count += 1;
                        } else if id == SECURITY_UPDATES_GUID {
                            security_count += 1;
                        } else if id == DEFINITION_UPDATES_GUID {
                            definition_count += 1;
                        } else if id == FEATURE_UPDATES_GUID {
                            feature_count += 1;
                        } else if id == DRIVER_UPDATES_GUID {
                            driver_count += 1;
                        } else {
                            other_count += 1;
                        }
                    }
                }

                if let Some(classification) = classification {
                    update_list.push(UpdateInfo { 
                        title, 
                        classification,
                        max_mb,
                    });
                }
            }
            summary = UpdateSummary {
                total_count: update_count,
                critical_count: critical_count,
                security_count: security_count, 
                definition_count: definition_count,
                feature_count: feature_count,
                driver_count: driver_count,
                other_count: other_count, 
                update_list
            };
            
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
        Ok(summary)
    } // End of unsafe block
}