//! This is the Windows Update Module for Shugo. We are able to see:
//! 
//! - Pending Windows Updates
//! - Update Classification (Critical, Security, Definition, Feature, Driver)
//! - Update Sizes (Min and Max)
//! - Update Products (what software/component is being updated)
//! - Update Descriptions
//! 
//! Unlike the Antivirus Module which uses WMI, this module interfaces directly with the
//! Windows Update Agent (WUA) API. This requires more complex COM interactions but 
//! provides detailed update information directly from Windows Update Services.
//! 
//! Note: Depending on your network and computer hardware, Scanning for updates can 
//! take around 5-30 seconds as it queries Microsoft's servers.

use windows::Win32::System::Com::*;
use windows::Win32::System::UpdateAgent::*;
use windows::Win32::Foundation::*;
use windows::core::*;

use crate::common::wmi_helpers::decimal_to_u128;

pub struct UpdateInfo {
    pub title: String,
    pub classification: String,
    pub min_mb: f64,
    pub max_mb: f64,
    pub product: String,
    pub description: String
}

pub struct UpdateSummary {
    pub total_count: i32,
    pub critical_count: i32,
    pub security_count: i32,
    pub definition_count: i32,
    pub feature_count: i32,
    pub driver_count: i32,
    pub other_count: i32,
    pub update_list: Vec<UpdateInfo>,
    pub query: String
}

/// Update Classification GUIDs
/// 
/// These are Microsoft's official GUIDs for update categories used by
/// the Windows Update Agent API to identify different types of updates.
const CRITICAL_UPDATES_GUID: &str = "e6cf1350-c01b-414d-a61f-263d14d133b4";
const SECURITY_UPDATES_GUID: &str = "0fa1201d-4330-4fa8-8ae9-b877473b6441";
const DEFINITION_UPDATES_GUID: &str = "e0789628-ce08-4437-be74-2495b842f43b";
const FEATURE_UPDATES_GUID: &str = "b54e7d24-7add-428f-8b75-90a396fa584f";
const DRIVER_UPDATES_GUID: &str = "ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0";

/// Grabbing updates for Windows
pub fn scan_updates() -> Result<UpdateSummary> {
    unsafe {
        /* 
            Shugo: COM Library Initialization

            Just like in the Antivirus Module, we need to initialize COM before
            using any Windows Update APIs. We're using COINIT_MULTITHREADED for
            consistency across all of Shugo's modules.

            For more information on `CoInitializeEx`:
            (https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializeex) - C++
            (https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Com/fn.CoInitializeEx.html) - Rust
        */
        let _com: HRESULT = CoInitializeEx(
            None, 
            COINIT_MULTITHREADED
        );

        match _com { 
            S_OK => {
                // COM initialized successfully
            },
            E_OUTOFMEMORY => {
                println!("COM initialization failed: Out of memory");
                return Err(_com.into());
            },
            E_INVALIDARG => {
                println!("COM initialization failed: Invalid argument");
                return Err(_com.into());
            },
            E_UNEXPECTED => {
                println!("COM initialization failed: Unexpected error");
                return Err(_com.into());
            }
            _ => {
                println!("COM initialization failed with HRESULT: 0x{:?}", _com);
                return Err(_com.into());
            }
        }

        let summary: UpdateSummary;

        {
            /*
                Shugo: Creating an Update Session

                Before we can grab updates, we need to make a session for the Windows Update Agent. Now as you can see we're 
                using `CLSCTX_ALL` instead of `CLSCTX_INPROC_SERVER` like we did in the Antivirus Module. Why do you think that is?

                The Windows Update service may run in a different process or even as a system service and `CLSCTX_ALL` allows COM
                to find it regardless of where it's running.

                For more information on `IUpdateSession`:
                (https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-iupdatesession) - C++
                (https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/UpdateAgent/struct.IUpdateSession.html) - Rust
            */
            let session: IUpdateSession = CoCreateInstance(
                &UpdateSession, 
                None, 
                CLSCTX_ALL
            )?;

            /*
                Shugo: Creating an Update Searcher

                We need an interface to search for our updates, to do that we use the `CreateUpdateSearcher` method from our `IUpdateSession`
                interface. This gives us an `IUpdateSearcher` interface which can search for updates on Windows servers.

                For more information on `IUpdateSearcher`: 
                (https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-iupdatesearcher) - C++
                (https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/UpdateAgent/struct.IUpdateSearcher.html) - Rust
            */
            let searcher: IUpdateSearcher = session.CreateUpdateSearcher()?;
            

            /*
                Shugo: Searching for Updates

                Using our `IUpdateSeacher` interface, we now have multiple methods we can use to get updates. We'll be using the method
                `Search` which performs a synchronous search for updates using a criteria in `BSTR` format. We'll use the criteria
                "IsInstalled=0". This tells the search to look for updates we haven't installed yet.

                Note: This is why the Update Module takes so long to grab information. We have to grab the updates from Windows servers
                which can take 5-30 seconds.

                For more information on `Search`:
                (https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdatesearcher-search) - C++
                (https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/UpdateAgent/struct.IUpdateSearcher.html#method.Search) - Rust
            */
            let search_criteria: BSTR = BSTR::from("IsInstalled=0");
            println!("Grabbing Updates, this may take 5-30 seconds...");
            let data: ISearchResult = searcher.Search(&search_criteria)?;

            /*
                Shugo: Grabbing Updates

                Once the search is complete, we then need to get our updates from that search. To do this we use the `Updates` method
                which will grab those updates and give us an `IUpdateCollection` interface. This allows us to work with our collection 
                of updates with multiple different methods.
                
                For example, we'll use the `Count` method to grab the total count of updates we have in our collection.

                For more information on `IUpdateCollection`: 
                (https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-iupdatecollection) - C++
                (https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/UpdateAgent/struct.IUpdateCollection.html) - Rust
            */
            let updates: IUpdateCollection = data.Updates()?;
            let update_count = updates.Count()?;

            let mut update_list: Vec<UpdateInfo> = Vec::new(); // Initializing Vector for updates

            // Counts For different classifications
            let mut critical_count = 0;
            let mut security_count = 0;
            let mut definition_count = 0;
            let mut feature_count = 0;
            let mut driver_count = 0;
            let mut other_count = 0;
            
            /*
                Shugo: Detail Gathering

                Now lets get our updates details. This for loop will go through each update gathering information like
                Title, Size, and Classification. We'll be using a lot of different methods here so don't worry if you
                lose track.
            */
            for i in 0..update_count { // We get updates at index i (COM collections are 0-indexed like Rust)

                /*
                    Shugo: Setting Up IUpdate Interface

                    We'll use the `get_Item` method which gets or sets an `IUpdate` interface in a collection. Their are multiple 
                    different `IUpdate` interfaces that we can use but this one gives us all the options we need.

                    For more information on `IUpdate`:
                    (https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-iupdate) - C++
                    (https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/UpdateAgent/struct.IUpdate.html) - Rust
                */
                let update: IUpdate = updates.get_Item(i)?;

                /*
                    Shugo: Update Size

                    To get our update size, we can use the methods `MaxDownloadSize` or `MinDownloadSize`. This will give us either a 
                    maximum size for a download or a minimum size. These sizes can vary massively as using `MaxDownloadSize` will
                    give us a size for worst case scenerio. Meaning a simple definitions update can say 1.5GB but will most likely
                    only be less than 1MB. Keep that in mind when using these methods.

                    Now we need to convert our DECIMAL type to a u128 type. For further information on how this works go to the helper
                    function in: `tools\shugo\src\common\wmi_helpers.rs`

                    Finally, we convert the u128 type to a f64 type and divide it by 1024.0 to get kilobytes (KB). Then divide it again
                    by 1024.0 one more time to get megabytes (MB).

                    For more information on `MaxDownloadSize` and MinDownloadSize:
                    (https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdate-get_maxdownloadsize) - MaxDownloadSize
                    (https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdate-get_mindownloadsize) - MinDownloadSize
                */
                let min_size: DECIMAL = update.MinDownloadSize()?;
                let max_size: DECIMAL = update.MaxDownloadSize()?;
                let min_bytes: u128 = decimal_to_u128(min_size);
                let max_bytes: u128 = decimal_to_u128(max_size);
                let min_mb: f64 = min_bytes as f64 / 1024.0 / 1024.0;
                let max_mb: f64 = max_bytes as f64 / 1024.0 / 1024.0;

                /*
                    Shugo: Update Title

                    Titles of updates can be grabbed easily using the `Title` method and converting it to a `String` type.

                    For more information on `Title`:
                    (https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdate-get_title) - C++
                */
                let title: String = update.Title()?.to_string();

                /*
                    Shugo: Update Categories

                    By using the `Categories` method, we can get the categories of the update and put them in a 
                    `ICategoryCollection` interface.
                    
                    Now we'll do a for loop here for two reasons:
                    - The first is you get two categories for each update, the update classification (UpdateClassification)
                    and the product receiving it (Product). We filter both types so we can display what's being updated
                    and what kind of update it is.
                    For more information on `Type`:
                    (https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-icategory-get_type) - C++

                    - The second reason is so we can grab a count of how many classifications of each type we have. Each 
                    (UpdateClassification) is tied to a GUID from Windows, this makes it easy to filter the classifications
                    using the `CategoryID` method.
                    For more information on `CategoryID`:
                    (https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-icategory-get_categoryid) - C++
                */
                let categories: ICategoryCollection = update.Categories()?;
                let mut classification: Option<String> = None; // Classification variable
                let mut product: Option<String> = None;

                for j in 0..categories.Count()? { 
                    let category: ICategory = categories.get_Item(j)?;
                    
                    if category.Type()? == "UpdateClassification" {
                       
                        classification = Some(category.Name()?.to_string());  // Grabbing the classification Name

                        let id: BSTR = category.CategoryID()?; // ID of the classification

                        // Grabbing count of classification type
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
                    } else if category.Type()? == "Product" {
                        product = Some(category.Name()?.to_string());
                    }
                }

                /*
                    Shugo: Update Description

                    Using the `Description` method we can grab the description of the update from Windows Update Agent.
                    This should always be filled and should never return empty.

                    For more information on `Description`:
                    (https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdate-get_description) - C++
                */
                let description: String = update.Description()?.to_string();

                if let (Some(classification), Some(product)) = (classification, product) {
                    update_list.push(UpdateInfo { 
                        title, 
                        classification,
                        min_mb,
                        max_mb,
                        product,
                        description
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
                update_list,
                query: search_criteria.to_string() 
            };
        }
        /*
            Shugo: Closing Thread

            Just like in the antivirus module, we must uninitialize COM when we're done.

            For more information on `CoUninitialize`:
            (https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-couninitialize) - C++
            (https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Com/fn.CoUninitialize.html) - Rust
        */
        CoUninitialize();
        Ok(summary)
    } // End of unsafe block
}