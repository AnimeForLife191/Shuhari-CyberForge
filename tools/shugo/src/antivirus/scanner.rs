//! Welcome to Shuhari CyberForge, a 
//! 

use windows::core::*; 
use windows::Win32::System::Com::*;
use windows::Win32::System::Wmi::*;
use crate::common::wmi_helpers::{string_property, integer_property};

pub struct ProductInfo {
    pub name: String,
    pub state: i32,
    pub is_active: bool,
    pub is_realtime: bool,
    pub definitions_new: bool
}

/// Grabing antivirus for Windows
pub fn scan_antivirus() -> Result<Vec<ProductInfo>> {
   
    unsafe { // We use windows unsafe block here because were using foreign functions that are unsafe with Rust
        /*
            WARDEN: COM Apartments

             As you see we are using 'CoInitializeEx(None, COINIT_MULTITHREADED)'. This initializes:
            - MTA (Multi-Threaded Apartment): Objects can move between threads
            - Alternative: STA (Single-Threaded) with 'CoInitialize(None)'

            Why use MTA for WARDEN, well why not....WARDEN might use threads later so trying to learn it now is better.
            Its also more flexible for system tools.

            The trade off of using MTA is the cleanup
        */

        let _com = CoInitializeEx(None, COINIT_MULTITHREADED);
        if _com.is_err() { // Error Handling
            println!("Error with COM initilaization in Antivirus module");
            return Err(_com.into());
        }

        // Vec for antivirus products
        let mut all_products: Vec<ProductInfo> = Vec::new();

        { // Scope for WMI Objects
            /*
                WARDEN: Understanding WMI Objects and Memory Management

                This scope is meant to be a controlled enviroment for WMI objects

                1. Problem: Were dealing with 2 serious problems that must be dealt with accordingly:
                - COM initialization: We must uninitialize COM when done (Look at Update module for more info on this)
                - VARIANT memory management: Windows allocates memory for VARIANT data

                2. Issue: When we call 'Get()' on a WMI object, Windows will fill a VARIANT struct and may allocate memory for it's contents. After we extract and use
                the data, the VARIANT still holds the allocated memory. If we don't free it, we leak memory on EVERY loop iteration. This is very bad Mkay

                3. Solution: To solve this, we call a method known as 'VariantClear()'. Use this after every variant when your done using it BUT before it goes out
                of scope. This way it releases any memory Windows allocated. DON'T WAIT UNTIL IT GOES OUT OF SCOPE
            */


            // We first obtain the locator using CoCreateInstance which obtains a pointer
            let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)?;
            // Why do we use 'CLSCTX_INPROC_SERVER' here?
            // For information on CLSCTX: https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ne-wtypesbase-clsctx

            // Then we grab the namespace path which is "ROOT\\SecurityCenter2" in BSTR format
            let namespace_path = BSTR::from("ROOT\\SecurityCenter2");

            // Now the fun part, We can connect to the namespace on the computer using 'ConnectServer()'
            // If you want more info on this method: https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemlocator-connectserver
            let services = locator.ConnectServer(
                &namespace_path, // This is the pointer to the specified namespace. This requires a valid BSTR
                &BSTR::default(), // This is for a user name for the connection, we'll use '&BSTR::default()' as NULL for this pointer. Their might be a "right way" to do this
                &BSTR::default(), // This is for a password for the connection
                &BSTR::default(), // This is for local
                0, // This is for flags. we'll use '0' for this value because it will return the call from 'ConnectServer' only after its established
                &BSTR::default(), // This can contain the name of the domain of the user to authenticate
                None // This is usually NULL
            )?;

            // This should look familiar to some of you, were basically grabing specific information we need
            let query = BSTR::from("Select displayName, productState FROM AntiVirusProduct");

            // This will execute a query to retrieve our objects
            // For more info on this method: https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-execquery
            let enum_object = services.ExecQuery(
                &BSTR::from("WQL"), // This specifies the query language to use supported by Windows and it MUST be "WQL". Windows says that not me
                &query, // This is where the query search will go. It cannot be NULL...why are you trying to search for nothing
                WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY, // This is where flags go and they affect the behavior of this method.
                None // This is usually NULL
            )?;

            loop { // Were just fetching each antivirus product with a loop...there is probably another way to do this but this works

                // The objects var allows us to store each complete antivirus product
                let mut objects = [None; 1];
                // This just tells us how many object were returned
                let mut returned = 0;

                // Now we use the 'Next()' method to fetch one product at a time, the second call will replace the last product with the next one...got it?
                // For more info on this method: https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-ienumwbemclassobject-next
                let _ = enum_object.Next(
                    WBEM_INFINITE, // This specifies the maximum amount of time in milliseconds that the call blocks before returning. I stole this line from the page
                    &mut objects, // This should point to a storage to hold the number of IWbemClassObject interface pointers specified by uCount
                    &mut returned // This receives the number of objects returned.
                );

                // If there is nothing to look at, why bother
                if returned == 0 {
                    break;
                }

                // Lets go through the objects now if any and see what we get
                if let Some(class_object) = &objects[0] {

                    // Now we need to convert our Windows information to be usable in Rust
                    // In 'common/wmi_helpers.rs' you'll find these functions
                    // Were putting class_object in obj and "displayName" in our name search
                    let name = string_property(class_object, "displayName")?;

                    // Heres the other one for the product state...same deal as above
                    let state = integer_property(class_object, "productState")?;
                    // Reminder: Use "0x{:X} for hexadecimal"

                    /*
                        WARDEN: BIT LOGIC

                        Their are many different Antivirus products out their and all keep the same bit logic for two bits...I think. 
                        (0xFF000): The (0xF0) represents the product ID while (0x0F) represents weather the product is enabled or disabled.
                        For example here is a Third party antivirus:
                        (0x40) = Disabled
                        (0x41) = Enabled
                        (0x42) = Realtime protection off but antivirus active
                        and with Windows Defender:
                        (0x60) = Disabled
                        (0x61) = Enabled
                        (0x62) = Realtime protection off but antivirus active
                        I want to point out I am not a professional at this, I am still learning how this works and for all I know
                        this could be the wrong way to explain it and for that I'm sorry. But this is how I think it works.
                    */
                    let is_active = ((state >> 12) & 0xF) != 0;
                    let is_realtime = ((state >> 12) & 0xF) == 1;
                    // For this were looking at (0x600FF) to see if definitions are up-to-date
                    let definitions_new = (state & 0xFF) == 0x00;
                    // I feel like this is confusing for a lot of people and I can see why if it is. Any decent information I found
                    // on how this works was still confusing, so hopefully this can be solved and explained more clearly in the future
                    // as SysDefense grows. As for now, I'll use https://stackoverflow.com/questions/4700897/wmi-security-center-productstate-clarification
                    // for information gathering on understanding the bit logic

                    // Pushing information to struct
                    let product = ProductInfo {
                        name: name,
                        state: state,
                        is_active: is_active,
                        is_realtime: is_realtime,
                        definitions_new: definitions_new
                    };
                    all_products.push(product);
                    
                    
                }
            } // End of loop
        } // End of scope
        CoUninitialize();
        Ok(all_products)
    }// End of unsafe block
}