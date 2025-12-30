use std::mem::MaybeUninit;
use windows::core::*;
use windows::Win32::System::Variant::*;
use windows::Win32::System::Com::*;
use windows::Win32::System::Wmi::*;

struct ProductInfo {
    name: String,
    state: i32,
    is_active: bool,
    is_realtime: bool,
    defin_new: bool
}

/// Grabing antivirus for Windows
pub fn antivirus_wmi_api() -> Result<()> {
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
        if _com.is_err() { 
            return Err(_com.into()); // Error Check
        }

        { // Scope for WMI Objects
            /*
                WARDEN: Understanding WMI Objects and Memory Management

                This scope is meant to be a controlled enviroment for WMI objects

                1. Problem: Were dealing with 2 serious problems that must be dealt with accordingly:
                - COM initialization: We must uninitialize COM when done (Look at update module for more info on this)
                - VARIANT memory management: Windows allocates memory for VARIANT data

                2. Issue: When we call 'Get()' on a WMI object, Windows will fill a VARIANT struct and may allocate memory for it's contents. After we extract and use
                the data, the VARIANT still holds the allocated memory. If we don't free it, we leak memory on EVERY loop iteration. This is bad Mkay

                3. Solution: To solve this, we call a method known as 'VariantClear()'. Use this after every variant when your done using it BUT before it goes out
                of scope. This way it releases any memory Windows allocated. DON'T WAIT UNTIL IT GOES OUT OF SCOPE
            */


            // We first obtain the locator using CoCreateInstance which obtains a pointer
            let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)?;

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


            let mut all_products: Vec<ProductInfo> = Vec::new();


            loop { // Were just fetching each antivirus product with a loop...there is probably another way to do this but this works

                // The objects var allows us to store each complete antivirus product
                let mut objects = [None; 1];
                // This just tells us how many object were returned
                let mut returned = 0;

                // Now we use the 'Next()' method to fetch one product at a time, the second call will replace the last product with the next one...got it?
                // For more info on this method: https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-ienumwbemclassobject-next
                let _ = enum_object.Next(
                    WBEM_INFINITE, // This specifies the maximum amount of time in milliseconds that the call blocks before returning. Just stole this line from the page
                    &mut objects, // This should point to a storage to hold the number of IWbemClassObject interface pointers specified by uCount
                    &mut returned // This receives the number of objects returned.
                );

                // If there is nothing to look at, why bother
                if returned == 0 {
                    break;
                }

                if let Some(class_object) = &objects[0] {

                    // And because I definitely knew I wanted to put these results in a struct, I made a helper function
                    // and totaly didn't stick this all in one block
                    // Were putting the class_object in obj and "displayName" in our name search
                    let name = string_property(class_object, "displayName")?;

                    // Heres the other one for the product state...same deal as above
                    let state = integer_property(class_object, "productState")?;
                    // Reminder: Use "0x{:X} for hexadecimal"

                    // Now we can look at the hexadecimal number for the product state, when looking at the state, we are looking at three sets of bits
                    // Just so you have an understanding of what your looking at, Here are the bits placement
                    // (0xF0000) Acts as the identifier for the product (e.g. 6 = Windows Defender)
                    // (0x0FF00) Tells us if the product is enabled or disabled (e.g 10 = Windows Defender Enabled or 01 = Windows Defender Disabled)
                    // (0x000FF) Will show us if our definitions are up to date (e.g 00 = Definitions Up-to-date or 10 = Need updating)
                    let is_active = ((state >> 12) & 0xF) != 0;
                    let is_realtime = ((state >> 12) & 0xF) == 1;
                    let defin_new = (state & 0xFF) == 0x00;

                    let product = ProductInfo {
                        name: name,
                        state: state,
                        is_active: is_active,
                        is_realtime: is_realtime,
                        defin_new: defin_new
                    };
                    all_products.push(product);
                    
                    
                }
            } // End of loop

            display_antivirus(&all_products);
        } // End of scope
        CoUninitialize();
    }// End of unsafe block
    Ok(())
}


fn string_property(obj: &IWbemClassObject, name: &str) -> Result<String> {
    unsafe {
        // This should create uninitialized memory for a VARIANT struct, with all bytes set to zero
        // .....I think thats how that works
        let mut variant = MaybeUninit::<VARIANT>::zeroed();

        // Now were gonna fill that memory with the information below
        // For more info on this method: https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-get
        obj.Get(
            &BSTR::from(name), // Name of the property were wanting
            0, // This must be zero....I don't know why but it does
            variant.as_mut_ptr(), // When successful, this assignes the correct type and value for the qualifier
            None, // Were leaving this NULL
            None // This one will be NULL too
        )?;

        // Now I am gonna try to explain this to the best of my ability
        // The 'assume.init()' is us saying that the memory is now properly initialized...because we %100 know thats right...right?
        let mut variant = variant.assume_init();

        // VARIANT is a C union wrapped in Rust structs
        // vt = "variant type" (16-bit integer)
        // VT_BSTR means this VARIANT contains a BSTR string
        // The double 'Anonymous' is because of Rusts representation of C unions
        let result = if variant.Anonymous.Anonymous.vt == VT_BSTR {
            // The third 'Anonymous' contains all the possible value types like bstrVal, lVal, boolVal, and more
            let bstr_ptr = &variant.Anonymous.Anonymous.Anonymous.bstrVal;
            // From here we are basically converting the BSTR string to a Rust String
            BSTR::from_wide(&bstr_ptr).to_string()
        } else {
            "Unknown".to_string()
        };

        // THIS IS IMPORTANT...PAY ATTENTION
        // When we are done using our VARIANT we have to dispose of it properly, otherwise we'll have a memory leak
        // This is because Windows allocated memory for the variant and that will continue to use up memory if not cleared
        // So we'll use 'VariantClear()' on EACH VARIANT after your done using it and BEFORE it leaves scope
        VariantClear(&mut variant)?;
        Ok(result)
    }
}

fn integer_property(obj: &IWbemClassObject, name: &str) -> Result<i32> {
    unsafe {
        // This should create uninitialized memory for a VARIANT struct, with all bytes set to zero
        // .....I think thats how that works
        let mut variant = MaybeUninit::<VARIANT>::zeroed();

        // Now were gonna fill that memory with the information below
        // For more info on this method: https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-get
        obj.Get(
            &BSTR::from(name), // Name of the property were wanting
            0, // This must be zero
            variant.as_mut_ptr(), // When successful, this assignes the correct type and value for the qualifier
            None, // Were leaving this NULL
            None // This one will be NULL too
        )?;

        // The last one worked...so should this one
        let mut variant = variant.assume_init();

        // Because were grabing an integer were gonna use VT_I4 instead
        let result = if variant.Anonymous.Anonymous.vt == VT_I4 {
            // Then we'll use lVal which is used for long/32-bit integers
            variant.Anonymous.Anonymous.Anonymous.lVal
        } else {
            67
        };

        // CLEAN UP
        VariantClear(&mut variant)?;
        Ok(result)
    }
}

fn display_antivirus(products: &Vec<ProductInfo>) {
    println!("\n{} Antivirus Product(s) Available", products.len());
    println!("{}", "=".repeat(30));

    if products.is_empty() {
        println!("Found No Antivirus");
        return;
    }

    for (i, prod) in products.iter().enumerate() {
        println!("{}. {}", i + 1, prod.name);
        println!("  - Is Running: {}", if prod.is_active {"Yes"} else {"No"});
        println!("  - Real-Time Protection: {}", if prod.is_realtime {"On"} else {"Off"});
        println!("  - Definitions Up-to-date: {}", if prod.defin_new {"Yes"} else {"No"});
        println!("  - Product State: 0x{:X}\n", prod.state);
    }
}