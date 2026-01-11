//! This is the Antivirus Module for Shugo. We are able to see:
//! 
//! - Antivirus Products
//! - Antivirus Status's
//! - Product States
//! 
//! Lets see how we grab that information:

use windows::core::*; 
use windows::Win32::System::Com::*;
use windows::Win32::System::Wmi::*;
use windows::Win32::Foundation::*;
use crate::common::wmi_helpers::{string_property, integer_property};

pub struct ProductInfo {
    pub name: String,
    pub state: i32,
    pub product_status: i32,
    pub definition_status: i32,
    pub product_owner: i32
}

/// Grabing Antivirus Products for Windows
pub fn scan_antivirus() -> Result<Vec<ProductInfo>> {
    
    // We'll be using the unsafe method a lot because were using foreign functions that
    // the Rust compiler can't check. This is our way of saying to Rust "Don't worry, we -
    // made sure this is handled safely" at least I'm sure it's safe.
    unsafe {
        /* 
            Shugo: COM Library

            Before we do anything, we need to initialize the COM library for use by the
            calling thread. This is usually only called once for each thread that uses
            the COM library.

            For more information on `CoInitializeEx`:
            (https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializeex) - C++
            (https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Com/fn.CoInitializeEx.html) - Rust
        */
        let _com: HRESULT = CoInitializeEx(
            None, // This has to be NULL as its already reserved
            COINIT_MULTITHREADED // This specifies the concurrency model and initialization options for the thread
        );

        // Lets make sure the errors we could possibly get are dealt with.
        // Were leaving out a couple errors as they shouldn't matter here.
        match _com { 
            S_OK => {
                // COM initialized successfully
            },
            E_OUTOFMEMORY => {
                // Memory problem occured
                println!("COM initialization failed: Out of memory");
                return Err(_com.into());
            },
            E_INVALIDARG => {
                // Invalid argument was passed
                println!("COM initialization failed: Invalid argument");
                return Err(_com.into());
            },
            E_UNEXPECTED => {
                // Something unexpected happened
                println!("COM initialization failed: Unexpected error");
                return Err(_com.into());
            }
            _ => {
                println!("COM initialization failed with HRESULT: 0x{:?}", _com);
                return Err(_com.into());
            }
        }

        // This vector will be used to hold our product information using our struct
        let mut all_products: Vec<ProductInfo> = Vec::new();

        {
            /*
                Shugo: Object Management

                You might be wondering why were using a big scope here. This scope will manage our objects we call using
                `CoCreateInstance` and drop them when they leave this scope.

                "Why do we need to drop them?":
                If we don't drop these objects, we can't close our thread. This turns into a memory leak which we don't want.

                "Shouldn't Rust be able to destroy these objects?":
                Rust will handle these objects by itself but it causes problems. When Rust destroys the objects, Windows still
                thinks their active, making us unable to close the thread. So we drop them manually.

                For more information on `CoCreateInstance`:
                (https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance) - C++
                (https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Com/fn.CoCreateInstance.html) - Rust
            */
            let locator: IWbemLocator = CoCreateInstance(
                &WbemLocator, // The CLSID associated with the data and code that will be used to create the object
                None, // Leaving NULL because object is not being created as part of an aggregate
                CLSCTX_INPROC_SERVER // The context in which the code that manages the newly created object will run
            )?;


            /*
                Shugo: WMI Connection

                We'll be using the `ConnectServer` method to make a connection through DCOM to a WMI namespace on the computer.
                The namespace needs to be in `BSTR` format otherwise it won't work. Most of the arguments in `ConnectServer`
                must be in `BSTR` format besides two.

                For more information on `ConnectServer`:
                (https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemlocator-connectserver) - C++
                (https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Wmi/trait.IWbemLocator_Impl.html#tymethod.ConnectServer) - Rust
            */
            let namespace_path: BSTR = BSTR::from("ROOT\\SecurityCenter2");
            let services: IWbemServices = locator.ConnectServer(
                &namespace_path, // This is the pointer to the specified namespace
                &BSTR::default(), // user name for the connection, we'll use '&BSTR::default()' as NULL for this pointer
                &BSTR::default(), // Password for the connection
                &BSTR::default(), // locale for connection
                0, // This is for flags. we'll use '0' for this value because it will return the call from `ConnectServer` only after its established
                &BSTR::default(), // This can contain the name of the domain of the user to authenticate
                None // This is usually NULL
            )?;
            

            /*
                Shugo: Querying Objects

                We can now look for the objects we want using the `ExecQuery` method. Because we want to grab the 
                Antivirus Products names and state we'll query "Select displayName, productState FROM AntiVirusProduct".

                For more information on `ExecQuery`:
                (https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-execquery) - C++
                (https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Wmi/struct.IWbemServices.html#method.ExecQuery) - Rust
            */
            let query: BSTR = BSTR::from("Select displayName, productState FROM AntiVirusProduct");
            let enum_object: IEnumWbemClassObject = services.ExecQuery(
                &BSTR::from("WQL"), // This specifies the query language to use supported by Windows and it MUST be "WQL", the acronym for WMI Query Language.
                &query, // This is where the query search will go. It cannot be NULL
                WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY, // This is where flags go and they affect the behavior of this method
                None // This is usually NULL
            )?;

            loop {

                /*
                    Shugo: Grabing Antivirus Information

                    We finally have the information we need from our query, now we need to extract it so we can use it.
                    Were using the `Next` method for `IWbemClassObject` to grab our objects. We'll also use two helper functions 
                    that you can find in `tools\shugo\common\wmi_helpers`. Go check them out to see how we convert `VARIANT` and `BSTR`.

                    For more information on `Next`:
                    (https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-ienumwbemclassobject-next) - C++
                    (https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Wmi/struct.IEnumWbemClassObject.html) - Rust
                */
                let mut objects: [Option<IWbemClassObject>; 1] = [None; 1];
                let mut returned = 0;
                let _ = enum_object.Next(
                    WBEM_INFINITE, // This specifies the maximum amount of time in milliseconds that the call blocks before returning. I stole this line from the page
                    &mut objects, // This should point to a storage to hold the number of IWbemClassObject interface pointers specified by uCount
                    &mut returned // This receives the number of objects returned.
                );
                if returned == 0 {
                    break;
                }
                if let Some(class_object) = &objects[0] {
                    let name = string_property(class_object, "displayName")?; // Helper function for grabbing displayName
                    let state = integer_property(class_object, "productState")?; // Helper function for grabbing productState

                    /*
                        Shugo: Bit Logic

                        Antivirus products carry a unique set of numbers called a product state in Decimal format. We can use the product state to see 
                        what state the antivirus is in. Before we go further, we must understand what were looking at. Now I can't find any decent 
                        information on the bit logic of the antivirus product state so information here must be taken with a grain of salt as this could be wrong. 
                        Here we go:

                        Let's say our product state is `397568`

                        To turn our product state into a hex digit value we need to do some math. 
                        Specifically division, take the product state and divide it by 16:

                        397568 / 16 = 24848, Remainder: 0
                        24848 / 16 = 1553,   Remainder: 0
                        1553 / 16 = 97,      Remainder: 1
                        97 / 16 = 6,         Remainder: 1
                        6 / 16 = 0,          Remainder: 6

                        Sweet, now we have our 8 hex digit number: 0x00061100
                        We'll cut out the 3 empty hex digits as they don't get used, I think
                        Now were left with a 5 hex digit number: 0x61100
                        
                        Now we could stop here but to make sure we know what information were looking at, 
                        we'll go one step further into making it binary:

                        Binary:  0110   00010001   00000000
                              [19-16]   [15 - 8]    [7 - 0]                  

                        Every 8 bits is a byte, we'll use these bytes to find our information more clearly. We'll go from right to left
                        and to represent the hex digit were looking at, I'll put `F` in their place:

                        Bits 0-7:
                        Signature Status (0x611FF): 00 = UpToDate signatures, 10 = OutOfDate signatures

                        Bits 8-11:
                        Product Owner (0x61F00): 1 = Windows, 0 = ThirdParty

                        Bits 12-15:
                        Product State (0x6F100): 0 = Off, 1 = On, 2 = Snoozed, 3 = Expired

                        Bits 16-19:
                        I am unsure of these four bits. I think it might just be an identifier, either way we dont use it.

                        Now remember, this could be totally wrong and some third party antivirus's don't always follow this format.
                    */
                    let definition_status = state & 0xFF;
                    let product_owner = (state >> 8) & 0xF;
                    let product_status = (state >> 12) & 0xF;
                    let product = ProductInfo {
                        name,
                        state,
                        product_status,
                        definition_status,
                        product_owner
                    };
                    all_products.push(product);
                    
                    
                }
            }
        }
        /*
            Shugo: Closing The Thread

            When we open a COM connection through a thread, we must close that thread when we're done. To do that
            we use `CoUninitialize`. Their are multiple different use cases for `CoUninitialize` and it must be
            used correctly according to how a thread was opened.

            For more information on `CoUninitialize`:
            (https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-couninitialize) - C++
            (https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Com/fn.CoUninitialize.html) - Rust
        */
        CoUninitialize();
        Ok(all_products)
    }// End of unsafe block
}