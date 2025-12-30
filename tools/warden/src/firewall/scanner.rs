use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::System::Variant::*;
use windows::Win32::System::Com::*;
use windows::Win32::System::Wmi::*;
use windows::Win32::NetworkManagement::WindowsFirewall::*;
use std::mem::MaybeUninit;

struct WindowsFirewallProfile {
    public: bool,
    private: bool,
    domain: bool
}

struct FirewallProductInfo {
    name: String,
    state: i32,
    is_active: bool
}

/// Grabing firewall for Windows
pub fn firewall_com_api() -> Result<()> {
    unsafe {
        /* 
            WARDEN - Firewall Module

            This module is closely similar to the Antivirus Module. So similar that I copied the logic of the antivirus product and changed a single argument.
            The Firewall module is also one of the easiest to make and understand with all you needing is a few lines of code to make it work.

            Here is how it works:
        */

        // 1. We must initialize a thread
        let _com = CoInitializeEx(None, COINIT_MULTITHREADED);
        if _com.is_err() {
            return Err(_com.into());
        }

        // This vector is for the profiles of public, private, and domain. Do we need a Vec for this, no...but it works
        let mut firewall_profiles: Vec<WindowsFirewallProfile> = Vec::new();

        {
            // 2. We gain access to the firewall policy
            let policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, CLSCTX_ALL)?;

            // 3. Now we can get a profile status for the profiles
            let public_fw = {
                // We first use the 'get_FirewallEnabled' method with the profiletype we want as an arg
                let firewall = policy.get_FirewallEnabled(NET_FW_PROFILE2_PUBLIC)?;
                // Then we want to turn the VARIANT_BOOL we get to a Rust bool by using the VARIANT_TRUE method
                // There is a VARIANT_FALSE so don't get them confused
                firewall == VARIANT_TRUE
            };

            // And Thats it, now you can see the status of different profiles types
            // NOTE: This seems to only grab information of Windows Defenders Profiles, Not a third party Firewall
            // for example, you can turn off the Windows Defender firewall but a third party software will still have their firewall active

            let private_fw = {
                let firewall = policy.get_FirewallEnabled(NET_FW_PROFILE2_PRIVATE)?;
                firewall == VARIANT_TRUE
            };

            let domain_fw = {
                let firewall = policy.get_FirewallEnabled(NET_FW_PROFILE2_DOMAIN)?;
                firewall == VARIANT_TRUE
            };

            let firewalls = WindowsFirewallProfile {
                public: public_fw,
                private: private_fw,
                domain: domain_fw
            };

            firewall_profiles.push(firewalls);
            // Now if you want to grab the name of the different Firewall Products you have like the antivirus, we can reuse our Antivirus code here
            // logic from antivirus module
            let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)?;
            let namespace_path = BSTR::from("ROOT\\SecurityCenter2");
            let services = locator.ConnectServer(
                &namespace_path, // This is the pointer to the specified namespace. This requires a valid BSTR
                &BSTR::default(), // This is for a user name for the connection, we'll use '&BSTR::default()' as NULL for this pointer. Their might be a "right way" to do this
                &BSTR::default(), // This is for a password for the connection
                &BSTR::default(), // This is for local
                0, // This is for flags. we'll use '0' for this value because it will return the call from 'ConnectServer' only after its established
                &BSTR::default(), // This can contain the name of the domain of the user to authenticate
                None // This is usually NULL
            )?;

            // THIS IS THE LINE, instead of using AntiVirusProduct we use FirewallProduct
            let query = BSTR::from("Select displayName, productState FROM FirewallProduct");
            let enum_object = services.ExecQuery(
                &BSTR::from("WQL"), // This specifies the query language to use supported by Windows and it MUST be "WQL". Windows says that not me
                &query, // This is where the query search will go. It cannot be NULL...why are you trying to search for nothing
                WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY, // This is where flags go and they affect the behavior of this method.
                None // This is usually NULL
            )?;

            let mut firewall_products: Vec<FirewallProductInfo> = Vec::new();
            loop { 
                let mut objects = [None; 1];
                let mut returned = 0;
                let _ = enum_object.Next(
                    WBEM_INFINITE, // This specifies the maximum amount of time in milliseconds that the call blocks before returning. Just stole this line from the page
                    &mut objects, // This should point to a storage to hold the number of IWbemClassObject interface pointers specified by uCount
                    &mut returned // This receives the number of objects returned.
                );
                if returned == 0 {
                    break;
                }

                if let Some(class_object) = &objects[0] {
                    let fw_name = string_property(class_object, "displayName")?;
                    let fw_state = integer_property(class_object, "productState")?;
                    let fw_active = ((fw_state >> 12) & 0xF) != 0;

                    let product = FirewallProductInfo {
                        name: fw_name,
                        state: fw_state,
                        is_active: fw_active
                    };

                    firewall_products.push(product);
                }
            }
            display_firewall(&firewall_profiles, &firewall_products);
        }
        CoUninitialize();
    }
    Ok(())
}

fn display_firewall(firewall: &Vec<WindowsFirewallProfile>, firewall_product: &Vec<FirewallProductInfo>) {
        println!("\n{} Firewall Product(s) Available:", firewall_product.len());
        println!("{}", "=".repeat(30));
        if firewall_product.is_empty() {
            println!("No Third Party Firewalls Detected");
            println!("Note: Windows Defender is most likely active as your firewall. It won't show up here.");
        } else {
            for (i, product) in firewall_product.iter().enumerate() {
                println!("{}. {}", i + 1, product.name);
                println!("  - Active: {}", if product.is_active {"Yes"} else {"No"});
                println!("  - State: 0x{:X}\n", product.state);
            }
        }
    

    for profile in firewall.iter() {
        println!("Public Firewall {}", if profile.public {"On"} else {"Off"});
        println!("Private Firewall {}", if profile.private {"On"} else {"Off"});
        println!("Domain Firewall {}\n", if profile.domain {"On"} else {"Off"});
    }
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