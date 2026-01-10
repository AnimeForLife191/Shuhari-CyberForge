use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::System::Com::*;
use windows::Win32::System::Wmi::*;
use windows::Win32::NetworkManagement::WindowsFirewall::*;

use crate::common::wmi_helpers::{string_property, integer_property};

pub struct WindowsFirewallProfile {
    pub public: bool,
    pub private: bool,
    pub domain: bool
}

pub struct FirewallProductInfo {
    pub name: String,
    pub state: i32,
    pub is_active: bool
}

/// Grabing firewall for Windows
pub fn scan_firewall() -> Result<(WindowsFirewallProfile, Vec<FirewallProductInfo>)> {
    /* 
        WARDEN - Firewall Module

        This module is closely similar to the Antivirus Module. So similar that I copied the logic of the antivirus product and changed a single argument.
        The Firewall module is also one of the easiest to make and understand.
    */
    unsafe {

        let _com: HRESULT = CoInitializeEx(None, COINIT_MULTITHREADED);
        if _com.is_err() {
            println!("Error with COM initilaization in Firewall module");
            return Err(_com.into());
        }
        
        let firewalls: WindowsFirewallProfile;
        let mut firewall_products: Vec<FirewallProductInfo> = Vec::new();

        {
            // We have to connect to the INetFwPolicy interface
            // for more info on 'INetFwPolicy2': https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwpolicy2
            let policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, CLSCTX_ALL)?;

            // And just like that we are allowed access into the firewall policy
            let public_fw = {
                // We first use the 'get_FirewallEnabled' method with the profiletype we want as an arg
                let firewall = policy.get_FirewallEnabled(NET_FW_PROFILE2_PUBLIC)?;
                // Then we want to turn the VARIANT_BOOL we get to a Rust bool by using the VARIANT_TRUE method
                // There is a VARIANT_FALSE so don't get them confused
                firewall == VARIANT_TRUE
            };

            // And Thats it, now you can see the status of different profiles types
            // NOTE: This seems to only grab information of Windows Defenders Profiles, Not a third party Firewall
            // for example, you can turn off the Windows Defender firewall and it will show off on the checks
            // but a third party software will still have their firewall active.

            let private_fw = {
                let firewall = policy.get_FirewallEnabled(NET_FW_PROFILE2_PRIVATE)?;
                firewall == VARIANT_TRUE
            };

            let domain_fw = {
                let firewall = policy.get_FirewallEnabled(NET_FW_PROFILE2_DOMAIN)?;
                firewall == VARIANT_TRUE
            };

            firewalls = WindowsFirewallProfile {
                public: public_fw,
                private: private_fw,
                domain: domain_fw
            };

            // Now if you want to grab the name of the different Firewall Products you have like the Antivirus module, we can reuse our Antivirus code here
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
                    // Check out common/wmi_helpers.rs to see how these functions work
                    let fw_name = string_property(class_object, "displayName")?;
                    let fw_state = integer_property(class_object, "productState")?;

                    // The firewall product also uses hexadecimal so we can decipher information like the Antivirus module
                    let fw_active = ((fw_state >> 12) & 0xF) != 0;

                    let product = FirewallProductInfo {
                        name: fw_name,
                        state: fw_state,
                        is_active: fw_active
                    };

                    firewall_products.push(product);
                }
            }
        }
        CoUninitialize();
        Ok((firewalls, firewall_products))
    }
}