//! This is the Firewall Module for Shugo. We are able to see
//! 
//! - Windows Firewall Profile States (Public, Private, Domain)
//! - Third-Party Firewall Products
//! - Firewall Product Status
//! 
//! This module uses TWO different APIs:
//! 1. Windows Firewall Policy API (INetFwPolicy2) - For Windows Defender Firewall profiles
//! 2. WMI SecurityCenter2 - For third-party firewall products
//! 
//! Note: The profile states ONLY reflect Windows Defender Firewall, not third-party firewalls.
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::System::Com::*;
use windows::Win32::System::Wmi::*;
use windows::Win32::NetworkManagement::WindowsFirewall::*;

use crate::common::wmi_helpers::{string_property, integer_property};

pub struct WindowsFirewallProfile {
    pub public: FirewallProfileDetails,
    pub private: FirewallProfileDetails,
    pub domain: FirewallProfileDetails
}

pub struct FirewallProfileDetails {
    pub profile_enabled: bool,
    pub inbound_blocked: bool,
    pub outbound_blocked: bool,
    pub notifications_disabled: bool

}

pub struct FirewallProductInfo {
    pub name: String,
    pub state: i32,
}

pub struct ModuleInfo {
    pub namespace: String,
    pub query: String
}

/// Grabing firewall for Windows
pub fn scan_firewall() -> Result<(WindowsFirewallProfile, Vec<FirewallProductInfo>, ModuleInfo)> {
    unsafe {
        /* 
            Shugo: COM Library Initialization

            Just like in the Antivirus and Update Modules, we need to initialize COM before using 
            any Windows APIs.
        */
        let _com: HRESULT = CoInitializeEx(None, COINIT_MULTITHREADED);
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
        
        let firewalls: WindowsFirewallProfile;
        let mut firewall_products: Vec<FirewallProductInfo> = Vec::new();
        let module: ModuleInfo;

        {
            /*
                Shugo: Windows Firewall Policy Interface

                Unlike the Antivirus and Update modules which use WMI or WUA, we can access 
                Windows Firewall settings directly through the INetFwPolicy2 interface.

                We use CLSCTX_ALL here because the firewall service may run in a different
                process, similar to the Windows Update service.

                For more information on `INetFwPolicy2`:
                (https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwpolicy2) - C++
            */
            let policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, CLSCTX_ALL)?;

            /*
                Shugo: Checking Firewall Profile States

                Windows Firewall has three network profiles:
                - Public: Used for untrusted networks (coffee shops, airports)
                - Private: Used for trusted home/work networks
                - Domain: Used when connected to a corporate domain

                Each profile can be independently enabled or disabled. We check each one using 
                `get_FirewallEnabled` with the appropriate profile type constant.

                We then check to see the state of inbound and outbound traffic from the profiles
                using `get_DefaultInboundAction` and `get_DefaultOutboundAction`.

                After that, we see if notifications are disabled using `get_NotificationsDisabled`

                IMPORTANT: These states only reflect Windows Defender Firewall. Third-party 
                firewalls (Norton, McAfee) are tracked separately through WMI.
            */
            let public_details: FirewallProfileDetails = {
                let profiletype: NET_FW_PROFILE_TYPE2 = NET_FW_PROFILE2_PUBLIC;

                let profile_enabled: bool = policy.get_FirewallEnabled(profiletype)? == VARIANT_TRUE;
                let inbound_blocked: bool = policy.get_DefaultInboundAction(profiletype)? == NET_FW_ACTION_BLOCK;
                let outbound_blocked: bool = policy.get_DefaultOutboundAction(profiletype)? == NET_FW_ACTION_BLOCK;
                let notifications_disabled: bool = policy.get_NotificationsDisabled(profiletype)? == VARIANT_TRUE;

                FirewallProfileDetails {
                    profile_enabled,
                    inbound_blocked,
                    outbound_blocked,
                    notifications_disabled

                }
            };

            let private_details: FirewallProfileDetails = {
                let profiletype: NET_FW_PROFILE_TYPE2 = NET_FW_PROFILE2_PRIVATE;

                let profile_enabled: bool = policy.get_FirewallEnabled(profiletype)? == VARIANT_TRUE;
                let inbound_blocked: bool = policy.get_DefaultInboundAction(profiletype)? == NET_FW_ACTION_BLOCK;
                let outbound_blocked: bool = policy.get_DefaultOutboundAction(profiletype)? == NET_FW_ACTION_BLOCK;
                let notifications_disabled: bool = policy.get_NotificationsDisabled(profiletype)? == VARIANT_TRUE;

                FirewallProfileDetails {
                    profile_enabled,
                    inbound_blocked,
                    outbound_blocked,
                    notifications_disabled

                }
            };

            let domain_details: FirewallProfileDetails = {
                let profiletype: NET_FW_PROFILE_TYPE2 = NET_FW_PROFILE2_DOMAIN;

                let profile_enabled: bool = policy.get_FirewallEnabled(profiletype)? == VARIANT_TRUE;
                let inbound_blocked: bool = policy.get_DefaultInboundAction(profiletype)? == NET_FW_ACTION_BLOCK;
                let outbound_blocked: bool = policy.get_DefaultOutboundAction(profiletype)? == NET_FW_ACTION_BLOCK;
                let notifications_disabled: bool = policy.get_NotificationsDisabled(profiletype)? == VARIANT_TRUE;

                FirewallProfileDetails {
                    profile_enabled,
                    inbound_blocked,
                    outbound_blocked,
                    notifications_disabled

                }
            };

            firewalls = WindowsFirewallProfile {
                public: public_details,
                private: private_details,
                domain: domain_details
            };

            /*
                Shugo: Third-Party Firewall Products via WMI

                Now we'll query WMI's SecurityCenter2 namespace to find third-party firewall products.
                This logic is nearly identical to the Antivirus Module, we just query "FirewallProduct"
                instead of "AntiVirusProduct".

                This lets us see products like Norton Firewall, Avast, etc.
            */
            let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)?;
            let namespace_path: BSTR = BSTR::from("ROOT\\SecurityCenter2");
            let services: IWbemServices = locator.ConnectServer(
                &namespace_path, 
                &BSTR::default(),
                &BSTR::default(),
                &BSTR::default(),
                0,
                &BSTR::default(),
                None
            )?;

            let query: BSTR = BSTR::from("Select displayName, productState FROM FirewallProduct");
            let enum_object = services.ExecQuery(
                &BSTR::from("WQL"),
                &query,
                WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY, 
                None 
            )?;

            /*
                Shugo: Processing Firewall Products

                Just like antivirus products, firewall products also use the productState hexadecimal 
                format. We extract bits 12-15 to determine if the firewall is active.
            */
            loop { 
                let mut objects: [Option<IWbemClassObject>; 1] = [None; 1];
                let mut returned = 0;
                let _ = enum_object.Next(
                    WBEM_INFINITE, 
                    &mut objects,
                    &mut returned 
                );
                if returned == 0 {
                    break;
                }

                if let Some(class_object) = &objects[0] {
                    let name: String = string_property(class_object, "displayName")?;
                    let state: i32 = integer_property(class_object, "productState")?;
                    
                    let product: FirewallProductInfo = FirewallProductInfo {
                        name,
                        state,
                    };

                    firewall_products.push(product);
                }
            }

            module = ModuleInfo {
                namespace: namespace_path.to_string(), 
                query: query.to_string()
            }
        }
        /*
            Shugo: Closing Thread

            Clean up COM when we're done.

            For more information on `CoUninitialize`:
            (https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-couninitialize) - C++
        */
        CoUninitialize();
        Ok((firewalls, firewall_products, module))
    }
}