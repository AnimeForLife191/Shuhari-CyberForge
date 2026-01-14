//! This is the UAC (User Account Controll) Module for Shugo. Here we can see:
//! 
//! - UAC Enable/Disable Status
//! - Prompt Behavior Level
//! 
//! Unlike the other modules, this one accesses the Windows Registry directly 
//! instead of using COM/WMI APIs. The Registry is Windows Hierarchical database for 
//! system configuration settings.
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::System::Registry::*;

pub struct UacInfo {
    pub lua_value: u32,
    pub prompt_level_value: u32,
    pub prompt_on_secure_desktop_value: u32,
    pub installer_detection_value: u32,
    pub validate_admin_code_signatures_value: u32,
    pub filter_admin_token_value: u32,
    pub enable_virtualization_value: u32,
    pub module_info: ModuleInfo
}

pub struct ModuleInfo {
    pub registry_key: String,
    pub queries: Vec<String>
}

/// Scanning UAC settings for Windows 
pub fn scan_uac() -> Result<UacInfo> {
    /* 
        Shugo: Using Windows Registry

        The Registry is Windows heirarchical database for system configuration.
        We'll be accessing it to grab the value of UAC (User Access Control) and seeing 
        if its turned on or off.

        UAC helps prevent unathorized changes to your system by prompting for administrator 
        approval before allowing apps to make changes.
    */
    unsafe {
        /*
            Shugo: Opening a Registry Key

            We need to open the registry key that contains UAC settings before we can read
            values from it. The key path we're opening is:
            HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System

            Note: Registry key names are NOT case sensitive

            For more information on `RegOpenKeyExW`:
            (https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexw) - C++
            (https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Registry/fn.RegOpenKeyExW.html) - Rust
        */
        let mut key: HKEY = HKEY::default();
        let subkey: PCWSTR = w!("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"); // This is our key path to the specified registry

        let _reg: WIN32_ERROR = RegOpenKeyExW( 
            HKEY_LOCAL_MACHINE, // This is a handle to open the specified registry path (e.g. HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER, HKEY_USERS)
            subkey, // The name of the registry subkey to be opened
            Some(0), // Specifies the option to apply when opening the key. Were gonna set it to 0
            KEY_READ, // This mask specifies the directed access rights to the key being opened. for info: https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights
            &mut key // This is a pointer to a variable that receives a handle to the opened key
        );
        match _reg {
            ERROR_SUCCESS => {
                // Registry key found
            },
            ERROR_FILE_NOT_FOUND => {
                // Registry key not found
                println!("Key not found");
                return Err(_reg.into());
            },
            _ => {
                // Some error opening
                println!("Error opening key");
                return Err(_reg.into());
            }
        }

        /*
            Shugo: Querying Registry Values

            Now that we have the key open, we can query specific values within it.

            EnableLUA (0 or 1):
            - 0 = UAC is disabled (all apps run with full admin rights)
            - 1 = UAC is enabled (apps need approval for admin tasks)

            ConsentPromptBehaviorAdmin:
            - 0 = Elevate without prompting (Most dangerous)
            - 1 = Prompt for credentials on secure desktop
            - 2 = Prompt for consent on secure desktop
            - 3 = Prompt for credentials (Default for non-admins)
            - 4 = Prompt for consent (Default for admins)
            - 5 = prompt for consent for non-Windows binaries (Most secure)

            PromptOnSecureDesktop:
            - 0 = Consent prompting occurs on user desktop
            - 1 = Force all UAC prompts to happen on user secure desktop

            EnableInstallerDetection Value:
            - 0 = Heuristically detection off for installing packages that require administrator
            - 1 = Heuristically detection on for installing packages that require administrator

            ValidateAdminCodeSignatures:
            - 0 = Doesn't enforce cryptographic signatures on interactive applications that require administrator
            - 1 = Enforces cryptographic signatures on interactive applications that require administrator

            FilterAdministratorToken: 
            - 0 = Built in admin accounts don't get UAC prompts
            - 1 = Built in admin accounts get UAC prompts

            For more information on `RegQueryValueExW`:
            (https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvalueexw) - C++
            (https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Registry/fn.RegQueryValueExW.html) - Rust
        */

        let mut query: Vec<String> = Vec::new();

        // Query EnableLUA value
        let value: PCWSTR = w!("EnableLUA"); // Registry value we want to retrieve
        let mut enable_lua: u32 = 0; // This will hold our data for our uac.
        let mut size: u32 = std::mem::size_of::<u32>() as u32; // This is a buffer for our size arg
        // Go check out the function to see what this data is for
        registry_query(key, value, &mut enable_lua, &mut size);
        query.push(value.to_string()?); // Query name

        // Query ConsentPromptBehaviorAdmin Value
        let value: PCWSTR = w!("ConsentPromptBehaviorAdmin");
        let mut prompt_behavior: u32 = 0;
        let mut size: u32 = std::mem::size_of::<u32>() as u32;
        registry_query(key, value, &mut prompt_behavior, &mut size);
        query.push(value.to_string()?);

        // Query PromptOnSecureDesktop Value
        let value: PCWSTR = w!("PromptOnSecureDesktop");
        let mut prompt_secure_desktop: u32 = 0;
        let mut size: u32 = std::mem::size_of::<u32>() as u32;
        registry_query(key, value, &mut prompt_secure_desktop, &mut size);
        query.push(value.to_string()?);

        // Query EnableInstallerDetection Value
        let value: PCWSTR = w!("EnableInstallerDetection");
        let mut installer_detection: u32 = 0;
        let mut size: u32 = std::mem::size_of::<u32>() as u32;
        registry_query(key, value, &mut installer_detection, &mut size);
        query.push(value.to_string()?);

        // Query ValidateAdminCodeSignatures Value
        let value: PCWSTR = w!("ValidateAdminCodeSignatures");
        let mut admin_signature: u32 = 0;
        let mut size: u32 = std::mem::size_of::<u32>() as u32;
        registry_query(key, value, &mut admin_signature, &mut size);
        query.push(value.to_string()?);

        // Query FilterAdministratorToken Value
        let value: PCWSTR = w!("FilterAdministratorToken");
        let mut admin_token: u32 = 0;
        let mut size: u32 = std::mem::size_of::<u32>() as u32;
        registry_query(key, value, &mut admin_token, &mut size);
        query.push(value.to_string()?);

        // Query FilterAdministratorToken Value
        let value: PCWSTR = w!("EnableVirtualization");
        let mut virtualization: u32 = 0;
        let mut size: u32 = std::mem::size_of::<u32>() as u32;
        registry_query(key, value, &mut virtualization, &mut size);
        query.push(value.to_string()?);

        /*
            Shugo: Closing the Registry Key

            Always close the registry keys when you're done with them. Leaving keys
            open can cause resource leaks.

            For more information on `RegCloseKey`:
            (https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regclosekey) - C++
            (https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Registry/fn.RegCloseKey.html) - Rust
        */
        let _ = RegCloseKey(key);

        let module_info: ModuleInfo = ModuleInfo {
            registry_key: subkey.to_string()?,
            queries: query
        };
        
        Ok(UacInfo {
            lua_value: enable_lua,
            prompt_level_value: prompt_behavior,
            prompt_on_secure_desktop_value: prompt_secure_desktop,
            installer_detection_value: installer_detection,
            validate_admin_code_signatures_value: admin_signature,
            filter_admin_token_value: admin_token,
            enable_virtualization_value: virtualization,
            module_info
        })
    }
}

fn registry_query(key: HKEY, reg_value: PCWSTR, value_pointer: &mut u32, size_pointer: &mut u32) {
    unsafe {
        let _ = RegQueryValueExW(
            key, // Our handle to the open registry key
            reg_value, // Our registry value we want to grab
            None, // This must be NULL
            None, // This is also NULL
            Some(value_pointer as *mut u32 as *mut u8), // A pointer to a buffer to recieve the values data
            Some(size_pointer) // A pointer to a variable that specifies the size of a buffer in bytes
        );
    }
}