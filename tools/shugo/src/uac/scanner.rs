use windows::core::*;
use windows::Win32::System::Registry::*;

pub struct UacInfo {
    pub lua_value: u32,
    pub enabled: bool,
    pub prompt_level: u32
}

pub fn scan_uac() -> Result<UacInfo> {

    /* 
        WARDEN: Using Registry in Windows

        The Registry is Windows heirarchical database for system configuration

        We'll be accessing it to grab the value of UAC (User Access Control) and seeing if its turned on or off
    */

    let mut key: HKEY = HKEY::default();
    let subkey = w!("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"); // This is our key path to the specified registry
    unsafe {
        // This allows us to open our specified registry key.
        // NOTE: Key names are NOT case sensitive
        let _ = RegOpenKeyExW( // for more info on RegOpenKeyExW: https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexw
            HKEY_LOCAL_MACHINE, // This is a handle to open the specified registry path (e.g. HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER, HKEY_USERS)
            subkey, // The name of the registry subkey to be opened
            Some(0), // Specifies the option to apply when opening the key. Were gonna set it to 0
            KEY_READ, // This mask specifies the directed access rights to the key being opened. for info: https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights
            &mut key // This is a pointer to a variable that receives a handle to the opened key
        );

        // Now we'll query our data we want from the key
        let value: PCWSTR = w!("EnableLUA"); // Registry value we want to retrieve
        let mut enable_lua: u32 = 0; // This will hold our data for our uac.
        let mut size: u32 = std::mem::size_of::<u32>() as u32; // This is a buffer for our size arg
        registry_query(key, value, &mut enable_lua, &mut size); // Go check out the function to see what this data is for

        // Now lets query our ConsentPromptBehaviorAdmin value
        let value: PCWSTR = w!("ConsentPromptBehaviorAdmin");
        let mut prompt_behavior: u32 = 0;
        let mut size: u32 = std::mem::size_of::<u32>() as u32;
        registry_query(key, value, &mut prompt_behavior, &mut size);

        // We'll close the key now otherwise we'll get an error
        let _ = RegCloseKey(key);
        
        Ok(UacInfo {
            lua_value: enable_lua,
            enabled: enable_lua == 1,
            prompt_level: prompt_behavior
        })
    }
}

fn registry_query(key: HKEY, reg_value: PCWSTR, value_pointer: &mut u32, size_pointer: &mut u32) {
    unsafe {
        let _ = RegQueryValueExW( // for more info on RegQueryValueExW: https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvalueexw
            key, // Our handle to the open registry key
            reg_value, // Our registry value we want to grab
            None, // This must be NULL
            None, // This is also NULL
            Some(value_pointer as *mut u32 as *mut u8), // A pointer to a buffer to recieve the values data
            Some(size_pointer) // A pointer to a variable that specifies the size of a buffer in bytes
        );
    }
}