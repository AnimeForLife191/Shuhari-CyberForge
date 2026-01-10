use windows::core::*;
use windows::Win32::NetworkManagement::NetManagement::*;

pub struct UserAccountInfo {
    pub username: String,
    pub account_type: String,
    pub is_enabled: bool,
    pub is_admin: bool
}

pub struct UserAccountSummary {
    pub total_users: usize,
    pub enabled_users: usize,
    pub admin_count: usize,
    pub guest_enabled: bool,
    pub accounts: Vec<UserAccountInfo>
}

pub fn scan_uas() -> Result<UserAccountSummary> {
    /* 
        WARDEN: Using NetUser API's
    */
    let mut buffer: *mut u8 = std::ptr::null_mut();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;
    let mut resume_handle: u32 = 0;

    unsafe {
        
        // The 'NetUserEnum' function retrieves information about all user accounts on a server
        // This also allocates memory so we'l need to clear it later
        // for more info on 'NetUserEnum': https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuserenum
        let result = NetUserEnum(
            None, // A pointer that secifies the DNS or NetBIOS name of a remote server on which to execute. We'll leave it Null for local computer
            1, // This specifies the information level of the data, go check out the above link to see more options
            FILTER_NORMAL_ACCOUNT, // Specifies the user account types to be included in the enumeration
            &mut buffer, // This is where we use our buffer variable to recieve our data
            u32::MAX, // We can set the maximum length in bytes of the returned data, well use MAX to return all
            &mut entries_read, // reads the count of entries actually enumerated
            &mut total_entries, // total entries available
            Some(&mut resume_handle) // Resume handle to continue existing search
        );

        if result != NERR_Success {
            return Err(Error::from_thread());
            
        }

        // Lets cast our buffer to the USER_INFO_1 array
        let users = std::slice::from_raw_parts(
            buffer as *const USER_INFO_1, 
            entries_read as usize
        );

        let mut accounts = Vec::new();
        let mut admin_count = 0;
        let mut enabled_users = 0;
        let mut guest_enabled = false;

        // Now lets process each user account
        for user in users {
            let username = user.usri1_name.to_string()?; // Name of user

            let is_enabled = (user.usri1_flags & UF_ACCOUNTDISABLE) == USER_ACCOUNT_FLAGS(0);

            if is_enabled {
                enabled_users += 1;
            }

            let is_admin = user.usri1_priv == USER_PRIV_ADMIN;

            if is_admin {
                admin_count += 1;
            }

            if username.to_lowercase() == "guest" && is_enabled {
                guest_enabled = true;
            }

            let account_type = match user.usri1_priv {
                USER_PRIV_ADMIN => "Administrator",
                USER_PRIV_USER => "Standard User",
                USER_PRIV_GUEST => "Guest",
                _ => "Unknown"
            };

            accounts.push(UserAccountInfo {
                username,
                account_type: account_type.to_string(),
                is_enabled,
                is_admin
            });
        }

        NetApiBufferFree(Some(buffer as *const _));

        Ok(UserAccountSummary {
            total_users: entries_read as usize, 
            enabled_users, 
            admin_count, 
            guest_enabled, 
            accounts 
        }) 
    }
}