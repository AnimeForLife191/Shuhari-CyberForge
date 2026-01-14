//! This is the User Account Security Module for Shugo. We are able to see:
//! 
//! - Local User Accounts
//! - Account Types (Administrator, Standard User, Guest)
//! - Account Status (Enabled/Disabled)
//! - Security Risks (Guest account enabled, multiple admins)
//! 
//! This module uses the NetUserEnum API to enumerate all local user accounts
//! and analyze their security configurations.
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

/// Scanning Local User Accounts for Windows
pub fn scan_uas() -> Result<UserAccountSummary> {

    /*
        Shugo: User Account Enumeration

        We'll be using the NetUserEnum function to retrieve information about all local user
        accounts on the system. This is different from our other modules becuase we're using
        the Network Management API instead of COM/WMI/Registry.

        For more information on `NetUserEnum`:
        (https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuserenum) - C++
        (https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/NetworkManagement/NetManagement/fn.NetUseEnum.html) - Rust
    */
    let mut buffer: *mut u8 = std::ptr::null_mut();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;
    let mut resume_handle: u32 = 0;

    unsafe {

        /*
            Shugo: Enumerating User Accounts

            `NetUserEnum` retrieves information about all user accounts and allocates memory for
            the results. We must free this memory later using `NetApiBufferFree`.

            Level 1 gives us basic info: username, privilege level, and flags.
            FILTER_NORMAL_ACCOUNT excludes system accounts and focuses on regular users.
        */
        let result: u32 = NetUserEnum(
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
            println!("NetUserEnum failed with error:");
            return Err(Error::from_hresult(HRESULT(result as i32)));
        }

        /*
            Shugo: Processing User Account Data

            We cast our buffer to a USER_INFO_! array and iterate through each user.
            For each account we check:
            - Is it enabled? (UF_ACCOUNTDISABLE flag)
            - Is it an admin? (USER_PRIV_ADMIN privilege level)
            - Is it the Guest account? (security risk if enabled)
        */
        let users: &[USER_INFO_1] = std::slice::from_raw_parts(
            buffer as *const USER_INFO_1, 
            entries_read as usize
        );

        let mut accounts = Vec::new();
        let mut admin_count = 0;
        let mut enabled_users = 0;
        let mut guest_enabled = false;

        for user in users {
            // Name of user
            let username: String = user.usri1_name.to_string()?; 

            // Is account enabled?
            let is_enabled: bool = (user.usri1_flags & UF_ACCOUNTDISABLE) == USER_ACCOUNT_FLAGS(0); 
            if is_enabled {
                enabled_users += 1;
            }

            // Is account admin?
            let is_admin: bool = user.usri1_priv == USER_PRIV_ADMIN; 
            if is_admin {
                admin_count += 1;
            }

            // Is guest account enabled?
            if username.to_lowercase() == "guest" && is_enabled { 
                guest_enabled = true;
            }

            // Determine account type from privilege level
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
        /*
            Shugo: Cleaning Up Memory

            NetUserEnum allocates memory that we must free using NetApiBufferFree.
            Failing to do this causes memory leaks.

            For more information on `NetApiBufferFree`:
            (https://learn.microsoft.com/en-us/windows/win32/api/lmapibuf/nf-lmapibuf-netapibufferfree) - C++
            (https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/NetworkManagement/NetManagement/fn.NetApiBufferFree.html) - Rust
        */

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