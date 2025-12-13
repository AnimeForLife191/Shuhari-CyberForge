use thiserror::Error;

#[derive(Error, Debug)]
pub enum DefenderError {
    #[error("Failed to access registry: {0}")]
    RegistryAccess(#[from] std::io::Error),

    #[error("Registry value not found: {0}")]
    ValueNotFound(String),

    #[error("This check is only available on Windows")]
    NotWindows
}

#[derive(Debug)]
pub struct DefenderStatus {
    pub installed: bool,
    pub enabled: bool,
    pub real_time_protection: bool,
    pub signature_version: Option<String>,
    pub signature_last_updated: Option<String>
}

// ========================================================
// IS WINDOWS DEFENDER INSTALLED?
// ========================================================

#[cfg(windows)] // Only Runs On Windows Machine
pub fn is_defender_installed() -> Result<bool, DefenderError> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE); // Creating Handle To The Specified Hive

    // Does "Windows Defender" Exist In Registry
    match hklm.open_subkey("SOFTWARE\\Microsoft\\Windows Defender") { // Path To The Specified Registry
        Ok(_) => Ok(true), // Found/Installed
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false), // Missing/Uninstalled
        Err(e) => Err(DefenderError::RegistryAccess(e)) // Registry Can't Be Accessed
    }
}

#[cfg(not(windows))] // Any Machine Not Windows Runs This
pub fn is_defender_installed() -> Result<bool, DefenderError> {
    Err(DefenderError::NotWindows)
}

// ========================================================
// IS WINDOWS DEFENDER ENABLED?
// ========================================================

#[cfg(windows)]
pub fn is_defender_enabled() -> Result<bool, DefenderError> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let defender_key = hklm.open_subkey("SOFTWARE\\Microsoft\\Windows Defender");

    // If Error, Return Immediately | If OK, Get Value
    match defender_key?.get_value::<u32, _>("DisableAntiSpyware") {
        Ok(0) => Ok(true), // Is Enabled
        Ok(_) => Ok(false), // Is Disabled
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(true) // Is Enabled By Default
        }
        Err(e) => Err(DefenderError::RegistryAccess(e))
    }
}

#[cfg(not(windows))]
pub fn is_defender_enabled() -> Result<bool, DefenderError> {
    Err(DefenderError::NotWindows)
}

// ========================================================
// ARE LATEST DEFINITIONS INSTALLED? 
// ========================================================

#[cfg(windows)]
pub fn get_signature_version() -> Result<String, DefenderError> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let sig_key = hklm.open_subkey("SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates")?; // TODO: Signature Vlaue Not Being Grabbed

    // Getting Signature Version
    match sig_key.get_value::<String, _>("ASSignatureVersion") {
        Ok(version) => Ok(version),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Trying Alternative Key Name
            match sig_key.get_value::<String, _>("SignatureVersion") {
                Ok(version) => Ok(version),
                Err(_) => Err(DefenderError::ValueNotFound("Signature version".to_string()))
            }
        }
        Err(e) => Err(DefenderError::RegistryAccess(e))
    }
}

#[cfg(windows)]
pub fn get_signature_last_update() -> Result<String, DefenderError> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let sig_key = hklm.open_subkey("SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates")?; // TODO: Double Check Registry Path

    match sig_key.get_value::<String, _>("SignatureUpdateTime") {
        Ok(time) => Ok(time),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {

            match sig_key.get_value::<String, _>("ASSignatureAppliedTime") {
                Ok(time) => Ok(time),
                Err(_) => Err(DefenderError::ValueNotFound("Signature update time".to_string()))
            }
        }
        Err(e) => Err(DefenderError::RegistryAccess(e))
    }
}

#[cfg(not(windows))]
pub fn get_signature_version() -> Result<String, DefenderError> {
    Err(DefenderError::NotWindows)
}

#[cfg(not(windows))]
pub fn get_signature_last_update() -> Result<String, DefenderError> {
    Err(DefenderError::NotWindows)
}

#[cfg(windows)]
pub fn is_real_time_protection_enabled() -> Result<bool, DefenderError> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    // Trying To Open Real-Time Protection Key
    let rt_key = match hklm.open_subkey("SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection") {
        Ok(key) => key,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Key Doesn't Exist, Possibly Disabled or Not Configured
            return Ok(false);
        }
        Err(e) => return Err(DefenderError::RegistryAccess(e))
    };

    // Checking DisableRealtimeMonitoring Value
    match rt_key.get_value::<u32, _>("DisableRealtimeMonitoring") {
        Ok(0) => Ok(true), // Enabled
        Ok(_) => Ok(false), // Disabled
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Value Doesn't Exist Means Enabled By Default
            Ok(true)
        }
        Err(e) => Err(DefenderError::RegistryAccess(e))
    }
}

#[cfg(not(windows))]
pub fn is_real_time_protection_enabled() -> Result<bool, DefenderError> {
    Err(DefenderError::NotWindows)
}

// ========================================================
// FULL STATUS CHECK
// ========================================================

#[cfg(windows)]
pub fn get_defender_status() -> Result<DefenderStatus, DefenderError> {
    Ok(DefenderStatus {
        installed: is_defender_installed()?,
        enabled: is_defender_enabled()?,
        real_time_protection: is_real_time_protection_enabled()?,
        signature_version: get_signature_version().ok(),
        signature_last_updated: get_signature_last_update().ok()
    })
}

#[cfg(not(windows))]
pub fn get_defender_status() -> Result<DefenderStatus, DefenderError> {
    Err(DefenderError::NotWindows)
}