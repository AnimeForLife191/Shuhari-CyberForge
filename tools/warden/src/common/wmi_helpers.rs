use std::mem::MaybeUninit;
use windows::core::*;
use windows::Win32::System::Variant::*;
use windows::Win32::System::Wmi::*;
use windows::Win32::Foundation::*;

/// Converting BSTR to a Rust String
pub fn string_property(obj: &IWbemClassObject, name: &str) -> Result<String> {
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
        // So we'll use 'VariantClear()' on EACH VARIANT after were done using it and BEFORE it leaves scope
        VariantClear(&mut variant)?;
        Ok(result)
    }
}

/// Converting vt to a Rust Integer
pub fn integer_property(obj: &IWbemClassObject, name: &str) -> Result<i32> {
    // This is the same as 'string property' with a few changes to how we convert
    unsafe {
        let mut variant = MaybeUninit::<VARIANT>::zeroed();
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
            -1
        };

        // CLEAN UP
        VariantClear(&mut variant)?;
        Ok(result)
    }
}

pub fn decimal_to_u64(decimal: DECIMAL) -> u128 {
    unsafe {((decimal.Hi32 as u128) << 64) | (decimal.Anonymous2.Lo64 as u128)}
}