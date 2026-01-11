use std::mem::MaybeUninit;
use windows::core::*;
use windows::Win32::System::Variant::*;
use windows::Win32::System::Wmi::*;
use windows::Win32::Foundation::*;

/// Converting BSTR to a Rust String
pub fn string_property(obj: &IWbemClassObject, name: &str) -> Result<String> {
    unsafe {
        /*
            Shugo: Writing In Memory

            To convert our objects to usable data, we need to take the output of the pointers and put them in memory to be written
            before we can read them.

            "Why do we need to access memory to do this?":
            Were interfacing with C code which expects uninitialized buffers. So we need to bridge the gap between Rust's strict 
            memory safety and the low-level operations that require dealing with uninitialized memory.

            How this works:
            We'll first call `MaybeUninit` which will create some uninitialized memory for us so all we need to do is put in some
            data.

            For more information on `MaybeUninit`:
            (https://doc.rust-lang.org/std/mem/union.MaybeUninit.html) - Rust
        */
        let mut variant: MaybeUninit<VARIANT> = MaybeUninit::<VARIANT>::zeroed();

        /*  
            Shugo: Filling Memory

            Then we'll fill that memory using the `Get` method on our object. This will get certain information from our object and
            put it in our uninitialized memory.

            For more information on `Get`: 
            (https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-get) - C++
            (https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Wmi/struct.IWbemClassObject.html#method.Get) - Rust
        */
        obj.Get(
            &BSTR::from(name), // Name of the property were wanting
            0, // This must be zero
            variant.as_mut_ptr(), // When successful, this assignes the correct type and value for the qualifier 
            None, // Were leaving this NULL
            None // This one will be NULL too
        )?;

        /*
            Shugo: Initializing Memory

            Now That we have filled our memory, we can initialize it using the `assume_init` method. This is us telling Rust that we 
            have made sure all information in the memory is correct.
        */
        let mut variant: VARIANT = variant.assume_init();

        /*  
            Shugo: Working With VARIANT

            VARIANT is pretty much a container for a large union that carries many types of data. To get the data we want, we'll
            navigate through the VARIANT Rust structs until we get the Value we want returned. We want to get a `BSTR` from this
            function so we'll go to `variant.Anonymous.Anonymous.vt` and equal it too VT_BSTR so we know we can pull a `BSTR`.

            Than instead of `Anonymous.Anonymous.vt` we'll do `Anonymous.Anonymous.Anonymous.bstrVal` so we can can grab the 
            `BSTR`.

            For more information on the `VARIANT` Structure:
            (https://learn.microsoft.com/en-us/windows/win32/api/oaidl/ns-oaidl-variant) - C++
            (https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Variant/index.html#structs) - Rust
        */
        let result: String = if variant.Anonymous.Anonymous.vt == VT_BSTR {
            let bstr = &variant.Anonymous.Anonymous.Anonymous.bstrVal; // The third 'Anonymous' contains all the possible value types like bstrVal, lVal, boolVal, and more
            bstr.to_string()// From here we are basically converting the BSTR string to a Rust String
        } else {
            "Unknown".to_string()
        };

        /*
            Shugo: Clearing Memory:

            Once we're done using our initialized memory, we need to clear the data in it. This is important because if we leave this
            data in memory, it will leave it initialized. This is a memory leak and should be dealt with every time you initialized 
            memory. To delete data in your initialized memory, call `VariantClear`.

            For information on `VariantClear`:
            (https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-variantclear) - C++
            (https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Variant/fn.VariantClear.html) - Rust
        */
        VariantClear(&mut variant)?;
        Ok(result)
    }
}

/// Converting vt to a Rust Integer
pub fn integer_property(obj: &IWbemClassObject, name: &str) -> Result<i32> {
    unsafe {
        let mut variant = MaybeUninit::<VARIANT>::zeroed();
        obj.Get(
            &BSTR::from(name),
            0, // This must be zero
            variant.as_mut_ptr(),
            None,
            None
        )?;
        let mut variant = variant.assume_init();
        let result = if variant.Anonymous.Anonymous.vt == VT_I4 { // Were grabing an integer here so lets use VT_I4
            variant.Anonymous.Anonymous.Anonymous.lVal // Then we'll use lVal which is used for long/32-bit integers
        } else {
            -1
        };
        VariantClear(&mut variant)?;
        Ok(result)
    }
}

/// Converting DECIMAL to u128
pub fn decimal_to_u128(decimal: DECIMAL) -> u128 {
    unsafe {((decimal.Hi32 as u128) << 64) | (decimal.Anonymous2.Lo64 as u128)}
}