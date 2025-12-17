use wmi::{WMIConnection, Variant};
use std::collections::HashMap;

pub fn antivirus_software() -> Result<(), Box<dyn std::error::Error>> {

    // This connects us to the name space we need for the antivirus query
    let wmi_con = WMIConnection::with_namespace_path("ROOT\\SecurityCenter2")?;

    // This allows us to query for certain or all information about the AntiVirusProduct
    let results: Vec<HashMap<String, Variant>> = wmi_con.raw_query("SELECT * FROM AntiVirusProduct")?;

    // This checks to see if we have any antivirus on the machine
    if results.is_empty() {
        println!("No antivirus products found!");
        return Ok(());
    }

    
    println!("Found {} antivirus product(s): \n", results.len());
    
    // Iterate through each antivirus product found
    for (i, av) in results.iter().enumerate() {
        println!("Product #{}", i + 1);

        // This will display all antivirus names found on the machine
        if let Some(Variant::String(name)) = av.get("displayName") {
            println!("  Name: {}", name);
        }

        // This will show the state of the antivirus
        if let Some(Variant::UI4(state)) = av.get("productState") {

            // We first grab the state of the antivirus which is supposed to be a 6 digit hex number (e.g. 393472)
            let state = *state as u32;

            // This outputs the state and shows it converted to hex (e.g. 0x060100)
            println!("  Raw State: {} (0x{:06X})", state, state);

            // Now we can decode the bits
            // This will show us if the antivirus is active (bits 12-15: 0x0 = disabled, anything else = enabled)
            let is_active: bool = ((state >> 12) & 0xF) != 0;
            println!("  Active: {}", if is_active { "Yes" } else { "No" });

            // This will tell us if RealTime protection is on (bits 12-15: 0x1 = on, 0x2 = off)
            // If the antivirus is disabled, this should be off
            let is_realtime_on: bool = ((state >> 12) & 0xF) == 1;
            println!("  RealTime Protection: {}", if is_realtime_on {" On "} else { "Off" } );

            // This checks the definitions of the antivirus to make sure there current (bits 0-7: 0x00 = updated)
            let is_definitions_updated: bool = (state & 0xFF) == 0x00;
            println!("  Definitions: {}", if is_definitions_updated { "Up-to-date" } else { "Out-of-date" });
        }

        println!(); // A blank line between products


    }
    

    Ok(())

}