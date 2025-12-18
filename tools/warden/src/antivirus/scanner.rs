use wmi::{WMIConnection, Variant};
use std::{collections::HashMap, net::ToSocketAddrs};



#[derive(Debug)]
struct AntiVirusProduct {
    name: String,
    state: u32,
    is_active: bool,
    realtime_on: bool,
    definitions_updated: bool
}



impl AntiVirusProduct {
    fn from_wmi_data(av: &HashMap<String, Variant>) -> Option<Self> {
        let name = match av.get("displayName") {
            Some(Variant::String(name)) => name.clone(),
            _ => return None
        };

        let state = match av.get("productState") {
            Some(Variant::UI4(state)) => *state as u32,
            _ => return None
        };

        // (bits 12-15: 0x0 = disabled, anything else = enabled)
        let is_active = ((state >> 12) & 0xF) != 0;
        // (bits 12-15: 0x1 = on, 0x2 = off)
        let realtime_on = ((state >> 12) & 0xF) == 1;
        // (bits 0-7: 0x00 = updated)
        let definitions_updated = (state & 0xFF) == 0x00;

        Some(Self {
            name, 
            state, 
            is_active,
            realtime_on, 
            definitions_updated
        })

    }

    // Displays output
    fn display(&self, index: usize) {
        println!("Product #{}", index);
        println!("  Name: {}", self.name);
        println!("  Raw State: {} (0x{:06X})", self.state, self.state);
        println!("  Active: {}", if self.is_active {"Yes"} else {"No"});
        println!("  RealTime Protection: {}", if self.realtime_on {"On"} else {"Off"});
        println!("  Definitions: {}", if self.definitions_updated {"Up-to-date"} else {"Out-of-date"});
    }

    // Helper method to get state as hex
    fn state_hex(&self) -> String {
        format!("0x{:06X}", self.state)
    }

    // Checks to see if product is fully protected
    fn is_fully_protected(&self) -> bool {
        self.is_active && self.realtime_on && self.definitions_updated
    }

    // Gives full summary to you
    fn summary(&self) -> String {
        let status = if self.is_active {"✅"} else {"❌"};
        let realtime = if self.realtime_on {"✅"} else {"❌"};
        let definitions = if self.definitions_updated {"✅"} else {"❌"};

        format!("{} {} {} - {}", status, realtime, definitions, self.name)
    }
}


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
    
    let products: Vec<AntiVirusProduct> = results
        .iter()
        .filter_map(AntiVirusProduct::from_wmi_data)
        .collect();

    // Iterate through each antivirus product found
    for (i, product) in products.iter().enumerate() {
        product.display(i + 1);
    }

    println!("\nSummary:");
    for product in &products {
        println!("  {}", product.summary());
    }

    let fully_protected = products.iter().filter(|p| p.is_fully_protected()).count();
    println!("\n{}/{} products fully protected", fully_protected, products.len());
    
    Ok(())

}
