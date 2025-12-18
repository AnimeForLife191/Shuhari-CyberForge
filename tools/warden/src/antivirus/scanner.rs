use wmi::{WMIConnection, Variant};
use std::collections::HashMap;



#[derive(Debug)]
struct AntiVirusProduct {
    name: String,
    state: u32,
    is_active: bool,
    realtime_on: bool,
    definitions_updated: bool
}


pub enum DisplayMode {
    Normal,
    Technical
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

    fn display_normal(&self, index: usize) {
        println!("{}. {}", index, self.name);
        println!("{}", "-".repeat(30));

        if self.is_fully_protected() {
            println!("✅ STATUS: Fully Protected");
            println!("    - Real-time scanning is active");
            println!("    - Virus definitions are current");
        } else if !self.is_active {
            println!("❌ STATUS: Disabled");
            println!("    - This antivirus is not running");
            println!("    - Your device may be at risk");
        } else if !self.realtime_on {
            println!("⚠️ STATUS: Partially Protected");
            println!("    - Antivirus is running");
            println!("    - Real-time protection is OFF");
            println!("    - New threats may not be blocked");
        } else if !self.definitions_updated {
            println!("⚠️ STATUS: Outdated");
            println!("    - Antivirus is running");
            println!("    - Virus definitions are old");
            println!("    - May not detect new threats");
        }
    }

    fn display_technical(&self, index: usize) {
        println!("Product #{}", index);
        println!("{}", "=".repeat(40));
        println!("Name:               {}", self.name);
        println!("State (Decimal):    {}", self.state);
        println!("State (Hex):        {}", self.state_hex());
        println!("Active:             {}", self.is_active);
        println!("Real-time:          {}", self.realtime_on);
        println!("Definitions:        {}", self.definitions_updated);
        

        // Bits decoded
        println!("\nBit Analysis:");
        println!("  Bits 12-15 (Active):     0x{:X}", (self.state >> 12) & 0xF);
        println!("  Bits 12-15 (Running):    0x{:X}", (self.state >> 8) & 0xF);
        println!("  Bits 0-7   (Definitions):0x{:02X}", self.state & 0xFF);
        println!();
    }

    fn display(&self, index: usize, mode: &DisplayMode) {
        match mode {
            DisplayMode::Normal => self.display_normal(index),
            DisplayMode::Technical => self.display_technical(index),
        }
    }

    // Helper method to get state as hex
    fn state_hex(&self) -> String {
        format!("0x{:06X}", self.state)
    }

    // Checks to see if product is fully protected
    fn is_fully_protected(&self) -> bool {
        self.is_active && self.realtime_on && self.definitions_updated
    }

}


pub fn antivirus_software(mode: DisplayMode) -> Result<(), Box<dyn std::error::Error>> {

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
        product.display(i + 1, &mode);
    }

    display_summary(&products, &mode);
    
    Ok(())

}

fn display_summary(products: &[AntiVirusProduct], mode: &DisplayMode) {
    match mode {
        DisplayMode::Normal => {
            let fully_protected = products.iter().filter(|p| p.is_fully_protected()).count();
            let disabled = products.iter().filter(|p| !p.is_active).count();
            let partial = products.len() - fully_protected - disabled;

            println!("\n{}", "=".repeat(40));
            println!("SUMMARY");
            println!("{}", "=". repeat(40));
            println!("Total antivirus programs: {}", products.len());
            println!("Fully protected: {}", fully_protected);

            if disabled > 0 {
                println!("Disabled: {}", disabled);
                println!("  - Enable at least one antivirus");
            }

            if partial > 0 {
                println!("Need attention: {}", partial);
                println!("Check real-time protection and updates");
            }

            if fully_protected == products.len() && products.len() > 0 {
                println!("All antivirus programs are fully protected")
            }
        }

        DisplayMode::Technical => {
            println!("\n{}", "=".repeat(40));
            println!("TECHNICAL SUMMARY");
            println!("{}", "=".repeat(40));

            for (i, product) in products.iter().enumerate() {
                println!("{}. {}:", i + 1, product.name);
                println!("  State: 0x{:06X} ({})", product.state, product.state);
                println!("  Fully Protected: {}", product.is_fully_protected());
                println!();
            }

            let security_score: f32 = products.iter().map(|p| {
                    let mut score = 0.0;
                    if p.is_active {score += 0.4;}
                    if p.realtime_on {score += 0.3;}
                    if p.definitions_updated {score += 0.3}
                    score
            }).sum::<f32>() / products.len() as f32 * 100.0;

            println!("Overall Security Score: {:.1}%", security_score);
        }
    }
}

pub fn antivirus_check() -> Result<(), Box<dyn std::error::Error>> {
    antivirus_software(DisplayMode::Normal)
}

pub fn antivirus_detailed_check() -> Result<(), Box<dyn std::error::Error>> {
    antivirus_software(DisplayMode::Technical)
}