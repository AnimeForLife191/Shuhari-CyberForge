use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AntiVirusProduct {
    display_name: String,
    product_state: u32
}


#[cfg(windows)]
pub fn antivirus_installed() -> Result<(), Box<dyn std::error::Error>> {
    use wmi::WMIConnection;

    let wmi = WMIConnection::with_namespace_path("ROOT\\SecurityCenter2")?;

    let av_products: Vec<AntiVirusProduct> = wmi.raw_query()
}