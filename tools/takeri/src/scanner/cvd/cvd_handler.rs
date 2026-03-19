use std::io::Read;
use reqwest::blocking::Response;
use reqwest::blocking::Client;
use std::fs::File;
use std::path::Path;
use uuid::Uuid;
use std::str::from_utf8;

pub const MAIN_CVD: &str = "https://database.clamav.net/main.cvd";
pub const DAILY_CVD: &str = "https://database.clamav.net/daily.cvd";

/// Helper
fn response_handler(client: &Client, url: &str) -> Result<Response, Box<dyn std::error::Error>> {
    let response = client.get(url).send()?;
    if !response.status().is_success() {
        return Err(format!("HTTP request failed: {}", response.status()).into());
    }
    Ok(response)
}

/// Client builder
pub fn build_client() -> Result<Client, Box<dyn std::error::Error>> {
    let uuid = Uuid::new_v4();
    let user_agent = format!("CVDUPDATE/1.0 ({})", uuid);

    Ok(Client::builder()
        .user_agent(user_agent)
        .build()?
    )
}

fn extract_version(header: &str) -> Result<&str, Box<dyn std::error::Error>> {
    header
        .split(':')
        .nth(2)
        .ok_or("Invalid CVD Header: No Version Found".into())
}

/// Getting cvd file
pub fn download_cvd(client: &Client, output_path: &Path, url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut response = response_handler(client, url)?;
    let mut file = File::create(output_path)?;

    std::io::copy(&mut response, &mut file)?;
    Ok(())
}
/// Getting cvd file-header
fn download_cvd_header_http(client: &Client, url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = client
        .get(url)
        .header("Range", "bytes=0-511")
        .header("Accept-Encoding", "identity")
        .send()?;

    if !response.status().is_success() {
        return Err(format!("HTTP request failed: {}", response.status()).into());
    }
    
    let bytes = response.bytes()?;

    if bytes.len() < 512 {
        return Err("CVD header too small".into());
    }
    let header = &bytes[..512];

    let null_pos = header.iter().position(|&b| b == 0);

    let actual_bytes = match null_pos {
        Some(pos) => {
            &header[..pos]
        }
        None => {
            &header[..]
        }
    };

    let header_string = from_utf8(actual_bytes)?;
    Ok(header_string.to_string())
}

pub fn cvd_version(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut header = [0u8;512];
    
    file.read_exact(&mut header)?;

    let header_str = match header.iter().position(|&b| b == 0) {
        Some(pos) => &header[..pos],
        None => &header
    };

    let header_string = from_utf8(header_str)?;

    let version = extract_version(header_string)?;

    Ok(version.to_string())
}

pub fn version_current(client: &Client, url: &str, path: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    let remote_header = download_cvd_header_http(client, url)?;
    let local_version = cvd_version(path)?;

    let remote_version = extract_version(&remote_header)?;
    Ok(local_version == remote_version)
}