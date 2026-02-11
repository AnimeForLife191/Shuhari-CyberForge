use chrono::{DateTime, Duration, Utc, serde::ts_seconds};
use serde::{Deserialize, Serialize};
use std::{path::{Path, PathBuf}};
use serde_json;
use std::fs;
use dirs;

use super::cvd_reader::{version_current, download_main_cvd};

pub struct FileSetup {
    pub database_dir: PathBuf,
    pub config_dir: PathBuf
}

#[derive(Serialize, Deserialize)]
pub struct DatabaseConfig {
    #[serde(with = "ts_seconds")]
    last_checked: DateTime<Utc>
}

pub fn setup_files() -> Result<FileSetup, Box<dyn std::error::Error>> {
    let data_dir = dirs::data_local_dir()
        .ok_or("Could not determine data directory")?;

    let config_dir = dirs::config_dir()
        .ok_or("Could not determine config directory")?;

    let database_dir = data_dir.join("Takeri-Scanner").join("database");
    let config_dir = config_dir.join("Takeri-Scanner");

    fs::create_dir_all(&database_dir)?;
    fs::create_dir_all(&config_dir)?;


    Ok(FileSetup {
        database_dir, 
        config_dir
    })
}

pub fn save_config(config_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = config_dir.join("config.json");

    let config = DatabaseConfig {
        last_checked: Utc::now()
    };

    let json_string = serde_json::to_string_pretty(&config)?;

    fs::write(&config_path, json_string)?;
    Ok(())
}

pub fn load_config(config_dir: &Path) -> Result<DatabaseConfig, Box<dyn std::error::Error>> {
    let config_path = config_dir.join("config.json");
    if !config_path.exists() {
        return Ok(DatabaseConfig { 
            last_checked: Utc::now(),
        });
    }
    
    let contents = fs::read_to_string(&config_path)?;

    let config: DatabaseConfig = serde_json::from_str(&contents)?;

    Ok(config)
}

pub fn check_update_config(path: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    let config = load_config(&path)?;
    let time_now = Utc::now();
    let time_since_last_check = time_now - config.last_checked;
    let time_limit = Duration::hours(24);

    if time_since_last_check > time_limit {
        Ok(true)
    } else {
        Ok(false)
    }
}

pub fn init_cvd() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let work_dirs = setup_files()?;
    let config_dir = work_dirs.config_dir;
    let database_dir = work_dirs.database_dir;
    
    let cvd_path = database_dir.join("main.cvd");
    let config_time_path = config_dir.join("config.json");
    if !config_time_path.exists() || check_update_config(&config_time_path)? {
        if !cvd_path.exists() || !version_current(&cvd_path)? {
            download_main_cvd(&cvd_path)?;
        }
        save_config(&config_dir)?;
    }
    Ok(cvd_path)
}