use chrono::{DateTime, Duration, Utc, serde::ts_seconds};
use serde::{Deserialize, Serialize};
use std::{path::{Path, PathBuf}};
use serde_json;
use std::fs;
use directories::ProjectDirs;

use super::cvd_handler::{version_current, download_cvd, MAIN_CVD, DAILY_CVD, build_client};

pub struct FileSetup {
    pub database_dir: PathBuf,
    pub config_dir: PathBuf
}

pub struct CvdPaths {
    pub main: PathBuf,
    pub daily: PathBuf
}

#[derive(Serialize, Deserialize)]
pub struct DatabaseConfig {
    #[serde(with = "ts_seconds")]
    last_checked: DateTime<Utc>
}

fn setup_dirs() -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error>> {
    let proj_dirs = ProjectDirs::from("", "", "Takeri-Scanner")
        .ok_or("Could not determine project directories")?;

    let database_dir = proj_dirs.data_local_dir().join("database");
    let config_dir = proj_dirs.config_dir().to_path_buf();

    fs::create_dir_all(&database_dir)?;
    fs::create_dir_all(&config_dir)?;

    Ok((database_dir, config_dir))
}

fn config_path(config_dir: &Path) -> PathBuf {
    config_dir.join("config.json")
}

fn load_config(config_dir: &Path) -> Result<DatabaseConfig, Box<dyn std::error::Error>> {
    let path = config_path(config_dir);

    if !path.exists() {
        return Ok(DatabaseConfig { 
            last_checked: Utc::now() - Duration::days(3650)
        });
    }

    let contents = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&contents)?)
}

fn save_config(config_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let path = config_path(config_dir);

    let config = DatabaseConfig {
        last_checked: Utc::now()
    };

    fs::write(path, serde_json::to_string_pretty(&config)?)?;
    Ok(())
}

fn should_update(config_dir: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    let config = load_config(config_dir)?;
    Ok(Utc::now() - config.last_checked > Duration::hours(24))
}

pub fn update_if_needed(database_dir: &Path, config_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !should_update(config_dir)? {
        return Ok(());
    }

    println!("Update Available...");
    let client = build_client()?;

    let main_path = database_dir.join("main.cvd");
    let daily_path = database_dir.join("daily.cvd");

    if !main_path.exists() || !version_current(&client, MAIN_CVD, &main_path)? {
        download_cvd(&client, &main_path, MAIN_CVD)?;
    }

    if !daily_path.exists() || !version_current(&client, DAILY_CVD, &daily_path)? {
        download_cvd(&client, &daily_path, DAILY_CVD)?;
    }

    save_config(config_dir)?;
    Ok(())
}

pub fn prepare_cvd() -> Result<CvdPaths, Box<dyn std::error::Error>> {
    let (database_dir, config_dir) = setup_dirs()?;
    println!("Grabbing CVD & Json files...");

    update_if_needed(&database_dir, &config_dir)?;

    let main = database_dir.join("main.cvd");
    let daily = database_dir.join("daily.cvd");

    if !main.exists() || !daily.exists() {
        return Err("CVD files missing after update".into());
    }

    Ok(CvdPaths { main, daily })
}