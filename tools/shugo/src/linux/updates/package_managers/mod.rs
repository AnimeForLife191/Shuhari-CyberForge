mod pacman;
mod apt;
mod dnf;
mod zypper;

use super::{
    package_managers::{
        pacman::pacman_check_updates,
        apt::apt_check_updates,
        dnf::dnf_check_updates,
        zypper::zypper_check_updates
    }
};

pub struct PendingUpdate {
    pub name: String,
    pub current_version: String, 
    pub new_version: String,
    pub classification: Option<String>,
    pub min_mb: Option<f64>,
    pub max_mb: Option<f64>,
    pub description: Option<String>
}

pub trait PackageManager {
    fn name(&self) -> &str;
    fn pending_updates(&self) -> Vec<PendingUpdate>;
}

pub struct Pacman;
pub struct Apt;
pub struct Dnf;
pub struct Zypper;

impl PackageManager for Pacman {
    fn name(&self) -> &str {
        "pacman"
    }
    fn pending_updates(&self) -> Vec<PendingUpdate> {
        pacman_check_updates("checkupdates", &[])
    }
}

impl PackageManager for Apt {
    fn name(&self) -> &str {
        "apt"
    }
    fn pending_updates(&self) -> Vec<PendingUpdate> {
        apt_check_updates("apt", &["list", "--upgradable"])
    }
}

impl PackageManager for Dnf {
    fn name(&self) -> &str {
        "dnf"
    }
    fn pending_updates(&self) -> Vec<PendingUpdate> {
        dnf_check_updates("dnf", &["check-update"])
    }
}

impl PackageManager for Zypper {
    fn name(&self) -> &str {
        "zypper"
    }
    fn pending_updates(&self) -> Vec<PendingUpdate> {
        zypper_check_updates("zypper", &["list-updates"])
    }
}