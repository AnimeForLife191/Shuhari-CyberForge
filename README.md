# WARDEN - Windows Security Auditor (MVP)

[![License: MIT](https://img.shields.io/badge/License-MIT%20-lightgrey.svg)](https://opensource.org/license/mit)
[![Rust](https://img.shields.io/badge/rust-1.92%2B-orange.svg)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/platform-Windows-blue.svg)](https://www.microsoft.com/windows)

**WARDEN** is a fast Windows security auditing tool that gives you instant visibility into your systems security. Written in Rust, it uses Windows APIs for reliability.
> **The First tool in the [SysDefense](VISION.md) security suite** - Hopefully to be a community-driven cybersecurity platform.

## Features

### Security Audit
- **Antivirus Detection** - Lists all installed AV products with real-time protection and definition status
- **Firewall Verification** - Checks Windows Firewall profiles and third-party firewall products
- **Update Identification** - Shows pending Windows updates with classification (Critical, Security, etc.) and sizes

### Technical Advantages
- **Native Performance** - Direct Windows API calls (COM/WMI)
- **Verbose Mode** - Extended technical information for security enthusiasts

## How to Install

Download from [Releases](https://github.com/AnimeForLife191/sysdefense/releases/tag/v0.1.0)
or build from source:
```bash
git clone https://github.com/AnimeForLife191/sysdefense
cd sysdefense
cargo build --release
```

Executable will be at `target\release\sysdefense-cli.exe`

## Usage

Run from the project directory after building:
```bash
.\target\release\sysdefense-cli.exe warden antivirus -v
```

Available commands:
- `warden antivirus` - Check antivirus status
- `warden firewall` - Check firewall configuration
- `warden updates` - Check Windows Update status

Add `-v` for verbose output with technical details.

**Example output:**
```
ANTIVIRUS PROTECTION AUDIT
==============================
Scan Details:
 - Scan Started: 00:00:00 UTC
 - WMI Namespace: ROOT\SecurityCenter2
 - Query: Select displayName, productState FROM AntiVirusProduct

Summary:
 - Products Found: 1
 - Active: 1/1
 - Real-time Protection: 1/1
 - Definitions Updated: 1/1

Product Details:

1. Windows Defender
 - Status: Active
 - Real-time: Enabled
 - Definitions: Up-to-date
 - Product Hexadecimal State: 0x61100
 - Product Raw State: 397568

Technical Information:
 - COM Apartment: MTA (Multi-threaded)
 - WMI Context: CLSCTX_INPROC_SERVER
```
## Roadmap

### Completed (Will be improved)
- Antivirus detection and status (Better error handling and output. Educational content needed)
- Windows Update status (Takes 5-30 seconds to load updates, could be faster? Educational content needed)
- Firewall detection and status (Better output. Educational content needed)
- User Account Control status (Better output, Educational content needed)
- User Account Security Audit (Better output, Educational content needed)

### Planned - Phase 2
- OS version and support life cycle
- Browser security basics
- SMBv1 protocol check
- RDP security audit
- PowerShell execution policy
- BitLocker encryption status

### Future - Phase 3
- Advanced browser extension analysis
- Network shares audit
- Windows privacy settings review
- Startup programs analysis
- Password policy enforcement check
- Windows Defender advanced feature status

## Want to Help?

You don't need to know Rust to help if you want:
- Star the [SysDefense repo](https://github.com/AnimeForLife191/sysdefense)
- Report bugs or suggest features
- Improve documentation
- Share ideas for new security checks
- Submit code improvements (all skill levels welcome!)

## More Info on SysDefense
If you're interested in SysDefense go check out my [SysDefense Vision](VISION.md)
