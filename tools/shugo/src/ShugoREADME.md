# Shugo - Windows Security Auditor (MVP)

**Shugo** is a fast Windows security auditing tool that gives you instant visibility into your systems security. Written in Rust, it uses Windows APIs for reliability.
> **The First tool in the [Shuhari CyberForge](README.md) security suite** - Hopefully to be a community-driven cybersecurity platform.

## Features

### Security Audit
- **Antivirus Detection** - Lists all installed AV products with real-time protection and definition status
- **Firewall Verification** - Checks Windows Firewall profiles and third-party firewall products
- **Update Identification** - Shows pending Windows updates with classification (Critical, Security, etc.) and sizes

### Technical Advantages
- **Native Performance** - Direct Windows API calls (COM/WMI)
- **Verbose Mode** - Extended technical information for security enthusiasts

## How to Install

Download from [Releases](https://github.com/AnimeForLife191/Shuhari-CyberForge/releases)
or build from source:
```bash
git clone https://github.com/AnimeForLife191/Shuhari-CyberForge
cd Shuhari-CyberForge
cargo build --release
```

Executable will be at `target\release\Shuhari-CyberForge-cli.exe`

## Usage

Run from the project directory after building:
```bash
.\target\release\shuhari-cyberforge-cli.exe shudo antivirus -v
```

Available commands:
- `shudo antivirus` - Check antivirus status
- `shudo firewall` - Check firewall configuration
- `shudo updates` - Check Windows Update status

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
- Antivirus detection and status
- Windows Update status
- Firewall detection and status
- User Account Control status
- User Account Security audit

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