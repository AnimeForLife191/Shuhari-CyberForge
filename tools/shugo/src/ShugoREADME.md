# Shugo - Windows Security Auditor (MVP)

**Shugo** is a fast Windows security auditing tool that gives you instant visibility into your systems security. Written in Rust, it uses Windows APIs for reliability.
> **The First tool in the [Shuhari CyberForge](README.md) security suite** - Hopefully to be a community-driven cybersecurity platform.

## Features

### Security Audit
- **Antivirus Detection** - Lists all installed AV products with real-time protection and definition status
- **Firewall Verification** - Checks Windows Firewall profiles and third-party firewall products
- **Update Identification** - Shows pending Windows updates with classification (Critical, Security, etc.), sizes, and descriptions
- **UAC Settings** - Shows UAC (User Access Control) Status, Prompt Level, and other related checks
- **UAS Settings** - Shows UAS (User Acount Security) account types, account status, and security risks

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
.\target\release\shuhari-cyberforge-cli.exe shugo antivirus -v
```

Available commands:
- `shugo antivirus` - Check antivirus status
- `shugo firewall` - Check firewall configuration
- `shugo updates` - Check Windows Update status
- `shugo uac` - Check UAC (User Account Control) settings
- `shugo uas` - Check UAS (User Account Security) settings

Add `-v` for verbose output with technical details.

**Example output:**
```
\shahari-cyberforge-cli.exe shugo antivirus -v

ANTIVIRUS PROTECTION AUDIT
==============================
Scan Details:
 - Scan Started: 00:00:00 UTC
 - WMI Namespace: ROOT\SecurityCenter2
 - Query: Select displayName, productState FROM AntiVirusProduct

Summary:
 - Products Found: 1
   - Products Inactive: 0
   - Products Active: 1
   - Products Snoozed: 0
   - Products Expired: 0

Product Details:
1. Windows Defender
 - Status: On
   - Hex Value (0x0F000): 1
 - Third-Party: No
   - Hex Value (0x00F00): 1
 - Definitions: Up-to-date
   - Hex Value (0x000F0): 0
 - Product State: 397568
 - Hexadecimal State: 0x61100

Security Assessment:
 - Antivirus Protection:
   - Antivirus Protection Is Active

 - Active Products:
   - Windows Defender
     - Definitions: Up-to-date

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