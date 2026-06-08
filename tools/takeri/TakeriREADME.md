# Takeri (猛) - High-Performance Malware Scanner in Rust (MVP)

**Takeri** is a fast, multi-threaded malware scanner written in Rust that uses real signature databases to detect known threats (Thanks to ClamAV). Built with performance in mind, it focuses on efficient file scanning using hash-based detection and magic-byte checking.
> **The Second tool in the [Shuhari CyberForge](README.md) security suite** - Hopefully to be a community-driven cybersecurity platform.

## Features

### Malware Scanning
- **Signature-Based Detection** - Uses real signature databases (`.hdb` and `.hsb`)
- **Smart File Filtering** – Skips files that don’t match known signature sizes for performance
- **Recursive Scanning** - Optional deep directory traversal
- **Multi-Hash Support** - Supports both MD5 and SHA256 signatures

### Performance
- **Parallel Scanning** - Built with Rayon for multi-threaded performance
- **Large Dataset Handling** – Handles hundreds of thousands of signatures in memory with HashMap and HashSet
- **Fast Throughput** – Capable of scanning 1.4 million files in a minute (Hardware will vary significantly.)

## Quick Start

### Linux
```bash
./target/release/Shuhari-CyberForge-CLI takeri scan -r /
```

### Windows
```powershell
.\target\release\Shuhari-CyberForge-CLI.exe takeri scan -r C:\
```

## How to Install

### Releases
Download from [Releases](https://github.com/AnimeForLife191/Shuhari-CyberForge/releases)
- Windows: `Shuhari-CyberForge-CLI.exe`
- Linux: `Shuhari-CyberForge-CLI`

### Build from source
```bash
git clone https://github.com/AnimeForLife191/Shuhari-CyberForge
cd Shuhari-CyberForge
cargo build --release
```

### Windows
```bash
target\release\Shuhari-CyberForge-CLI.exe
```

### Linux
```bash
target/release/Shuhari-CyberForge-CLI
```

## How to Use

Run from the project directory after building:
### Windows
```bash
.\target\release\Shuhari-CyberForge-CLI.exe takeri scan [-r] <path>
```

### Linux
```bash
./target/release/Shuhari-CyberForge-CLI takeri scan [-r] <path>
```

Add `-r` as the {arg} for scanning recursively through directories

**Example output**
```
./target/release/Shuhari-CyberForge-CLI takeri scan -r /

Grabbing CVD & Json files...
Database MD5 Signatures: 540131
Database SHA256 Signatures: 183
-------Scan Summary-------
Scanned files: 747172
Infected files: 1
Suspicious files: 1
Skipped files: 947979
Failed files: 1
--------------------------

FAILED FILES:

 - /usr/bin/cupsd: Permission denied (os error 13)

SUSPICIOUS FILES:

1. /usr/lib32/libform.so
   Claims to be: .so
   Actually is: Unknown Format

INFECTED FILES DETECTED:

1. /home/{user}/.config/Code - OSS/User/History/-387ef922/bIYo.txt
   Malware: Eicar-Test-Signature
   Size: 68 bytes

 CRITICAL: Malware detected. Quarantine or delete infected files immediately.
```

## Roadmap

LIKELY TO CHANGE
### Completed MVP (Will be improved)
- MD5 & SHA256 Signature Scanning
- Magic Byte Checking
- ClamAV .cvd Updating

### Planned - Phase 1
- Hash Command
- Scan Modes
- Smarter File Selection
- Heuristic Scanning
- Output Improvements
- Result Export

### Phase 2
- Targeted Scanning
- Directory Filters
- YARA Rule System
- Archive Scanning

### Phase 3
- Memory Scanning