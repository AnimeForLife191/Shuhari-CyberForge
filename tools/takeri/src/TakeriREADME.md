# Takeri (猛) - Malware Scanner (MVP)

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
- **Fast Throughput** – Capable of scanning 1.7 million files in a minute. (Hardware will very results)
