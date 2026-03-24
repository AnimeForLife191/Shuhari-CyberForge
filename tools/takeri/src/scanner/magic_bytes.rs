use std::collections::HashMap;

// NOTE: Switch to .ndb with ClamAV

pub struct MagicBytes {
    signatures: HashMap<&'static str, Vec<Vec<u8>>>,
    formats: Vec<(Vec<u8>, &'static str)>
}

impl MagicBytes {
    pub fn new() -> Self {
        let mut map: HashMap<&'static str, Vec<Vec<u8>>> = HashMap::new();

        let pe = vec![vec![0x4D, 0x5A]];
        for ext in &["exe", "dll", "sys", "scr", "cpl", "drv", "ocx", "efi"] {
            map.insert(ext, pe.clone());
        }

        let elf = vec![vec![0x7F, 0x45, 0x4C, 0x46]];
        for ext in &["elf", "so", "dylib"] {
            map.insert(ext, elf.clone());
        }

        let zip = vec![vec![0x50, 0x4B, 0x03, 0x04]];
        for ext in &["zip", "jar", "docx", "xlsx", "pptx"] {
            map.insert(ext, zip.clone());
        }

        let ole = vec![vec![0xD0, 0xCF, 0x11, 0xE0]];
        for ext in &["doc", "xls", "ppt", "msi"] {
            map.insert(ext, ole.clone());
        }

        map.insert("pdf",  vec![vec![0x25, 0x50, 0x44, 0x46]]);
        map.insert("png",  vec![vec![0x89, 0x50, 0x4E, 0x47]]);
        map.insert("gif",  vec![vec![0x47, 0x49, 0x46, 0x38]]);
        map.insert("7z",   vec![vec![0x37, 0x7A, 0xBC, 0xAF]]);
        map.insert("rar",  vec![vec![0x52, 0x61, 0x72, 0x21]]);
        map.insert("gz",   vec![vec![0x1F, 0x8B]]);
        map.insert("cab",  vec![vec![0x4D, 0x53, 0x43, 0x46]]);
        map.insert("iso",  vec![vec![0x43, 0x44, 0x30, 0x30, 0x31]]);
        map.insert("jpg",  vec![vec![0xFF, 0xD8, 0xFF]]);
        map.insert("sh",   vec![vec![0x23, 0x21]]);

        let formats = vec![
            (vec![0x4D, 0x5A], "PE Executable (Windows)"),
            (vec![0x7F, 0x45, 0x4C, 0x46], "ELF Binary (Linux)"),
            (vec![0x50, 0x4B, 0x03, 0x04], "ZIP Archive"),
            (vec![0xD0, 0xCF, 0x11, 0xE0], "OLE2 Document (Office/MSI)"),
            (vec![0x25, 0x50, 0x44, 0x46], "PDF Document"),
            (vec![0x89, 0x50, 0x4E, 0x47], "PNG Image"),
            (vec![0x47, 0x49, 0x46, 0x38], "GIF Image"),
            (vec![0x37, 0x7A, 0xBC, 0xAF], "7-Zip Archive"),
            (vec![0x52, 0x61, 0x72, 0x21], "RAR Archive"),
            (vec![0x1F, 0x8B], "GZIP Archive"),
            (vec![0x4D, 0x53, 0x43, 0x46], "Cabinet Archive"),
            (vec![0x43, 0x44, 0x30, 0x30, 0x31], "ISO Image"),
            (vec![0xFF, 0xD8, 0xFF], "JPEG Image"),
            (vec![0x23, 0x21], "Script")
        ];

        Self { signatures: map, formats }
    }

    pub fn check(&self, extension: &str, bytes: &[u8]) -> Option<bool> {
        let sigs = self.signatures.get(extension)?;
        Some(sigs.iter().any(|sig| bytes.starts_with(sig)))
    }

    pub fn identify(&self, bytes: &[u8]) -> &str {
        self.formats
            .iter()
            .find(|(magic, _)| bytes.starts_with(magic))
            .map(|(_, name)| *name)
            .unwrap_or("Unknown Format")
    }
}