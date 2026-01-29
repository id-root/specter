use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct PayloadConfig {
    pub file_path: String,
}

#[derive(Debug, Clone)]
pub struct PayloadManager {
    pub payloads: Vec<String>,
}

impl PayloadManager {
    pub fn new(config: Option<PayloadConfig>) -> Result<Self> {
        let mut payloads = Vec::new();

        if let Some(cfg) = config {
            let path = Path::new(&cfg.file_path);
            let file = File::open(path).context(format!("Failed to open payload file: {:?}", path))?;
            let reader = BufReader::new(file);

            for line in reader.lines() {
                let line = line?;
                if !line.trim().is_empty() {
                    payloads.push(line);
                }
            }
        } else {
            // Default safe test payload if none provided
            payloads.push("alert('Spectre Authorized Test')".to_string());
        }

        Ok(Self { payloads })
    }

    pub fn get_payloads(&self) -> &[String] {
        &self.payloads
    }
}
