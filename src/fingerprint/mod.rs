use serde::{Deserialize, Serialize};
use std::io::{BufReader, Read};
use std::path::Path;

#[derive(Serialize, Deserialize, Debug)]
pub struct Fingerprint {
    pub protocol: String,
    pub probes: Vec<Probe>,
}

impl Fingerprint {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Vec<Self> {
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) => {
                tracing::warn!("open fingerprint file error: {}", error.to_string());
                return vec![];
            }
        };
        let mut reader = BufReader::new(file);
        let mut content = String::new();
        reader.read_to_string(&mut content).unwrap();
        let fingerprint: Vec<Fingerprint> = serde_json::from_str(&content).unwrap();
        fingerprint
    }

    pub fn get_tcp_fingerprint() -> Option<Fingerprint> {
        let mut fingerprints = Self::from_file("./fingerprint/fingerprint.json");
        fingerprints.retain(|item| item.protocol.eq("TCP"));
        if fingerprints.is_empty() {
            return None;
        }
        fingerprints.pop()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Probe {
    pub probe_name: Option<String>,
    pub probe_string: String,
    pub matches: Vec<Match>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Match {
    pub pattern: String,
    pub name: String,
    pub discontinue: bool,
    pub version_info: Option<VersionInfo>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VersionInfo {
    pub cpe_name: String,
    pub device_type: String,
    pub host_name: String,
    pub info: String,
    pub operating_system: String,
    pub vendor_product_name: String,
    pub version: String,
}
