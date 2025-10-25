use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserConfig {
    pub uuid: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub server_addr: String,

    pub udp_session_timeout: u64,

    pub udp_socket_timeout: u64,

    pub cert_path: String,

    pub key_path: String,

    // Optional limits for UDP session management
    // If set to None, the defaults in code apply (unbounded or conservative defaults)
    pub udp_max_sessions: Option<usize>,

    pub udp_max_reassembly_bytes_per_session: Option<usize>,

    pub users: Vec<UserConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_addr: "[::]:443".to_string(),
            udp_session_timeout: 30,
            udp_socket_timeout: 60,
            cert_path: "server.crt".to_string(),
            key_path: "server.key".to_string(),
            udp_max_sessions: None,
            udp_max_reassembly_bytes_per_session: None,
            users: vec![],
        }
    }
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path).context("Failed to read config file")?;

        toml::from_str(&content).context("Failed to parse config file")
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self).context("Failed to serialize config")?;

        fs::write(path, content).context("Failed to write config file")?;

        Ok(())
    }
}
