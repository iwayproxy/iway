use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct UserConfig {
    uuid: String,
    password: String,
}

impl UserConfig {
    pub fn uuid(&self) -> &str {
        &self.uuid
    }

    pub fn password(&self) -> &str {
        &self.password
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    server_addr: String,

    udp_session_timeout: u64,

    udp_socket_timeout: u64,

    cert_path: String,

    key_path: String,

    // Optional limits for UDP session management
    // If set to None, the defaults in code apply (unbounded or conservative defaults)
    udp_max_sessions: Option<usize>,

    udp_max_reassembly_bytes_per_session: Option<usize>,

    users: Vec<UserConfig>,
}

// Default configuration values as constants to avoid repeated allocations
const DEFAULT_SERVER_ADDR: &str = "[::]:443";
const DEFAULT_CERT_PATH: &str = "server.crt";
const DEFAULT_KEY_PATH: &str = "server.key";

impl Default for Config {
    fn default() -> Self {
        Self {
            server_addr: DEFAULT_SERVER_ADDR.to_string(),
            udp_session_timeout: 30,
            udp_socket_timeout: 10,
            cert_path: DEFAULT_CERT_PATH.to_string(),
            key_path: DEFAULT_KEY_PATH.to_string(),
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

    pub fn server_addr(&self) -> &str {
        &self.server_addr
    }

    pub fn cert_path(&self) -> &str {
        &self.cert_path
    }

    pub fn key_path(&self) -> &str {
        &self.key_path
    }

    pub fn users(&self) -> &[UserConfig] {
        &self.users
    }
}
