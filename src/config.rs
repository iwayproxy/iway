use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
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

/// Trojan 协议配置
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TrojanConfig {
    /// 是否启用 Trojan 协议
    #[serde(default = "default_trojan_enabled")]
    enabled: bool,
    /// 服务器监听地址（Trojan 专用）
    #[serde(default = "default_server_addr")]
    server_addr: String,

    /// TLS 证书路径（Trojan 专用）
    #[serde(default = "default_cert_path")]
    cert_path: String,

    /// TLS 密钥路径（Trojan 专用）
    #[serde(default = "default_key_path")]
    key_path: String,

    /// 用户配置列表（Trojan 专用）
    #[serde(default)]
    users: Vec<UserConfig>,

    /// 认证失败时的 fallback 地址（通常指向伪装的 HTTP 服务器）
    #[serde(default = "default_trojan_fallback_addr")]
    fallback_addr: String,
}

impl Default for TrojanConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_addr: DEFAULT_SERVER_ADDR.to_string(),
            cert_path: DEFAULT_CERT_PATH.to_string(),
            key_path: DEFAULT_KEY_PATH.to_string(),
            users: vec![],
            fallback_addr: "127.0.0.1:80".to_string(),
        }
    }
}

impl TrojanConfig {
    #[allow(dead_code)]
    pub fn enabled(&self) -> bool {
        self.enabled
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

    pub fn fallback_addr(&self) -> &str {
        &self.fallback_addr
    }
}

/// TUIC 协议配置
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TuicConfig {
    /// 是否启用 Tuic 协议
    #[serde(default = "default_tuic_enabled")]
    enabled: bool,

    /// 服务器监听地址（Tuic 专用）
    #[serde(default = "default_server_addr")]
    server_addr: String,

    /// TLS 证书路径（Tuic 专用）
    #[serde(default = "default_cert_path")]
    cert_path: String,

    /// TLS 密钥路径（Tuic 专用）
    #[serde(default = "default_key_path")]
    key_path: String,

    /// 用户配置列表（Tuic 专用）
    #[serde(default)]
    users: Vec<UserConfig>,
}

impl Default for TuicConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_addr: DEFAULT_SERVER_ADDR.to_string(),
            cert_path: DEFAULT_CERT_PATH.to_string(),
            key_path: DEFAULT_KEY_PATH.to_string(),
            users: vec![],
        }
    }
}

impl TuicConfig {
    pub fn enabled(&self) -> bool {
        self.enabled
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsCacheConfig {
    #[serde(default = "default_dns_cache_size")]
    max_entries: u64,

    #[serde(default = "default_dns_cache_ttl")]
    ttl_secs: u64,
}

impl Default for DnsCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 2000,
            ttl_secs: 300,
        }
    }
}
/// UDP 会话配置
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UdpSessionConfig {
    /// UDP 会话超时时间（秒）
    #[serde(default = "default_udp_session_timeout")]
    session_timeout: u64,

    /// UDP 套接字超时时间（秒）
    #[serde(default = "default_udp_socket_timeout")]
    socket_timeout: u64,

    /// UDP 会话数上限（None 表示无限制）
    max_sessions: Option<usize>,

    /// 单个 UDP 会话的重组缓冲区大小上限（字节）
    max_reassembly_bytes_per_session: Option<usize>,
}

impl Default for UdpSessionConfig {
    fn default() -> Self {
        Self {
            session_timeout: 30,
            socket_timeout: 10,
            max_sessions: None,
            max_reassembly_bytes_per_session: None,
        }
    }
}

/// 全局配置结构
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    /// Trojan 协议配置
    #[serde(default)]
    trojan: TrojanConfig,

    /// TUIC 协议配置
    #[serde(default)]
    tuic: TuicConfig,

    /// DNS 缓存配置
    #[serde(default)]
    dns_cache: DnsCacheConfig,

    /// UDP 会话配置
    #[serde(default)]
    udp_session: UdpSessionConfig,
}

// 默认值常量定义
const DEFAULT_SERVER_ADDR: &str = "[::]:443";
const DEFAULT_CERT_PATH: &str = "server.crt";
const DEFAULT_KEY_PATH: &str = "server.key";

fn default_server_addr() -> String {
    DEFAULT_SERVER_ADDR.to_string()
}

fn default_cert_path() -> String {
    DEFAULT_CERT_PATH.to_string()
}

fn default_key_path() -> String {
    DEFAULT_KEY_PATH.to_string()
}

fn default_dns_cache_size() -> u64 {
    2000
}

fn default_dns_cache_ttl() -> u64 {
    300
}

fn default_udp_session_timeout() -> u64 {
    30
}

fn default_udp_socket_timeout() -> u64 {
    10
}

fn default_trojan_enabled() -> bool {
    false
}

fn default_tuic_enabled() -> bool {
    false
}

fn default_trojan_fallback_addr() -> String {
    "127.0.0.1:80".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            trojan: TrojanConfig::default(),
            tuic: TuicConfig::default(),
            dns_cache: DnsCacheConfig::default(),
            udp_session: UdpSessionConfig::default(),
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

    // 主配置访问方法
    // 子配置访问方法
    pub fn trojan(&self) -> &TrojanConfig {
        &self.trojan
    }

    pub fn tuic(&self) -> &TuicConfig {
        &self.tuic
    }
}
