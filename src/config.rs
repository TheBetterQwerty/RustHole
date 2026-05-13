#![allow(unused)]
use std::{fs::OpenOptions, path::PathBuf, sync::OnceLock};

use serde::Deserialize;
use toml;

#[derive(Deserialize, Debug)]
pub struct TomlConfig {
    pub server: Server,
    pub upstream: Upstream,
    pub blacklist: Blacklist,
}

#[derive(Deserialize, Debug)]
pub struct Server {
    pub listen_addr: String,
    pub tcp_enabled: bool,
    pub max_udp_size: usize,
    pub workers: usize,
}

#[derive(Deserialize, Debug)]
pub struct Upstream {
    pub servers: Vec<String>,
    pub timeout_ms: u64,
    pub retries: usize,
}

#[derive(Deserialize, Debug)]
pub struct Blacklist {
    pub files: Vec<String>,
}

pub fn parse_toml_file() -> Result<TomlConfig, String> {
    let toml_file = std::env::current_dir()
        .unwrap()
        .join("config.toml")
        .to_string_lossy()
        .to_string();

    if !std::fs::exists(&toml_file).unwrap() {
        std::fs::write(&toml_file, r#"[server]
listen_addr = "127.0.0.1:2053"
tcp_enabled = true
max_udp_size = 512
workers = 4

[upstream]
servers = []
timeout_ms = 5000
retries = 3

[blacklist]
files = []
        "#);
    }

    let file_contents = match std::fs::read_to_string(&toml_file) {
        Ok(x) => x,
        Err(err) => return Err(format!("Error: {err} (Reading File {toml_file})", )),
    };

    let data: TomlConfig = match toml::from_str(&file_contents) {
        Ok(x) => return Ok(x),
        Err(err) => return Err(format!("Error: incorrect config file at {}", toml_file)),
    };
}
