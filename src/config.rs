#![allow(unused)]
use std::{fs::OpenOptions, path::PathBuf, sync::OnceLock};

use serde::Deserialize;
use toml;

#[derive(Deserialize, Debug, Clone)]
pub struct TomlConfig {
    pub server: Server,
    pub cache: Cache,
    pub upstream: Upstream,
    pub blacklist: Blacklist,
    pub assets: Assets,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Assets {
    pub folder: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Server {
    pub listen_addr_ipv4: String,
    pub listen_addr_ipv6: String,
    pub dashboard: String,
    pub tcp_enabled: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Cache {
    pub max_cache: usize,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Upstream {
    pub servers: Vec<String>,
    pub retries: usize,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Blacklist {
    pub files: Vec<String>,
}

const TOML_FILE_BASIC_CONFIG: &str =
r#"[server]
listen_addr_ipv4 = "127.0.0.1:2053"
listen_addr_ipv6 = "[::1]:2053"
dashboard = "127.0.0.1:8000"
tcp_enabled = false

[assets]
folder = ""

[cache]
max_cache = 10000

[upstream]
servers = ["1.1.1.1:53", "8.8.8.8:53"]
retries = 3

[blacklist]
files = []
"#;

pub fn parse_toml_file() -> Result<TomlConfig, String> {
    let toml_file = std::env::current_dir()
        .unwrap()
        .join("config.toml")
        .to_string_lossy()
        .to_string();

    if !std::fs::exists(&toml_file).unwrap() {
        std::fs::write(&toml_file, TOML_FILE_BASIC_CONFIG);
        println!("[+] Config File Created at {}. Change it to fit your needs", toml_file);
        std::process::exit(0);
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
