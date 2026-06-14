#![allow(unused)]
use std::sync::{Arc, Mutex, RwLock};
use std::sync::atomic::AtomicU64;
use std::time::Instant;
use std::io::Result;
use std::{io::Write, net::TcpListener};
use std::collections::HashMap;
use axum::extract::State;
use axum::{Json, Router};
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use serde::{Deserialize, Serialize};
use tokio::time;

#[derive(Debug, Serialize, Deserialize)]
pub struct Dashboard {
    pub stats: Stats, // This
    pub analytics: Analytics,
    pub blocklists: Vec<Blocklist>, // This
    pub top_domains: Vec<DomainStat>,
    pub top_blocked: Vec<DomainStat>,
    pub top_clients: Mutex<HashMap<String, u64>>, // Make this Client: queries
    pub record_types: Mutex<HashMap<String, u64>>,
    pub response_codes: Mutex<HashMap<String, u64>>,
    pub cache: CacheStats,
    pub activity: Vec<ActivityEntry>,
    pub resolver: ResolverInfo,
    pub system: SystemInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Stats {
    pub total_queries: AtomicU64,
    pub allowed_queries: AtomicU64,
    pub blocked_queries: AtomicU64,

    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,

    pub unique_clients: AtomicU64,
    pub unique_domains: AtomicU64,

    pub avg_qps: u64,
    pub peak_qps: u64,

    pub avg_response_time_ms: f64,

    pub memory_usage_mb: AtomicU64,
    pub cpu_usage_percent: f64,

    pub uptime_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Analytics {
    pub timeline: Vec<TimelinePoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelinePoint {
    pub time: String,
    pub queries: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blocklist {
    pub name: String,
    pub entries: u64,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainStat {
    pub domain: String,
    pub count: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CacheStats {
    pub size: AtomicU64,
    pub capacity: usize,

    pub evictions: AtomicU64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityEntry {
    pub timestamp: String,
    pub client: String,
    pub domain: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverInfo {
    pub upstream: String,
    pub protocol: String,
    pub dnssec: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub os: String,
    pub version: String,
}


impl Dashboard {
    pub fn new() -> Self {
        Self {
            stats: Stats {
                total_queries: AtomicU64::new(0),
                allowed_queries: AtomicU64::new(0),
                blocked_queries: AtomicU64::new(0),

                cache_hits: AtomicU64::new(0),
                cache_misses: AtomicU64::new(0),

                unique_clients: AtomicU64::new(0),
                unique_domains: AtomicU64::new(0),

                avg_qps: 0,
                peak_qps: 0,

                avg_response_time_ms: 0.0,
                memory_usage_mb: AtomicU64::new(0),
                cpu_usage_percent: 0.0,
                uptime_seconds: get_time(),
            },

            analytics: Analytics {
                timeline: Vec::new(),
            },

            blocklists: Vec::new(),

            top_domains: Vec::new(),

            top_blocked: Vec::new(),

            top_clients: Mutex::new(HashMap::new()),

            record_types: Mutex::new(HashMap::new()),

            response_codes: Mutex::new(HashMap::new()),

            cache: CacheStats {
                size: AtomicU64::new(1),
                capacity: 0usize,

                evictions: AtomicU64::new(0),
            },

            activity: Vec::new(),

            resolver: ResolverInfo {
                upstream: String::new(),
                protocol: String::new(),
                dnssec: false,
            },

            system: SystemInfo {
                hostname: std::fs::read_to_string("/etc/hostname").expect("Error: Reading hostname"),
                os: std::env::consts::OS.to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
        }
    }

    fn to_le_string(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

fn get_time() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => panic!("SystemTime before UNIX EPOCH!"),
    }
}

pub async fn start_api(addrs: &str, body: Arc<Dashboard>) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addrs).await?;

    let app = Router::new()
        .route("/", get(handler))
        .route("/dashboard", get(dashboard_data))
        .with_state(body);

    axum::serve(listener, app).await
}

async fn handler() -> Html<String> {
    let data = std::fs::read_to_string("index.html")
        .unwrap_or_else(|error|
            format!( r#"<!doctype html><html><body> <h1>Error</h1> <p>{}</p> </body> </html>"#,
                error.to_string())
        );

    Html(data)
}

async fn dashboard_data(State(body): State<Arc<Dashboard>>) -> impl IntoResponse {
    serde_json::to_string(body.as_ref()).unwrap()
}
