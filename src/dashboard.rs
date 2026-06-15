use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicU64;
use std::io::Result;
use std::collections::HashMap;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderValue, Response as OtherResponse, header};
use axum::{Json, Router};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use crate::misc::get_blacklisted_domains;

#[derive(Debug, Serialize, Deserialize)]
pub struct Dashboard {
    pub stats: Stats, // This
    pub blocklists: Vec<Blocklist>, // This
    pub record_types: Mutex<HashMap<String, u64>>,
    pub response_codes: Mutex<HashMap<String, u64>>,
    pub cache: CacheStats,
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
pub struct Blocklist {
    pub name: String,
    pub entries: u64,
    pub enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CacheStats {
    pub size: AtomicU64,
    pub capacity: usize,
    pub evictions: AtomicU64,
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

            blocklists: Vec::new(),

            record_types: Mutex::new(HashMap::new()),

            response_codes: Mutex::new(HashMap::new()),

            cache: CacheStats {
                size: AtomicU64::new(1),
                capacity: 0usize,

                evictions: AtomicU64::new(0),
            },


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
}

fn get_time() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => panic!("SystemTime before UNIX EPOCH!"),
    }
}

fn cpu_usage() -> f64 {
    let (total_1, busy_1) = match std::fs::read_to_string("/proc/stat") {
        Ok(data) => {
            let (data, _) = match data.split_once("\n") {
                Some(x) => x,
                None => ("", ""),
            };

            let a = data
                .split_whitespace()
                .filter_map(|f| f.parse::<u64>().ok())
                .collect::<Vec<_>>();

            let x = a[0] + a[1] + a[2] + a[3] + a[4] + a[5] + a[6] + a[7];
            let y = x - a[3] - a[4];

            (x,y)
        },
        Err(_) => {
            return 0.0;
        }
    };

    std::thread::sleep(std::time::Duration::from_millis(500));

    let (total_2, busy_2) = match std::fs::read_to_string("/proc/stat") {
        Ok(data) => {
            let (data, _) = match data.split_once("\n") {
                Some(x) => x,
                None => ("", ""),
            };

            let a = data
                .split_whitespace()
                .filter_map(|f| f.parse::<u64>().ok())
                .collect::<Vec<_>>();

            let x = a[0] + a[1] + a[2] + a[3] + a[4] + a[5] + a[6] + a[7];
            let y = x - a[3] - a[4];

            (x,y)
        },
        Err(_) => {
            return 0.0;
        }
    };

    ((busy_2 - busy_1) as f64 / (total_2 - total_1) as f64) * 100.0
}

pub struct ApiConfig {
    pub addrs: String,
    pub assets: String
}

pub async fn start_api(apiconf: ApiConfig, configs: Arc<crate::RuntimeState>) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(&apiconf.addrs).await?;
    println!("Dashboard Hosted on http://{}", &apiconf.addrs);

    let app = Router::new()
        .route("/", get(handler))
        .route("/favicon", get(favicon))
        .route("/api", post(api))
        .route("/dashboard", get(dashboard_data))
        .with_state((configs, apiconf.assets));

    axum::serve(listener, app).await
}

async fn handler(
    State((_, folder)): State<(Arc<crate::RuntimeState>, String)>
) -> Html<String> {
    let path = format!("{}/{}", folder, "index.html");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|error|
            format!( r#"<!doctype html><html><body> <h1>Error</h1> <p>{}</p> </body> </html>"#,
                error.to_string())
        );

    println!("Path: {}", path);

    Html(data)
}

async fn favicon(
    State((_, folder)): State<(Arc<crate::RuntimeState>, String)>
) -> OtherResponse<Body> {
    let data = std::fs::read(
            format!("{}/{}", folder, "dns_icon.png")
        )
        .unwrap_or(vec![0]);

    OtherResponse::builder()
        .header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("image/x-icon")
        )
        .body(Body::from(data))
        .unwrap()
}

async fn dashboard_data(
    State((body, _)): State<(Arc<crate::RuntimeState>, String)>
) -> impl IntoResponse {

    match body.dashboard.write() {
        Ok(mut guard) => {
            guard.stats.cpu_usage_percent = cpu_usage();
        },
        Err(err) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Lock poisoned: {}", err),
            ).into_response();
        }
    }

    // Update dashboard data here
    let dash = match body.dashboard.read() {
        Ok(guard) => guard,
        Err(err) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Lock poisoned: {}", err),
            ).into_response();
        }
    };

    match serde_json::to_string(&*dash) {
        Ok(json) => (axum::http::StatusCode::OK, json).into_response(),
        Err(err) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Serialization failed: {}", err),
        ).into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct Data {
    upstreams: Vec<String>,
    blocklists: Vec<String>
}

#[derive(Serialize)]
struct Response {
    ok: bool,
}

async fn api(
    State((config, _)): State<(Arc<crate::RuntimeState>, String)>,
    Json(data): Json<Data>
) -> impl IntoResponse {
    if !data.upstreams.is_empty() {
        match config.mutable.write() {
            Ok(mut guard) => guard.upstream_servers.servers.extend_from_slice(&data.upstreams),
            Err(err) => {
                return (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Lock poisoned: {}", err),
                ).into_response();
            }
        }
    }

    if !data.blocklists.is_empty() {
        let new_blocklist_domains = match config.dashboard.write() {
            Ok(mut guard) => match get_blacklisted_domains(&data.blocklists, &mut guard) {
                Ok(domains) => domains,
                Err(err) => {
                    return (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to get blacklisted domains: {}", err),
                    ).into_response();
                }
            },
            Err(err) => {
                return (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Lock poisoned: {}", err),
                ).into_response();
            }
        };

        match config.mutable.write() {
            Ok(mut guard) => guard.blacklist.extend(new_blocklist_domains),
            Err(err) => {
                return (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Lock poisoned: {}", err),
                ).into_response();
            }
        }
    }


    (
        axum::http::StatusCode::OK,
        Json(Response { ok: true }),
    ).into_response()
}
