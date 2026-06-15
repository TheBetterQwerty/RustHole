use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::str::FromStr;
use std::{
    collections::{HashMap, HashSet},
};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use socket2::{Domain, Socket, Type};
use tokio::net::UdpSocket;
use crate::config::Upstream;
use crate::dashboard::Dashboard;

mod query;
mod config;
mod misc;
mod cache;
mod dashboard;

type CacheMap = RwLock<HashMap<cache::CacheKey, cache::CacheValue>>;

pub struct RuntimeConfig {
    // Contains Mutable Stuff
    pub upstream_servers: Upstream,
    pub blacklist: HashSet<Name>
}

pub struct Config {
    // Contains Immutable Stuff
    pub socket_ipv4: UdpSocket,
    pub socket_ipv6: UdpSocket,
    pub upstream   : UdpSocket,
    pub max_cache  : usize,
}

pub struct RuntimeState {
    pub mutable:    RwLock<RuntimeConfig>,
    pub immutable:  Config,
    pub dashboard:  Arc<RwLock<Dashboard>>,
    pub cache:      CacheMap
}


async fn handle_ipv4(config: Arc<RuntimeState>) {
    let mut buffer = [0u8; 4096];

    loop {
        let (nbytes, addrs) = match config.immutable.socket_ipv4.recv_from(&mut buffer).await {
            Ok((0, _)) => {
                eprintln!("[!] Error: No Data Recieved");
                continue;
            },
            Ok((x, addrs)) => (x, addrs),
            Err(err) => {
                eprintln!("[!] Error: {err}");
                continue;
            }
        };

        let query_clone = Arc::clone(&config);

        tokio::spawn(async move {
            query::handle_client(&buffer[..nbytes].to_vec(), addrs, query_clone).await;
        });
    }
}

async fn handle_ipv6(config: Arc<RuntimeState>) {
    let mut buffer = [0u8; 4096];

    loop {
        let (nbytes, addrs) = match config.immutable.socket_ipv6.recv_from(&mut buffer).await {
            Ok((0, _)) => {
                eprintln!("[!] Error: No Data Recieved");
                continue;
            },
            Ok((x, addrs)) => (x, addrs),
            Err(err) => {
                eprintln!("[!] Error: {err}");
                continue;
            }
        };

        let query_clone = Arc::clone(&config);

        tokio::spawn(async move {
            query::handle_client(&buffer[..nbytes].to_vec(), addrs, query_clone).await;
        });
    }
}

#[tokio::main]
async fn main() {
    let config = match config::parse_toml_file() {
        Ok(x) => x,
        Err(err) => {
            eprintln!("[!] Error: Parsing TOML file - {err}");
            return;
        }
    };

    // create toml config
    let mut dashboard = dashboard::Dashboard::new();
    dashboard.resolver.upstream.push_str(match config.upstream.servers.get(0) {
        Some(x) => x,
        None => {
            eprintln!("[!] Error: Please set a default upstream server in TOML file");
            return;
        }
    });
    dashboard.resolver.protocol.push_str("DNS");

    let socket_ipv4 = match UdpSocket::bind(&config.server.listen_addr_ipv4).await {
        Ok(x) => {
            print!("<<>> RustHole Running on {} ", &config.server.listen_addr_ipv4);
            x
        },
        Err(err) => {
            eprintln!("[!] Error: Binding to {} {err}", &config.server.listen_addr_ipv4);
            return;
        }
    };

    let socket_ipv6 = {
        let addrs: SocketAddr = match config.server.listen_addr_ipv6.parse() {
            Ok(x) => x,
            Err(err) => {
                eprintln!("[!] Error: Parsing IPV6 addrs - {err}");
                return;
            }
        };

        let raw_sockfd = match Socket::new(Domain::IPV6, Type::DGRAM, None) {
            Ok(x) => x,
            Err(err) => {
                eprintln!("[!] Error: Creating socket {err}");
                return;
            }
        };

        if let Err(err) = raw_sockfd.set_only_v6(true) {
            eprintln!("[!] Error: Setting socket to IPV6 only - {err}");
            return;
        }

        if let Err(err) = raw_sockfd.bind(&addrs.into()) {
            eprintln!("[!] Error: Setting socket to IPV6 only - {err}");
            return;
        }

        if let Err(err) = raw_sockfd.set_nonblocking(true) {
            eprintln!("[!] Error: Setting nonblocking socket - {err}");
            return;
        }

        let udp_sockfd = std::net::UdpSocket::from(raw_sockfd);

        match UdpSocket::from_std(udp_sockfd) {
            Ok(x) => {
                println!("and {} <<>>", &config.server.listen_addr_ipv6);
                x
            },
            Err(err) => {
                eprintln!("[!] Error: Creating tokio UDP Socket - {err}");
                return;
            }
        }
    };

    let upstream = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(x) => x,
        Err(err) => {
            eprintln!("[!] Error: Binding to {} {err}", "0.0.0.0:0");
            return;
        }
    };

    let blacklisted_domains: HashSet<Name> = match misc::get_blacklisted_domains(&config.blacklist.files, &mut dashboard) {
        Ok(x) => {
            println!(";; Loaded: {} blocked sites", x.len());
            x
        },
        Err(err) => {
            eprintln!("[!] Error: Blocklist Reader - {err}");
            return;
        }
    };

        let mut hashmap = HashMap::new();
    let domain = match Name::from_str("localhost.") {
        Ok(x) => x,
        Err(err) => {
            eprintln!("[!] Error: Creating a entry {err}");
            return;
        }
    };

    // Localhost PointBack IPv4
    hashmap.insert(
        cache::CacheKey {
            name: domain.clone(),
            query_type: RecordType::A,
            query_class: DNSClass::IN
        },
        cache::CacheValue::new_no_expiry(misc::create_record_A(domain, Ipv4Addr::new(127, 0, 0, 1)))
    );

    dashboard.cache.capacity = hashmap.capacity();

    let state = Arc::new(RuntimeState {
        mutable: RwLock::new(RuntimeConfig {
            upstream_servers: config.upstream,
            blacklist: blacklisted_domains,
        }),
        immutable: Config {
            socket_ipv4: socket_ipv4,
            socket_ipv6: socket_ipv6,
            upstream: upstream,
            max_cache: config.cache.max_cache,
        },
        dashboard: Arc::new(RwLock::new(dashboard)),
        cache: RwLock::new(hashmap)
    });

    let state_v4_clone = Arc::clone(&state);
    let state_v6_clone = Arc::clone(&state);

    tokio::spawn(async move {
        handle_ipv4(state_v4_clone).await;
    });

    tokio::spawn(async move {
        handle_ipv6(state_v6_clone).await;
    });

    // start_api
    let _ = dashboard::start_api(
        dashboard::ApiConfig {
            addrs: config.server.dashboard,
            assets: config.assets.folder,
        },
        state
    ).await;
}
