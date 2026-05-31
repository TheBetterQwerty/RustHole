use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, OnceLock, RwLock};
use std::str::FromStr;
use std::{
    collections::{HashMap, HashSet}, net::SocketAddr
};
use tokio::net::UdpSocket;
use hickory_proto::op::{MessageType, UpdateMessage};
use hickory_proto::{op::Message, rr::{ Name, DNSClass, RecordType}};
use std::sync::atomic::Ordering::Relaxed;
use crate::cache::Purge;
use crate::dashboard::Dashboard;

mod config;
mod misc;
mod cache;
mod dashboard;

struct DNSConfiguration {
    socket_ipv4: UdpSocket,
    socket_ipv6: UdpSocket,
    upstream: UdpSocket,
    blacklist: HashSet<Name>,
    toml: config::TomlConfig
}

/*
 *  TODO:
 */

type CacheMap = Arc<RwLock<HashMap<cache::CacheKey, cache::CacheValue>>>;
static DNS_CONFIG: OnceLock<DNSConfiguration> = OnceLock::new();

async fn upstream_query(packet: &[u8], dns_packet: &Message, query_cache: CacheMap, key: cache::CacheKey) -> Option<Message> {
    let config = match DNS_CONFIG.get() {
        Some(x) => x,
        None => {
            eprintln!("[!] Error: getting config!");
            return None;
        }
    };

    let mut servers = config.toml.upstream.servers.iter();
    let mut upstream_buffer = [0u8; 4096];

    'upstream: loop {
        dbg!("Upstream Server Asking");
        let _ = config.upstream.send_to(
            packet,
            match servers.next() {
                Some(x) => x,
                None => break 'upstream None,
            }
        ).await;

        let (bytes_read, _addrs) = match config.upstream.recv_from(&mut upstream_buffer).await {
            Ok((0, _)) => {
                eprintln!("[!] Error: No Data Recieved");
                break 'upstream None;
            },
            Ok((x, addrs)) => (x, addrs),
            Err(err) => {
                eprintln!("[!] Error: {err}");
                break 'upstream None;
            }
        };

        let upstream_resp = match Message::from_vec(&upstream_buffer[..bytes_read]) {
            Ok(x) => x,
            Err(err) => {
                eprintln!("[!] Error: Decoding error {err}");
                break 'upstream None;
            },
        };

        if (dns_packet.id() == upstream_resp.id()) && (upstream_resp.metadata.message_type == MessageType::Response) {
            // insert it into hashmap
            let mut cache = match query_cache.write() {
                Ok(x) => x,
                Err(err) => {
                    eprintln!("[!] Error: Getting a lock on cache {err}!");
                    return None;
                }
            };

            let value = match misc::get_record(&upstream_resp) {
                Some(x) => cache::CacheValue::new(x),
                None => {
                    eprintln!("[!] Error: Not Answer queries was found!");
                    return Some(upstream_resp);
                }
            };

            (*cache).insert(key, value);

            return Some(upstream_resp);
        }
    }

}

async fn handle_client(packet: &[u8], addrs: SocketAddr, dns_queries: CacheMap, dashboard: Arc<Dashboard>) {
    let dns_config = match DNS_CONFIG.get() {
        Some(x) => x,
        None => {
            eprintln!("[!] Error: getting config!");
            return;
        }
    };

    let dns_packet = match Message::from_vec(packet) {
        Ok(x) => x,
        Err(err) => {
            eprintln!("[!] Error: Decoding error {err}");
            return;
        },
    };

    {
        /* DASHBOARD RECORD TYPES */
        let mut record_types = dashboard.record_types.lock().unwrap();
        let record_type = dns_packet.queries.get(0).unwrap().query_type().to_string();
        record_types.entry(record_type)
            .and_modify(|val| *val += 1)
            .or_insert(1);
    }

    {
        /* DASHBOARD RESPONSE CODES */
        let mut response_codes = dashboard.response_codes.lock().unwrap();
        let response_code = dns_packet.response_code;
        response_codes.entry(response_code.to_string())
            .and_modify(|val| *val += 1)
            .or_insert(1);
    }

    let requested_domain = match misc::get_domain(&dns_packet) {
        Some(x) => x,
        None => {
            eprintln!("[!] Error: No domain was requested in QUERY");
            return;
        }
    };

    dashboard.stats.total_queries.fetch_add(1, Relaxed);

    if dns_config.blacklist.contains(&requested_domain) {
        // Block the domain
        let resp_pkt = misc::create_response(
            &dns_packet,
            match addrs {
                SocketAddr::V4(_) => misc::create_record_A(
                    requested_domain,
                    Ipv4Addr::new(0, 0, 0, 0)
                ),
                SocketAddr::V6(_) => misc::create_record_AAAA(
                    requested_domain,
                    Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)
                ),
            }
        );

        let resp_bytes = match resp_pkt.to_vec() {
            Ok(x) => x,
            Err(err) => {
                eprintln!("[!] Error: Converting DNS packet to bytes {err}");
                return;
            }
        };

        match addrs {
            SocketAddr::V4(socket) => {
                let _ = dns_config.socket_ipv4.send_to(&resp_bytes, socket).await;
            },
            SocketAddr::V6(socket) => {
                let _ = dns_config.socket_ipv6.send_to(&resp_bytes, socket).await;
            }
        }

        dashboard.stats.blocked_queries.fetch_add(1, Relaxed);
        dbg!("Blocked");
    } else {
        dashboard.stats.allowed_queries.fetch_add(1, Relaxed);

        let key = match dns_packet.queries.get(0) {
            Some(x) => cache::CacheKey::new(x),
            None => {
                eprintln!("[!] Error: No queries found in QUERY packet");
                return;
            }
        };

        let cached_record = {
            let query_cache = match dns_queries.read() {
                Ok(x) => x,
                Err(err) => {
                    eprintln!("[!] Error: reading dns_queries {err}");
                    return;
                }
            };
            (*query_cache).get(&key).cloned()
        };

        let dns_response = match cached_record {
            Some(rec) => {
                dbg!("Cache hit");
                dashboard.stats.cache_hits.fetch_add(1, Relaxed);

                {
                    let query_cache_len = {
                        match dns_queries.read() {
                            Ok(x) => x.len(),
                            Err(err) => {
                                eprintln!("[!] Error: {err}");
                                return;
                            },
                        }
                    };

                    if query_cache_len >= dns_config.toml.cache.max_cache {
                        // Run the function to remove expired caches
                        if let Ok(mut cache) = dns_queries.write() {
                            (*cache).purge_cache();
                        }
                    }
                }

                if rec.expired() {
                    dbg!("Cache hit but record expired");
                    // remove and make a request to the DNS server
                    {
                        if let Ok(mut cache) = dns_queries.write() {
                            (*cache).remove(&key);
                        } else {
                            eprintln!("[!] Error: Getting a lock on cache!");
                        }
                    }

                    dashboard.cache.size.fetch_add(1, Relaxed);
                    upstream_query(packet, &dns_packet, dns_queries, key).await
                } else {
                    Some(misc::create_response(&dns_packet, rec.answer))
                }
            },
            None => {
                dbg!("Cache Miss");
                dashboard.stats.cache_misses.fetch_add(1, Relaxed);

                // Make Upstream Request
                dashboard.cache.size.fetch_add(1, Relaxed);
                upstream_query(packet, &dns_packet, dns_queries, key).await
            }
        };

        dbg!(&dns_response);

        let dns_resp_bytes = match dns_response {
            Some(x) => match x.to_vec() {
                Ok(x) => x,
                Err(err) => {
                    eprintln!("[!] Error: Encoding error {err}!");
                    return;
                }
            },
            None => return
        };

        match addrs {
            SocketAddr::V4(socket) => {
                let _ = dns_config.socket_ipv4.send_to(&dns_resp_bytes, socket).await;
            },
            SocketAddr::V6(socket) => {
                let _ = dns_config.socket_ipv6.send_to(&dns_resp_bytes, socket).await;
            }
        }
    }
}

async fn handle_ipv4(query_cache: CacheMap, dashboard: Arc<Dashboard>) {
    let mut buffer = [0u8; 4096];
    let config = match DNS_CONFIG.get() {
        Some(x) => x,
        None => {
            eprintln!("[!] Error: getting config!");
            return;
        }
    };

    loop {
        let (nbytes, addrs) = match config.socket_ipv4.recv_from(&mut buffer).await {
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

        let mut clients = dashboard.top_clients.lock().unwrap();

        clients.entry(addrs.to_string())
            .and_modify(|val| *val += 1)
            .or_insert(1);

        let query_clone = Arc::clone(&query_cache);
        let dash_clone = Arc::clone(&dashboard);

        tokio::spawn(async move {
            handle_client(&buffer[..nbytes].to_vec(), addrs, query_clone, dash_clone).await;
        });
    }
}

async fn handle_ipv6(query_cache: CacheMap, dashboard: Arc<Dashboard>) {
    let mut buffer = [0u8; 4096];
    let config = match DNS_CONFIG.get() {
        Some(x) => x,
        None => {
            eprintln!("[!] Error: getting config!");
            return;
        }
    };

    loop {
        let (nbytes, addrs) = match config.socket_ipv6.recv_from(&mut buffer).await {
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

        let mut clients = dashboard.top_clients.lock().unwrap();

        clients.entry(addrs.to_string())
            .and_modify(|val| *val += 1)
            .or_insert(1);

        let query_clone = Arc::clone(&query_cache);
        let dash_clone = Arc::clone(&dashboard);

        tokio::spawn(async move {
            handle_client(&buffer[..nbytes].to_vec(), addrs, query_clone, dash_clone).await;
        });
    }
}

#[tokio::main]
async fn main() {
    let config = match config::parse_toml_file() {
        Ok(x) => x,
        Err(err) => {
            eprintln!("{}", err);
            return;
        }
    };

    let mut dashboard = dashboard::Dashboard::new();
    dashboard.resolver.upstream.push_str(config.upstream.servers.get(0).unwrap());
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

    let socket_ipv6 = match UdpSocket::bind(&config.server.listen_addr_ipv6).await {
        Ok(x) => {
            println!("and {} <<>>", &config.server.listen_addr_ipv6);
            x
        },
        Err(err) => {
            eprintln!("[!] Error: Binding to {} {err}", &config.server.listen_addr_ipv6);
            return;
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
            eprintln!("[!] Error: {err}");
            return;
        }
    };

    if DNS_CONFIG.set(DNSConfiguration {
        socket_ipv4,
        socket_ipv6,
        upstream,
        blacklist: blacklisted_domains,
        toml: config,
    }).is_err() {
        eprintln!("[!] Error: Setting DNS_CONFIG!");
        return;
    }

    let mut hashmap = HashMap::new();
    let domain = match Name::from_str("localhost") {
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
    let dashboard = Arc::new(dashboard);
    let query_cache: CacheMap = Arc::new(RwLock::new(hashmap));
    let query_cache_ipv4 = Arc::clone(&query_cache);

    let dashboard_clone_ipv4 = Arc::clone(&dashboard);
    let dashboard_clone_ipv6 = Arc::clone(&dashboard);

    tokio::spawn(async move {
        handle_ipv4(query_cache_ipv4, dashboard_clone_ipv4).await;
    });

    tokio::spawn(async move {
        handle_ipv6(query_cache, dashboard_clone_ipv6).await;
    });

    // start_api
    let _ = dashboard::start_api("127.0.0.1:8080", dashboard);
}
