use std::sync::{Arc, OnceLock, RwLock};
use std::{
    collections::{HashMap, HashSet}, net::SocketAddr
};
use tokio::net::UdpSocket;
use hickory_proto::op::{MessageType, UpdateMessage};
use hickory_proto::{op::Message, rr::Name};

use crate::cache::Purge;

mod config;
mod misc;
mod cache;

struct DNSConfiguration {
    socket: UdpSocket,
    upstream: UdpSocket,
    blacklist: HashSet<Name>,
    toml: config::TomlConfig
}

// TODO: Remove All Unwraps;
type CacheMap = Arc<RwLock<HashMap<cache::CacheKey, cache::CacheValue>>>;
static DNS_CONFIG: OnceLock<DNSConfiguration> = OnceLock::new();

async fn upstream_query(packet: &[u8], dns_packet: &Message, query_cache: CacheMap, key: cache::CacheKey) -> Option<Message> {
    let config = DNS_CONFIG.get().unwrap();
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
                    return None;
                }
            };

            (*cache).insert(key, value);

            return Some(upstream_resp);
        }
    }

}

async fn handle_client(packet: &[u8], addrs: SocketAddr, dns_queries: CacheMap) {
    let dns_config = DNS_CONFIG.get().unwrap();

    let dns_packet = match Message::from_vec(packet) {
        Ok(x) => x,
        Err(err) => {
            eprintln!("[!] Error: Decoding error {err}");
            return;
        },
    };

    let requested_domain = match misc::get_domain(&dns_packet) {
        Some(x) => x,
        None => {
            eprintln!("[!] Error: No domain was requested in QUERY");
            return;
        }
    };

    if dns_config.blacklist.contains(&requested_domain) {
        // Block the domain
        let resp_pkt = misc::create_response(
            &dns_packet,
            misc::blocked_record(requested_domain)
        );

        let resp_bytes = match resp_pkt.to_vec() {
            Ok(x) => x,
            Err(err) => {
                eprintln!("[!] Error: Converting DNS packet to bytes {err}");
                return;
            }
        };

        let _ = dns_config.socket.send_to(&resp_bytes, addrs).await;
        dbg!("Blocked");
    } else {
        let key = match dns_packet.queries.get(0) {
            Some(x) => cache::CacheKey::new(x),
            None => {
                eprintln!("[!] Error: No queries found in QUERY packet");
                return;
            }
        };

        let cached_record = {
            let query_cache = dns_queries.read().unwrap();
            (*query_cache).get(&key).cloned()
        };

        let dns_response = match cached_record {
            Some(rec) => {
                dbg!("Cache hit");

                {
                    let query_cache_len = { dns_queries.read().unwrap().len() };
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

                    upstream_query(packet, &dns_packet, dns_queries, key).await
                } else {
                    Some(misc::create_response(&dns_packet, rec.answer))
                }
            },
            None => {
                dbg!("Cache Miss");
                // Make Upstream Request
                upstream_query(packet, &dns_packet, dns_queries, key).await
            }
        };

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

        let _ = dns_config.socket.send_to(&dns_resp_bytes, addrs).await;
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

    let blacklisted_domains: HashSet<Name> = match misc::get_blacklisted_domains(&config.blacklist.files) {
        Ok(x) => x,
        Err(err) => {
            eprintln!("[!] Error: {err}");
            return;
        }
    };

    let socket = match UdpSocket::bind(&config.server.listen_addr).await {
        Ok(x) => x,
        Err(err) => {
            eprintln!("[!] Error: Binding to {} {err}", &config.server.listen_addr);
            return;
        }
    };

    let upstream = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(x) => x,
        Err(err) => {
            eprintln!("[!] Error: Binding to {} {err}", &config.server.listen_addr);
            return;
        }
    };

    if DNS_CONFIG.set(DNSConfiguration {
        socket,
        upstream,
        blacklist: blacklisted_domains,
        toml: config,
    }).is_err() {
        eprintln!("[!] Error: Setting DNS_CONFIG!");
        return;
    }

    let mut buf = [0u8; 4096];
    let query_cache: CacheMap = Arc::new(RwLock::new(HashMap::new()));

    let dnsconfig = &DNS_CONFIG.get().unwrap();

    /* ------------------------ Shows Data --------------------------------- */
    println!("<<>> RustHole Running on {} <<>>", &dnsconfig.toml.server.listen_addr);
    println!(";; Loaded: {} blocked sites", dnsconfig.blacklist.len());

    loop {
        let (nbytes, addrs) = match dnsconfig.socket.recv_from(&mut buf).await {
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

        let cache_clone = Arc::clone(&query_cache);

        tokio::spawn(async move {
            handle_client(&buf[..nbytes].to_vec(), addrs, cache_clone).await;
        });
    }
}
