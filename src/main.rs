use std::sync::{Arc, Mutex};
use std::{
    collections::{HashMap, HashSet}, net::SocketAddr, sync::OnceLock
};
use hickory_proto::rr::Record;
use tokio::net::UdpSocket;
use hickory_proto::op::{MessageType, UpdateMessage};
use hickory_proto::{op::Message, rr::Name};

use crate::misc::get_record;

mod config;
mod misc;

struct Configuration {
    socket: UdpSocket,
    upstream: UdpSocket,
    blacklist: HashSet<Name>,
    toml: config::TomlConfig
}

type Cache<T,X> = Arc<Mutex<HashMap<T,X>>>;

static GLOBAL_CONFIG: OnceLock<Configuration> = OnceLock::new();

async fn handle_client(packet: &[u8], addrs: SocketAddr, cache: Cache<Name, Record>) {
    let config = GLOBAL_CONFIG.get().unwrap();

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

    if config.blacklist.contains(&requested_domain) {
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

        let _ = config.socket.send_to(&resp_bytes, addrs).await;
    } else {
        let dns_response = {
            let cached_record = {
                let cache = match cache.lock() {
                    Ok(x) => x,
                    Err(err) => {
                        eprintln!("[!] Error: Getting a lock on cache {err}!");
                        return;
                    }
                };

                cache.get(&requested_domain).cloned()
            };

            match cached_record {
                Some(rec) => {
                    dbg!("Cache hit");
                    Some(misc::create_response(&dns_packet, rec))
                },
                None => {
                    dbg!("Cache Miss");
                    let mut servers = config.toml.upstream.servers.iter();
                    let mut upstream_buffer = [0u8; 512];

                    'upstream: loop {
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
                            let mut cache = match cache.lock() {
                                Ok(x) => x,
                                Err(err) => {
                                    eprintln!("[!] Error: Getting a lock on cache {err}!");
                                    return;
                                }
                            };

                            let record = match get_record(&upstream_resp) {
                                Some(x) => x,
                                None => {
                                    eprintln!("[!] Error: Not Answer queries was found!");
                                    return;
                                }
                            };

                            cache.insert(requested_domain, record);

                            break 'upstream Some(upstream_resp);
                        }
                    }
                }
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

        let _ = config.socket.send_to(&dns_resp_bytes, addrs).await;
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

    /* ------------------------ Shows Data --------------------------------- */
    println!("<<>> RustHole Running on {} <<>>", &config.server.listen_addr);
    println!(";; Loaded: {} blocked sites", blacklisted_domains.len());

    let cache: Cache<Name, Record>= Arc::new(Mutex::new(HashMap::new()));

    if GLOBAL_CONFIG.set(
        Configuration {
            socket,
            upstream,
            blacklist: blacklisted_domains,
            toml: config
        }
    ).is_err() {
        eprintln!("[!] Error: GLOBAL_CONFIG was already set!");
        return;
    }

    let mut buf = [0u8; 512];

    loop {
        let config = GLOBAL_CONFIG.get().unwrap();
        let (nbytes, addrs) = match config.socket.recv_from(&mut buf).await {
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

        let cache_clone = Arc::clone(&cache);
        tokio::spawn(async move {
            handle_client(&buf[..nbytes], addrs, cache_clone).await;
        });
    }
}
