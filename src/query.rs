use std::{net::{Ipv4Addr, Ipv6Addr, SocketAddr}, sync::Arc};
use hickory_proto::op::{Message, MessageType, UpdateMessage};
use crate::{RuntimeState, cache::*, misc};
use std::sync::atomic::Ordering::Relaxed;

async fn upstream_query(packet: &[u8], dns_packet: &Message, config: &Arc<RuntimeState>, key: CacheKey) -> Option<Message> {
    let servers = match config.mutable.read() {
        Ok(guard) => guard.upstream_servers.servers.clone(),
        Err(err) => {
            eprintln!("[!] Error: Poisoned Lock - {err}");
            return None;
        }
    };

    let mut servers = servers.iter();
    let mut upstream_buffer = [0u8; 4096];

    'upstream: loop {
        dbg!("Upstream Server Asking");
        let _ = config.immutable.upstream.send_to(
            packet,
            match servers.next() {
                Some(x) => x,
                None => break 'upstream None,
            }
        ).await;

        let (bytes_read, _addrs) = match config.immutable.upstream.recv_from(&mut upstream_buffer).await {
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
            let mut cache = match config.cache.write() {
                Ok(x) => x,
                Err(err) => {
                    eprintln!("[!] Error: Poisoned Lock {err}!");
                    return None;
                }
            };

            let value = match misc::get_record(&upstream_resp) {
                Some(x) => CacheValue::new(x),
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

pub async fn handle_client(packet: &[u8], addrs: SocketAddr, config: Arc<RuntimeState>) {
    let dns_packet = match Message::from_vec(packet) {
        Ok(x) => x,
        Err(err) => {
            eprintln!("[!] Error: Decoding error {err}");
            return;
        },
    };

    match config.dashboard.write() {
        Ok(x) => {
            /* DASHBOARD RECORD TYPES */
            let record_type = match dns_packet.queries.get(0) {
                Some(l) => l.query_type().to_string(),
                None => {
                    eprintln!("[!] Error: No dns query found in packet");
                    return;
                }
            };

            match x.record_types.lock() {
                Ok(mut record_types) => {
                    record_types.entry(record_type)
                        .and_modify(|val| *val += 1)
                        .or_insert(1);
                },
                Err(err) => {
                    eprintln!("[!] Error: Poisoned Lock {err}!");
                    return;
                }
            }

            /* DASHBOARD RESPONSE CODES */
            let response_code = dns_packet.response_code;
            match x.response_codes.lock() {
                Ok(mut response_codes) => {
                    response_codes.entry(response_code.to_string())
                        .and_modify(|val| *val += 1)
                        .or_insert(1);
                },
                Err(err) => {
                    eprintln!("[!] Error: Poisoned Lock {err}!");
                    return;
                }
            }

        },
        Err(err) => {
            eprintln!("[!] Error: Poisoned Lock - {err}");
            return;
        }
    }

    let requested_domain = match misc::get_domain(&dns_packet) {
        Some(x) => x,
        None => {
            eprintln!("[!] Error: No domain was requested in QUERY");
            return;
        }
    };

    match config.dashboard.write() {
        Ok(guard) => { guard.stats.total_queries.fetch_add(1, Relaxed); },
        Err(err) => {
            eprintln!("[!] Error: Poisoned Lock - {err}");
            return;
        }
    }

    let cache_hit = match config.mutable.read() {
        Ok(guard) => guard.blacklist.contains(&requested_domain),
        Err(err) => {
            eprintln!("[!] Error: Poisoned Lock - {err}");
            return;
        }
    };

    if cache_hit {
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
                let _ = config.immutable.socket_ipv4.send_to(&resp_bytes, socket).await;
            },
            SocketAddr::V6(socket) => {
                let _ = config.immutable.socket_ipv6.send_to(&resp_bytes, socket).await;
            }
        }

        match config.dashboard.write() {
            Ok(guard) => { guard.stats.blocked_queries.fetch_add(1, Relaxed); },
            Err(err) => {
                eprintln!("[!] Error: Poisoned Lock - {err}");
                return;
            }
        }
        dbg!("Blocked");
    } else {
        match config.dashboard.write() {
            Ok(guard) => { guard.stats.allowed_queries.fetch_add(1, Relaxed); },
            Err(err) => {
                eprintln!("[!] Error: Poisoned Lock - {err}");
                return;
            }
        }

        let key = match dns_packet.queries.get(0) {
            Some(x) => CacheKey::new(x),
            None => {
                eprintln!("[!] Error: No queries found in QUERY packet");
                return;
            }
        };

        let cached_record = {
            let query_cache = match config.cache.read() {
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
                match config.dashboard.write() {
                    Ok(guard) => { guard.stats.cache_hits.fetch_add(1, Relaxed); },
                    Err(err) => {
                        eprintln!("[!] Error: Poisoned Lock - {err}");
                        return;
                    }
                }

                {
                    let query_cache_len = {
                        match config.cache.read() {
                            Ok(x) => x.len(),
                            Err(err) => {
                                eprintln!("[!] Error: {err}");
                                return;
                            },
                        }
                    };

                    if query_cache_len >= config.immutable.max_cache {
                        // Run the function to remove expired caches
                        if let Ok(mut cache) = config.cache.write() {
                            (*cache).purge_cache();
                        }
                    }
                }

                if rec.expired() {
                    dbg!("Cache hit but record expired");
                    // remove and make a request to the DNS server
                    {
                        if let Ok(mut cache) = config.cache.write() {
                            (*cache).remove(&key);
                        } else {
                            eprintln!("[!] Error: Getting a lock on cache!");
                        }
                    }

                    match config.dashboard.write() {
                        Ok(guard) => { guard.cache.size.fetch_add(1, Relaxed); },
                        Err(err) => {
                            eprintln!("[!] Error: Poisoned Lock - {err}");
                            return;
                        }
                    }
                    upstream_query(packet, &dns_packet, &config, key).await
                } else {
                    Some(misc::create_response(&dns_packet, rec.answer))
                }
            },
            None => {
                dbg!("Cache Miss");
                // Make Upstream Request
                let packet = upstream_query(packet, &dns_packet, &config, key).await;

                if packet.is_some() {
                    // Packet maybe NONE
                    match config.dashboard.write() {
                        Ok(guard) => {
                            guard.stats.cache_misses.fetch_add(1, Relaxed);
                            guard.cache.size.fetch_add(1, Relaxed);
                        },
                        Err(err) => {
                            eprintln!("[!] Error: Poisoned Lock - {err}");
                            return;
                        }
                    }
                }

                packet
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
                let _ = config.immutable.socket_ipv4.send_to(&dns_resp_bytes, socket).await;
            },
            SocketAddr::V6(socket) => {
                let _ = config.immutable.socket_ipv6.send_to(&dns_resp_bytes, socket).await;
            }
        }
    }
}


