use std::{
    collections::HashSet, io::Write, net::SocketAddr, sync::{LazyLock, Mutex, OnceLock}
};
use tokio::net::UdpSocket;
use hickory_proto::op::{MessageType, UpdateMessage};
use hickory_proto::{op::Message, rr::Name};

mod config;
mod misc;

struct Configuration {
    socket: UdpSocket,
    upstream: UdpSocket,
    blacklist: HashSet<Name>,
    toml: config::TomlConfig
}

static GLOBAL_CONFIG: OnceLock<Configuration> = OnceLock::new();
static BLOCKED_QUERIES: LazyLock<Mutex<u128>> = LazyLock::new(|| Mutex::new(0u128));
static ALLOWED_QUERIES: LazyLock<Mutex<u128>> = LazyLock::new(|| Mutex::new(0u128));

async fn handle_client(packet: Vec<u8>, addrs: SocketAddr) {
    let config = GLOBAL_CONFIG.get().unwrap();

    let dns_packet = match Message::from_vec(&packet) {
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
        {
            let mut a = BLOCKED_QUERIES.lock().unwrap();
            let b = ALLOWED_QUERIES.lock().unwrap();
            *a += 1;
            print!("\r; Queries Blocked: {} | Queries Allowed: {}", *a, *b);
            std::io::stdout().flush().ok();
        }

        let resp_pkt = match misc::block_response(&dns_packet) {
            Ok(x) => x,
            Err(err) => {
                eprintln!("[!] Error: {err}");
                return;
            },
        };

        let resp_bytes = match resp_pkt.to_vec() {
            Ok(x) => x,
            Err(err) => {
                eprintln!("[!] Error: Converting DNS packet to bytes {err}");
                return;
            }
        };

        let _ = config.socket.send_to(&resp_bytes, addrs).await;
    } else {
        {
            let a = BLOCKED_QUERIES.lock().unwrap();
            let mut b = ALLOWED_QUERIES.lock().unwrap();
            *b += 1;
            print!("\r; Queries Blocked: {} | Queries Allowed: {}", *a, *b);
            std::io::stdout().flush().ok();
        }

        let mut servers = config.toml.upstream.servers.iter();
        let mut upstream_buffer = [0u8; 512];

        'upstream: loop {
            let _ = config.upstream.send_to(
                &packet,
                match servers.next() {
                    Some(x) => x,
                    None => break 'upstream,
                }
            ).await;

            let (bytes_read, _addrs) = match config.upstream.recv_from(&mut upstream_buffer).await {
                Ok((0, _)) => {
                    eprintln!("[!] Error: No Data Recieved");
                    break 'upstream;
                },
                Ok((x, addrs)) => (x, addrs),
                Err(err) => {
                    eprintln!("[!] Error: {err}");
                    break 'upstream;
                }
            };

            let upstream_resp = match Message::from_vec(&upstream_buffer[..bytes_read]) {
                Ok(x) => x,
                Err(err) => {
                    eprintln!("[!] Error: Decoding error {err}");
                    break 'upstream;
                },
            };

            if (dns_packet.id() == upstream_resp.id()) && (upstream_resp.metadata.message_type == MessageType::Response) {
                let _ = config.socket.send_to(&upstream_buffer[..bytes_read], addrs).await;
                break 'upstream;
            }
        }
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

        tokio::spawn(async move {
            handle_client(buf[..nbytes].to_vec(), addrs).await;
        });
    }
}
