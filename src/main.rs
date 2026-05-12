use std::{net::{Ipv4Addr, UdpSocket}};
use hickory_proto::{op::{self, Message}, rr::{RData, Record}};

mod config;

fn main() {
    let config = match config::parse_toml_file() {
        Ok(x) => x,
        Err(err) => {
            eprintln!("{}", err);
            return;
        }
    };

    let socket = UdpSocket::bind(&config.server.listen_addr).unwrap(); // 127.0.0.1:53
    println!("[+] Listening on {}", &config.server.listen_addr);

    let mut buf = [0u8; 65535];

    loop {
        let (nbytes, addrs) = socket.recv_from(&mut buf).unwrap();
        let dns_packet_bytes = &buf[..nbytes];
        let dns_packet = op::Message::from_vec(dns_packet_bytes).unwrap();
        println!("Client: {:?}\n\n", dns_packet);

        // Response
        let mut resp_pkt = Message::response(dns_packet.id, dns_packet.op_code);

        for q in dns_packet.queries.iter() {
            resp_pkt.add_query(q.clone());
        }

        let record = Record::from_rdata(
            dns_packet.queries[0].name().clone(),
            60u32,
            RData::A(Ipv4Addr::new(0, 0, 0, 0).into())
        );
        resp_pkt.add_answer(record);

        resp_pkt.set_edns(dns_packet.edns.unwrap());

        println!("Response: {:?}", resp_pkt);

        let resp_pkt_bytes = resp_pkt.to_vec().unwrap();
        let _ = socket.send_to(&resp_pkt_bytes, addrs);
    }
}
