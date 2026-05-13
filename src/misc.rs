use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::collections::HashSet;
use hickory_proto::{op::Message, rr::{Name, RData, Record}};

pub fn block_response(request: &Message) -> Result<Message, String> {
    let mut resp_pkt = Message::response(request.id, request.op_code);
    resp_pkt.add_queries(request.queries.clone());

    let record = Record::from_rdata(
        match get_domain(request) {
            Some(x) => x,
            None => return Err(format!("No queries found!"))
        },
        60u32,
        RData::A(Ipv4Addr::new(0, 0, 0, 0).into())
    );
    resp_pkt.add_answer(record);

    resp_pkt.set_edns(match &request.edns {
        Some(x) => x.clone(),
        None => return Err(format!("no edns found in QUERY packet"))
    });

    Ok(resp_pkt)
}

pub fn get_domain(request: &Message) -> Option<Name> {
    match request.queries.get(0) {
        Some(x) => {
            let x = x.name()
                .to_ascii()
                .trim_end_matches('.')
                .to_lowercase()
                .to_string();

            Name::from_str(&x).ok()
        },
        None => return None
    }
}

pub fn get_blacklisted_domains(files: &[String]) -> Result<HashSet<Name>, String> {
    let mut domains: HashSet<Name> = HashSet::new();

    for file in files {
        let fptr = File::open(file).map_err(|err| format!("{err}"))?;
        let reader = BufReader::new(fptr);

        for line in reader.lines() {
            let line = line.map_err(|err| format!("{err}"))?;
            let domain = line.trim().to_lowercase();

            if domain.is_empty() || domain.starts_with(&[';', '#']){
                continue;
            }

            domains.insert(Name::from_str(&domain).map_err(|err| format!("{err}"))?);
        }
    }

    Ok(domains)
}

