use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::collections::HashSet;
use hickory_proto::{op::Message, rr::{Name, RData, Record}};
use regex::Regex;

pub fn blocked_record(domain: Name) -> Record {
    Record::from_rdata(
        domain,
        60u32,
        RData::A(Ipv4Addr::new(0, 0, 0, 0).into())
    )

}

pub fn create_response(request: &Message, record: Record) -> Message {
    let mut resp_pkt = Message::response(request.id, request.op_code);
    resp_pkt.add_queries(request.queries.clone());

    resp_pkt.add_answer(record);

    if request.edns.is_some() {
        resp_pkt.set_edns(request.edns.clone().unwrap());
    }

    resp_pkt
}

pub fn get_record(request: &Message) -> Option<Record> {
    request.answers.iter().nth(0).cloned()
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
    let regex = Regex::new(r#"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?\b"#)
        .map_err(|e| format!("{e}"))?;

    for file in files {
        let fptr = File::open(file).map_err(|err| format!("{err}"))?;
        let reader = BufReader::new(fptr);

        for line in reader.lines() {
            let line = line.map_err(|err| format!("{err}"))?;
            if line.starts_with(&['#', ';']) {
                continue;
            }
            for m in regex.find_iter(&line) {
                let domain = m.as_str().to_lowercase();
                domains.insert(
                    Name::from_str(&domain)
                        .map_err(|err| format!("{err}"))?
                );
            }
        }
    }

    Ok(domains)
}

