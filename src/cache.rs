use std::{cmp::Ordering, collections::HashMap, time::{Duration, Instant}};

use hickory_proto::{op::Query, rr::{DNSClass, Name, Record, RecordType}};

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct CacheKey {
    pub name: Name,
    pub query_type: RecordType,
    pub query_class: DNSClass,
}

impl CacheKey {
    pub fn new(query: &Query) -> Self {
        Self {
            name: query.name.clone(),
            query_type: query.query_type,
            query_class: query.query_class
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CacheValue {
    pub answer: Record,
    pub cached_at: Instant,
    pub no_expiry: bool,
}

impl CacheValue {
    pub fn new(answer: Record) -> Self {
        Self {
            answer: answer,
            cached_at: Instant::now(),
            no_expiry: false
        }
    }

    pub fn new_no_expiry(answer: Record) -> Self {
        Self {
            answer: answer,
            cached_at: Instant::now(),
            no_expiry: true
        }
    }

    pub fn expired(&self) -> bool {
        if self.no_expiry == true {
            return false;
        }

        let time_since = self.cached_at.duration_since(Instant::now());
        let ttl = Duration::from_secs(self.answer.ttl as u64);
        match time_since.cmp(&ttl) {
            Ordering::Greater => true,
            _ => false,
        }
    }
}

pub trait Purge {
    fn purge_cache(&mut self);
}

impl Purge for HashMap<CacheKey, CacheValue> {
    fn purge_cache(&mut self) {
        self.retain(|_, value| !value.expired());
    }
}
