# RustHole

RustHole is a lightweight DNS sinkhole and forwarding resolver written in Rust.

It blocks blacklisted domains locally and forwards allowed DNS queries to upstream DNS servers.

---

# How it Works

1. RustHole binds to a UDP socket and listens for incoming DNS requests.

2. When a DNS query arrives:

   * The requested domain is extracted from the DNS packet.
   * The domain is normalized to lowercase and checked against the loaded blacklist.

3. If the domain is blacklisted:

   * RustHole generates a DNS response locally.
   * The response returns a sinkhole address such as `0.0.0.0`.

4. If the domain is not blacklisted:

   * The original DNS packet is forwarded to an upstream DNS server.
   * The upstream response is received and proxied back to the client.

5. Blacklists are loaded into memory on startup for fast lookup performance using hash-based matching.

6. DNS response caching:

   * The DNS response recieved from the upstream server's is stored in cache.
   * Expiry time is set for each record, unused and expired caches are purged in due time.

7. RustHole now supports IPV6 packets.

8. Web Dashboard that allows adding of more upstream dns servers and blocklists

---

# Future Updates

* DNS-over-HTTPS upstream support
* TCP DNS support
* Blocklist auto-updates
* Rate limiting
