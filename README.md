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

---

# Future Updates

* DNS response caching
* DNS-over-HTTPS upstream support
* TCP DNS support
* IPv6 support
* Web dashboard
* Real-time query monitoring
* Query logging
* Configurable block responses
* Blocklist auto-updates
* Rate limiting

