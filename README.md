# rust-toy-dns

A toy DNS server for learning about the Domain Name System and high performance networking in Rust.

If you are looking for a non-toy DNS server written in Rust, check out [trust-dns](https://github.com/bluejekyll/trust-dns).

## Getting Started

```
cargo run
```

### Testing

```shell
cargo run &
dig @127.0.0.1 -p 8080 +noedns google.com
```

### Capturing traffic

```shell
netcat -ul 5300 > query.bin &
dig @127.0.0.1 -p 5300 example.com
# kill netcat
cat query.bin | nc -u 1.1.1.1 53 | tee response.bin
```


## Security

Disclaimer: This is a personal project, I am not a security expert and make no guarantee of security.

The history of DNS security is a bit of a mess, I've made a best effort to navigate it and implement mitigations for known issues.

### Cache Poisoning Attacks

With only a 16 bit transation ID and no cryptographic verification, DNS over UDP is vulnerable to an attacker injecting malicious responses. If no IP verification is done and the source port can be guessed, an attacker can simply send a query as normal and then inject a few thousand malicious response packets with guessed transaction IDs until a collision happens. See also [\[1\]](http://cr.yp.to/djbdns/forgery.html) [\[2\]](https://en.m.wikipedia.org/wiki/Dan_Kaminsky#Flaw_in_DNS).

Mitigation:

- UDP source port is randomized for each query, this adds 14-16 bits of entropy
- Transaction ID is randomized for each query using a cryptographic generator
- Responses must originate from the IP address the query was sent to

### Cache Snooping Attacks

If multiple clients share a caching DNS server, they can both time responses for a domain and look at the returned TTL values to determine if a domain was previously queried and if so how long ago it was cached.

Mitigation:

- Optionally zero out TTL values on responses
- Ignore non-recurive queries to caching server

### Other Attacks

Mitigation:

- Separated DNS server and recursive resolver functionality (DNS servers and recursive resolvers should never run on the same )
- No TCP support for now, it has additional issues where it is easy to cache poison because only the first packet in multi-packet responses include the transaction ID
- Only IN and ANY question classes are allowed for implementation simplicity

### On DNSSEC

A set of security extensions introduced in 1997 that have failed to reach wide acceptance and have a number of critisims. Implementation would add substantial complexity. I am more interested in pursuing modern alternatives like DNSCrypt, DNS over TLS, or DNS over HTTPS.

## TODO

- [X] Factor out resolver trait and test, for adding more than just a non-caching proxy resolver
- [X] Factor out server struct and test
- [X] Caching proxy resolver
- [X] Fix cached ttls
- [X] Drop requests over concurrency limit instead of waiting for lock
- [ ] Cache negative responses
- [ ] Truncate to-long responses (and set TC bit)
- [ ] Support for extended UDP responses
- [ ] Support common record types (PTR, SOA)
- [ ] Increase incoming UDP socket buffer size (similar to socket_tryreservein, something like 128KB is enough)
- [ ] Response compression & better packet cursor - https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
- [ ] Fuzz testing
- [ ] Benchmarking
- [ ] Initialize from from resolver.conf etc
- [ ] Recursive resolver (note http://cr.yp.to/djbdns/separation.html)
- [ ] TODO: Use cryptographic generator to select ports instead of relying on Linux's behavior of finding an open port when binding to port zero. There are two main issues with Linux's behavior. First, older kernels have a "trivially predictable" prandom_u32 implementation used to select a port. Newer kernels utilize SipHash which is a "PITA" to guess, but still not cryptographically secure. Second, Linux selects from a relatively small set of source ports. Specifically it prefers to use odd ports for outgoing connections, and only from the configured empheral port range (net.ipv4.ip_local_port_range) which is usually 32768-60999. That's effectively one quarter of the available ports, meaning instead of 16 bits of security against cache poisoning we get under 14 bits, a relatively small but still meaningful difference.

2022-05-05T16:01:16.762355Z  INFO rust_dns::server: Query mobile.events.data.microsoft.com A from 172.17.0.1
thread 'tokio-runtime-worker' panicked at 'called `Result::unwrap()` on an `Err` value: Utf8Error { valid_up_to: 39, error_len: Some(1) }', src/protocol.rs:768:61
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

## Notes

Inspired by https://github.com/EmilHernvall/dnsguide.

Written with reference to:

- http://cr.yp.to/djbdns.html
- [RFC 1123](https://datatracker.ietf.org/doc/html/rfc1123#section-6) - Requirements for Internet Hosts - SUPPORT SERVICES - DOMAIN NAME TRANSLATION
- [RFC 1034](https://datatracker.ietf.org/doc/html/rfc1034) - DOMAIN NAMES - CONCEPTS AND FACILITIES
- [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035) - DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION
- [RFC 2181](https://datatracker.ietf.org/doc/html/rfc2181) - Clarifications to the DNS Specification
- [RFC 4343](https://datatracker.ietf.org/doc/html/rfc4343) - Domain Name System (DNS) Case Insensitivity Clarification
- [RFC 6891](https://datatracker.ietf.org/doc/html/rfc6891) - Extension Mechanisms for DNS (EDNS(0))
