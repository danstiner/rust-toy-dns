# rust-toy-dns

A toy DNS server for learning about DNS and high performance networking in Rust.

If you are looking for a production ready DNS server written in safe Rust, check out [trust-dns](https://github.com/bluejekyll/trust-dns).

## Getting Started

```
cargo run
```

### Testing

```
dig @127.0.0.1 -p 8080 +noedns google.com
```

## TODO

- [X] Factor out resolver trait and test, for adding more than just a non-caching proxy resolver
- [ ] Factor out server struct and test
- [ ] Caching proxy resolver
- [ ] Recursive resolver
- [ ] Fuzz testing
- [ ] Benchmarking
- [ ] Initialize from from resolver.conf etc

## Security

- [X] Implement [source port randomization](https://en.m.wikipedia.org/wiki/Dan_Kaminsky#Flaw_in_DNS)

## Notes

Written to follow RFC 1035: https://datatracker.ietf.org/doc/html/rfc1035

Inspired by https://github.com/EmilHernvall/dnsguide
