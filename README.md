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
