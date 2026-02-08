// Minimal DNS resolution test
// Compile: rustc test-dns.rs -o test-dns
// Run: ./test-dns kels-registry.kels-registry-a.kels

use std::net::ToSocketAddrs;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let host = args.get(1).map(|s| s.as_str()).unwrap_or("kels-registry.kels-registry-a.kels");

    println!("Resolving: {}:80", host);

    match format!("{}:80", host).to_socket_addrs() {
        Ok(addrs) => {
            for addr in addrs {
                println!("  Resolved: {}", addr);
            }
        }
        Err(e) => {
            println!("  DNS error: {}", e);
            println!("  Error kind: {:?}", e.kind());
        }
    }
}
