//! ZDHT mDNS-SD stub for LAN discovery.
//!
//! Uses DNS Service Discovery (RFC 6763) over Multicast DNS (RFC 6762)
//! to find other ZERO nodes on the local network without relying on the global DHT.

pub fn start_mdns_discovery() {
    // Stub: would use mdns-sd crate to broadcast/listen for "_zero._udp.local."
}
