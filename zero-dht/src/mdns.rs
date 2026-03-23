//! ZDHT mDNS-SD stub for LAN discovery.
//!
//! Uses DNS Service Discovery (RFC 6763) over Multicast DNS (RFC 6762)
//! to find other ZERO nodes on the local network without relying on the global DHT.

use mdns_sd::{ServiceDaemon, ServiceInfo};
use std::collections::HashMap;
use tracing::info;

/// Start mDNS-SD discovery and registration.
pub fn start_mdns_discovery(port: u16) {
    // Create a daemon
    let mdns = ServiceDaemon::new().expect("Failed to create mDNS daemon");

    // Create our service info
    let service_type = "_zero._udp.local.";
    let instance_name = format!("zero-node-{}", port);
    let host_name = format!("{}.local.", instance_name);
    let mut properties = HashMap::new();
    properties.insert("version".to_string(), "1.0".to_string());

    let my_service = ServiceInfo::new(
        service_type,
        &instance_name,
        &host_name,
        "", // IP is discovered automatically
        port,
        properties,
    )
    .expect("valid service info");

    // Register our service
    mdns.register(my_service)
        .expect("Failed to register mDNS service");
    info!("mDNS: Registered ZERO node on port {}", port);

    // Browse for other ZERO nodes
    let browse_receiver = mdns.browse(service_type).expect("Failed to browse mDNS");

    std::thread::spawn(move || {
        while let Ok(event) = browse_receiver.recv() {
            if let mdns_sd::ServiceEvent::ServiceResolved(info) = event {
                info!(
                    "mDNS: Resolved new ZERO node: {} at {:?}",
                    info.get_fullname(),
                    info.get_addresses()
                );
                // logic: add to discovery list
            }
        }
    });
}
