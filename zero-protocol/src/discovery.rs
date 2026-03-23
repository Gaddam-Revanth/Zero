//! LAN Discovery using mDNS-SD.
#![allow(missing_docs)]

use crate::error::ZeroError;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::HashMap;
use std::net::IpAddr;
use tracing::info;

pub const ZERO_SERVICE_TYPE: &str = "_zero-protocol._udp.local.";

/// Manages LAN discovery for a ZERO node.
pub struct DiscoveryManager {
    mdns: ServiceDaemon,
    service_type: &'static str,
}

impl DiscoveryManager {
    /// Create a new mDNS discovery manager.
    pub fn new() -> Result<Self, ZeroError> {
        let mdns = ServiceDaemon::new().map_err(|e| ZeroError::Custom(e.to_string()))?;
        Ok(Self {
            mdns,
            service_type: ZERO_SERVICE_TYPE,
        })
    }

    /// Register local node on mDNS.
    pub fn register_service(
        &self,
        node_id: &str,
        port: u16,
        addresses: Vec<IpAddr>,
    ) -> Result<(), ZeroError> {
        let mut properties = HashMap::new();
        properties.insert("node_id".to_string(), node_id.to_string());
        properties.insert("v".to_string(), "1.0".to_string());

        let host_name = format!("{}.local.", node_id);
        let service_info = ServiceInfo::new(
            self.service_type,
            node_id,
            &host_name,
            &addresses[..],
            port,
            Some(properties),
        )
        .map_err(|e| ZeroError::Custom(e.to_string()))?;

        self.mdns
            .register(service_info)
            .map_err(|e| ZeroError::Custom(e.to_string()))?;
        info!("Registered ZERO service mDNS: {} on port {}", node_id, port);
        Ok(())
    }

    /// Browse for other ZERO services on LAN.
    pub fn start_browsing(&self) -> Result<mdns_sd::Receiver<ServiceEvent>, ZeroError> {
        let receiver = self
            .mdns
            .browse(self.service_type)
            .map_err(|e| ZeroError::Custom(format!("{:?}", e)))?;
        info!("Started mDNS browsing for {}", self.service_type);
        Ok(receiver)
    }
}
