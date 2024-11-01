use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Eq, Hash, PartialEq)]
pub enum Filter {
    IpAddress(IpAddr),
    Port(u16),
    Protocol(u8),
}

#[derive(Debug)]
pub enum Policy {
    Whitelist,
    Blacklist,
}

#[derive(Debug)]
pub struct IpFirewall {
    rules: HashMap<Filter, u8>,
    policy: Policy,
}

impl IpFirewall {
    pub fn new(policy: Policy) -> Self {
        Self {
            rules: HashMap::new(),
            policy,
        }
    }

    pub fn add_rule(&mut self, filter: Filter, priority: u8) {
        self.rules.insert(filter, priority);
    }

    pub fn check(&self, packet: crate::firewall_packet::FirewallPacket) -> bool {
        let mut block = false;
        let mut allow = false;
        let mut max_priority = 0;

        for (filter, priority) in &self.rules {
            if *priority > max_priority {
                match filter {
                    Filter::IpAddress(ip) => {
                        if packet.src_ip == *ip || packet.dst_ip == *ip {
                            max_priority = *priority;
                            match self.policy {
                                Policy::Whitelist => allow = true,
                                Policy::Blacklist => block = true,
                            }
                        }
                    }
                    Filter::Port(port) => {
                        if packet.src_port == *port || packet.dst_port == *port {
                            max_priority = *priority;
                            match self.policy {
                                Policy::Whitelist => allow = true,
                                Policy::Blacklist => block = true,
                            }
                        }
                    }
                    Filter::Protocol(protocol) => {
                        if packet.ip_version == *protocol {
                            max_priority = *priority;
                            match self.policy {
                                Policy::Whitelist => allow = true,
                                Policy::Blacklist => block = true,
                            }
                        }
                    }
                }
            }
        }

        match self.policy {
            Policy::Whitelist => allow,
            Policy::Blacklist => !block,
        }
    }
}