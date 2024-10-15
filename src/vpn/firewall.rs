use crate::vpn::firewall_packet::FirewallPacket;
use pnet::packet::ip::IpNextHeaderProtocol;
use std::net::IpAddr;

pub struct IpFirewall {
    rules: Vec<Rule>,
}

pub struct Rule {
    filter: Filter,
    action: Action,
}

#[derive(Clone)]
pub enum Action {
    Allow,
    Block,
}

pub enum Filter {
    IpAddress(IpAddr),
    Port(u16),
    IpVersion(u8),
    NextHeaderProtocol(IpNextHeaderProtocol),
    And(Box<Filter>, Box<Filter>),
}

impl IpFirewall {
    pub fn new() -> IpFirewall {
        IpFirewall { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, filter: Filter, action: Action) {
        self.rules.push(Rule { filter, action });
    }

    pub fn check(&self, packet: &FirewallPacket) -> Action {
        for rule in &self.rules {
            if self.matches(&rule.filter, packet) {
                return rule.action.clone();
            }
        }
        Action::Allow
    }

    fn matches(&self, filter: &Filter, packet: &FirewallPacket) -> bool {
        match filter {
            Filter::IpAddress(addr) => *addr == packet.ip_address,
            Filter::Port(p) => *p == packet.port,
            Filter::IpVersion(v) => *v == packet.ip_version,
            Filter::NextHeaderProtocol(p) => *p == packet.next_header_protocol,
            Filter::And(f1, f2) => self.matches(f1, packet) && self.matches(f2, packet),
        }
    }
}