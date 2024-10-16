use crate::vpn::firewall_packet::FirewallPacket;
use pnet::packet::ip::IpNextHeaderProtocol;
use std::net::IpAddr;

pub struct IpFirewall {
    rules: Vec<Rule>,
    policy: Policy,
}

pub struct Rule {
    filter: Filter,
    priority: u32,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Policy {
    Whitelist,
    Blacklist,
}

pub enum Filter {
    IpAddress(IpAddr),
    Port(u16),
    IpVersion(u8),
    NextHeaderProtocol(IpNextHeaderProtocol),
    And(Box<Filter>, Box<Filter>),
    Or(Box<Filter>, Box<Filter>),
    Not(Box<Filter>),
}

impl IpFirewall {
    pub fn new(policy: Policy) -> IpFirewall {
        IpFirewall {
            rules: Vec::new(),
            policy,
        }
    }

    pub fn add_rule(&mut self, filter: Filter, priority: u32) {
        let rule = Rule { filter, priority };
        self.rules.push(rule);
        self.rules.sort_by_key(|rule| std::cmp::Reverse(rule.priority));
    }

    pub fn check(&self, firewall_packet: FirewallPacket) -> bool {
        let rule_match = self.rules
            .iter()
            .any(|rule| self.matches(&rule.filter, firewall_packet));

        match (rule_match, self.policy) {
            (true, Policy::Whitelist) => true,   // ルールに一致し、ホワイトリストなら許可
            (false, Policy::Whitelist) => false, // ルールに一致せず、ホワイトリストなら拒否
            (true, Policy::Blacklist) => false,  // ルールに一致し、ブラックリストなら拒否
            (false, Policy::Blacklist) => true,  // ルールに一致せず、ブラックリストなら許可
        }
    }

    fn matches(&self, filter: &Filter, firewall_packet: FirewallPacket) -> bool {
        match filter {
            Filter::IpAddress(addr) => *addr == firewall_packet.src_ip || *addr == firewall_packet.dst_ip,
            Filter::Port(p) => *p == firewall_packet.src_port || *p == firewall_packet.dst_port,
            Filter::IpVersion(v) => *v == firewall_packet.ip_version,
            Filter::NextHeaderProtocol(p) => *p == firewall_packet.next_header_protocol,
            Filter::And(f1, f2) => self.matches(f1, firewall_packet) && self.matches(f2, firewall_packet),
            Filter::Or(f1, f2) => self.matches(f1, firewall_packet) || self.matches(f2, firewall_packet),
            Filter::Not(f) => !self.matches(f, firewall_packet),
        }
    }
}
