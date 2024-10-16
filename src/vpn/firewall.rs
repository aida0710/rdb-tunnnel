use crate::vpn::packet_header::IpHeader;
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

    pub fn check(&self, ip_header: IpHeader, src_port: u16, dst_port: u16) -> bool {
        let rule_match = self.rules
            .iter()
            .any(|rule| self.matches(&rule.filter, ip_header, src_port, dst_port));

        match (rule_match, self.policy) {
            (true, Policy::Whitelist) => true,   // ルールに一致し、ホワイトリストなら許可
            (false, Policy::Whitelist) => false, // ルールに一致せず、ホワイトリストなら拒否
            (true, Policy::Blacklist) => false,  // ルールに一致し、ブラックリストなら拒否
            (false, Policy::Blacklist) => true,  // ルールに一致せず、ブラックリストなら許可
        }
    }

    fn matches(&self, filter: &Filter, ip_header: IpHeader, src_port: u16, dst_port: u16) -> bool {
        match filter {
            Filter::IpAddress(addr) => *addr == ip_header.src_ip || *addr == ip_header.dst_ip,
            Filter::Port(p) => *p == src_port || *p == dst_port,
            Filter::IpVersion(v) => *v == ip_header.version,
            Filter::NextHeaderProtocol(p) => *p == IpNextHeaderProtocol(ip_header.protocol),
            Filter::And(f1, f2) => self.matches(f1, ip_header, src_port, dst_port) && self.matches(f2, ip_header, src_port, dst_port),
            Filter::Or(f1, f2) => self.matches(f1, ip_header, src_port, dst_port) || self.matches(f2, ip_header, src_port, dst_port),
            Filter::Not(f) => !self.matches(f, ip_header, src_port, dst_port),
        }
    }
}
