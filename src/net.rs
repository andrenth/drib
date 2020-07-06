use std::net::IpAddr;
use std::str::FromStr;

use ipnet::AddrParseError;
use ipnet::{Ipv4Net, Ipv6Net};
use iprange::IpNet;
use trust_dns_resolver::config::LookupIpStrategy;

use crate::parser::{self, Parse, ParseError};

pub trait Net: IpNet + FromStr<Err = AddrParseError> {
    fn protocol() -> &'static str;
    fn max_prefix() -> usize;
    fn from_ip_addr(ip: IpAddr) -> Option<Self>;
    fn lookup_strategy() -> LookupIpStrategy;
}

impl Net for Ipv4Net {
    fn protocol() -> &'static str {
        "ipv4"
    }

    fn max_prefix() -> usize {
        32
    }

    fn from_ip_addr(ip: IpAddr) -> Option<Ipv4Net> {
        match ip {
            IpAddr::V4(ip4) => Some(Ipv4Net::from(ip4.clone())),
            IpAddr::V6(_) => None,
        }
    }

    fn lookup_strategy() -> LookupIpStrategy {
        LookupIpStrategy::Ipv4Only
    }
}

impl Net for Ipv6Net {
    fn protocol() -> &'static str {
        "ipv6"
    }

    fn max_prefix() -> usize {
        128
    }

    fn from_ip_addr(ip: IpAddr) -> Option<Ipv6Net> {
        match ip {
            IpAddr::V4(_) => None,
            IpAddr::V6(ip6) => Some(Ipv6Net::from(ip6.clone())),
        }
    }

    fn lookup_strategy() -> LookupIpStrategy {
        LookupIpStrategy::Ipv6Only
    }
}

impl<T: Net> Parse for T {
    fn parse(s: &str) -> Result<T, ParseError> {
        parser::parse_net(s)
    }
}
