#![allow(dead_code)]
use cidr_utils::cidr::IpCidr;
use ipnet::{IpAddrRange, Ipv4AddrRange};
use itertools::{iproduct, Product};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime};
use trust_dns_resolver::{AsyncResolver, TokioHandle};

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq, Serialize, Deserialize)]
enum AddressType {
    IP,
    Range,
    Mask,
    UNKNOWN,
}
const IP_REGEX: &str =
    "((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3}";
fn get_address_type(address: &str) -> AddressType {
    let address_rages = regex::Regex::new(&format!("^{}$", IP_REGEX)).unwrap();
    let address_range_regex_str = format!("^{}-{}$", IP_REGEX, IP_REGEX);
    let address_range_regex = regex::Regex::new(&address_range_regex_str).unwrap();
    let address_mask_regex_str = format!("^{}/\\d+$", IP_REGEX);
    let address_mask_regex = regex::Regex::new(&address_mask_regex_str).unwrap();
    return if address_rages.is_match(address) {
        AddressType::IP
    } else if address_range_regex.is_match(address) {
        AddressType::Range
    } else if address_mask_regex.is_match(address) {
        AddressType::Mask
    } else {
        AddressType::UNKNOWN
    };
}

fn resolve_ips_from_range_address(address: &str) -> Result<Vec<IpAddr>, String> {
    if address.is_empty() {
        return Ok(vec![]);
    }
    let ip_range = address.split("-").collect::<Vec<&str>>();
    let ip_range = Ipv4AddrRange::new(
        ip_range.get(0).unwrap().parse().unwrap(),
        ip_range.get(1).unwrap().parse().unwrap(),
    );
    let ip_range = IpAddrRange::from(ip_range);
    let result = ip_range.collect::<Vec<IpAddr>>();
    Ok(result)
}

fn resolve_ips_from_mask_address(address: &str) -> Result<Vec<IpAddr>, String> {
    let cidr = IpCidr::from_str(address);
    return match cidr {
        Ok(data) => {
            let result = data.iter().collect::<Vec<IpAddr>>();
            Ok(result)
        }
        Err(_) => Err(address.to_string()),
    };
}

async fn resolve_ips_from_domain(
    address: &str,
    resolver: &AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>,
) -> Result<Vec<IpAddr>, String> {
    let mut ips: Vec<IpAddr> = Vec::new();
    let result = address.to_socket_addrs();
    match result {
        Ok(addrs) => {
            for ip in addrs {
                ips.push(ip.ip())
            }
        }
        Err(_) => {
            let result = resolver.lookup_ip(address).await;
            match result {
                Ok(addrs) => {
                    ips.extend(addrs.iter());
                }
                Err(_) => return Err(address.to_string()),
            }
        }
    }
    Ok(ips)
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ParseAddress<'a> {
    pub valid_address: HashSet<IpAddr>,
    #[serde(borrow)]
    pub invalid_address: HashSet<&'a str>,
}

impl<'a> ParseAddress<'a> {
    pub async fn resolve_ips(addresses: &'a str) -> ParseAddress {
        let mut valid_address = HashSet::new();
        let mut invalid_address = HashSet::new();
        let async_resolver: AsyncResolver<
            GenericConnection,
            GenericConnectionProvider<TokioRuntime>,
        > = AsyncResolver::new(
            ResolverConfig::default(),
            ResolverOpts::default(),
            TokioHandle,
        )
        .expect("failed to create resolver");
        let address_vec = addresses.split(",").collect::<Vec<&str>>();
        for address in address_vec {
            let address_type = get_address_type(address);
            let match_result = match address_type {
                AddressType::UNKNOWN => resolve_ips_from_domain(address, &async_resolver).await,
                // AddressType::UNKNOWN => resolve_ips_from_domain(address, &dns_resolver),
                AddressType::IP => Ok(vec![address.parse().unwrap()]),
                AddressType::Range => resolve_ips_from_range_address(address),
                AddressType::Mask => resolve_ips_from_mask_address(address),
            };
            match match_result {
                Ok(data) => {
                    valid_address.extend(data);
                }
                Err(_) => {
                    invalid_address.insert(address);
                }
            };
        }
        ParseAddress {
            valid_address,
            invalid_address,
        }
    }
}

#[cfg(test)]
pub mod attack_service_test {
    use crate::utils::address::{get_address_type, AddressType};

    #[test]
    fn check_address_type_test() {
        let mut address = String::from("127.0.0.1");
        let result = get_address_type(&address);
        assert_eq!(result, AddressType::IP);
        address = String::from("127.0.0.1-127.0.0.10");
        let result = get_address_type(&address);
        assert_eq!(result, AddressType::Range);
        address = String::from("127.0.0.1/24");
        let result = get_address_type(&address);
        assert_eq!(result, AddressType::Mask);
        address = String::from("300.0.0.0");
        let result = get_address_type(&address);
        assert_eq!(result, AddressType::UNKNOWN);
    }
}

#[derive(Debug)]
pub struct SocketIterator<'s> {
    product_it: Product<Box<std::slice::Iter<'s, u16>>, Box<std::slice::Iter<'s, IpAddr>>>,
}

impl<'s> SocketIterator<'s> {
    pub fn new(ips: &'s [IpAddr], ports: &'s [u16]) -> Self {
        let ports_it = Box::new(ports.iter());
        let ips_it = Box::new(ips.iter());
        Self {
            product_it: iproduct!(ports_it, ips_it),
        }
    }
}

impl<'s> Iterator for SocketIterator<'s> {
    type Item = SocketAddr;
    fn next(&mut self) -> Option<Self::Item> {
        self.product_it
            .next()
            .map(|(port, ip)| SocketAddr::new(*ip, *port))
    }
}
