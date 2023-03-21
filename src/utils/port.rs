use std::collections::HashSet;

pub enum PortType {
    Port,
    Range,
}

fn get_port_type(port: &str) -> PortType {
    return if port.contains("-") {
        PortType::Range
    } else {
        PortType::Port
    };
}
pub fn resolve_ports_or_all(addresses: Option<String>) -> HashSet<u16> {
    if addresses.is_none() {
        let result = 1..=65535;
        return result.collect::<HashSet<u16>>();
    }
    resolve_ports(addresses)
}

pub fn resolve_ports(addresses: Option<String>) -> HashSet<u16> {
    let mut result = HashSet::new();
    if addresses.is_none() {
        return result;
    }
    let address = addresses.unwrap();
    let ports_list = address.split(",").collect::<Vec<&str>>();
    for port in ports_list {
        let port_type = get_port_type(port);
        match port_type {
            PortType::Port => {
                result.insert(port.parse::<u16>().unwrap());
            }
            PortType::Range => {
                let mut range = port.split("-");
                let start = range.next().unwrap().parse::<u16>().unwrap();
                let end = range.next().unwrap().parse::<u16>().unwrap();
                let range = start..=end;
                result.extend(range.collect::<Vec<u16>>())
            }
        }
    }
    result
}
