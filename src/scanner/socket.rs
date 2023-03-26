#![allow(dead_code)]
use socket2::{Domain, Protocol, SockAddr, Type};
use std::net::IpAddr;
use std::os::fd::FromRawFd;
use std::os::fd::IntoRawFd;
use std::time::Duration;
use tokio::net::{TcpSocket, UdpSocket};

#[derive(Debug)]
pub enum IpType {
    V4,
    V6,
}
#[derive(Debug, Copy, Clone)]
pub enum TransportLayerProtocol {
    TCP,
    UDP,
}

pub struct Socket;

impl Socket {
    fn v4_tcp_socket() -> TcpSocket {
        let socket = TcpSocket::new_v4().unwrap();
        socket.set_reuseaddr(true).unwrap();
        socket.set_reuseport(true).unwrap();
        socket
            .set_linger(Some(std::time::Duration::from_millis(1000)))
            .unwrap();
        socket
    }

    fn v6_tcp_socket() -> TcpSocket {
        let socket = TcpSocket::new_v6().unwrap();
        socket
    }

    pub fn get_tcp_socket(ip_type: IpType) -> TcpSocket {
        return match ip_type {
            IpType::V4 => Socket::v4_tcp_socket(),
            IpType::V6 => Socket::v6_tcp_socket(),
        };
    }

    pub fn get_udp_socket(ip_type: IpType) -> UdpSocket {
        let socket = match ip_type {
            IpType::V4 => {
                socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap()
            }
            IpType::V6 => {
                socket2::Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap()
            }
        };
        let std = std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(0, 0, 0, 0), 0);
        let addr = SockAddr::from(std);
        socket.bind(&addr).unwrap();
        socket.set_nonblocking(true).unwrap();
        socket.set_ttl(30).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let socket =
            UdpSocket::from_std(unsafe { std::net::UdpSocket::from_raw_fd(socket.into_raw_fd()) })
                .unwrap();
        socket
    }
}

#[derive(Debug)]
pub struct ScannerReply {
    activity: bool,
    name: String,
    ip_addr: Option<IpAddr>,
    port: Option<u16>,
    version: Option<String>,
    transport_layer_protocol: Option<TransportLayerProtocol>,
}

impl ScannerReply {
    pub fn new() -> ScannerReply {
        ScannerReply {
            activity: false,
            name: "*".to_string(),
            ip_addr: None,
            port: None,
            version: None,
            transport_layer_protocol: None,
        }
    }
    pub fn activity(&self) -> bool {
        self.activity
    }
    pub fn set_activity(&mut self, activity: bool) {
        self.activity = activity;
    }
    pub fn name(&self) -> String {
        self.name.to_string()
    }
    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }
    pub fn version(&self) -> Option<String> {
        self.version.clone()
    }
    pub fn set_version(&mut self, version: String) {
        self.version = Some(version);
    }
    pub fn ip_addr(&self) -> Option<IpAddr> {
        self.ip_addr
    }
    pub fn set_ip_addr(&mut self, ip_addr: Option<IpAddr>) {
        self.ip_addr = ip_addr;
    }
    pub fn port(&self) -> Option<u16> {
        self.port
    }
    pub fn set_port(&mut self, port: Option<u16>) {
        self.port = port;
    }
    pub fn transport_layer_protocol(&self) -> Option<TransportLayerProtocol> {
        self.transport_layer_protocol
    }
    pub fn set_transport_layer_protocol(
        &mut self,
        transport_layer_protocol: Option<TransportLayerProtocol>,
    ) {
        self.transport_layer_protocol = transport_layer_protocol;
    }
}
