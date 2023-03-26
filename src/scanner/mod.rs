use crate::fingerprint::Fingerprint;
use crate::scanner::ping::resolve_ping_ip;
use crate::scanner::socket::{IpType, ScannerReply, Socket, TransportLayerProtocol};
use crate::utils::address::SocketIterator;
use futures::future::join_all;
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

mod ping;
mod socket;

#[derive(Debug)]
#[allow(dead_code)]
pub struct Scanner {
    ips: Vec<IpAddr>,
    ports: Vec<u16>,
    batch_size: u16,
    ping: bool,
}

impl Scanner {
    pub async fn new(ips: Vec<IpAddr>, ports: Vec<u16>, batch_size: u16, ping: bool) -> Self {
        let ips = if ping {
            resolve_ping_ip(ips).await
        } else {
            ips
        };
        Self {
            ips,
            ports,
            batch_size,
            ping,
        }
    }
    pub async fn run(self) {
        let ports = self.ports;
        let ips = self.ips;

        let (tx, mut rx) = tokio::sync::mpsc::channel(10);

        tokio::spawn(Scanner::scan_socket_list(ips, ports, tx));

        while let Some(msg) = rx.recv().await {
            let transport_layer_protocol = msg.transport_layer_protocol().unwrap();
            match transport_layer_protocol {
                TransportLayerProtocol::TCP => {
                    tracing::info!(
                        "{}:{} [TCP|{}|{}]",
                        msg.ip_addr().unwrap(),
                        msg.port().unwrap(),
                        msg.name(),
                        match msg.version() {
                            None => "*".to_string(),
                            Some(version) => version,
                        }
                    )
                }
                TransportLayerProtocol::UDP => {}
            }
        }

        tracing::info!("run scan socket finished.")
    }

    async fn scan_socket_list(
        ips: Vec<IpAddr>,
        ports: Vec<u16>,
        tx: tokio::sync::mpsc::Sender<ScannerReply>,
    ) {
        let mut socket_iterator: SocketIterator = SocketIterator::new(&ips, &ports);
        let mut handles = vec![];
        while let Some(socket_addr) = socket_iterator.next() {
            let tx1 = tx.clone();
            handles.push(Scanner::scan_socket(socket_addr, tx1));
        }

        let batch_size = 1000;
        while let false = handles.is_empty() {
            let mut drain = vec![];
            if handles.len() > batch_size {
                drain = handles.drain(batch_size..).collect::<Vec<_>>();
            }
            join_all(handles).await;
            handles = drain;
        }
    }
    async fn scan_socket(socket_addr: SocketAddr, tx: tokio::sync::mpsc::Sender<ScannerReply>) {
        match Scanner::tcp_connect(socket_addr).await {
            Ok(tcp_stream) => {
                Self::check_tcp_connect(tcp_stream, tx).await;
            }
            Err(_error) => {
                // todo!("when tcp can't connect used udp socket check")
            }
        };
    }

    async fn check_tcp_connect(
        mut tcp_stream: TcpStream,
        tx: tokio::sync::mpsc::Sender<ScannerReply>,
    ) {
        let mut scanner_reply = ScannerReply::new();
        scanner_reply.set_activity(true);
        scanner_reply.set_transport_layer_protocol(Some(TransportLayerProtocol::TCP));
        scanner_reply.set_ip_addr(Some(tcp_stream.peer_addr().unwrap().ip()));
        scanner_reply.set_port(Some(tcp_stream.peer_addr().unwrap().port()));

        let fingerprint = match Fingerprint::get_tcp_fingerprint() {
            None => {
                println!("send1");
                tx.send(scanner_reply).await.unwrap();
                return;
            }
            Some(data) => data,
        };
        for probe in fingerprint.probes {
            let probe_string = probe.probe_string;
            tcp_stream.write_all(probe_string.as_bytes()).await.unwrap();
            let mut buf = Vec::new();
            tcp_stream.flush().await.unwrap();
            tcp_stream.shutdown().await.unwrap();
            tcp_stream.read_to_end(&mut buf).await.unwrap();
            for match_info in probe.matches {
                let pattern = match_info.pattern;
                if pattern.is_empty() {
                    tx.send(scanner_reply).await.unwrap();
                    return;
                }
                let server_name = match_info.name;
                let regex = regex::Regex::new(&pattern).unwrap();
                let banner = format!("{:#}", String::from_utf8_lossy(&buf)).clone();
                let caps = regex.captures(&banner);
                if caps.is_some() {
                    scanner_reply.set_name(server_name);
                    let caps = caps.unwrap();
                    if caps.name("version").is_some() {
                        scanner_reply
                            .set_version(caps.name("version").unwrap().as_str().to_string())
                    }
                    tx.send(scanner_reply).await.unwrap();
                    return;
                }
                // if regex.is_match(&banner) {
                //     if caps.is_some() {
                //         let caps = caps.unwrap();
                //         println!("{:?}", &caps.name("title"));
                //     }
                // }
            }
        }
        tx.send(scanner_reply).await.unwrap();
    }

    async fn tcp_connect(socket_addr: SocketAddr) -> Result<TcpStream, SocketAddr> {
        let tcp_socket = Socket::get_tcp_socket(IpType::V4);
        let tcp_stream = tokio::time::timeout(
            tokio::time::Duration::from_millis(1000),
            tcp_socket.connect(socket_addr),
        )
        .await;
        return match tcp_stream {
            Ok(connection_result) => match connection_result {
                Ok(tcp_stream) => Ok(tcp_stream),
                Err(_error) => Err(socket_addr),
            },
            Err(_error) => Err(socket_addr),
        };
    }

    #[allow(dead_code)]
    async fn udp_connect(socket_addr: SocketAddr) -> Result<UdpSocket, SocketAddr> {
        let udp_socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let _result = udp_socket.connect(socket_addr).await;
        let mut buf = [0u8; 32];
        let result = udp_socket.send(&buf[..32]).await.unwrap();
        tracing::info!("result: {:?}", result);
        let (_len, _socket_addr) = udp_socket.recv_from(&mut buf).await.unwrap();
        tracing::info!("result: {:?}", result);
        Ok(udp_socket)
    }
}
