use colored::Colorize;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::util;
use pnet::packet::Packet;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{FromRawFd, IntoRawFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::oneshot::Receiver;
use tokio::task::JoinHandle;
use tokio::time::timeout;

pub async fn resolve_ping_ip(ips: Vec<IpAddr>) -> Vec<IpAddr> {
    let client = Client::new().unwrap();
    let mut task = vec![];
    for ip in ips {
        task.push(ping(client.clone(), ip));
    }
    let mut result: Vec<Result<String, String>> = futures::future::join_all(task).await;
    result.retain(|item| {
        if item.is_err() {
            tracing::info!(
                "ping {} {}",
                item.as_ref().err().unwrap(),
                "don't connection".to_string().red()
            );
        }
        item.is_ok()
    });
    result
        .into_iter()
        .map(|item| {
            tracing::info!(
                "ping {} {}",
                &item.as_ref().unwrap(),
                "connection".to_string().green()
            );
            item.unwrap().parse::<IpAddr>().unwrap()
        })
        .collect::<Vec<IpAddr>>()
}

async fn ping(client: Client, addr: IpAddr) -> Result<String, String> {
    let payload = [0; 56];
    let mut pinger = client.pinger(addr).await;
    let result = pinger.ping(&payload).await;
    result
}

#[derive(Clone)]
struct AsyncSocket {
    inner: Arc<tokio::net::UdpSocket>,
}

impl AsyncSocket {
    pub fn new() -> Self {
        let socket = make_socket();
        Self {
            inner: Arc::new(socket),
        }
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.inner.recv_from(buf).await
    }

    pub async fn send_to(&self, buf: &mut [u8], target: &SocketAddr) -> std::io::Result<usize> {
        self.inner.send_to(buf, target).await
    }
}

#[derive(Clone, Default)]
struct ReplyMap(Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<String>>>>);

impl ReplyMap {
    pub fn new_waiter(&self, host: IpAddr) -> Result<Receiver<String>, String> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self
            .0
            .lock()
            .unwrap()
            .insert(host.to_string(), tx)
            .is_some()
        {
            return Err(format!("new waiter error: {}", host.to_string()));
        }
        Ok(rx)
    }

    pub fn remove(&self, host: IpAddr) -> Option<tokio::sync::oneshot::Sender<String>> {
        self.0.lock().unwrap().remove(&host.to_string())
    }
}

#[derive(Clone)]
struct Client {
    socket: AsyncSocket,
    reply_map: ReplyMap,
    recv: Arc<JoinHandle<()>>,
}

impl Client {
    pub fn new() -> std::io::Result<Self> {
        let socket = AsyncSocket::new();
        let reply_map = ReplyMap::default();
        let recv = tokio::spawn(recv_task(socket.clone(), reply_map.clone()));
        Ok(Self {
            socket,
            reply_map,
            recv: Arc::new(recv),
        })
    }

    pub async fn pinger(&self, host: IpAddr) -> Pinger {
        Pinger::new(host, self.socket.clone(), self.reply_map.clone())
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if Arc::strong_count(&self.recv) <= 1 {
            self.recv.abort();
        }
    }
}

async fn recv_task(socket: AsyncSocket, reply_map: ReplyMap) {
    let mut buf = [0; 2048];
    loop {
        if let Ok((_size, addr)) = socket.recv_from(&mut buf).await {
            if let Some(waiter) = reply_map.remove(addr.ip()) {
                let _ = waiter.send(addr.to_string());
            } else {
                tracing::warn!("no one is waiting for ICMP packet.");
            }
        }
    }
}

struct Pinger {
    pub host: IpAddr,
    socket: AsyncSocket,
    reply_map: ReplyMap,
}
impl Pinger {
    pub fn new(host: IpAddr, socket: AsyncSocket, response_map: ReplyMap) -> Pinger {
        Pinger {
            host,
            socket,
            reply_map: response_map,
        }
    }
    pub async fn ping(&mut self, payload: &[u8]) -> Result<String, String> {
        let reply_waiter = self.reply_map.new_waiter(self.host).unwrap();
        let mut packet = make_icmp_echo_packet(rand::random::<u16>(), 0, &payload);
        self.socket
            .send_to(&mut packet, &SocketAddr::new(self.host, 0))
            .await
            .unwrap();
        let result = timeout(Duration::from_millis(500), reply_waiter).await;
        return match result {
            Ok(data) => match data {
                Ok(_) => Ok(self.host.to_string()),
                Err(_) => Err(self.host.to_string()),
            },
            Err(_) => Err(self.host.to_string()),
        };
    }
}
fn make_socket() -> tokio::net::UdpSocket {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)).unwrap();
    socket.set_nonblocking(false).unwrap();
    socket.set_ttl(30).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let socket = tokio::net::UdpSocket::from_std(unsafe {
        std::net::UdpSocket::from_raw_fd(socket.into_raw_fd())
    })
    .unwrap();
    socket
}

fn make_icmp_echo_packet(ident: u16, seq_cnt: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = vec![0; 8 + payload.len()];
    let mut package = MutableEchoRequestPacket::new(&mut buf[..]).unwrap();
    package.set_icmp_type(IcmpTypes::EchoRequest);
    package.set_identifier(ident);
    package.set_sequence_number(seq_cnt);
    package.set_payload(payload);
    let checksum = util::checksum(package.packet(), 10);
    package.set_checksum(checksum);
    let package_vec = package.packet().to_vec();
    package_vec
}
