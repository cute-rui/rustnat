use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::utils::{addr_to_str, create_tcp_socket, socket_set_opt, socket_recv};

/// PortTest checks whether a port is reachable from LAN and WAN
pub struct PortTest;

impl PortTest {
    pub fn new() -> Self {
        Self
    }

    /// Test port reachability from LAN via TCP connect
    pub fn test_lan(
        &self,
        addr: &SocketAddrV4,
        source_ip: Option<Ipv4Addr>,
        interface: Option<&str>,
        info: bool,
    ) -> i32 {
        let sock = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP));
        let sock = match sock {
            Ok(s) => s,
            Err(e) => {
                if info {
                    log::info!("LAN > {:<21} [ UNKNOWN ]", addr_to_str(addr));
                } else {
                    log::debug!("LAN > {:<21} [ UNKNOWN ]", addr_to_str(addr));
                }
                log::debug!("Cannot test port {} from LAN because: {}", addr_to_str(addr), e);
                return 0;
            }
        };

        let bind_addr = source_ip.map(|ip| SocketAddrV4::new(ip, 0));
        if let Err(e) = socket_set_opt(
            &sock,
            false,
            bind_addr,
            interface,
            Some(Duration::from_secs(1)),
        ) {
            if info {
                log::info!("LAN > {:<21} [ UNKNOWN ]", addr_to_str(addr));
            } else {
                log::debug!("LAN > {:<21} [ UNKNOWN ]", addr_to_str(addr));
            }
            log::debug!("Cannot test port {} from LAN because: {}", addr_to_str(addr), e);
            return 0;
        }

        match sock.connect(&SockAddr::from(*addr)) {
            Ok(_) => {
                if info {
                    log::info!("LAN > {:<21} [ OPEN ]", addr_to_str(addr));
                } else {
                    log::debug!("LAN > {:<21} [ OPEN ]", addr_to_str(addr));
                }
                1
            }
            Err(_) => {
                if info {
                    log::info!("LAN > {:<21} [ CLOSED ]", addr_to_str(addr));
                } else {
                    log::debug!("LAN > {:<21} [ CLOSED ]", addr_to_str(addr));
                }
                -1
            }
        }
    }

    /// Test port reachability from WAN using external services
    pub fn test_wan(
        &self,
        addr: &SocketAddrV4,
        source_ip: Option<Ipv4Addr>,
        interface: Option<&str>,
        info: bool,
    ) -> i32 {
        let port = addr.port();
        let ret01 = self.test_ifconfigco(port, source_ip, interface);
        if ret01 == 1 {
            if info {
                log::info!("WAN > {:<21} [ OPEN ]", addr_to_str(addr));
            } else {
                log::debug!("WAN > {:<21} [ OPEN ]", addr_to_str(addr));
            }
            return 1;
        }
        let ret02 = self.test_transmission(port, source_ip, interface);
        if ret02 == 1 {
            if info {
                log::info!("WAN > {:<21} [ OPEN ]", addr_to_str(addr));
            } else {
                log::debug!("WAN > {:<21} [ OPEN ]", addr_to_str(addr));
            }
            return 1;
        }
        if ret01 == -1 && ret02 == -1 {
            if info {
                log::info!("WAN > {:<21} [ CLOSED ]", addr_to_str(addr));
            } else {
                log::debug!("WAN > {:<21} [ CLOSED ]", addr_to_str(addr));
            }
            return -1;
        }
        if info {
            log::info!("WAN > {:<21} [ UNKNOWN ]", addr_to_str(addr));
        } else {
            log::debug!("WAN > {:<21} [ UNKNOWN ]", addr_to_str(addr));
        }
        0
    }

    fn test_ifconfigco(
        &self,
        port: u16,
        source_ip: Option<Ipv4Addr>,
        interface: Option<&str>,
    ) -> i32 {
        let result = (|| -> io::Result<i32> {
            let ip = crate::utils::resolve_host("ifconfig.co")?;
            let server_addr = SocketAddrV4::new(ip, 80);
            let bind_addr = source_ip.map(|ip| SocketAddrV4::new(ip, 0));
            let sock = create_tcp_socket(
                bind_addr,
                interface,
                Some(Duration::from_secs(8)),
                false,
                server_addr,
            )?;
            let request = format!(
                "GET /port/{} HTTP/1.0\r\nHost: ifconfig.co\r\nUser-Agent: curl/8.0.0 (Natter)\r\nAccept: */*\r\nConnection: close\r\n\r\n",
                port
            );
            sock.send(request.as_bytes())?;
            let mut response = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                match socket_recv(&sock, &mut buf) {
                    Ok(0) => break,
                    Ok(n) => response.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => break,
                    Err(e) => return Err(e),
                }
            }
            log::debug!("port-test: ifconfig.co: {:?}", String::from_utf8_lossy(&response));
            let resp_str = String::from_utf8_lossy(&response);
            if let Some(pos) = resp_str.find("\r\n\r\n") {
                let body = &resp_str[pos + 4..];
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
                    if v["reachable"].as_bool() == Some(true) {
                        return Ok(1);
                    } else {
                        return Ok(-1);
                    }
                }
            }
            Ok(0)
        })();
        match result {
            Ok(v) => v,
            Err(e) => {
                log::debug!("Cannot test port {} from ifconfig.co because: {}", port, e);
                0
            }
        }
    }

    fn test_transmission(
        &self,
        port: u16,
        source_ip: Option<Ipv4Addr>,
        interface: Option<&str>,
    ) -> i32 {
        let result = (|| -> io::Result<i32> {
            let ip = crate::utils::resolve_host("portcheck.transmissionbt.com")?;
            let server_addr = SocketAddrV4::new(ip, 80);
            let bind_addr = source_ip.map(|ip| SocketAddrV4::new(ip, 0));
            let sock = create_tcp_socket(
                bind_addr,
                interface,
                Some(Duration::from_secs(8)),
                false,
                server_addr,
            )?;
            let request = format!(
                "GET /{} HTTP/1.0\r\nHost: portcheck.transmissionbt.com\r\nUser-Agent: curl/8.0.0 (Natter)\r\nAccept: */*\r\nConnection: close\r\n\r\n",
                port
            );
            sock.send(request.as_bytes())?;
            let mut response = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                match socket_recv(&sock, &mut buf) {
                    Ok(0) => break,
                    Ok(n) => response.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => break,
                    Err(e) => return Err(e),
                }
            }
            log::debug!(
                "port-test: portcheck.transmissionbt.com: {:?}",
                String::from_utf8_lossy(&response)
            );
            let resp_str = String::from_utf8_lossy(&response);
            if let Some(pos) = resp_str.find("\r\n\r\n") {
                let body = resp_str[pos + 4..].trim();
                if body == "1" {
                    return Ok(1);
                } else if body == "0" {
                    return Ok(-1);
                }
            }
            Ok(0)
        })();
        match result {
            Ok(v) => v,
            Err(e) => {
                log::debug!(
                    "Cannot test port {} from portcheck.transmissionbt.com because: {}",
                    port, e
                );
                0
            }
        }
    }
}
