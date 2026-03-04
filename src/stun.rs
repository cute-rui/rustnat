use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use rand::Rng;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::utils::{addr_to_uri, socket_set_opt, socket_recv};

/// STUN Client for NAT mapping discovery (RFC 5389)
pub struct StunClient {
    pub stun_server_list: Vec<(String, u16)>,
    pub source_host: Ipv4Addr,
    pub source_port: u16,
    pub interface: Option<String>,
    pub udp: bool,
}

#[derive(Debug)]
pub struct ServerUnavailable(pub String);

impl std::fmt::Display for ServerUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl StunClient {
    pub fn new(
        stun_server_list: Vec<(String, u16)>,
        source_host: Ipv4Addr,
        source_port: u16,
        interface: Option<String>,
        udp: bool,
    ) -> Result<Self, String> {
        if stun_server_list.is_empty() {
            return Err("STUN server list is empty".to_string());
        }
        Ok(Self {
            stun_server_list,
            source_host,
            source_port,
            interface,
            udp,
        })
    }

    /// Get the NAT mapping, rotating through STUN servers on failure
    pub fn get_mapping(&mut self) -> io::Result<(SocketAddrV4, SocketAddrV4)> {
        let first = self.stun_server_list[0].clone();
        loop {
            match self._get_mapping() {
                Ok(result) => return Ok(result),
                Err(e) => {
                    let current = &self.stun_server_list[0];
                    let uri = format!("{}:{}", current.0, current.1);
                    log::warn!("stun: STUN server {} is unavailable: {}", uri, e);

                    // rotate
                    let removed = self.stun_server_list.remove(0);
                    self.stun_server_list.push(removed);

                    if self.stun_server_list[0] == first {
                        log::error!("stun: No STUN server is available right now");
                        std::thread::sleep(Duration::from_secs(10));
                    }
                }
            }
        }
    }

    fn _get_mapping(&mut self) -> Result<(SocketAddrV4, SocketAddrV4), ServerUnavailable> {
        let (stun_host, stun_port) = self.stun_server_list[0].clone();

        // Resolve STUN host
        let stun_ip = crate::utils::resolve_host(&stun_host)
            .map_err(|e| ServerUnavailable(format!("DNS resolution failed: {}", e)))?;
        let stun_addr = SocketAddrV4::new(stun_ip, stun_port);

        let sock_type = if self.udp { Type::DGRAM } else { Type::STREAM };
        let protocol = if self.udp {
            Some(Protocol::UDP)
        } else {
            Some(Protocol::TCP)
        };

        let sock = Socket::new(Domain::IPV4, sock_type, protocol)
            .map_err(|e| ServerUnavailable(e.to_string()))?;

        let bind_addr = SocketAddrV4::new(self.source_host, self.source_port);
        socket_set_opt(
            &sock,
            true,
            Some(bind_addr),
            self.interface.as_deref(),
            Some(Duration::from_secs(3)),
        )
        .map_err(|e| ServerUnavailable(e.to_string()))?;

        sock.connect(&SockAddr::from(stun_addr))
            .map_err(|e| ServerUnavailable(e.to_string()))?;

        let inner_addr = sock
            .local_addr()
            .map_err(|e| ServerUnavailable(e.to_string()))?;
        let inner_v4 = inner_addr
            .as_socket_ipv4()
            .ok_or_else(|| ServerUnavailable("Not IPv4".to_string()))?;

        self.source_host = *inner_v4.ip();
        self.source_port = inner_v4.port();

        // Build STUN Binding Request
        let mut rng = rand::thread_rng();
        let mut request = [0u8; 20];
        // Message Type: Binding Request (0x0001), Length: 0
        request[0] = 0x00;
        request[1] = 0x01;
        request[2] = 0x00;
        request[3] = 0x00;
        // Magic Cookie: 0x2112A442
        request[4] = 0x21;
        request[5] = 0x12;
        request[6] = 0xA4;
        request[7] = 0x42;
        // Transaction ID: "NATR" + 8 random bytes
        request[8] = b'N';
        request[9] = b'A';
        request[10] = b'T';
        request[11] = b'R';
        let r1: u32 = rng.gen();
        let r2: u32 = rng.gen();
        request[12..16].copy_from_slice(&r1.to_be_bytes());
        request[16..20].copy_from_slice(&r2.to_be_bytes());

        sock.send(&request)
            .map_err(|e| ServerUnavailable(e.to_string()))?;

        let mut buf = [0u8; 1500];
        let n = socket_recv(&sock, &mut buf)
            .map_err(|e| ServerUnavailable(e.to_string()))?;

        if n < 20 {
            return Err(ServerUnavailable("STUN response too short".to_string()));
        }

        // Parse response attributes
        let mut payload = &buf[20..n];
        let mut mapped_ip: u32 = 0;
        let mut mapped_port: u16 = 0;
        let mut found = false;

        while payload.len() >= 4 {
            let attr_type = u16::from_be_bytes([payload[0], payload[1]]);
            let attr_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
            if payload.len() < 4 + attr_len {
                break;
            }

            // MAPPED-ADDRESS (0x0001) or XOR-MAPPED-ADDRESS (0x0020)
            if (attr_type == 1 || attr_type == 0x0020) && attr_len >= 8 {
                mapped_port = u16::from_be_bytes([payload[6], payload[7]]);
                mapped_ip = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
                if attr_type == 0x0020 {
                    mapped_port ^= 0x2112;
                    mapped_ip ^= 0x2112A442;
                }
                found = true;
                break;
            }

            // Advance with 4-byte alignment padding
            let padded_len = (attr_len + 3) & !3;
            if 4 + padded_len > payload.len() {
                break;
            }
            payload = &payload[4 + padded_len..];
        }

        if !found {
            return Err(ServerUnavailable("Invalid STUN response".to_string()));
        }

        let outer_ip = Ipv4Addr::from(mapped_ip);
        let outer_addr = SocketAddrV4::new(outer_ip, mapped_port);

        log::debug!(
            "stun: Got address {} from {}, source {}",
            addr_to_uri(&outer_addr, self.udp),
            addr_to_uri(&stun_addr, self.udp),
            addr_to_uri(&inner_v4, self.udp)
        );

        Ok((inner_v4, outer_addr))
    }
}
