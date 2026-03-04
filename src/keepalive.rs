use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use rand::Rng;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::utils::{addr_to_uri, socket_set_opt, socket_recv};

/// KeepAlive maintains the NAT mapping by periodically sending data through the punched port
pub struct KeepAlive {
    sock: Option<Socket>,
    pub host: String,
    pub port: u16,
    pub source_host: Ipv4Addr,
    pub source_port: u16,
    pub interface: Option<String>,
    pub udp: bool,
    reconn: bool,
}

impl KeepAlive {
    pub fn new(
        host: String,
        port: u16,
        source_host: Ipv4Addr,
        source_port: u16,
        interface: Option<String>,
        udp: bool,
    ) -> Self {
        Self {
            sock: None,
            host,
            port,
            source_host,
            source_port,
            interface,
            udp,
            reconn: false,
        }
    }

    fn connect(&mut self) -> io::Result<()> {
        let sock_type = if self.udp { Type::DGRAM } else { Type::STREAM };
        let protocol = if self.udp {
            Some(Protocol::UDP)
        } else {
            Some(Protocol::TCP)
        };
        let sock = Socket::new(Domain::IPV4, sock_type, protocol)?;
        let bind_addr = SocketAddrV4::new(self.source_host, self.source_port);

        socket_set_opt(
            &sock,
            true,
            Some(bind_addr),
            self.interface.as_deref(),
            Some(Duration::from_secs(3)),
        )?;

        let server_ip = crate::utils::resolve_host(&self.host)?;
        let server_addr = SocketAddrV4::new(server_ip, self.port);
        sock.connect(&SockAddr::from(server_addr))?;

        if !self.udp {
            log::debug!(
                "keep-alive: Connected to host {}",
                addr_to_uri(&server_addr, self.udp)
            );
            if self.reconn {
                log::info!("keep-alive: connection restored");
            }
        }
        self.reconn = false;
        self.sock = Some(sock);
        Ok(())
    }

    pub fn keep_alive(&mut self) -> io::Result<()> {
        if self.sock.is_none() {
            self.connect()?;
        }
        if self.udp {
            self.keep_alive_udp()?;
        } else {
            self.keep_alive_tcp()?;
        }
        log::debug!("keep-alive: OK");
        Ok(())
    }

    pub fn disconnect(&mut self) {
        if let Some(sock) = self.sock.take() {
            drop(sock);
            self.reconn = true;
        }
    }

    fn keep_alive_tcp(&mut self) -> io::Result<()> {
        let sock = self.sock.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "Not connected")
        })?;
        let request = format!(
            "HEAD /natter-keep-alive HTTP/1.1\r\nHost: {}\r\nUser-Agent: curl/8.0.0 (Natter)\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n",
            self.host
        );
        sock.send(request.as_bytes())?;

        let mut buf = [0u8; 4096];
        // read until timeout (which is expected)
        loop {
            match socket_recv(&sock, &mut buf) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "Keep-alive server closed connection",
                    ));
                }
                Ok(_) => continue,
                Err(e) => {
                    if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut
                    {
                        return Ok(());
                    }
                    return Err(e);
                }
            }
        }
    }

    fn keep_alive_udp(&mut self) -> io::Result<()> {
        let sock = self.sock.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "Not connected")
        })?;
        // Build a DNS query for keepalive.natter
        let mut rng = rand::thread_rng();
        let txid: u16 = rng.gen();
        let mut packet = Vec::with_capacity(64);
        // DNS Header
        packet.extend_from_slice(&txid.to_be_bytes());
        packet.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: standard query
        packet.extend_from_slice(&0x0001u16.to_be_bytes()); // qdcount
        packet.extend_from_slice(&0x0000u16.to_be_bytes()); // ancount
        packet.extend_from_slice(&0x0000u16.to_be_bytes()); // nscount
        packet.extend_from_slice(&0x0000u16.to_be_bytes()); // arcount
        // Question: keepalive.natter
        packet.push(9);
        packet.extend_from_slice(b"keepalive");
        packet.push(6);
        packet.extend_from_slice(b"natter");
        packet.push(0);
        packet.extend_from_slice(&0x0001u16.to_be_bytes()); // QTYPE: A
        packet.extend_from_slice(&0x0001u16.to_be_bytes()); // QCLASS: IN

        sock.send(&packet)?;

        let mut buf = [0u8; 1500];
        loop {
            match socket_recv(&sock, &mut buf) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "Keep-alive server closed connection",
                    ));
                }
                Ok(_) => continue,
                Err(e) => {
                    if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut
                    {
                        // fix: Keep-alive cause STUN socket timeout on Windows
                        #[cfg(target_os = "windows")]
                        {
                            self.disconnect();
                        }
                        return Ok(());
                    }
                    return Err(e);
                }
            }
        }
    }
}

impl Drop for KeepAlive {
    fn drop(&mut self) {
        self.disconnect();
    }
}
