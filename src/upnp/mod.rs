pub mod device;
pub mod service;

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::utils::{socket_set_opt, socket_recv_from};
use device::UPnPDevice;

/// UPnP/IGD Client for port forwarding via routers
pub struct UPnPClient {
    ssdp_addr: SocketAddrV4,
    pub router: Option<UPnPDevice>,
    bind_ip: Option<Ipv4Addr>,
    interface: Option<String>,
    // Forward state for renewal
    fwd_host: String,
    fwd_port: u16,
    fwd_dest_host: String,
    fwd_dest_port: u16,
    fwd_udp: bool,
    fwd_duration: u32,
    fwd_started: bool,
}

impl UPnPClient {
    pub fn new(bind_ip: Option<Ipv4Addr>, interface: Option<String>) -> Self {
        Self {
            ssdp_addr: SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900),
            router: None,
            bind_ip,
            interface,
            fwd_host: String::new(),
            fwd_port: 0,
            fwd_dest_host: String::new(),
            fwd_dest_port: 0,
            fwd_udp: false,
            fwd_duration: 0,
            fwd_started: false,
        }
    }

    pub fn discover_router(&mut self) -> io::Result<Option<&UPnPDevice>> {
        let mut router_list = Vec::new();
        match self.discover() {
            Ok(devs) => {
                for dev in devs {
                    if dev.forward_srv.is_some() {
                        router_list.push(dev);
                    }
                }
            }
            Err(e) => {
                log::error!("upnp: failed to discover router: {}", e);
            }
        }
        if router_list.is_empty() {
            self.router = None;
        } else {
            if router_list.len() > 1 {
                log::warn!("upnp: multiple routers found: {}", router_list.len());
            }
            self.router = Some(router_list.remove(0));
        }
        Ok(self.router.as_ref())
    }

    fn discover(&self) -> io::Result<Vec<UPnPDevice>> {
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        let bind_addr = self.bind_ip.map(|ip| SocketAddrV4::new(ip, 0));
        socket_set_opt(
            &sock,
            true,
            bind_addr,
            self.interface.as_deref(),
            Some(Duration::from_secs(1)),
        )?;

        let ssdp_sa = SockAddr::from(self.ssdp_addr);

        let dat01 = format!(
            "M-SEARCH * HTTP/1.1\r\nST: ssdp:all\r\nMX: 2\r\nMAN: \"ssdp:discover\"\r\nHOST: {}:{}\r\n\r\n",
            self.ssdp_addr.ip(),
            self.ssdp_addr.port()
        );
        let dat02 = format!(
            "M-SEARCH * HTTP/1.1\r\nST: upnp:rootdevice\r\nMX: 2\r\nMAN: \"ssdp:discover\"\r\nHOST: {}:{}\r\n\r\n",
            self.ssdp_addr.ip(),
            self.ssdp_addr.port()
        );

        sock.send_to(dat01.as_bytes(), &ssdp_sa)?;
        sock.send_to(dat02.as_bytes(), &ssdp_sa)?;

        let mut upnp_urls: std::collections::HashMap<Ipv4Addr, std::collections::HashSet<String>> =
            std::collections::HashMap::new();

        let mut buf = [0u8; 4096];
        loop {
            match socket_recv_from(&sock, &mut buf) {
                Ok((n, addr)) => {
                    let response = String::from_utf8_lossy(&buf[..n]);
                    let re = regex::Regex::new(r"LOCATION: *(http://[^\[]\S+)\s+").unwrap();
                    if let Some(caps) = re.captures(&response) {
                        let location = caps[1].to_string();
                        log::debug!("upnp: Got URL {}", location);
                        if let Some(v4) = addr.as_socket_ipv4() {
                            upnp_urls
                                .entry(*v4.ip())
                                .or_insert_with(std::collections::HashSet::new)
                                .insert(location);
                        }
                    }
                }
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    break
                }
                Err(e) => return Err(e),
            }
        }

        let mut devs = Vec::new();
        for (ipaddr, urls) in upnp_urls {
            let mut dev = UPnPDevice::new(
                ipaddr,
                urls.into_iter().collect(),
                self.bind_ip,
                self.interface.clone(),
            );
            dev.load_services();
            devs.push(dev);
        }
        Ok(devs)
    }

    pub fn forward(
        &mut self,
        host: &str,
        port: u16,
        dest_host: &str,
        dest_port: u16,
        udp: bool,
        duration: u32,
    ) -> io::Result<()> {
        let router = self.router.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "No router is available")
        })?;
        let srv = router.forward_srv.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "No forward service on router")
        })?;
        srv.forward_port(host, port, dest_host, dest_port, udp, duration)?;
        self.fwd_host = host.to_string();
        self.fwd_port = port;
        self.fwd_dest_host = dest_host.to_string();
        self.fwd_dest_port = dest_port;
        self.fwd_udp = udp;
        self.fwd_duration = duration;
        self.fwd_started = true;
        Ok(())
    }

    pub fn renew(&self) -> io::Result<()> {
        if !self.fwd_started {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "UPnP forward not started",
            ));
        }
        let router = self.router.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "No router")
        })?;
        let srv = router.forward_srv.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "No forward service")
        })?;
        srv.forward_port(
            &self.fwd_host,
            self.fwd_port,
            &self.fwd_dest_host,
            self.fwd_dest_port,
            self.fwd_udp,
            self.fwd_duration,
        )?;
        log::debug!("upnp: OK");
        Ok(())
    }
}
