use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use crate::utils::{create_tcp_socket, resolve_host, split_url, socket_recv};

/// UPnP Service representing a service on a UPnP device
pub struct UPnPService {
    pub service_type: Option<String>,
    pub service_id: Option<String>,
    pub scpd_url: Option<String>,
    pub control_url: Option<String>,
    pub eventsub_url: Option<String>,
    pub bind_ip: Option<Ipv4Addr>,
    pub interface: Option<String>,
}

impl UPnPService {
    pub fn new(bind_ip: Option<Ipv4Addr>, interface: Option<String>) -> Self {
        Self {
            service_type: None,
            service_id: None,
            scpd_url: None,
            control_url: None,
            eventsub_url: None,
            bind_ip,
            interface,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.service_type.is_some() && self.service_id.is_some() && self.control_url.is_some()
    }

    pub fn is_forward(&self) -> bool {
        if let Some(ref st) = self.service_type {
            let fwd_types = [
                "urn:schemas-upnp-org:service:WANIPConnection:1",
                "urn:schemas-upnp-org:service:WANIPConnection:2",
                "urn:schemas-upnp-org:service:WANPPPConnection:1",
            ];
            if fwd_types.contains(&st.as_str())
                && self.service_id.is_some()
                && self.control_url.is_some()
            {
                return true;
            }
        }
        false
    }

    pub fn forward_port(
        &self,
        host: &str,
        port: u16,
        dest_host: &str,
        dest_port: u16,
        udp: bool,
        duration: u32,
    ) -> io::Result<()> {
        if !self.is_forward() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "Unsupported service type: {:?}",
                    self.service_type
                ),
            ));
        }

        let control_url = self.control_url.as_ref().unwrap();
        let service_type = self.service_type.as_ref().unwrap();
        let (ctl_hostname, ctl_port, ctl_path) =
            split_url(control_url).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let proto = if udp { "UDP" } else { "TCP" };
        let content = format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
  s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <m:AddPortMapping xmlns:m="{}">
      <NewRemoteHost>{}</NewRemoteHost>
      <NewExternalPort>{}</NewExternalPort>
      <NewProtocol>{}</NewProtocol>
      <NewInternalPort>{}</NewInternalPort>
      <NewInternalClient>{}</NewInternalClient>
      <NewEnabled>1</NewEnabled>
      <NewPortMappingDescription>Natter</NewPortMappingDescription>
      <NewLeaseDuration>{}</NewLeaseDuration>
    </m:AddPortMapping>
  </s:Body>
</s:Envelope>
"#,
            service_type, host, port, proto, dest_port, dest_host, duration
        );

        let data = format!(
            "POST {} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: curl/8.0.0 (Natter)\r\nAccept: */*\r\nSOAPAction: \"{}#AddPortMapping\"\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            ctl_path, ctl_hostname, ctl_port, service_type, content.len(), content
        );

        let ip = resolve_host(&ctl_hostname)?;
        let server_addr = SocketAddrV4::new(ip, ctl_port);
        let bind_addr = self.bind_ip.map(|ip| SocketAddrV4::new(ip, 0));

        let sock = create_tcp_socket(
            bind_addr,
            self.interface.as_deref(),
            Some(Duration::from_secs(3)),
            false,
            server_addr,
        )?;
        sock.send(data.as_bytes())?;

        let mut response = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match socket_recv(&sock, &mut buf) {
                Ok(0) => break,
                Ok(n) => response.extend_from_slice(&buf[..n]),
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    break
                }
                Err(e) => return Err(e),
            }
        }

        let r = String::from_utf8_lossy(&response);
        let re_errno = regex::Regex::new(r"<errorCode\s*>([^<]*?)</errorCode\s*>").unwrap();
        let re_errmsg =
            regex::Regex::new(r"<errorDescription\s*>([^<]*?)</errorDescription\s*>").unwrap();
        let errno = re_errno
            .captures(&r)
            .map(|c| c[1].trim().to_string())
            .unwrap_or_default();
        let errmsg = re_errmsg
            .captures(&r)
            .map(|c| c[1].trim().to_string())
            .unwrap_or_default();

        if !errno.is_empty() || !errmsg.is_empty() {
            log::error!(
                "upnp: Error from service: [{}] {}",
                errno, errmsg
            );
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("UPnP error: [{}] {}", errno, errmsg),
            ));
        }
        Ok(())
    }
}
