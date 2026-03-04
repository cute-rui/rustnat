use std::io;
use std::net::Ipv4Addr;

use crate::utils::{full_url, http_get};

use super::service::UPnPService;

/// UPnP Device representing a network device discovered via SSDP
pub struct UPnPDevice {
    pub ipaddr: Ipv4Addr,
    pub xml_urls: Vec<String>,
    pub services: Vec<UPnPService>,
    pub forward_srv: Option<UPnPService>,
    bind_ip: Option<Ipv4Addr>,
    interface: Option<String>,
}

impl UPnPDevice {
    pub fn new(
        ipaddr: Ipv4Addr,
        xml_urls: Vec<String>,
        bind_ip: Option<Ipv4Addr>,
        interface: Option<String>,
    ) -> Self {
        Self {
            ipaddr,
            xml_urls,
            services: Vec::new(),
            forward_srv: None,
            bind_ip,
            interface,
        }
    }

    pub fn load_services(&mut self) {
        if !self.services.is_empty() {
            return;
        }
        let mut all_services: Vec<UPnPService> = Vec::new();
        for url in &self.xml_urls.clone() {
            match self.get_srv_list(url) {
                Ok(srvs) => all_services.extend(srvs),
                Err(e) => {
                    log::warn!("upnp: failed to load service from {}: {}", url, e);
                }
            }
        }

        // Find first forward-capable service
        let mut forward_idx = None;
        for (i, srv) in all_services.iter().enumerate() {
            if srv.is_forward() {
                forward_idx = Some(i);
                break;
            }
        }

        if let Some(idx) = forward_idx {
            // Move the forward service out
            let fwd = all_services.remove(idx);
            self.forward_srv = Some(UPnPService {
                service_type: fwd.service_type,
                service_id: fwd.service_id,
                scpd_url: fwd.scpd_url,
                control_url: fwd.control_url,
                eventsub_url: fwd.eventsub_url,
                bind_ip: self.bind_ip,
                interface: self.interface.clone(),
            });
        }

        self.services = all_services;
    }

    fn get_srv_list(&self, url: &str) -> io::Result<Vec<UPnPService>> {
        let body = http_get(url, self.bind_ip, self.interface.as_deref())?;
        let xmlcontent = String::from_utf8_lossy(&body);

        let mut services = Vec::new();
        let re_service =
            regex::Regex::new(r"<service\s*>([\s\S]+?)</service\s*>").unwrap();
        let re_type =
            regex::Regex::new(r"<serviceType\s*>([^<]*?)</serviceType\s*>").unwrap();
        let re_id =
            regex::Regex::new(r"<serviceId\s*>([^<]*?)</serviceId\s*>").unwrap();
        let re_scpd =
            regex::Regex::new(r"<SCPDURL\s*>([^<]*?)</SCPDURL\s*>").unwrap();
        let re_control =
            regex::Regex::new(r"<controlURL\s*>([^<]*?)</controlURL\s*>").unwrap();
        let re_event =
            regex::Regex::new(r"<eventSubURL\s*>([^<]*?)</eventSubURL\s*>").unwrap();

        for caps in re_service.captures_iter(&xmlcontent) {
            let srv_str = &caps[1];
            let mut srv = UPnPService::new(self.bind_ip, self.interface.clone());

            if let Some(m) = re_type.captures(srv_str) {
                srv.service_type = Some(m[1].trim().to_string());
            }
            if let Some(m) = re_id.captures(srv_str) {
                srv.service_id = Some(m[1].trim().to_string());
            }
            if let Some(m) = re_scpd.captures(srv_str) {
                srv.scpd_url = full_url(m[1].trim(), url).ok();
            }
            if let Some(m) = re_control.captures(srv_str) {
                srv.control_url = full_url(m[1].trim(), url).ok();
            }
            if let Some(m) = re_event.captures(srv_str) {
                srv.eventsub_url = full_url(m[1].trim(), url).ok();
            }
            if srv.is_valid() {
                services.push(srv);
            }
        }
        Ok(services)
    }
}
