use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use rand::Rng;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::utils::{resolve_host, socket_recv, socket_recv_from};

// --- Constants ---

const STUN_SERVER_TCP: &[&str] = &[
    "fwa.lifesizecloud.com",
    "global.turn.twilio.com",
    "turn.cloudflare.com",
    "stun.voip.blackberry.com",
    "stun.radiojar.com",
];

const STUN_SERVER_UDP: &[&str] = &[
    "stun.miwifi.com",
    "stun.chat.bilibili.com",
    "stun.hitv.com",
    "stun.cdnbye.com",
];

const PORT_TEST_SERVER: &str = "portcheck.transmissionbt.com";
const KEEP_ALIVE_SERVER: &str = "www.baidu.com";

const MTU: usize = 1500;
const STUN_PORT: u16 = 3478;
const MAGIC_COOKIE: u32 = 0x2112a442;
const BIND_REQUEST: u16 = 0x0001;
const BIND_RESPONSE: u16 = 0x0101;
const FAMILY_IPV4: u8 = 0x01;
const CHANGE_PORT: u32 = 0x0002;
const CHANGE_IP: u32 = 0x0004;
const ATTRIB_MAPPED_ADDRESS: u16 = 0x0001;
const ATTRIB_CHANGE_REQUEST: u16 = 0x0003;
const ATTRIB_XOR_MAPPED_ADDRESS: u16 = 0x0020;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    Unknown,
    OpenInternet,
    FullCone,
    Restricted,
    PortRestricted,
    Symmetric,
    SymUdpFirewall,
}

impl std::fmt::Display for NatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatType::Unknown => write!(f, "Unknown"),
            NatType::OpenInternet => write!(f, "Open Internet"),
            NatType::FullCone => write!(f, "Full Cone"),
            NatType::Restricted => write!(f, "Restricted"),
            NatType::PortRestricted => write!(f, "Port Restricted"),
            NatType::Symmetric => write!(f, "Symmetric"),
            NatType::SymUdpFirewall => write!(f, "Symmetric UDP Firewall"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckStatus {
    Na,
    Ok,
    Fail,
}

impl std::fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckStatus::Na => write!(f, "[   NA   ]"),
            CheckStatus::Ok => write!(f, "[   OK   ]"),
            CheckStatus::Fail => write!(f, "[  FAIL  ]"),
        }
    }
}

// --- STUN protocol helpers ---

fn random_tran_id(use_magic_cookie: bool) -> [u8; 16] {
    let mut rng = rand::thread_rng();
    let mut id = [0u8; 16];
    if use_magic_cookie {
        // Compatible with rfc3489, rfc5389 and rfc8489
        id[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        rng.fill(&mut id[4..16]);
    } else {
        // Compatible with rfc3489
        rng.fill(&mut id[..]);
    }
    id
}

fn pack_stun_message(msg_type: u16, tran_id: &[u8; 16], payload: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(20 + payload.len());
    msg.extend_from_slice(&msg_type.to_be_bytes());
    msg.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    msg.extend_from_slice(tran_id);
    msg.extend_from_slice(payload);
    msg
}

fn unpack_stun_message(data: &[u8]) -> Option<(u16, [u8; 16], &[u8])> {
    if data.len() < 20 {
        return None;
    }
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    let msg_length = u16::from_be_bytes([data[2], data[3]]) as usize;
    let mut tran_id = [0u8; 16];
    tran_id.copy_from_slice(&data[4..20]);
    let end = (20 + msg_length).min(data.len());
    let payload = &data[20..end];
    Some((msg_type, tran_id, payload))
}

fn extract_mapped_addr(payload: &[u8]) -> Option<(Ipv4Addr, u16)> {
    let mut pos = 0;
    while pos + 4 <= payload.len() {
        let attrib_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let attrib_length = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        if pos + 4 + attrib_length > payload.len() {
            break;
        }
        let value = &payload[pos + 4..pos + 4 + attrib_length];

        if (attrib_type == ATTRIB_MAPPED_ADDRESS || attrib_type == ATTRIB_XOR_MAPPED_ADDRESS)
            && attrib_length >= 8
        {
            let family = value[1];
            if family == FAMILY_IPV4 {
                let mut port = u16::from_be_bytes([value[2], value[3]]);
                let mut ip = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
                if attrib_type == ATTRIB_XOR_MAPPED_ADDRESS {
                    port ^= (MAGIC_COOKIE >> 16) as u16;
                    ip ^= MAGIC_COOKIE;
                }
                return Some((Ipv4Addr::from(ip), port));
            }
        }

        // Advance with 4-byte alignment padding
        let padded_len = (attrib_length + 3) & !3;
        pos += 4 + padded_len;
    }
    None
}

// --- Socket helpers ---

fn new_socket_reuse(sock_type: Type, protocol: Protocol) -> io::Result<Socket> {
    let sock = Socket::new(Domain::IPV4, sock_type, Some(protocol))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    {
        sock.set_reuse_port(true)?;
    }
    Ok(sock)
}

fn get_free_port(udp: bool) -> io::Result<u16> {
    let (sock_type, protocol) = if udp {
        (Type::DGRAM, Protocol::UDP)
    } else {
        (Type::STREAM, Protocol::TCP)
    };
    let sock = new_socket_reuse(sock_type, protocol)?;
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    sock.bind(&SockAddr::from(addr))?;
    let local = sock.local_addr()?;
    let port = local
        .as_socket_ipv4()
        .map(|a| a.port())
        .unwrap_or(0);
    Ok(port)
}

fn resolve_all(hostname: &str) -> Vec<Ipv4Addr> {
    use std::net::ToSocketAddrs;
    let addr_str = format!("{}:0", hostname);
    match addr_str.to_socket_addrs() {
        Ok(addrs) => addrs
            .filter_map(|a| match a {
                std::net::SocketAddr::V4(v4) => Some(*v4.ip()),
                _ => None,
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

// --- StunTest ---

pub struct StunTest {
    source_ip: Ipv4Addr,
    stun_ip_tcp: Vec<Ipv4Addr>,
    stun_ip_udp: Vec<Ipv4Addr>,
}

/// Result of a TCP STUN test
type TcpTestResult = Option<(SocketAddrV4, (Ipv4Addr, u16))>;

/// Result of a UDP STUN test
type UdpTestResult = Option<(SocketAddrV4, (Ipv4Addr, u16), bool, bool)>;

impl StunTest {
    pub fn new(source_ip: Ipv4Addr) -> Result<Self, String> {
        let mut stun_ip_tcp = Vec::new();
        for hostname in STUN_SERVER_TCP {
            stun_ip_tcp.extend(resolve_all(hostname));
        }
        let mut stun_ip_udp = Vec::new();
        for hostname in STUN_SERVER_UDP {
            stun_ip_udp.extend(resolve_all(hostname));
        }
        if stun_ip_tcp.is_empty() || stun_ip_udp.is_empty() {
            return Err("cannot resolve hostname".to_string());
        }
        Ok(Self {
            source_ip,
            stun_ip_tcp,
            stun_ip_udp,
        })
    }

    /// TCP STUN Binding Request (rfc5389/rfc8489)
    fn tcp_test(&self, stun_host: Ipv4Addr, source_port: u16) -> TcpTestResult {
        let tran_id = random_tran_id(true);
        let sock = new_socket_reuse(Type::STREAM, Protocol::TCP).ok()?;
        sock.set_nodelay(true).ok()?;
        sock.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
        sock.set_write_timeout(Some(Duration::from_secs(3))).ok()?;

        let bind_addr = SocketAddrV4::new(self.source_ip, source_port);
        sock.bind(&SockAddr::from(bind_addr)).ok()?;

        let stun_addr = SocketAddrV4::new(stun_host, STUN_PORT);
        sock.connect(&SockAddr::from(stun_addr)).ok()?;

        let data = pack_stun_message(BIND_REQUEST, &tran_id, &[]);
        sock.send(&data).ok()?;

        let mut buf = [0u8; MTU];
        let n = socket_recv(&sock, &mut buf).ok()?;

        let (msg_type, msg_id, payload) = unpack_stun_message(&buf[..n])?;
        if tran_id != msg_id || msg_type != BIND_RESPONSE {
            return None;
        }

        let source_addr = sock.local_addr().ok()?;
        let source_v4 = source_addr.as_socket_ipv4()?;
        let mapped_addr = extract_mapped_addr(payload)?;

        // Attempt graceful shutdown
        let _ = sock.shutdown(std::net::Shutdown::Both);

        Some((source_v4, mapped_addr))
    }

    /// UDP STUN Binding Request (rfc3489) with optional change-ip/change-port
    fn udp_test(
        &self,
        stun_host: Ipv4Addr,
        source_port: u16,
        change_ip: bool,
        change_port: bool,
    ) -> UdpTestResult {
        let timeout = Duration::from_secs(3);
        let repeat = 3;
        let time_start = Instant::now();

        let tran_id = random_tran_id(false);
        let sock = new_socket_reuse(Type::DGRAM, Protocol::UDP).ok()?;
        sock.set_read_timeout(Some(timeout)).ok()?;

        let bind_addr = SocketAddrV4::new(self.source_ip, source_port);
        sock.bind(&SockAddr::from(bind_addr)).ok()?;

        let mut flags: u32 = 0;
        if change_ip {
            flags |= CHANGE_IP;
        }
        if change_port {
            flags |= CHANGE_PORT;
        }

        let data = if flags != 0 {
            let mut payload = Vec::with_capacity(8);
            payload.extend_from_slice(&ATTRIB_CHANGE_REQUEST.to_be_bytes());
            payload.extend_from_slice(&4u16.to_be_bytes());
            payload.extend_from_slice(&flags.to_be_bytes());
            pack_stun_message(BIND_REQUEST, &tran_id, &payload)
        } else {
            pack_stun_message(BIND_REQUEST, &tran_id, &[])
        };

        let stun_sa = SockAddr::from(SocketAddrV4::new(stun_host, STUN_PORT));
        // Send packets repeatedly to avoid packet loss
        for _ in 0..repeat {
            let _ = sock.send_to(&data, &stun_sa);
        }

        let mut buf = [0u8; MTU];
        loop {
            let elapsed = time_start.elapsed();
            if elapsed >= timeout {
                return None;
            }
            let remaining = timeout - elapsed;
            sock.set_read_timeout(Some(remaining)).ok()?;

            match socket_recv_from(&sock, &mut buf) {
                Ok((n, recv_addr)) => {
                    if n < 20 {
                        continue;
                    }
                    let (msg_type, msg_id, payload) = match unpack_stun_message(&buf[..n]) {
                        Some(v) => v,
                        None => continue,
                    };
                    if tran_id != msg_id || msg_type != BIND_RESPONSE {
                        continue;
                    }

                    let source_addr = sock.local_addr().ok()?;
                    let source_v4 = source_addr.as_socket_ipv4()?;
                    let mapped_addr = extract_mapped_addr(payload)?;

                    let recv_v4 = recv_addr.as_socket_ipv4()?;
                    let ip_changed = recv_v4.ip() != &stun_host;
                    let port_changed = recv_v4.port() != STUN_PORT;

                    return Some((source_v4, mapped_addr, ip_changed, port_changed));
                }
                Err(e) => {
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut
                    {
                        return None;
                    }
                    return None;
                }
            }
        }
    }

    /// Get TCP mapping, rotating through servers on failure
    fn get_tcp_mapping(&mut self, source_port: u16) -> Result<(SocketAddrV4, (Ipv4Addr, u16)), String> {
        if self.stun_ip_tcp.is_empty() {
            return Err("No TCP STUN server available".to_string());
        }
        let first = self.stun_ip_tcp[0];
        loop {
            let server_ip = self.stun_ip_tcp[0];
            if let Some((source, mapped)) = self.tcp_test(server_ip, source_port) {
                return Ok((source, mapped));
            }
            // Rotate
            let removed = self.stun_ip_tcp.remove(0);
            self.stun_ip_tcp.push(removed);
            if self.stun_ip_tcp[0] == first {
                return Err("No STUN server available".to_string());
            }
        }
    }

    /// Get UDP mapping, rotating through servers on failure
    fn get_udp_mapping(&mut self, source_port: u16) -> Result<(SocketAddrV4, (Ipv4Addr, u16)), String> {
        if self.stun_ip_udp.is_empty() {
            return Err("No UDP STUN server available".to_string());
        }
        let first = self.stun_ip_udp[0];
        loop {
            let server_ip = self.stun_ip_udp[0];
            if let Some((source, mapped, _, _)) =
                self.udp_test(server_ip, source_port, false, false)
            {
                return Ok((source, mapped));
            }
            let removed = self.stun_ip_udp.remove(0);
            self.stun_ip_udp.push(removed);
            if self.stun_ip_udp[0] == first {
                return Err("No STUN server available".to_string());
            }
        }
    }

    /// Check if TCP NAT is cone (same mapping via ≥3 servers)
    fn check_tcp_cone(&self, source_port: u16) -> i32 {
        let mut mapped_addr_first: Option<(Ipv4Addr, u16)> = None;
        let mut count = 0;
        for &server_ip in &self.stun_ip_tcp {
            if count >= 3 {
                return 1;
            }
            if let Some((_source, mapped)) = self.tcp_test(server_ip, source_port) {
                if let Some(first) = mapped_addr_first {
                    if mapped != first {
                        return -1;
                    }
                }
                mapped_addr_first = Some(mapped);
                count += 1;
            }
        }
        0
    }

    /// Check TCP full-cone by listen + keep-alive + STUN + port check
    fn check_tcp_fullcone(&mut self, source_port: u16) -> i32 {
        // Open listening socket
        let srv_sock = match new_socket_reuse(Type::STREAM, Protocol::TCP) {
            Ok(s) => s,
            Err(_) => return 0,
        };
        let bind_addr = SocketAddrV4::new(self.source_ip, source_port);
        if srv_sock.bind(&SockAddr::from(bind_addr)).is_err() {
            return 0;
        }
        if srv_sock.listen(5).is_err() {
            return 0;
        }

        // Make keep-alive connection
        let ka_sock = match new_socket_reuse(Type::STREAM, Protocol::TCP) {
            Ok(s) => s,
            Err(_) => return 0,
        };
        if ka_sock.bind(&SockAddr::from(bind_addr)).is_err() {
            return 0;
        }

        let ka_ip = match resolve_host(KEEP_ALIVE_SERVER) {
            Ok(ip) => ip,
            Err(_) => return 0,
        };
        let ka_addr = SocketAddrV4::new(ka_ip, 80);
        ka_sock.set_read_timeout(Some(Duration::from_secs(3))).ok();
        ka_sock.set_write_timeout(Some(Duration::from_secs(3))).ok();
        if ka_sock.connect(&SockAddr::from(ka_addr)).is_err() {
            return 0;
        }
        let req = format!(
            "GET /~ HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\r\n",
            KEEP_ALIVE_SERVER
        );
        if ka_sock.send(req.as_bytes()).is_err() {
            return 0;
        }

        // Get STUN mapping
        let (source_addr, mapped_addr) = match self.get_tcp_mapping(source_port) {
            Ok(v) => v,
            Err(_) => return 0,
        };
        let public_port = mapped_addr.1;

        // Check if open internet
        let source_tuple = (*source_addr.ip(), source_addr.port());
        if source_tuple == mapped_addr {
            return 2;
        }

        // Check public port via Transmission portcheck
        let pt_ip = match resolve_host(PORT_TEST_SERVER) {
            Ok(ip) => ip,
            Err(_) => return 0,
        };
        let pt_sock = match Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)) {
            Ok(s) => s,
            Err(_) => return 0,
        };
        pt_sock.set_read_timeout(Some(Duration::from_secs(8))).ok();
        pt_sock.set_write_timeout(Some(Duration::from_secs(8))).ok();
        let pt_bind = SocketAddrV4::new(self.source_ip, 0);
        let _ = pt_sock.bind(&SockAddr::from(pt_bind));
        let pt_addr = SocketAddrV4::new(pt_ip, 80);
        if pt_sock.connect(&SockAddr::from(pt_addr)).is_err() {
            return 0;
        }
        let req = format!(
            "GET /{} HTTP/1.0\r\nHost: {}\r\nUser-Agent: curl/8.0.0 (Natter)\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            public_port, PORT_TEST_SERVER
        );
        if pt_sock.send(req.as_bytes()).is_err() {
            return 0;
        }

        let mut response = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match socket_recv(&pt_sock, &mut buf) {
                Ok(0) => break,
                Ok(n) => response.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }

        // Parse response body
        let resp_str = String::from_utf8_lossy(&response);
        if let Some(pos) = resp_str.find("\r\n\r\n") {
            let content = resp_str[pos + 4..].trim();
            if content == "1" {
                return 1;
            } else if content == "0" {
                return -1;
            }
        }
        0
    }

    /// Detect UDP NAT type using classic STUN (RFC 3489) algorithm
    pub fn check_udp_nat_type(&mut self, source_port: u16) -> NatType {
        let source_port = if source_port == 0 {
            get_free_port(true).unwrap_or(0)
        } else {
            source_port
        };

        let mut ret_test1_1: Option<(SocketAddrV4, (Ipv4Addr, u16), bool, bool)> = None;
        let mut ret_test1_2: Option<(SocketAddrV4, (Ipv4Addr, u16), bool, bool)> = None;
        let mut ret_test2: Option<(SocketAddrV4, (Ipv4Addr, u16), bool, bool)> = None;
        let mut ret_test3: Option<(SocketAddrV4, (Ipv4Addr, u16), bool, bool)> = None;
        let mut found = false;

        let stun_ips = self.stun_ip_udp.clone();
        for &server_ip in &stun_ips {
            let ret = self.udp_test(server_ip, source_port, false, false);
            if ret.is_none() {
                continue;
            }
            if ret_test1_1.is_none() {
                ret_test1_1 = ret;
                continue;
            }
            ret_test1_2 = ret;

            // Test 2: change_ip + change_port
            let ret = self.udp_test(server_ip, source_port, true, true);
            if let Some((_, _, ip_changed, port_changed)) = ret {
                if !ip_changed || !port_changed {
                    // Server doesn't support change, try another
                    continue;
                }
            }
            ret_test2 = ret;

            // Test 3: change_port only
            ret_test3 = self.udp_test(server_ip, source_port, false, true);
            found = true;
            break;
        }

        if !found {
            return NatType::Unknown;
        }

        let (source_1_1, mapped_1_1, _, _) = ret_test1_1.unwrap();
        let (_source_1_2, mapped_1_2, _, _) = ret_test1_2.unwrap();

        if mapped_1_1 != mapped_1_2 {
            return NatType::Symmetric;
        }

        let source_tuple = (*source_1_1.ip(), source_1_1.port());
        if source_tuple == mapped_1_1 {
            if ret_test2.is_some() {
                NatType::OpenInternet
            } else {
                NatType::SymUdpFirewall
            }
        } else if ret_test2.is_some() {
            NatType::FullCone
        } else if ret_test3.is_some() {
            NatType::Restricted
        } else {
            NatType::PortRestricted
        }
    }

    /// Detect TCP NAT type
    pub fn check_tcp_nat_type(&mut self, source_port: u16) -> NatType {
        let source_port = if source_port == 0 {
            get_free_port(false).unwrap_or(0)
        } else {
            source_port
        };

        let ret = self.check_tcp_fullcone(source_port);
        match ret {
            2 => return NatType::OpenInternet,
            1 => return NatType::FullCone,
            -1 => {
                // Full cone test failed, check cone type
                let cone_ret = self.check_tcp_cone(source_port);
                return match cone_ret {
                    1 => NatType::PortRestricted,
                    -1 => NatType::Symmetric,
                    _ => NatType::Unknown,
                };
            }
            _ => {
                // Inconclusive full cone, try cone check
                let cone_ret = self.check_tcp_cone(source_port);
                return match cone_ret {
                    1 => NatType::PortRestricted,
                    -1 => NatType::Symmetric,
                    _ => NatType::Unknown,
                };
            }
        }
    }
}

// --- Public entry point ---

pub fn do_check() {
    let version = env!("CARGO_PKG_VERSION");
    eprintln!("> NatterCheck v{} (Rust)\n", version);

    print_check("Checking TCP NAT...", |st| {
        let nat_type = st.check_tcp_nat_type(0);
        let status = match nat_type {
            NatType::OpenInternet | NatType::FullCone => CheckStatus::Ok,
            NatType::Unknown => CheckStatus::Na,
            _ => CheckStatus::Fail,
        };
        (status, format!("NAT Type: {}", nat_type))
    });

    print_check("Checking UDP NAT...", |st| {
        let nat_type = st.check_udp_nat_type(0);
        let status = match nat_type {
            NatType::OpenInternet | NatType::FullCone => CheckStatus::Ok,
            NatType::Unknown => CheckStatus::Na,
            _ => CheckStatus::Fail,
        };
        (status, format!("NAT Type: {}", nat_type))
    });
}

fn print_check<F>(label: &str, func: F)
where
    F: FnOnce(&mut StunTest) -> (CheckStatus, String),
{
    eprint!("{:<36} ", label);
    let _ = io::stderr().flush();

    match StunTest::new(Ipv4Addr::UNSPECIFIED) {
        Ok(mut st) => {
            let (status, info) = func(&mut st);
            eprintln!("{} ... {}", status, info);
        }
        Err(e) => {
            eprintln!("{} ... {}", CheckStatus::Fail, e);
        }
    }
}
