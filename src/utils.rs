use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket};
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

/// Set socket options: reuse, bind, interface, timeout
pub fn socket_set_opt(
    sock: &Socket,
    reuse: bool,
    bind_addr: Option<SocketAddrV4>,
    interface: Option<&str>,
    timeout: Option<Duration>,
) -> io::Result<()> {
    if reuse {
        sock.set_reuse_address(true)?;
        #[cfg(unix)]
        {
            sock.set_reuse_port(true)?;
        }
    }
    if let Some(iface) = interface {
        #[cfg(target_os = "linux")]
        {
            sock.bind_device(Some(iface.as_bytes()))?;
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = iface;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Binding to an interface is not supported on your platform.",
            ));
        }
    }
    if let Some(addr) = bind_addr {
        sock.bind(&SockAddr::from(addr))?;
    }
    if let Some(t) = timeout {
        sock.set_read_timeout(Some(t))?;
        sock.set_write_timeout(Some(t))?;
    }
    Ok(())
}

/// Create a connected TCP socket with options
pub fn create_tcp_socket(
    bind_addr: Option<SocketAddrV4>,
    interface: Option<&str>,
    timeout: Option<Duration>,
    reuse: bool,
    connect_to: SocketAddrV4,
) -> io::Result<Socket> {
    let sock = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket_set_opt(&sock, reuse, bind_addr, interface, timeout)?;
    sock.connect(&SockAddr::from(connect_to))?;
    Ok(sock)
}

/// Create a connected UDP socket with options
pub fn create_udp_socket(
    bind_addr: Option<SocketAddrV4>,
    interface: Option<&str>,
    timeout: Option<Duration>,
    reuse: bool,
    connect_to: SocketAddrV4,
) -> io::Result<Socket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket_set_opt(&sock, reuse, bind_addr, interface, timeout)?;
    sock.connect(&SockAddr::from(connect_to))?;
    Ok(sock)
}

/// Format addr as "ip:port"
pub fn addr_to_str(addr: &SocketAddrV4) -> String {
    format!("{}:{}", addr.ip(), addr.port())
}

/// Format addr as "tcp://ip:port" or "udp://ip:port"
pub fn addr_to_uri(addr: &SocketAddrV4, udp: bool) -> String {
    let proto = if udp { "udp" } else { "tcp" };
    format!("{}://{}:{}", proto, addr.ip(), addr.port())
}

/// Validate an IPv4 address string
pub fn validate_ip(s: &str) -> Result<Ipv4Addr, String> {
    s.parse::<Ipv4Addr>()
        .map_err(|_| format!("Invalid IP address: {}", s))
}

/// Validate a port number
pub fn validate_port(p: u16) -> Result<u16, String> {
    Ok(p)
}

/// Normalize IPv4 (e.g., "10.1" -> "10.0.0.1")
pub fn ip_normalize(s: &str) -> Result<Ipv4Addr, String> {
    // std Ipv4Addr doesn't parse "10.1" so do a socket-level check
    use std::net::ToSocketAddrs;
    // Try standard parse first
    if let Ok(ip) = s.parse::<Ipv4Addr>() {
        return Ok(ip);
    }
    // Try resolving as hostname
    let addr_str = format!("{}:0", s);
    if let Ok(mut addrs) = addr_str.to_socket_addrs() {
        if let Some(SocketAddr::V4(v4)) = addrs.next() {
            return Ok(*v4.ip());
        }
    }
    Err(format!("Invalid IP address: {}", s))
}

/// Parse "host:port" with a default port
pub fn parse_host_port(s: &str, default_port: u16) -> (String, u16) {
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    if parts.len() == 2 {
        let port = parts[1].parse::<u16>().unwrap_or(default_port);
        (parts[0].to_string(), port)
    } else {
        (s.to_string(), default_port)
    }
}

/// Resolve hostname to IPv4 address
pub fn resolve_host(host: &str) -> io::Result<Ipv4Addr> {
    use std::net::ToSocketAddrs;
    let addr_str = format!("{}:0", host);
    for addr in addr_str.to_socket_addrs()? {
        if let SocketAddr::V4(v4) = addr {
            return Ok(*v4.ip());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("Cannot resolve host: {}", host),
    ))
}

/// Split an HTTP URL into (hostname, port, path)
pub fn split_url(url: &str) -> Result<(String, u16, String), String> {
    let re = regex::Regex::new(r"^http://([^\[\]:/]+)(?::([0-9]+))?(/\S*)?$").unwrap();
    if let Some(caps) = re.captures(url) {
        let hostname = caps[1].to_string();
        let port: u16 = caps
            .get(2)
            .map(|m| m.as_str().parse().unwrap_or(80))
            .unwrap_or(80);
        let path = caps
            .get(3)
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        Ok((hostname, port, path))
    } else {
        Err(format!("Unsupported URL: {}", url))
    }
}

/// Make a relative URL absolute
pub fn full_url(u: &str, refurl: &str) -> Result<String, String> {
    if !u.starts_with('/') {
        return Ok(u.to_string());
    }
    let (hostname, port, _) = split_url(refurl)?;
    Ok(format!("http://{}:{}{}", hostname, port, u))
}

/// Simple HTTP GET request, returns response body bytes
pub fn http_get(
    url: &str,
    bind_ip: Option<Ipv4Addr>,
    interface: Option<&str>,
) -> io::Result<Vec<u8>> {
    let (hostname, port, path) =
        split_url(url).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let ip = resolve_host(&hostname)?;
    let server_addr = SocketAddrV4::new(ip, port);
    let bind_addr = bind_ip.map(|ip| SocketAddrV4::new(ip, 0));

    let sock = create_tcp_socket(
        bind_addr,
        interface,
        Some(Duration::from_secs(3)),
        false,
        server_addr,
    )?;
    let mut stream: TcpStream = sock.into();
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: curl/8.0.0 (Natter)\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        path, hostname
    );
    stream.write_all(request.as_bytes())?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;

    if !response.starts_with(b"HTTP/") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid response from HTTP server",
        ));
    }
    if let Some(pos) = find_subsequence(&response, b"\r\n\r\n") {
        Ok(response[pos + 4..].to_vec())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid response from HTTP server",
        ))
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Check if a socket error represents a closed/aborted socket
pub fn is_closed_socket_err(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
    ) || matches!(err.raw_os_error(), Some(9) | Some(10038) | Some(10004))
    // 9 = EBADF, 10038 = WSAENOTSOCK, 10004 = WSAEINTR
}

/// Safe wrapper for socket2 recv (handles MaybeUninit)
pub fn socket_recv(sock: &Socket, buf: &mut [u8]) -> io::Result<usize> {
    let buf_uninit: &mut [MaybeUninit<u8>] =
        unsafe { &mut *(buf as *mut [u8] as *mut [MaybeUninit<u8>]) };
    sock.recv(buf_uninit)
}

/// Safe wrapper for socket2 recv_from (handles MaybeUninit)
pub fn socket_recv_from(sock: &Socket, buf: &mut [u8]) -> io::Result<(usize, SockAddr)> {
    let buf_uninit: &mut [MaybeUninit<u8>] =
        unsafe { &mut *(buf as *mut [u8] as *mut [MaybeUninit<u8>]) };
    sock.recv_from(buf_uninit)
}

