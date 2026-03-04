use std::io::{self, Read, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use super::Forward;
use crate::utils::{addr_to_uri, socket_set_opt};

/// ForwardTestServer: built-in HTTP/UDP test server
pub struct ForwardTestServer {
    running: Arc<AtomicBool>,
}

impl ForwardTestServer {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Forward for ForwardTestServer {
    fn start_forward(
        &mut self,
        ip: &str,
        port: u16,
        _to_ip: &str,
        _to_port: u16,
        udp: bool,
    ) -> io::Result<()> {
        let sock = if udp {
            Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?
        } else {
            Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?
        };
        let bind_addr: SocketAddrV4 = format!("0.0.0.0:{}", port)
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        socket_set_opt(&sock, true, Some(bind_addr), None, None)?;

        log::debug!(
            "fwd-test: Starting test server at {}",
            addr_to_uri(&bind_addr, udp)
        );

        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();

        if udp {
            let std_sock: std::net::UdpSocket = sock.into();
            thread::Builder::new()
                .name("test-server-udp".into())
                .spawn(move || {
                    let mut buf = [0u8; 8192];
                    while running.load(Ordering::SeqCst) {
                        match std_sock.recv_from(&mut buf) {
                            Ok((_, addr)) => {
                                log::debug!("fwd-test: got client {:?}", addr);
                                let _ = std_sock.send_to(b"It works! - Natter\r\n", addr);
                            }
                            Err(_) => return,
                        }
                    }
                })?;
        } else {
            let listener: std::net::TcpListener = sock.into();
            thread::Builder::new()
                .name("test-server-http".into())
                .spawn(move || {
                    for stream in listener.incoming() {
                        if !running.load(Ordering::SeqCst) {
                            return;
                        }
                        match stream {
                            Ok(mut conn) => {
                                let _ = conn.set_read_timeout(Some(Duration::from_secs(3)));
                                let mut buf = [0u8; 8192];
                                let _ = conn.read(&mut buf);
                                let content =
                                    "<html><body><h1>It works!</h1><hr/>Natter</body></html>";
                                let response = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\nServer: Natter\r\n\r\n{}\r\n",
                                    content.len(),
                                    content
                                );
                                let _ = conn.write_all(response.as_bytes());
                                let _ = conn.shutdown(std::net::Shutdown::Both);
                            }
                            Err(_) => return,
                        }
                    }
                })?;
        }

        thread::sleep(Duration::from_secs(1));
        Ok(())
    }

    fn stop_forward(&mut self) -> io::Result<()> {
        if self.running.load(Ordering::SeqCst) {
            log::debug!("fwd-test: Stopping test server");
            self.running.store(false, Ordering::SeqCst);
        }
        Ok(())
    }
}

impl Drop for ForwardTestServer {
    fn drop(&mut self) {
        let _ = self.stop_forward();
    }
}
