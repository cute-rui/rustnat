use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use super::Forward;
use crate::utils::{addr_to_str, addr_to_uri, is_closed_socket_err, socket_set_opt};

/// ForwardSocket: Pure Rust TCP/UDP port forwarding
pub struct ForwardSocket {
    running: Arc<AtomicBool>,
    sock: Option<Socket>,
}

impl ForwardSocket {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            sock: None,
        }
    }
}

impl Forward for ForwardSocket {
    fn start_forward(
        &mut self,
        ip: &str,
        port: u16,
        to_ip: &str,
        to_port: u16,
        udp: bool,
    ) -> io::Result<()> {
        if ip == to_ip && port == to_port {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Cannot forward to the same address {}:{}", ip, port),
            ));
        }

        let sock_type = if udp { Type::DGRAM } else { Type::STREAM };
        let protocol = if udp {
            Some(Protocol::UDP)
        } else {
            Some(Protocol::TCP)
        };
        let sock = Socket::new(Domain::IPV4, sock_type, protocol)?;
        let bind_addr: SocketAddrV4 = format!("0.0.0.0:{}", port).parse().unwrap();
        socket_set_opt(&sock, true, Some(bind_addr), None, None)?;

        let to_addr: SocketAddrV4 = format!("{}:{}", to_ip, to_port).parse().unwrap();
        log::debug!(
            "fwd-socket: Starting socket {} forward to {}",
            addr_to_uri(&bind_addr, udp),
            addr_to_uri(&to_addr, udp)
        );

        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();

        if udp {
            let std_sock: std::net::UdpSocket = sock.into();
            let outbound_addr = to_addr;
            thread::Builder::new()
                .name("fwd-socket-udp".into())
                .spawn(move || {
                    let server_sock = Arc::new(std_sock);
                    let mut outbound_socks: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
                    let mut buf = [0u8; 8192];
                    while running.load(Ordering::SeqCst) {
                        let (n, addr) = match server_sock.recv_from(&mut buf) {
                            Ok(r) => r,
                            Err(e) => {
                                if !is_closed_socket_err(&e) {
                                    log::error!(
                                        "fwd-socket: socket recvfrom thread is exiting: {}",
                                        e
                                    );
                                }
                                return;
                            }
                        };
                        let s = outbound_socks.entry(addr).or_insert_with(|| {
                            let udp_sock =
                                UdpSocket::bind("0.0.0.0:0").expect("bind udp outbound");
                            udp_sock
                                .set_read_timeout(Some(Duration::from_secs(60)))
                                .ok();
                            udp_sock
                                .connect(SocketAddr::V4(outbound_addr))
                                .expect("connect udp outbound");
                            let s = Arc::new(udp_sock);
                            let s2 = s.clone();
                            let srv = server_sock.clone();
                            let client_addr = addr;
                            thread::Builder::new()
                                .name("fwd-socket-udp-send".into())
                                .spawn(move || {
                                    let mut buf2 = [0u8; 8192];
                                    loop {
                                        match s2.recv(&mut buf2) {
                                            Ok(0) => return,
                                            Ok(n) => {
                                                let _ = srv.send_to(&buf2[..n], client_addr);
                                            }
                                            Err(_) => return,
                                        }
                                    }
                                })
                                .ok();
                            s
                        });
                        if n > 0 {
                            let _ = s.send(&buf[..n]);
                        }
                    }
                })?;
        } else {
            let listener: std::net::TcpListener = sock.into();
            let max_threads = 128usize;
            thread::Builder::new()
                .name("fwd-socket-tcp".into())
                .spawn(move || {
                    for inbound in listener.incoming() {
                        if !running.load(Ordering::SeqCst) {
                            return;
                        }
                        let mut sock_inbound = match inbound {
                            Ok(s) => s,
                            Err(e) => {
                                if !is_closed_socket_err(&e) {
                                    log::error!(
                                        "fwd-socket: socket listening thread is exiting: {}",
                                        e
                                    );
                                }
                                return;
                            }
                        };
                        let mut sock_outbound =
                            match std::net::TcpStream::connect(SocketAddr::V4(to_addr)) {
                                Ok(s) => s,
                                Err(e) => {
                                    log::error!("fwd-socket: cannot forward port: {}", e);
                                    continue;
                                }
                            };
                        // inbound -> outbound
                        let mut in_read = match sock_inbound.try_clone() {
                            Ok(s) => s,
                            Err(_) => continue,
                        };
                        let mut out_write = match sock_outbound.try_clone() {
                            Ok(s) => s,
                            Err(_) => continue,
                        };
                        thread::Builder::new()
                            .name("fwd-tcp-i2o".into())
                            .spawn(move || {
                                let _ = std::io::copy(&mut in_read, &mut out_write);
                                let _ = out_write.shutdown(std::net::Shutdown::Both);
                                let _ = in_read.shutdown(std::net::Shutdown::Both);
                            })
                            .ok();
                        // outbound -> inbound
                        thread::Builder::new()
                            .name("fwd-tcp-o2i".into())
                            .spawn(move || {
                                let _ = std::io::copy(&mut sock_outbound, &mut sock_inbound);
                                let _ = sock_inbound.shutdown(std::net::Shutdown::Both);
                                let _ = sock_outbound.shutdown(std::net::Shutdown::Both);
                            })
                            .ok();
                    }
                })?;
        }

        thread::sleep(Duration::from_secs(1));
        Ok(())
    }

    fn stop_forward(&mut self) -> io::Result<()> {
        if self.running.load(Ordering::SeqCst) {
            log::debug!("fwd-socket: Stopping socket");
            self.running.store(false, Ordering::SeqCst);
        }
        Ok(())
    }
}

impl Drop for ForwardSocket {
    fn drop(&mut self) {
        let _ = self.stop_forward();
    }
}
