pub mod none;
pub mod test_server;
pub mod socket_forward;
pub mod iptables;
pub mod nftables;
pub mod gost;
pub mod socat;

use std::io;

/// Trait for port forwarding methods
pub trait Forward: Send {
    fn start_forward(
        &mut self,
        ip: &str,
        port: u16,
        to_ip: &str,
        to_port: u16,
        udp: bool,
    ) -> io::Result<()>;

    fn stop_forward(&mut self) -> io::Result<()>;
}

/// Create a forwarder by method name
pub fn create_forwarder(method: &str) -> io::Result<Box<dyn Forward>> {
    match method {
        "none" => Ok(Box::new(none::ForwardNone)),
        "test" => Ok(Box::new(test_server::ForwardTestServer::new())),
        "socket" => Ok(Box::new(socket_forward::ForwardSocket::new())),
        "iptables" => Ok(Box::new(iptables::ForwardIptables::new(false, false)?)),
        "sudo-iptables" => Ok(Box::new(iptables::ForwardIptables::new(false, true)?)),
        "iptables-snat" => Ok(Box::new(iptables::ForwardIptables::new(true, false)?)),
        "sudo-iptables-snat" => Ok(Box::new(iptables::ForwardIptables::new(true, true)?)),
        "nftables" => Ok(Box::new(nftables::ForwardNftables::new(false, false)?)),
        "sudo-nftables" => Ok(Box::new(nftables::ForwardNftables::new(false, true)?)),
        "nftables-snat" => Ok(Box::new(nftables::ForwardNftables::new(true, false)?)),
        "sudo-nftables-snat" => Ok(Box::new(nftables::ForwardNftables::new(true, true)?)),
        "socat" => Ok(Box::new(socat::ForwardSocat::new()?)),
        "gost" => Ok(Box::new(gost::ForwardGost::new()?)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Unknown method name: {}", method),
        )),
    }
}
