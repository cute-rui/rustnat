use std::io;

use super::Forward;

/// ForwardNone: Does nothing, no forwarding
pub struct ForwardNone;

impl Forward for ForwardNone {
    fn start_forward(
        &mut self,
        _ip: &str,
        _port: u16,
        _to_ip: &str,
        _to_port: u16,
        _udp: bool,
    ) -> io::Result<()> {
        Ok(())
    }

    fn stop_forward(&mut self) -> io::Result<()> {
        Ok(())
    }
}
