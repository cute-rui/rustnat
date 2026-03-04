pub mod tcp;
pub mod wg_config;
pub mod wireguard;

use async_trait::async_trait;
use std::io;

use crate::relay::protocol::Frame;

/// Abstract tunnel stream for sending/receiving framed data.
/// Both TCP and WireGuard tunnel backends implement this trait.
#[async_trait]
pub trait TunnelStream: Send + Sync {
    /// Send a complete frame through the tunnel
    async fn send_frame(&mut self, frame: &Frame) -> io::Result<()>;

    /// Receive a complete frame from the tunnel
    async fn recv_frame(&mut self) -> io::Result<Frame>;

    /// Close the tunnel
    async fn close(&mut self) -> io::Result<()>;
}
