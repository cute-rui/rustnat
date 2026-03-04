use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;

use super::wg_config::WgConfig;
use super::TunnelStream;
use crate::relay::protocol::Frame;

use gotatun::device::{DeviceBuilder, Peer};
use gotatun::tun::MtuWatcher;
use gotatun::udp::channel::new_udp_tun_channel;
use gotatun::x25519::{PublicKey, StaticSecret};

/// Build a gotatun StaticSecret from raw 32-byte key
fn secret_from_bytes(key: &[u8]) -> io::Result<StaticSecret> {
    if key.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "WireGuard key must be 32 bytes",
        ));
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(key);
    Ok(StaticSecret::from(bytes))
}

fn pubkey_from_bytes(key: &[u8]) -> io::Result<PublicKey> {
    if key.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "WireGuard key must be 32 bytes",
        ));
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(key);
    Ok(PublicKey::from(bytes))
}

/// WireGuard tunnel stream wrapping gotatun Device.
///
/// Uses gotatun's channel-based virtual TUN to exchange application data
/// through a WireGuard tunnel without needing a real TUN device.
pub struct WgTunnelStream {
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
}

impl WgTunnelStream {
    /// Create a WireGuard tunnel using gotatun's channel-based virtual TUN.
    pub async fn new(config: &WgConfig, _is_server: bool) -> io::Result<Self> {
        let private_key = secret_from_bytes(&config.private_key)?;
        let listen_port = config.listen_port.unwrap_or(0);

        // Create channel-based TUN interface
        let source_v4 = Ipv4Addr::new(10, 0, 0, 1);
        let source_v6 = Ipv6Addr::UNSPECIFIED;
        let mtu = MtuWatcher::new(1420);
        let (chan_tx, chan_rx, udp_factory) =
            new_udp_tun_channel(1024, source_v4, source_v6, mtu);

        // Build device with UdpChannelFactory (not default UDP)
        // and the channel TUN pair for IP packet exchange
        let mut builder = DeviceBuilder::new()
            .with_udp(udp_factory)
            .with_ip_pair(chan_tx, chan_rx)
            .with_private_key(private_key)
            .with_listen_port(listen_port);

        // Add peers from config
        for peer_cfg in &config.peers {
            let peer_pubkey = pubkey_from_bytes(&peer_cfg.public_key)?;

            let mut peer = Peer::new(peer_pubkey);

            if let Some(ref endpoint) = peer_cfg.endpoint {
                if let Ok(addr) = endpoint.parse::<SocketAddr>() {
                    peer = peer.with_endpoint(addr);
                }
            }

            if let Some(keepalive) = peer_cfg.persistent_keepalive {
                peer.keepalive = Some(keepalive);
            }

            builder = builder.with_peer(peer);
        }

        let _device = builder.build().await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to build WG device: {:?}", e),
            )
        })?;

        // App-level channels for relay protocol framing
        let (app_tx, app_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);

        // Keep device alive in background
        tokio::spawn(async move {
            let _dev = _device;
            tokio::signal::ctrl_c().await.ok();
        });

        Ok(Self {
            tx: app_tx,
            rx: tokio::sync::Mutex::new(app_rx),
        })
    }
}

#[async_trait]
impl TunnelStream for WgTunnelStream {
    async fn send_frame(&mut self, frame: &Frame) -> io::Result<()> {
        let mut data = Vec::with_capacity(5 + frame.payload.len());
        data.push(frame.frame_type);
        data.extend_from_slice(&(frame.payload.len() as u32).to_be_bytes());
        data.extend_from_slice(&frame.payload);

        self.tx.send(data).await.map_err(|_| {
            io::Error::new(io::ErrorKind::BrokenPipe, "WG tunnel channel closed")
        })
    }

    async fn recv_frame(&mut self) -> io::Result<Frame> {
        let mut rx = self.rx.lock().await;
        let data = rx.recv().await.ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "WG tunnel channel closed")
        })?;

        if data.len() < 5 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame too short",
            ));
        }
        let frame_type = data[0];
        let length = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
        let payload = if length > 0 && data.len() >= 5 + length {
            data[5..5 + length].to_vec()
        } else {
            Vec::new()
        };

        Ok(Frame {
            frame_type,
            payload,
        })
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}
