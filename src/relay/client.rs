use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use tokio::net::TcpStream as TokioTcpStream;
use tokio::sync::Mutex;

use crate::relay::protocol::*;
use crate::tunnel::TunnelStream;

/// Run the relay client — establishes tunnel connection, registers, and forwards traffic
pub async fn run<S: TunnelStream + 'static>(
    tunnel_stream: S,
    local_port: u16,
    local_addr: &str,
    protocol: &str,
) -> io::Result<()> {
    let tunnel = Arc::new(Mutex::new(tunnel_stream));

    // Send Register frame
    let req = RegisterRequest {
        port: local_port,
        protocol: protocol.to_string(),
    };
    {
        let mut tun = tunnel.lock().await;
        tun.send_frame(&Frame::register(&req)).await?;
    }

    log::info!("Sent Register request: port={}, protocol={}", local_port, protocol);

    // Read RegisterAck
    let ack = {
        let mut tun = tunnel.lock().await;
        let frame = tun.recv_frame().await?;
        if frame.frame_type != FRAME_TYPE_REGISTER_ACK {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected RegisterAck frame",
            ));
        }
        serde_json::from_slice::<RegisterAck>(&frame.payload).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("bad ack: {}", e))
        })?
    };

    if ack.status != "ok" {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Registration failed: {}", ack.message),
        ));
    }

    log::info!(
        "Relay active! External address: {}:{}",
        ack.outer_ip,
        ack.outer_port
    );
    eprintln!(
        "  Relay mapped: {}:{} -> {}:{}",
        ack.outer_ip, ack.outer_port, local_addr, local_port
    );

    // Track local connections (conn_id -> sender for data to local)
    let connections: Arc<Mutex<HashMap<u32, tokio::sync::mpsc::Sender<Vec<u8>>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let target = format!("{}:{}", local_addr, local_port);

    // Main loop: read frames from tunnel
    loop {
        let frame = {
            let mut tun = tunnel.lock().await;
            match tun.recv_frame().await {
                Ok(f) => f,
                Err(e) => {
                    log::warn!("Tunnel read error: {}", e);
                    break;
                }
            }
        };

        match frame.frame_type {
            FRAME_TYPE_NEW_CONN => {
                let nc: NewConnection = match serde_json::from_slice(&frame.payload) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let conn_id = nc.conn_id;
                log::info!("New connection {} from {}", conn_id, nc.remote_addr);

                // Connect to local service
                let local_stream = match TokioTcpStream::connect(&target).await {
                    Ok(s) => s,
                    Err(e) => {
                        log::warn!(
                            "Failed to connect to local {}:{}: {}",
                            local_addr,
                            local_port,
                            e
                        );
                        let mut tun = tunnel.lock().await;
                        let _ = tun.send_frame(&Frame::close_conn(conn_id)).await;
                        continue;
                    }
                };

                let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
                {
                    let mut conns = connections.lock().await;
                    conns.insert(conn_id, tx);
                }

                let tun_for_conn = tunnel.clone();
                let conns_cleanup = connections.clone();
                tokio::spawn(async move {
                    let (mut local_read, mut local_write) = local_stream.into_split();

                    // local -> tunnel
                    let tun_w = tun_for_conn.clone();
                    let local_to_tun = tokio::spawn(async move {
                        let mut buf = vec![0u8; 4096];
                        loop {
                            match tokio::io::AsyncReadExt::read(&mut local_read, &mut buf).await {
                                Ok(0) => break,
                                Ok(n) => {
                                    let mut tun = tun_w.lock().await;
                                    if tun
                                        .send_frame(&Frame::data(conn_id, &buf[..n]))
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        let mut tun = tun_w.lock().await;
                        let _ = tun.send_frame(&Frame::close_conn(conn_id)).await;
                    });

                    // tunnel -> local
                    let tun_to_local = tokio::spawn(async move {
                        while let Some(data) = rx.recv().await {
                            if tokio::io::AsyncWriteExt::write_all(&mut local_write, &data)
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    });

                    let _ = tokio::join!(local_to_tun, tun_to_local);

                    let mut conns = conns_cleanup.lock().await;
                    conns.remove(&conn_id);
                    log::debug!("Connection {} handler finished", conn_id);
                });
            }

            FRAME_TYPE_DATA => {
                if let Some(df) = frame.as_data_frame() {
                    let conns = connections.lock().await;
                    if let Some(tx) = conns.get(&df.conn_id) {
                        let _ = tx.send(df.data).await;
                    }
                }
            }

            FRAME_TYPE_CLOSE_CONN => {
                if let Ok(cc) = serde_json::from_slice::<CloseConnection>(&frame.payload) {
                    let mut conns = connections.lock().await;
                    conns.remove(&cc.conn_id);
                }
            }

            FRAME_TYPE_PING => {
                let mut tun = tunnel.lock().await;
                let _ = tun.send_frame(&Frame::pong()).await;
            }

            FRAME_TYPE_CLOSE => {
                log::info!("Server sent Close");
                break;
            }

            _ => {}
        }
    }

    Ok(())
}
