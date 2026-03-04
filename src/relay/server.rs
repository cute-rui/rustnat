use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use tokio::net::TcpListener as TokioTcpListener;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::sync::Mutex;

use crate::relay::protocol::*;
use crate::tunnel::TunnelStream;

static NEXT_CONN_ID: AtomicU32 = AtomicU32::new(1);

/// Configuration for the relay server
pub struct RelayServerConfig {
    pub listen_addr: String,
    pub forward_port: u16,
    pub protocol: String, // "tcp" or "udp"
}

/// Run the relay server — accepts tunnel connections and forwards traffic
pub async fn run<S: TunnelStream + 'static>(
    tunnel_stream: S,
    bind_addr: SocketAddr,
) -> io::Result<()> {
    let tunnel = Arc::new(Mutex::new(tunnel_stream));

    // Read Register frame from client
    let register_req = {
        let mut tun = tunnel.lock().await;
        let frame = tun.recv_frame().await?;
        if frame.frame_type != FRAME_TYPE_REGISTER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected Register frame",
            ));
        }
        serde_json::from_slice::<RegisterRequest>(&frame.payload).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("bad register: {}", e))
        })?
    };

    log::info!(
        "Client registered: port={}, protocol={}",
        register_req.port,
        register_req.protocol
    );

    // Bind a listener on the server side to accept external connections
    let external_listener = TokioTcpListener::bind(bind_addr).await?;
    let local_addr = external_listener.local_addr()?;
    log::info!("Relay server listening for external connections on {}", local_addr);

    // Send RegisterAck to client
    {
        let ack = RegisterAck {
            status: "ok".to_string(),
            outer_ip: local_addr.ip().to_string(),
            outer_port: local_addr.port(),
            message: format!("Relay active on {}", local_addr),
        };
        let mut tun = tunnel.lock().await;
        tun.send_frame(&Frame::register_ack(&ack)).await?;
    }

    // Track active connections
    let connections: Arc<Mutex<HashMap<u32, tokio::sync::mpsc::Sender<Vec<u8>>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Spawn task to read frames from tunnel and dispatch to connections
    let tunnel_read = tunnel.clone();
    let conns_read = connections.clone();
    let reader_handle = tokio::spawn(async move {
        loop {
            let frame = {
                let mut tun = tunnel_read.lock().await;
                match tun.recv_frame().await {
                    Ok(f) => f,
                    Err(e) => {
                        log::warn!("Tunnel read error: {}", e);
                        break;
                    }
                }
            };

            match frame.frame_type {
                FRAME_TYPE_DATA => {
                    if let Some(df) = frame.as_data_frame() {
                        let conns = conns_read.lock().await;
                        if let Some(tx) = conns.get(&df.conn_id) {
                            let _ = tx.send(df.data).await;
                        }
                    }
                }
                FRAME_TYPE_CLOSE_CONN => {
                    if let Ok(cc) = serde_json::from_slice::<CloseConnection>(&frame.payload) {
                        let mut conns = conns_read.lock().await;
                        conns.remove(&cc.conn_id);
                        log::debug!("Connection {} closed by client", cc.conn_id);
                    }
                }
                FRAME_TYPE_PING => {
                    let mut tun = tunnel_read.lock().await;
                    let _ = tun.send_frame(&Frame::pong()).await;
                }
                FRAME_TYPE_CLOSE => {
                    log::info!("Client sent Close frame");
                    break;
                }
                _ => {}
            }
        }
    });

    // Accept external connections and forward through tunnel
    let tunnel_write = tunnel.clone();
    let conns_write = connections.clone();
    let accept_handle = tokio::spawn(async move {
        loop {
            let (ext_stream, ext_addr) = match external_listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    log::warn!("Accept error: {}", e);
                    continue;
                }
            };

            let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
            log::info!("External connection {} from {}", conn_id, ext_addr);

            // Notify client of new connection
            {
                let nc = NewConnection {
                    conn_id,
                    remote_addr: ext_addr.to_string(),
                };
                let mut tun = tunnel_write.lock().await;
                if tun.send_frame(&Frame::new_conn(&nc)).await.is_err() {
                    break;
                }
            }

            // Create channel for data back to this connection
            let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
            {
                let mut conns = conns_write.lock().await;
                conns.insert(conn_id, tx);
            }

            // Spawn handler for this external connection
            let tun_for_conn = tunnel_write.clone();
            let conns_cleanup = conns_write.clone();
            tokio::spawn(async move {
                let (mut ext_read, mut ext_write) = ext_stream.into_split();

                // Task: external -> tunnel
                let tun_w = tun_for_conn.clone();
                let ext_to_tun = tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    loop {
                        match tokio::io::AsyncReadExt::read(&mut ext_read, &mut buf).await {
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
                    // Notify close
                    let mut tun = tun_w.lock().await;
                    let _ = tun.send_frame(&Frame::close_conn(conn_id)).await;
                });

                // Task: tunnel -> external
                let tun_to_ext = tokio::spawn(async move {
                    while let Some(data) = rx.recv().await {
                        if tokio::io::AsyncWriteExt::write_all(&mut ext_write, &data)
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                });

                let _ = tokio::join!(ext_to_tun, tun_to_ext);

                // Cleanup
                let mut conns = conns_cleanup.lock().await;
                conns.remove(&conn_id);
                log::debug!("Connection {} handler finished", conn_id);
            });
        }
    });

    tokio::select! {
        _ = reader_handle => log::info!("Tunnel reader finished"),
        _ = accept_handle => log::info!("Accept loop finished"),
    }

    Ok(())
}
