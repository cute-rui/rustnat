use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// --- Frame Format ---
// [u8 frame_type][u32 big-endian length][payload]

pub const FRAME_TYPE_REGISTER: u8 = 0x01;
pub const FRAME_TYPE_REGISTER_ACK: u8 = 0x02;
pub const FRAME_TYPE_DATA: u8 = 0x03;
pub const FRAME_TYPE_PING: u8 = 0x04;
pub const FRAME_TYPE_PONG: u8 = 0x05;
pub const FRAME_TYPE_CLOSE: u8 = 0x06;
pub const FRAME_TYPE_NEW_CONN: u8 = 0x07;
pub const FRAME_TYPE_CLOSE_CONN: u8 = 0x08;

pub const MAX_FRAME_SIZE: usize = 65536;

#[derive(Debug, Clone)]
pub struct Frame {
    pub frame_type: u8,
    pub payload: Vec<u8>,
}

/// Client registration request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub port: u16,
    pub protocol: String, // "tcp" or "udp"
}

/// Server registration acknowledgement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterAck {
    pub status: String,     // "ok" or "error"
    pub outer_ip: String,
    pub outer_port: u16,
    pub message: String,
}

/// New connection notification (server -> client)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewConnection {
    pub conn_id: u32,
    pub remote_addr: String,
}

/// Data frame with connection ID for multiplexing
#[derive(Debug, Clone)]
pub struct DataFrame {
    pub conn_id: u32,
    pub data: Vec<u8>,
}

/// Close connection notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloseConnection {
    pub conn_id: u32,
}

impl Frame {
    pub fn new(frame_type: u8, payload: Vec<u8>) -> Self {
        Self {
            frame_type,
            payload,
        }
    }

    pub fn register(req: &RegisterRequest) -> Self {
        Self::new(
            FRAME_TYPE_REGISTER,
            serde_json::to_vec(req).unwrap_or_default(),
        )
    }

    pub fn register_ack(ack: &RegisterAck) -> Self {
        Self::new(
            FRAME_TYPE_REGISTER_ACK,
            serde_json::to_vec(ack).unwrap_or_default(),
        )
    }

    pub fn data(conn_id: u32, data: &[u8]) -> Self {
        let mut payload = Vec::with_capacity(4 + data.len());
        payload.extend_from_slice(&conn_id.to_be_bytes());
        payload.extend_from_slice(data);
        Self::new(FRAME_TYPE_DATA, payload)
    }

    pub fn new_conn(nc: &NewConnection) -> Self {
        Self::new(
            FRAME_TYPE_NEW_CONN,
            serde_json::to_vec(nc).unwrap_or_default(),
        )
    }

    pub fn close_conn(conn_id: u32) -> Self {
        let cc = CloseConnection { conn_id };
        Self::new(
            FRAME_TYPE_CLOSE_CONN,
            serde_json::to_vec(&cc).unwrap_or_default(),
        )
    }

    pub fn ping() -> Self {
        Self::new(FRAME_TYPE_PING, Vec::new())
    }

    pub fn pong() -> Self {
        Self::new(FRAME_TYPE_PONG, Vec::new())
    }

    pub fn close() -> Self {
        Self::new(FRAME_TYPE_CLOSE, Vec::new())
    }

    /// Parse payload as DataFrame (conn_id + data)
    pub fn as_data_frame(&self) -> Option<DataFrame> {
        if self.payload.len() < 4 {
            return None;
        }
        let conn_id = u32::from_be_bytes([
            self.payload[0],
            self.payload[1],
            self.payload[2],
            self.payload[3],
        ]);
        let data = self.payload[4..].to_vec();
        Some(DataFrame { conn_id, data })
    }
}

/// Write a frame to an async writer
pub async fn write_frame<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    frame: &Frame,
) -> io::Result<()> {
    let len = frame.payload.len() as u32;
    writer.write_u8(frame.frame_type).await?;
    writer.write_u32(len).await?;
    if !frame.payload.is_empty() {
        writer.write_all(&frame.payload).await?;
    }
    writer.flush().await?;
    Ok(())
}

/// Read a frame from an async reader
pub async fn read_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> io::Result<Frame> {
    let frame_type = reader.read_u8().await?;
    let length = reader.read_u32().await? as usize;

    if length > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame too large: {} bytes", length),
        ));
    }

    let mut payload = vec![0u8; length];
    if length > 0 {
        reader.read_exact(&mut payload).await?;
    }

    Ok(Frame {
        frame_type,
        payload,
    })
}
