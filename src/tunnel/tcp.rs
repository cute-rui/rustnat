use std::io;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};

use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};
use rand::RngCore;
use sha2::{Digest, Sha256};

use super::TunnelStream;
use crate::relay::protocol::{read_frame, write_frame, Frame};

const DIRECTION_CLIENT: u8 = 0;
const DIRECTION_SERVER: u8 = 1;

fn derive_key(password: &str, challenge: &[u8; 16]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(challenge);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// TCP tunnel — wraps a TcpStream with frame-based protocol, and optional AEAD encryption
pub struct TcpTunnelStream {
    reader: BufReader<tokio::io::ReadHalf<TcpStream>>,
    writer: BufWriter<tokio::io::WriteHalf<TcpStream>>,

    cipher: Option<ChaCha20Poly1305>,
    tx_counter: u64,
    rx_counter: u64,
    tx_direction: u8,
    rx_direction: u8,
}

impl TcpTunnelStream {
    /// Connect to a remote TCP tunnel endpoint
    pub async fn connect(addr: &str, password: Option<String>) -> io::Result<Self> {
        let mut stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;

        let mut cipher = None;
        if let Some(pass) = password {
            let mut challenge = [0u8; 16];
            stream.read_exact(&mut challenge).await?;
            let key = derive_key(&pass, &challenge);
            cipher = Some(ChaCha20Poly1305::new(&key.into()));
        }

        let (read_half, write_half) = tokio::io::split(stream);
        Ok(Self {
            reader: BufReader::new(read_half),
            writer: BufWriter::new(write_half),
            cipher,
            tx_counter: 0,
            rx_counter: 0,
            tx_direction: DIRECTION_CLIENT,
            rx_direction: DIRECTION_SERVER,
        })
    }
}

#[async_trait]
impl TunnelStream for TcpTunnelStream {
    async fn send_frame(&mut self, frame: &Frame) -> io::Result<()> {
        if let Some(cipher) = &self.cipher {
            let mut plain = Vec::with_capacity(1 + frame.payload.len());
            plain.push(frame.frame_type);
            plain.extend_from_slice(&frame.payload);

            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[0] = self.tx_direction;
            nonce_bytes[4..].copy_from_slice(&self.tx_counter.to_be_bytes());
            let nonce = Nonce::from_slice(&nonce_bytes);

            let ciphertext = cipher
                .encrypt(nonce, plain.as_slice())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "encryption failed"))?;

            self.writer.write_u32(ciphertext.len() as u32).await?;
            self.writer.write_all(&ciphertext).await?;
            self.writer.flush().await?;

            self.tx_counter += 1;
            Ok(())
        } else {
            write_frame(&mut self.writer, frame).await
        }
    }

    async fn recv_frame(&mut self) -> io::Result<Frame> {
        if let Some(cipher) = &self.cipher {
            let len = self.reader.read_u32().await? as usize;
            if len > crate::relay::protocol::MAX_FRAME_SIZE + 16 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("encrypted frame too large: {} bytes", len),
                ));
            }

            let mut ciphertext = vec![0u8; len];
            self.reader.read_exact(&mut ciphertext).await?;

            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[0] = self.rx_direction;
            nonce_bytes[4..].copy_from_slice(&self.rx_counter.to_be_bytes());
            let nonce = Nonce::from_slice(&nonce_bytes);

            let plaintext = cipher
                .decrypt(nonce, ciphertext.as_slice())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decryption failed to verify MAC"))?;

            if plaintext.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "empty decrypted frame",
                ));
            }

            self.rx_counter += 1;
            Ok(Frame {
                frame_type: plaintext[0],
                payload: plaintext[1..].to_vec(),
            })
        } else {
            read_frame(&mut self.reader).await
        }
    }

    async fn close(&mut self) -> io::Result<()> {
        self.writer.shutdown().await
    }
}

/// TCP tunnel listener — accepts multiple client connections
pub struct TcpTunnelListener {
    listener: TcpListener,
    password: Option<String>,
}

impl TcpTunnelListener {
    pub async fn bind(addr: &str, password: Option<String>) -> io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        log::info!("TCP tunnel listening on {}", addr);
        if password.is_some() {
            log::info!("TCP tunnel encryption enabled");
        }
        Ok(Self { listener, password })
    }

    /// Accept a new client connection
    pub async fn accept(&self) -> io::Result<(TcpTunnelStream, std::net::SocketAddr)> {
        let (mut stream, addr) = self.listener.accept().await?;
        stream.set_nodelay(true)?;
        log::info!("TCP tunnel: accepted connection from {}", addr);

        let mut cipher = None;
        if let Some(pass) = &self.password {
            let mut challenge = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut challenge);
            stream.write_all(&challenge).await?;

            let key = derive_key(pass, &challenge);
            cipher = Some(ChaCha20Poly1305::new(&key.into()));
        }

        let (read_half, write_half) = tokio::io::split(stream);
        let ts = TcpTunnelStream {
            reader: BufReader::new(read_half),
            writer: BufWriter::new(write_half),
            cipher,
            tx_counter: 0,
            rx_counter: 0,
            tx_direction: DIRECTION_SERVER,
            rx_direction: DIRECTION_CLIENT,
        };
        Ok((ts, addr))
    }
}
