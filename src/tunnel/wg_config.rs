use std::io;

use gotatun::x25519::{PublicKey, StaticSecret};

/// Parsed WireGuard configuration
#[derive(Debug, Clone)]
pub struct WgConfig {
    pub private_key: Vec<u8>,     // 32 bytes
    pub listen_port: Option<u16>,
    pub address: Option<String>,  // e.g. "10.0.0.1/24"
    pub peers: Vec<WgPeerConfig>,
}

#[derive(Debug, Clone)]
pub struct WgPeerConfig {
    pub public_key: Vec<u8>,      // 32 bytes
    pub endpoint: Option<String>, // e.g. "1.2.3.4:51820"
    pub allowed_ips: Vec<String>, // e.g. ["0.0.0.0/0"]
    pub persistent_keepalive: Option<u16>,
}

impl WgConfig {
    /// Parse a WireGuard .conf file
    pub fn from_file(path: &str) -> io::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::parse(&content)
    }

    /// Build config from CLI args
    pub fn from_args(
        private_key_b64: &str,
        peer_public_key_b64: &str,
        listen_port: Option<u16>,
        endpoint: Option<&str>,
    ) -> io::Result<Self> {
        let private_key = decode_key(private_key_b64).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, e)
        })?;
        let public_key = decode_key(peer_public_key_b64).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, e)
        })?;

        Ok(Self {
            private_key,
            listen_port,
            address: None,
            peers: vec![WgPeerConfig {
                public_key,
                endpoint: endpoint.map(|s| s.to_string()),
                allowed_ips: vec!["0.0.0.0/0".to_string()],
                persistent_keepalive: Some(25),
            }],
        })
    }

    /// Parse WireGuard .conf format
    fn parse(content: &str) -> io::Result<Self> {
        let mut private_key = Vec::new();
        let mut listen_port = None;
        let mut address = None;
        let mut peers = Vec::new();

        let mut current_peer: Option<WgPeerConfig> = None;
        let mut in_interface = false;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line.eq_ignore_ascii_case("[Interface]") {
                if let Some(peer) = current_peer.take() {
                    peers.push(peer);
                }
                in_interface = true;
                continue;
            }

            if line.eq_ignore_ascii_case("[Peer]") {
                if let Some(peer) = current_peer.take() {
                    peers.push(peer);
                }
                in_interface = false;
                current_peer = Some(WgPeerConfig {
                    public_key: Vec::new(),
                    endpoint: None,
                    allowed_ips: Vec::new(),
                    persistent_keepalive: None,
                });
                continue;
            }

            let parts: Vec<&str> = line.splitn(2, '=').collect();
            if parts.len() != 2 {
                continue;
            }
            let key = parts[0].trim().to_lowercase();
            let value = parts[1].trim();

            if in_interface {
                match key.as_str() {
                    "privatekey" => {
                        private_key = decode_key(value).map_err(|e| {
                            io::Error::new(io::ErrorKind::InvalidData, e)
                        })?;
                    }
                    "listenport" => {
                        listen_port = value.parse().ok();
                    }
                    "address" => {
                        address = Some(value.to_string());
                    }
                    _ => {}
                }
            } else if let Some(ref mut peer) = current_peer {
                match key.as_str() {
                    "publickey" => {
                        peer.public_key = decode_key(value).map_err(|e| {
                            io::Error::new(io::ErrorKind::InvalidData, e)
                        })?;
                    }
                    "endpoint" => {
                        peer.endpoint = Some(value.to_string());
                    }
                    "allowedips" => {
                        peer.allowed_ips = value
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .collect();
                    }
                    "persistentkeepalive" => {
                        peer.persistent_keepalive = value.parse().ok();
                    }
                    _ => {}
                }
            }
        }

        if let Some(peer) = current_peer {
            peers.push(peer);
        }

        if private_key.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing PrivateKey in config",
            ));
        }

        Ok(Self {
            private_key,
            listen_port,
            address,
            peers,
        })
    }

    /// Generate a new WireGuard key pair (private_key, public_key) as base64 strings
    pub fn generate_keypair() -> (String, String) {
        use base64::Engine;
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&secret);
        let priv_b64 = base64::engine::general_purpose::STANDARD.encode(secret.as_bytes());
        let pub_b64 = base64::engine::general_purpose::STANDARD.encode(public.as_bytes());
        (priv_b64, pub_b64)
    }
}

fn decode_key(b64: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| format!("invalid base64 key: {}", e))
}
