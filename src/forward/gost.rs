use std::io;
use std::process::{Child, Command};
use std::time::Duration;

use super::Forward;

/// ForwardGost: uses the gost proxy tool for port forwarding
pub struct ForwardGost {
    proc: Option<Child>,
    udp_timeout: u32,
}

impl ForwardGost {
    pub fn new() -> io::Result<Self> {
        let output = Command::new("gost")
            .arg("-V")
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .output()
            .map_err(|e| {
                io::Error::new(io::ErrorKind::NotFound, format!("gost not available: {}", e))
            })?;
        let version_str = String::from_utf8_lossy(&output.stdout).to_string()
            + &String::from_utf8_lossy(&output.stderr);
        let re = regex::Regex::new(r"gost v?(\d+)\.(\d+)").unwrap();
        if let Some(caps) = re.captures(&version_str) {
            let major: u32 = caps[1].parse().unwrap_or(0);
            let minor: u32 = caps[2].parse().unwrap_or(0);
            log::debug!("fwd-gost: Found gost ({}.{})", major, minor);
            if (major, minor) < (2, 3) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "gost >= (2, 3) required",
                ));
            }
        } else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Cannot parse gost version",
            ));
        }
        Ok(Self {
            proc: None,
            udp_timeout: 60,
        })
    }
}

impl Forward for ForwardGost {
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
        let proto = if udp { "udp" } else { "tcp" };
        log::debug!(
            "fwd-gost: Starting gost {}:{} forward to {}:{}",
            ip, port, to_ip, to_port
        );
        let mut gost_arg = format!("-L={}://:{}/{}:{}", proto, port, to_ip, to_port);
        if udp {
            gost_arg.push_str(&format!("?ttl={}s", self.udp_timeout));
        }
        let child = Command::new("gost").arg(&gost_arg).spawn()?;
        self.proc = Some(child);
        std::thread::sleep(Duration::from_secs(1));
        if let Some(ref mut p) = self.proc {
            if let Ok(Some(_)) = p.try_wait() {
                self.proc = None;
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "gost exited too quickly",
                ));
            }
        }
        Ok(())
    }

    fn stop_forward(&mut self) -> io::Result<()> {
        log::debug!("fwd-gost: Stopping gost");
        if let Some(ref mut p) = self.proc {
            let _ = p.kill();
            let _ = p.wait();
        }
        self.proc = None;
        Ok(())
    }
}

impl Drop for ForwardGost {
    fn drop(&mut self) {
        let _ = self.stop_forward();
    }
}
