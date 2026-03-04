use std::io;
use std::process::{Child, Command};
use std::time::Duration;

use super::Forward;

/// ForwardSocat: uses the socat tool for port forwarding
pub struct ForwardSocat {
    proc: Option<Child>,
    udp_timeout: u32,
    max_children: u32,
}

impl ForwardSocat {
    pub fn new() -> io::Result<Self> {
        let output = Command::new("socat")
            .arg("-V")
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .output()
            .map_err(|e| {
                io::Error::new(io::ErrorKind::NotFound, format!("socat not available: {}", e))
            })?;
        let version_str = String::from_utf8_lossy(&output.stdout).to_string()
            + &String::from_utf8_lossy(&output.stderr);
        let re = regex::Regex::new(r"socat version (\d+)\.(\d+)\.(\d+)").unwrap();
        if let Some(caps) = re.captures(&version_str) {
            let major: u32 = caps[1].parse().unwrap_or(0);
            let minor: u32 = caps[2].parse().unwrap_or(0);
            let patch: u32 = caps[3].parse().unwrap_or(0);
            log::debug!("fwd-socat: Found socat ({}.{}.{})", major, minor, patch);
            if (major, minor, patch) < (1, 7, 2) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "socat >= (1, 7, 2) required",
                ));
            }
        } else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Cannot parse socat version",
            ));
        }
        Ok(Self {
            proc: None,
            udp_timeout: 60,
            max_children: 128,
        })
    }
}

impl Forward for ForwardSocat {
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
        let proto = if udp { "UDP" } else { "TCP" };
        log::debug!(
            "fwd-socat: Starting socat {}:{} forward to {}:{}",
            ip, port, to_ip, to_port
        );

        let mut cmd = Command::new("socat");
        if udp {
            cmd.arg(format!("-T{}", self.udp_timeout));
        }
        cmd.arg(format!(
            "{}4-LISTEN:{},reuseaddr,fork,max-children={}",
            proto, port, self.max_children
        ));
        cmd.arg(format!("{}4:{}:{}", proto, to_ip, to_port));

        let child = cmd.spawn()?;
        self.proc = Some(child);
        std::thread::sleep(Duration::from_secs(1));
        if let Some(ref mut p) = self.proc {
            if let Ok(Some(_)) = p.try_wait() {
                self.proc = None;
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "socat exited too quickly",
                ));
            }
        }
        Ok(())
    }

    fn stop_forward(&mut self) -> io::Result<()> {
        log::debug!("fwd-socat: Stopping socat");
        if let Some(ref mut p) = self.proc {
            let _ = p.kill();
            let _ = p.wait();
        }
        self.proc = None;
        Ok(())
    }
}

impl Drop for ForwardSocat {
    fn drop(&mut self) {
        let _ = self.stop_forward();
    }
}
