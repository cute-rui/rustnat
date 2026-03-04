use std::io;
use std::process::Command;

use super::Forward;
use crate::utils::addr_to_uri;

/// ForwardIptables: uses iptables DNAT/SNAT rules for port forwarding
pub struct ForwardIptables {
    rules: Vec<Vec<String>>,
    iptables_cmd: Vec<String>,
    snat: bool,
}

impl ForwardIptables {
    pub fn new(snat: bool, sudo: bool) -> io::Result<Self> {
        let mut cmd = if sudo {
            vec!["sudo".into(), "-n".into(), "iptables".into()]
        } else {
            vec!["iptables".into()]
        };

        // Check iptables availability
        let output = Command::new(&cmd[0])
            .args(&cmd[1..])
            .arg("--version")
            .output()
            .map_err(|e| {
                io::Error::new(io::ErrorKind::NotFound, format!("iptables not available: {}", e))
            })?;
        let version_str = String::from_utf8_lossy(&output.stdout);
        let re = regex::Regex::new(r"iptables v(\d+)\.(\d+)\.(\d+)").unwrap();
        if let Some(caps) = re.captures(&version_str) {
            let major: u32 = caps[1].parse().unwrap_or(0);
            let minor: u32 = caps[2].parse().unwrap_or(0);
            let patch: u32 = caps[3].parse().unwrap_or(0);
            log::debug!("fwd-iptables: Found iptables ({}.{}.{})", major, minor, patch);
            if (major, minor, patch) < (1, 4, 1) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "iptables >= (1, 4, 1) required",
                ));
            }
            // Add -w flag for versions >= 1.4.20
            if (major, minor, patch) >= (1, 4, 20) {
                cmd.push("-w".into());
            }
        } else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Cannot parse iptables version",
            ));
        }

        // Check nat table
        let status = Command::new(&cmd[0])
            .args(&cmd[1..])
            .args(["-t", "nat", "--list-rules"])
            .output()?;
        if !status.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Cannot access iptables nat table",
            ));
        }

        let mut inst = Self {
            rules: Vec::new(),
            iptables_cmd: cmd,
            snat,
        };
        inst.iptables_init()?;
        Ok(inst)
    }

    fn run_ipt(&self, args: &[&str]) -> io::Result<Vec<u8>> {
        let output = Command::new(&self.iptables_cmd[0])
            .args(&self.iptables_cmd[1..])
            .args(args)
            .output()?;
        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "iptables command failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        Ok(output.stdout)
    }

    fn iptables_init(&self) -> io::Result<()> {
        // Check if NATTER chain exists
        let res = Command::new(&self.iptables_cmd[0])
            .args(&self.iptables_cmd[1..])
            .args(["-t", "nat", "--list-rules", "NATTER"])
            .stderr(std::process::Stdio::null())
            .output()?;
        if res.status.success() {
            return Ok(());
        }
        log::debug!("fwd-iptables: Creating Natter chain");
        self.run_ipt(&["-t", "nat", "-N", "NATTER"])?;
        self.run_ipt(&["-t", "nat", "-I", "PREROUTING", "-j", "NATTER"])?;
        self.run_ipt(&["-t", "nat", "-I", "OUTPUT", "-j", "NATTER"])?;
        self.run_ipt(&["-t", "nat", "-N", "NATTER_SNAT"])?;
        self.run_ipt(&["-t", "nat", "-I", "POSTROUTING", "-j", "NATTER_SNAT"])?;
        self.run_ipt(&["-t", "nat", "-I", "INPUT", "-j", "NATTER_SNAT"])?;
        Ok(())
    }

    fn iptables_clean(&mut self) {
        while let Some(rule) = self.rules.pop() {
            let rule_rm: Vec<String> = rule
                .iter()
                .map(|a| {
                    if a == "-I" || a == "-A" {
                        "-D".to_string()
                    } else {
                        a.clone()
                    }
                })
                .collect();
            let args: Vec<&str> = rule_rm.iter().map(|s| s.as_str()).collect();
            if let Err(e) = self.run_ipt(&args) {
                log::error!("fwd-iptables: Failed to clean rule: {}", e);
            }
        }
    }

    fn check_sys_forward(&self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let fpath = "/proc/sys/net/ipv4/ip_forward";
            if std::path::Path::new(fpath).exists() {
                let content = std::fs::read_to_string(fpath)?;
                if content.trim() != "1" {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "IP forwarding is not allowed. Please do `sysctl net.ipv4.ip_forward=1`",
                    ));
                }
            } else {
                log::warn!("fwd-iptables: '{}' not found", fpath);
            }
        }
        Ok(())
    }
}

impl Forward for ForwardIptables {
    fn start_forward(
        &mut self,
        ip: &str,
        port: u16,
        to_ip: &str,
        to_port: u16,
        udp: bool,
    ) -> io::Result<()> {
        if ip != to_ip {
            self.check_sys_forward()?;
        }
        if ip == to_ip && port == to_port {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Cannot forward to the same address {}:{}", ip, port),
            ));
        }
        let proto = if udp { "udp" } else { "tcp" };
        let port_s = format!("{}", port);
        let dest = format!("{}:{}", to_ip, to_port);
        let to_port_s = format!("{}", to_port);

        log::debug!(
            "fwd-iptables: Adding rule {}:{} forward to {}",
            ip, port, dest
        );

        let rule: Vec<String> = vec![
            "-t", "nat", "-I", "NATTER", "-p", proto,
            "--dst", ip, "--dport", &port_s,
            "-j", "DNAT", "--to-destination", &dest,
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect();
        let args: Vec<&str> = rule.iter().map(|s| s.as_str()).collect();
        if let Err(e) = self.run_ipt(&args) {
            self.iptables_clean();
            return Err(e);
        }
        self.rules.push(rule);

        if self.snat {
            let rule: Vec<String> = vec![
                "-t", "nat", "-I", "NATTER_SNAT", "-p", proto,
                "--dst", to_ip, "--dport", &to_port_s,
                "-j", "SNAT", "--to-source", ip,
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect();
            let args: Vec<&str> = rule.iter().map(|s| s.as_str()).collect();
            if let Err(e) = self.run_ipt(&args) {
                self.iptables_clean();
                return Err(e);
            }
            self.rules.push(rule);
        }
        Ok(())
    }

    fn stop_forward(&mut self) -> io::Result<()> {
        log::debug!("fwd-iptables: Cleaning up Natter rules");
        self.iptables_clean();
        Ok(())
    }
}

impl Drop for ForwardIptables {
    fn drop(&mut self) {
        let _ = self.stop_forward();
    }
}
