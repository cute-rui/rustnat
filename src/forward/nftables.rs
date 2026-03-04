use std::io;
use std::process::Command;

use super::Forward;

/// ForwardNftables: uses nftables DNAT/SNAT rules for port forwarding
pub struct ForwardNftables {
    handle: i64,
    handle_snat: i64,
    nftables_cmd: Vec<String>,
    snat: bool,
}

impl ForwardNftables {
    pub fn new(snat: bool, sudo: bool) -> io::Result<Self> {
        let cmd = if sudo {
            vec!["sudo".into(), "-n".into(), "nft".into()]
        } else {
            vec!["nft".into()]
        };

        // Check nftables availability
        let output = Command::new(&cmd[0])
            .args(&cmd[1..])
            .arg("--version")
            .output()
            .map_err(|e| {
                io::Error::new(io::ErrorKind::NotFound, format!("nftables not available: {}", e))
            })?;
        let version_str = String::from_utf8_lossy(&output.stdout);
        let re = regex::Regex::new(r"nftables v(\d+)\.(\d+)\.(\d+)").unwrap();
        if let Some(caps) = re.captures(&version_str) {
            let major: u32 = caps[1].parse().unwrap_or(0);
            let minor: u32 = caps[2].parse().unwrap_or(0);
            let patch: u32 = caps[3].parse().unwrap_or(0);
            log::debug!("fwd-nftables: Found nftables ({}.{}.{})", major, minor, patch);
            if (major, minor, patch) < (0, 9, 6) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "nftables >= (0, 9, 6) required",
                ));
            }
        } else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Cannot parse nftables version",
            ));
        }

        let mut inst = Self {
            handle: -1,
            handle_snat: -1,
            nftables_cmd: cmd,
            snat,
        };
        inst.nftables_init()?;
        Ok(inst)
    }

    fn run_nft(&self, args: &[&str]) -> io::Result<Vec<u8>> {
        let output = Command::new(&self.nftables_cmd[0])
            .args(&self.nftables_cmd[1..])
            .args(args)
            .output()?;
        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "nftables command failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        Ok(output.stdout)
    }

    fn nftables_init(&self) -> io::Result<()> {
        // Check if natter table exists
        let res = Command::new(&self.nftables_cmd[0])
            .args(&self.nftables_cmd[1..])
            .args(["list", "table", "ip", "natter"])
            .stderr(std::process::Stdio::null())
            .output()?;
        if res.status.success() {
            return Ok(());
        }

        log::debug!("fwd-nftables: Creating Natter table");
        let initial_rules = r#"
            table ip natter {
                chain natter_dnat { }
                chain natter_snat { }
                chain prerouting {
                    type nat hook prerouting priority -105; policy accept;
                    jump natter_dnat;
                }
                chain output {
                    type nat hook output priority -105; policy accept;
                    jump natter_dnat;
                }
                chain postrouting {
                    type nat hook postrouting priority 95; policy accept;
                    jump natter_snat;
                }
                chain input {
                    type nat hook input priority 95; policy accept;
                    jump natter_snat;
                }
            }
        "#;
        self.run_nft(&[initial_rules])?;
        Ok(())
    }

    fn nftables_clean(&mut self) {
        log::debug!("fwd-nftables: Cleaning up Natter rules");
        if self.handle > 0 {
            let cmd = format!(
                "delete rule ip natter natter_dnat handle {}",
                self.handle
            );
            if let Err(e) = self.run_nft(&[&cmd]) {
                log::error!("fwd-nftables: Failed to clean dnat rule: {}", e);
            }
            self.handle = -1;
        }
        if self.handle_snat > 0 {
            let cmd = format!(
                "delete rule ip natter natter_snat handle {}",
                self.handle_snat
            );
            if let Err(e) = self.run_nft(&[&cmd]) {
                log::error!("fwd-nftables: Failed to clean snat rule: {}", e);
            }
            self.handle_snat = -1;
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
                log::warn!("fwd-nftables: '{}' not found", fpath);
            }
        }
        Ok(())
    }
}

impl Forward for ForwardNftables {
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

        log::debug!(
            "fwd-nftables: Adding rule {}:{} forward to {}:{}",
            ip, port, to_ip, to_port
        );

        let rule_cmd = format!(
            "insert rule ip natter natter_dnat ip daddr {} {} dport {} dnat to {}:{}",
            ip, proto, port, to_ip, to_port
        );
        let output = self.run_nft(&["--echo", "--handle", &rule_cmd])?;
        let output_str = String::from_utf8_lossy(&output);
        let re = regex::Regex::new(r"# handle (\d+)").unwrap();
        if let Some(caps) = re.captures(&output_str) {
            self.handle = caps[1].parse().unwrap_or(-1);
        } else {
            self.nftables_clean();
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Unknown nftables handle",
            ));
        }

        if self.snat {
            let snat_cmd = format!(
                "insert rule ip natter natter_snat ip daddr {} {} dport {} snat to {}",
                to_ip, proto, to_port, ip
            );
            let output = self.run_nft(&["--echo", "--handle", &snat_cmd])?;
            let output_str = String::from_utf8_lossy(&output);
            if let Some(caps) = re.captures(&output_str) {
                self.handle_snat = caps[1].parse().unwrap_or(-1);
            } else {
                self.nftables_clean();
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Unknown nftables handle",
                ));
            }
        }
        Ok(())
    }

    fn stop_forward(&mut self) -> io::Result<()> {
        self.nftables_clean();
        Ok(())
    }
}

impl Drop for ForwardNftables {
    fn drop(&mut self) {
        let _ = self.stop_forward();
    }
}
