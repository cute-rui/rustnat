mod checker;
mod forward;
mod keepalive;
mod logger;
mod port_test;
mod relay;
mod stun;
mod tunnel;
mod upnp;
mod utils;

use std::net::{Ipv4Addr, SocketAddrV4};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;

use forward::Forward;
use keepalive::KeepAlive;
use logger::NatterLogger;
use port_test::PortTest;
use stun::StunClient;
use upnp::UPnPClient;
use utils::{addr_to_str, addr_to_uri, parse_host_port, validate_ip};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Expose your port behind full-cone NAT to the Internet.
#[derive(Parser)]
#[command(name = "rustnat", version = VERSION, about, disable_help_flag = true)]
struct Args {
    /// Show this help message and exit
    #[arg(long = "help", action = clap::ArgAction::Help)]
    _help: Option<bool>,

    /// Verbose mode, printing debug messages
    #[arg(short = 'v')]
    verbose: bool,

    /// Run natter-check and exit
    #[arg(long = "check")]
    check: bool,

    /// Exit when mapped address is changed
    #[arg(short = 'q')]
    quit_on_change: bool,

    /// UDP mode
    #[arg(short = 'u')]
    udp: bool,

    /// Enable UPnP/IGD discovery
    #[arg(short = 'U')]
    upnp: bool,

    /// Seconds between each keep-alive
    #[arg(short = 'k', default_value = "15")]
    interval: u32,

    /// Hostname or address to STUN server (can be specified multiple times)
    #[arg(short = 's', action = clap::ArgAction::Append)]
    stun_servers: Vec<String>,

    /// Hostname or address to keep-alive server
    #[arg(short = 'h')]
    keepalive_server: Option<String>,

    /// Script path for notifying mapped address
    #[arg(short = 'e')]
    notify_script: Option<String>,

    /// Network interface name or IP to bind
    #[arg(short = 'i', default_value = "0.0.0.0")]
    bind_interface: String,

    /// Port number to bind
    #[arg(short = 'b', default_value = "0")]
    bind_port: u16,

    /// Forward method (iptables, nftables, socat, gost, socket, etc.)
    #[arg(short = 'm')]
    method: Option<String>,

    /// IP address of forward target
    #[arg(short = 't', default_value = "0.0.0.0")]
    target_ip: String,

    /// Port number of forward target
    #[arg(short = 'p', default_value = "0")]
    target_port: u16,

    /// Keep retrying until the port of forward target is open
    #[arg(short = 'r')]
    keep_retry: bool,

    // --- Relay tunnel options ---

    /// Run as relay server (accept tunnel connections)
    #[arg(long = "relay-server")]
    relay_server: bool,

    /// Run as relay client (connect to relay server)
    #[arg(long = "relay-client")]
    relay_client: bool,

    /// Relay server address (listen for server, connect for client)
    #[arg(long = "relay-addr")]
    relay_addr: Option<String>,

    /// Relay tunnel mode: "tcp" or "wg"
    #[arg(long = "relay-mode", default_value = "tcp")]
    relay_mode: String,

    /// Password for TCP relay auth and encryption
    #[arg(long = "tcp-password")]
    tcp_password: Option<String>,

    /// WireGuard private key (base64)
    #[arg(long = "wg-key")]
    wg_private_key: Option<String>,

    /// WireGuard peer public key (base64)
    #[arg(long = "wg-peer-key")]
    wg_peer_public_key: Option<String>,

    /// WireGuard config file path (.conf)
    #[arg(long = "wg-conf")]
    wg_config: Option<String>,
}

enum NatterAction {
    Retry,
    Exit,
}

fn natter_main(args: &Args, show_title: bool) -> Result<(), NatterAction> {
    let udp_mode = args.udp;
    let interval = args.interval;
    let exit_when_changed = args.quit_on_change;
    let keep_retry = args.keep_retry;

    // Determine bind IP vs interface
    let (bind_ip, bind_interface) = if validate_ip(&args.bind_interface).is_ok() {
        (
            args.bind_interface
                .parse::<Ipv4Addr>()
                .unwrap_or(Ipv4Addr::UNSPECIFIED),
            None,
        )
    } else {
        (Ipv4Addr::UNSPECIFIED, Some(args.bind_interface.clone()))
    };
    let mut bind_port = args.bind_port;

    let to_ip_parsed = args
        .target_ip
        .parse::<Ipv4Addr>()
        .unwrap_or(Ipv4Addr::UNSPECIFIED);
    let mut to_ip = to_ip_parsed;
    let mut to_port = args.target_port;

    // Build STUN server list
    let stun_srv_list: Vec<(String, u16)> = if !args.stun_servers.is_empty() {
        args.stun_servers
            .iter()
            .map(|s| parse_host_port(s, 3478))
            .collect()
    } else {
        let mut list = vec![
            "fwa.lifesizecloud.com",
            "global.turn.twilio.com",
            "turn.cloudflare.com",
            "stun.nextcloud.com",
            "stun.freeswitch.org",
            "stun.voip.blackberry.com",
            "stun.sipnet.com",
            "stun.radiojar.com",
            "stun.sonetel.com",
            "stun.telnyx.com",
        ]
        .into_iter()
        .map(|s| (s.to_string(), 3478u16))
        .collect::<Vec<_>>();

        if !udp_mode {
            list.push(("turn.cloud-rtc.com".to_string(), 80));
        } else {
            let mut udp_list = vec![
                ("stun.miwifi.com".to_string(), 3478u16),
                ("stun.chat.bilibili.com".to_string(), 3478),
                ("stun.hitv.com".to_string(), 3478),
                ("stun.cdnbye.com".to_string(), 3478),
                ("stun.douyucdn.cn".to_string(), 18000),
            ];
            udp_list.extend(list);
            list = udp_list;
        }
        list
    };

    // Keep-alive server
    let (keepalive_host, keepalive_port) = if let Some(ref srv) = args.keepalive_server {
        if udp_mode {
            parse_host_port(srv, 53)
        } else {
            parse_host_port(srv, 80)
        }
    } else if udp_mode {
        ("119.29.29.29".to_string(), 53)
    } else {
        ("www.baidu.com".to_string(), 80)
    };

    // Determine forward method
    let method = if let Some(ref m) = args.method {
        m.clone()
    } else if to_ip == Ipv4Addr::UNSPECIFIED
        && to_port == 0
        && bind_ip == Ipv4Addr::UNSPECIFIED
        && bind_port == 0
        && bind_interface.is_none()
    {
        "test".to_string()
    } else if to_ip == Ipv4Addr::UNSPECIFIED && to_port == 0 {
        "none".to_string()
    } else {
        "socket".to_string()
    };

    let is_test = method == "test";
    let is_none = method == "none";

    //
    // Natter
    //
    if show_title {
        log::info!("Natter v{} (Rust)", VERSION);
        if std::env::args().count() == 1 {
            log::info!("Tips: Use `--help` to see help messages");
        }
    }

    // Create forwarder
    let mut forwarder = forward::create_forwarder(&method).map_err(|e| {
        log::error!("Failed to create forwarder '{}': {}", method, e);
        NatterAction::Exit
    })?;

    let port_test = PortTest::new();

    // STUN
    let mut stun_client = StunClient::new(
        stun_srv_list,
        bind_ip,
        bind_port,
        bind_interface.clone(),
        udp_mode,
    )
    .map_err(|e| {
        log::error!("{}", e);
        NatterAction::Exit
    })?;

    let (natter_addr, outer_addr) = stun_client.get_mapping().map_err(|e| {
        log::error!("STUN mapping failed: {}", e);
        NatterAction::Exit
    })?;
    let mut bind_ip_actual = *natter_addr.ip();
    bind_port = natter_addr.port();

    // Keep alive
    let mut keep_alive = KeepAlive::new(
        keepalive_host,
        keepalive_port,
        bind_ip_actual,
        bind_port,
        bind_interface.clone(),
        udp_mode,
    );
    keep_alive.keep_alive().map_err(|e| {
        log::error!("Keep-alive failed: {}", e);
        NatterAction::Retry
    })?;

    // Get mapping again after keep-alive connection
    let outer_addr_prev = outer_addr;
    let (natter_addr, mut outer_addr) = stun_client.get_mapping().map_err(|e| {
        log::error!("STUN re-mapping failed: {}", e);
        NatterAction::Retry
    })?;
    if outer_addr != outer_addr_prev {
        log::warn!("Network is unstable, or not full cone");
    }

    // Set actual target IP
    if to_ip == Ipv4Addr::LOCALHOST || to_ip == Ipv4Addr::UNSPECIFIED {
        to_ip = *natter_addr.ip();
    }
    if to_port == 0 {
        to_port = outer_addr.port();
    }

    // For test/none modes, target = natter
    if is_test || is_none {
        to_ip = *natter_addr.ip();
        to_port = natter_addr.port();
    }

    let to_addr = SocketAddrV4::new(to_ip, to_port);

    // Start forwarding
    forwarder
        .start_forward(
            &natter_addr.ip().to_string(),
            natter_addr.port(),
            &to_addr.ip().to_string(),
            to_addr.port(),
            udp_mode,
        )
        .map_err(|e| {
            log::error!("Forward start failed: {}", e);
            NatterAction::Exit
        })?;

    // UPnP
    let mut upnp_ready = false;
    let mut upnp_client: Option<UPnPClient> = None;

    if args.upnp {
        let mut u = UPnPClient::new(Some(*natter_addr.ip()), bind_interface.clone());
        log::info!("");
        log::info!("Scanning UPnP Devices...");
        match u.discover_router() {
            Ok(Some(router)) => {
                log::info!("[UPnP] Found router {}", router.ipaddr);
                match u.forward(
                    "",
                    bind_port,
                    &bind_ip_actual.to_string(),
                    bind_port,
                    udp_mode,
                    interval * 3,
                ) {
                    Ok(_) => upnp_ready = true,
                    Err(e) => log::error!("upnp: failed to forward port: {}", e),
                }
            }
            Ok(None) => log::warn!("upnp: No router found"),
            Err(e) => log::error!("upnp: {}", e),
        }
        upnp_client = Some(u);
    }

    // Display route information
    log::info!("");
    let mut route_str = String::new();
    if !is_test && !is_none {
        route_str.push_str(&format!(
            "{} <--{}--> ",
            addr_to_uri(&to_addr, udp_mode),
            method
        ));
    }
    route_str.push_str(&format!(
        "{} <--Natter--> {}",
        addr_to_uri(&natter_addr, udp_mode),
        addr_to_uri(&outer_addr, udp_mode)
    ));
    log::info!("{}", route_str);
    log::info!("");

    // Test mode notice
    if is_test {
        log::info!("Test mode in on.");
        log::info!(
            "Please check [ {}://{} ]",
            if udp_mode { "udp" } else { "http" },
            addr_to_str(&outer_addr)
        );
        log::info!("");
    }

    // Call notification script
    if let Some(ref script) = args.notify_script {
        let protocol = if udp_mode { "udp" } else { "tcp" };
        let (inner_ip, inner_port) = if !is_none && !is_test {
            (to_addr.ip().to_string(), to_addr.port().to_string())
        } else {
            (
                natter_addr.ip().to_string(),
                natter_addr.port().to_string(),
            )
        };
        log::info!("Calling script: {}", script);
        let _ = std::process::Command::new(script)
            .args([
                protocol,
                &inner_ip,
                &inner_port,
                &outer_addr.ip().to_string(),
                &outer_addr.port().to_string(),
            ])
            .status();
    }

    // Display check results, TCP only
    if !udp_mode {
        let ret1 = port_test.test_lan(&to_addr, None, None, true);
        let ret2 = port_test.test_lan(&natter_addr, None, None, true);
        let ret3 = port_test.test_lan(
            &outer_addr,
            Some(*natter_addr.ip()),
            bind_interface.as_deref(),
            true,
        );
        let ret4 = port_test.test_wan(
            &outer_addr,
            Some(*natter_addr.ip()),
            bind_interface.as_deref(),
            true,
        );
        if ret1 == -1 {
            log::warn!("!! Target port is closed !!");
        } else if ret1 == 1 && ret3 == -1 && ret4 == -1 {
            log::warn!("!! Hole punching failed !!");
        } else if ret3 == 1 && ret4 == -1 {
            log::warn!("!! You may be behind a firewall !!");
        }
        log::info!("");

        // retry if target port is closed
        if keep_retry && ret1 == -1 {
            log::info!("Retry after {} seconds...", interval);
            std::thread::sleep(Duration::from_secs(interval as u64));
            let _ = forwarder.stop_forward();
            keep_alive.disconnect();
            return Err(NatterAction::Retry);
        }
    }

    //
    // Main loop
    //
    let mut need_recheck = false;
    let mut cnt: u32 = 0;
    loop {
        // Force recheck every 20th loop
        cnt = (cnt + 1) % 20;
        if cnt == 0 {
            need_recheck = true;
        }

        if need_recheck {
            log::debug!("Start recheck");
            need_recheck = false;

            if udp_mode
                || port_test.test_lan(
                    &outer_addr,
                    Some(*natter_addr.ip()),
                    bind_interface.as_deref(),
                    false,
                ) == -1
            {
                // Check through STUN
                match stun_client.get_mapping() {
                    Ok((_, outer_addr_curr)) => {
                        if outer_addr_curr != outer_addr {
                            let _ = forwarder.stop_forward();
                            keep_alive.disconnect();
                            if exit_when_changed {
                                log::info!(
                                    "Natter is exiting because mapped address has changed"
                                );
                                return Err(NatterAction::Exit);
                            }
                            return Err(NatterAction::Retry);
                        }
                    }
                    Err(e) => {
                        log::error!("STUN recheck failed: {}", e);
                        need_recheck = true;
                    }
                }
            }
        }

        // Keep alive
        let ts = Instant::now();
        if let Err(e) = keep_alive.keep_alive() {
            // Check for EADDRNOTAVAIL
            if let Some(os_err) = e.raw_os_error() {
                // EADDRNOTAVAIL = 99 on Linux, 10049 on Windows
                if os_err == 99 || os_err == 10049 {
                    if exit_when_changed {
                        log::info!(
                            "Natter is exiting because local IP address has changed"
                        );
                        return Err(NatterAction::Exit);
                    }
                    let _ = forwarder.stop_forward();
                    return Err(NatterAction::Retry);
                }
            }
            if udp_mode {
                log::debug!("keep-alive: UDP response not received: {}", e);
            } else {
                log::error!("keep-alive: connection broken: {}", e);
            }
            keep_alive.disconnect();
            need_recheck = true;
        }

        // UPnP renew
        if upnp_ready {
            if let Some(ref u) = upnp_client {
                if let Err(e) = u.renew() {
                    log::error!("upnp: failed to renew upnp: {}", e);
                }
            }
        }

        // Sleep for the remaining interval
        let elapsed = ts.elapsed();
        let sleep_dur = Duration::from_secs(interval as u64).saturating_sub(elapsed);
        if !sleep_dur.is_zero() {
            std::thread::sleep(sleep_dur);
        }
    }
}

fn run_relay(args: &Args) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime");

    rt.block_on(async {
        if let Err(e) = run_relay_async(args).await {
            log::error!("Relay error: {}", e);
            process::exit(1);
        }
    });
}

async fn run_relay_async(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let relay_addr = args
        .relay_addr
        .as_deref()
        .ok_or("--relay-addr is required")?;

    match args.relay_mode.as_str() {
        "tcp" => {
            if args.relay_server {
                log::info!("Starting TCP relay server on {}", relay_addr);
                let listener = tunnel::tcp::TcpTunnelListener::bind(
                    relay_addr,
                    args.tcp_password.clone(),
                )
                .await?;

                // Accept multiple clients
                loop {
                    let (stream, client_addr) = listener.accept().await?;
                    let bind_port = args.bind_port;
                    let bind_ip: std::net::Ipv4Addr =
                        args.bind_interface.parse().unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
                    let bind_addr = std::net::SocketAddr::new(
                        std::net::IpAddr::V4(bind_ip),
                        bind_port,
                    );

                    tokio::spawn(async move {
                        log::info!("Handling relay client from {}", client_addr);
                        if let Err(e) = relay::server::run(stream, bind_addr).await {
                            log::warn!("Relay client {} error: {}", client_addr, e);
                        }
                    });
                }
            } else if args.relay_client {
                log::info!("Connecting TCP relay to {}", relay_addr);
                let stream = tunnel::tcp::TcpTunnelStream::connect(
                    relay_addr,
                    args.tcp_password.clone(),
                )
                .await?;

                let local_addr = &args.target_ip;
                let local_port = args.target_port;
                let protocol = if args.udp { "udp" } else { "tcp" };

                relay::client::run(stream, local_port, local_addr, protocol).await?;
            }
        }
        "wg" => {
            // Build WireGuard config from CLI args or config file
            let wg_config = if let Some(ref conf_path) = args.wg_config {
                tunnel::wg_config::WgConfig::from_file(conf_path)?
            } else {
                let private_key = args
                    .wg_private_key
                    .as_deref()
                    .ok_or("--wg-key or --wg-conf is required for WG mode")?;
                let peer_key = args
                    .wg_peer_public_key
                    .as_deref()
                    .ok_or("--wg-peer-key is required for WG mode")?;

                let endpoint = if args.relay_client {
                    Some(relay_addr)
                } else {
                    None
                };
                let listen_port = if args.relay_server {
                    let port = relay_addr
                        .rsplit(':')
                        .next()
                        .and_then(|p| p.parse::<u16>().ok());
                    port
                } else {
                    None
                };

                tunnel::wg_config::WgConfig::from_args(
                    private_key,
                    peer_key,
                    listen_port,
                    endpoint,
                )?
            };

            let is_server = args.relay_server;
            let stream =
                tunnel::wireguard::WgTunnelStream::new(&wg_config, is_server).await?;

            if args.relay_server {
                let bind_port = args.bind_port;
                let bind_ip: std::net::Ipv4Addr =
                    args.bind_interface.parse().unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
                let bind_addr = std::net::SocketAddr::new(
                    std::net::IpAddr::V4(bind_ip),
                    bind_port,
                );
                relay::server::run(stream, bind_addr).await?;
            } else if args.relay_client {
                let local_addr = &args.target_ip;
                let local_port = args.target_port;
                let protocol = if args.udp { "udp" } else { "tcp" };
                relay::client::run(stream, local_port, local_addr, protocol).await?;
            }
        }
        other => {
            return Err(format!("Unknown relay mode: {}. Use 'tcp' or 'wg'.", other).into());
        }
    }

    Ok(())
}

fn main() {
    NatterLogger::init();
    let args = Args::parse();

    NatterLogger::set_verbose(args.verbose);

    if args.check {
        checker::do_check();
        process::exit(0);
    }

    // Handle relay modes
    if args.relay_server || args.relay_client {
        run_relay(&args);
        return;
    }

    // Handle Ctrl+C
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
        process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    let mut show_title = true;
    loop {
        match natter_main(&args, show_title) {
            Ok(()) => break,
            Err(NatterAction::Retry) => {
                show_title = false;
                continue;
            }
            Err(NatterAction::Exit) => {
                process::exit(0);
            }
        }
    }
}
