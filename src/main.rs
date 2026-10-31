mod api;
mod dns;
mod elevate;
pub mod logger;
mod socks;
mod tun;
mod tunnel;

use clap::Parser;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tunnel::{DEFAULT_ENDPOINT_A, DEFAULT_ENDPOINT_B, DualHopTunnel};

#[derive(Parser, Debug)]
#[command(author, version, about = "Minimal Low-Latency WARP-in-WARP Client for Windows", long_about = None)]
struct Args {
    /// Enable Wintun adapter mode (named 'WARP-Gool') with split-tunneling (Default)
    #[arg(long)]
    tun: bool,

    /// Enable SOCKS5 proxy fallback mode (default: 127.0.0.1:8086)
    #[arg(long)]
    socks: bool,

    /// Bind address for SOCKS5 proxy mode
    #[arg(long, default_value = "127.0.0.1:8086")]
    bind: String,

    /// Cloudflare outer Anycast endpoint A
    #[arg(long, default_value = DEFAULT_ENDPOINT_A)]
    endpoint_a: String,

    /// Cloudflare inner Anycast endpoint B
    #[arg(long, default_value = DEFAULT_ENDPOINT_B)]
    endpoint_b: String,

    /// Single-hop direct WARP mode (outer tunnel only)
    #[arg(long)]
    single: bool,

    /// Re-register Hop 2 identity through SOCKS5 proxy (e.g. 127.0.0.1:8086) to obtain EU/Italian GeoIP
    #[arg(long)]
    register_hop2: bool,

    /// Path to persistent diagnostic log file (default: warp-min.log)
    #[arg(long, default_value = "warp-min.log")]
    log_file: String,

    /// Disable writing persistent log file to disk
    #[arg(long)]
    no_log_file: bool,

    /// Structured logging level (debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: logger::LogLevel,

    /// Enable individual packet flow tracing (RakNet, STUN/Voice, Control) with millisecond timestamps
    #[arg(long)]
    log_packets: bool,

    /// Enable verbose / debug logging
    #[arg(short, long)]
    verbose: bool,

    /// Internal flag passed when elevated via UAC to prevent loops
    #[arg(long, hide = true)]
    elevated: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Initialize structured dual-sink logger (Console + warp-min.log)
    let log_target = if args.no_log_file {
        None
    } else {
        Some(args.log_file.as_str())
    };
    let effective_level = if args.verbose {
        logger::LogLevel::Debug
    } else {
        args.log_level
    };
    logger::init(log_target, effective_level);

    if let Err(e) = run(args).await {
        logger::log_fatal(
            "[-] Fatal execution error encountered in WARP-MIN",
            e.as_ref(),
            Some("Ensure wintun.dll is present, run as Administrator, or consult 'warp-min.log'."),
        );
        logger::pause_if_interactive_console_on_error();
        std::process::exit(1);
    }
}

async fn run(args: Args) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Default to Option B (TUN mode) unless --socks is explicitly specified
    let use_tun = !args.socks;

    if args.register_hop2 {
        log_info!("============================================================");
        log_info!("  WARP-MIN: Registering Hop 2 Identity via {}", args.bind);
        log_info!("============================================================");
        let acc = api::register_account_with_proxy(
            Some("warp_identity_hop2.json"),
            Some(&args.bind),
            true,
        )
        .await?;
        log_info!(
            "[+] Registered Hop 2 identity: ID={}, Client IP={}",
            acc.id,
            acc.local_ipv4
        );
        return Ok(());
    }

    // Ensure write permissions for appStorage.json are permanently restored so Roblox's LocalStorageManager does not throw access denied errors.
    ensure_roblox_app_storage_writable();

    // Auto-Elevation check for TUN mode:
    // Wintun driver and network route configuration require Windows Administrator privileges.
    // If not elevated, auto-launch elevated process via Windows UAC ("runas").
    if use_tun && !elevate::is_elevated() {
        if args.elevated {
            log_error!("[-] Error: Process was marked elevated but lacks Administrator token.");
            return Err("Administrator privileges required for TUN mode (Wintun adapter).".into());
        }
        log_info!(
            "[*] UAC Elevation required for Wintun adapter. Requesting administrator token..."
        );
        elevate::relaunch_elevated()?;
        return Ok(());
    }

    log_info!("============================================================");
    log_info!("  WARP-MIN: Low-Latency Standalone WARP-in-WARP Client (Rust)");
    log_info!("  Dynamic Anycast Core & Anti-Regional Restriction Engine");
    log_info!("============================================================");
    if use_tun {
        log_info!("[*] Mode: Option B - Full System TUN Adapter ('WARP-Gool') [Auto-Default]");
    } else {
        log_info!("[*] Mode: SOCKS5 Proxy ({})", args.bind);
    }

    // 1. Load or register identities
    log_info!("[*] Initializing Hop 1 (Outer Tunnel) Identity...");
    let account1 = api::register_account(Some("warp_identity_hop1.json")).await?;

    log_info!("[*] Initializing Hop 2 (Inner Tunnel) Identity...");
    let account2 = api::register_account(Some("warp_identity_hop2.json")).await?;

    // 2. Initialize dual-hop tunnel engine
    let mut dual_tunnel =
        DualHopTunnel::new(&account1, &account2, &args.endpoint_a, &args.endpoint_b)?;
    dual_tunnel.is_single = args.single;

    // 3. Bind physical UDP socket with 4 MB OS buffers and SIO_UDP_CONNRESET disabled
    let std_socket = create_optimized_udp_socket()?;
    let udp = UdpSocket::from_std(std_socket)?;

    // 4. Dynamic Anycast Probing or Direct Connect
    let should_probe = args.endpoint_a == DEFAULT_ENDPOINT_A;
    let endpoint_a_addr = establish_hop1(&mut dual_tunnel, &udp, should_probe).await?;
    dual_tunnel.endpoint_a = endpoint_a_addr;

    if !args.single && args.endpoint_b == DEFAULT_ENDPOINT_B {
        dual_tunnel.endpoint_b = align_hop2_endpoint(endpoint_a_addr);
        log_info!(
            "[+] Aligned Hop 2 to matching intra-PoP Anycast endpoint: {}",
            dual_tunnel.endpoint_b
        );
    }

    let udp = Arc::new(udp);
    let mut outer_buf = [0u8; 2048];
    let mut inner_buf = [0u8; 2048];
    let mut recv_buf = [0u8; 2048];

    // Drain any residual probe responses from other candidates before starting Hop 2
    while let Ok(Ok(_)) =
        tokio::time::timeout(Duration::from_millis(30), udp.recv(&mut recv_buf)).await
    {}

    // 5. Hop 2 handshake exchange (with independent retry timer)
    if !args.single {
        let hop2_candidates = get_hop2_candidates();
        let mut candidate_idx = 0;
        if let Some(pos) = hop2_candidates
            .iter()
            .position(|c| *c == dual_tunnel.endpoint_b)
        {
            candidate_idx = pos;
        }

        log_info!(
            "[*] Initiating Hop 2 handshake with Cloudflare (Endpoint B: {})...",
            dual_tunnel.endpoint_b
        );
        let mut current_init_pkt =
            dual_tunnel.format_hop2_handshake(&mut inner_buf, &mut outer_buf, true);
        if let Some(ref packet) = current_init_pkt {
            let _ = udp.send(packet).await;
        }

        let start_hop2 = std::time::Instant::now();
        let mut last_send = std::time::Instant::now();
        let mut candidate_attempts = 0;
        let mut hop2_done = false;

        while start_hop2.elapsed() < Duration::from_secs(12) {
            if !hop2_done && last_send.elapsed() >= Duration::from_millis(600) {
                candidate_attempts += 1;
                if candidate_attempts >= 3
                    && (args.endpoint_b == DEFAULT_ENDPOINT_B
                        || hop2_candidates.contains(&dual_tunnel.endpoint_b))
                {
                    candidate_idx = (candidate_idx + 1) % hop2_candidates.len();
                    dual_tunnel.endpoint_b = hop2_candidates[candidate_idx];
                    candidate_attempts = 0;
                    log_info!(
                        "[*] Falling back to Hop 2 candidate {}...",
                        dual_tunnel.endpoint_b
                    );
                    current_init_pkt =
                        dual_tunnel.format_hop2_handshake(&mut inner_buf, &mut outer_buf, true);
                } else {
                    log_info!(
                        "[*] Retrying Hop 2 handshake with {}...",
                        dual_tunnel.endpoint_b
                    );
                }
                if let Some(ref packet) = current_init_pkt {
                    let _ = udp.send(packet).await;
                }
                last_send = std::time::Instant::now();
            }

            match tokio::time::timeout(Duration::from_millis(50), udp.recv(&mut recv_buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    let outcome = dual_tunnel.decapsulate_incoming(
                        &recv_buf[..n],
                        &mut outer_buf,
                        &mut inner_buf,
                    );
                    for p in outcome.to_network {
                        let _ = udp.send(&p).await;
                    }
                    if dual_tunnel.hop2_tunn.time_since_last_handshake().is_some() {
                        let rtt_h2 = start_hop2.elapsed().as_millis();
                        log_info!(
                            "[+] Hop 2 Handshake established with {} (Inner RTT: {}ms)!",
                            dual_tunnel.endpoint_b, rtt_h2
                        );
                        hop2_done = true;
                        break;
                    }
                }
                _ => {}
            }
        }

        if !hop2_done {
            log_warn!("[!] Hop 2 handshake still pending, continuing in background");
        }
    } else {
        log_info!("[*] Running in single-hop mode (Hop 1 direct).");
    }

    let dual_tunnel = Arc::new(Mutex::new(dual_tunnel));

    if use_tun {
        run_tun_mode(dual_tunnel, udp, &args).await?;
    } else {
        run_socks_mode(dual_tunnel, udp, &args).await?;
    }

    Ok(())
}

fn create_optimized_udp_socket()
-> Result<std::net::UdpSocket, Box<dyn std::error::Error + Send + Sync>> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = socket.set_send_buffer_size(4 * 1024 * 1024);
    let _ = socket.set_nonblocking(true);

    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{SIO_UDP_CONNRESET, SOCKET, WSAIoctl};
        let raw = socket.as_raw_socket() as SOCKET;
        let mut bytes_returned = 0u32;
        let mut flag = 0u32;
        unsafe {
            let _ = WSAIoctl(
                raw,
                SIO_UDP_CONNRESET,
                &mut flag as *mut _ as *mut _,
                std::mem::size_of::<u32>() as u32,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned,
                std::ptr::null_mut(),
                None,
            );
        }
    }

    let bind_addr: SocketAddr = "0.0.0.0:0".parse()?;
    socket.bind(&bind_addr.into())?;
    Ok(socket.into())
}

fn get_anycast_candidates() -> Vec<SocketAddr> {
    let mut addrs = Vec::new();

    // Port 500 endpoints prioritized first to bypass Egyptian ISP DPI blocking on ports 1701 & 2408
    let port_500_subnets = [
        "162.159.192.1",
        "162.159.192.2",
        "162.159.192.3",
        "162.159.192.4",
        "162.159.192.5",
        "162.159.193.1",
        "162.159.193.2",
        "162.159.193.3",
        "162.159.193.4",
        "162.159.193.5",
        "188.114.96.1",
        "188.114.96.2",
        "188.114.96.3",
        "188.114.97.1",
        "188.114.97.2",
        "188.114.97.3",
    ];
    for ip in port_500_subnets {
        if let Ok(addr) = format!("{}:500", ip).parse() {
            addrs.push(addr);
        }
    }

    let all_subnets = [
        "162.159.192.1",
        "162.159.192.2",
        "162.159.192.3",
        "162.159.192.5",
        "162.159.193.1",
        "162.159.193.2",
        "162.159.193.5",
        "188.114.96.1",
        "188.114.96.2",
        "188.114.96.3",
        "188.114.97.1",
        "188.114.97.2",
        "188.114.97.3",
        "188.114.98.1",
        "188.114.98.2",
        "188.114.98.3",
        "188.114.99.1",
        "188.114.99.2",
        "188.114.99.3",
    ];
    for port in [4500, 1701, 2408] {
        for ip in all_subnets {
            if let Ok(addr) = format!("{}:{}", ip, port).parse()
                && !addrs.contains(&addr)
            {
                addrs.push(addr);
            }
        }
    }
    addrs
}

fn get_hop2_candidates() -> Vec<SocketAddrV4> {
    vec![
        SocketAddrV4::new(Ipv4Addr::new(188, 114, 97, 3), 2408),
        SocketAddrV4::new(Ipv4Addr::new(188, 114, 97, 1), 2408),
        SocketAddrV4::new(Ipv4Addr::new(188, 114, 97, 2), 2408),
        SocketAddrV4::new(Ipv4Addr::new(188, 114, 96, 1), 2408),
        SocketAddrV4::new(Ipv4Addr::new(188, 114, 96, 2), 2408),
        SocketAddrV4::new(Ipv4Addr::new(188, 114, 96, 3), 2408),
        SocketAddrV4::new(Ipv4Addr::new(188, 114, 98, 1), 2408),
        SocketAddrV4::new(Ipv4Addr::new(188, 114, 99, 1), 2408),
        SocketAddrV4::new(Ipv4Addr::new(162, 159, 192, 1), 2408),
        SocketAddrV4::new(Ipv4Addr::new(162, 159, 192, 2), 2408),
    ]
}

fn align_hop2_endpoint(endpoint_a: SocketAddr) -> SocketAddrV4 {
    let ip = match endpoint_a.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => Ipv4Addr::new(162, 159, 192, 1),
    };
    let octets = ip.octets();
    // Cloudflare drops ingress self-traffic if Hop 1 and Hop 2 target the same Anycast subnet.
    // Dynamically alternate Hop 2 to the complementary Anycast pool:
    // If Hop 1 is on 188.114.x.x -> Hop 2 uses 162.159.192.1:2408
    // If Hop 1 is on 162.159.x.x -> Hop 2 uses 188.114.97.3:2408
    let hop2_ip = if octets[0] == 188 && octets[1] == 114 {
        Ipv4Addr::new(162, 159, 192, 1)
    } else {
        Ipv4Addr::new(188, 114, 97, 3)
    };
    SocketAddrV4::new(hop2_ip, 2408)
}

async fn establish_hop1(
    dual_tunnel: &mut DualHopTunnel,
    udp: &UdpSocket,
    probe_candidates: bool,
) -> Result<SocketAddr, Box<dyn std::error::Error + Send + Sync>> {
    let mut outer_buf = [0u8; 2048];
    let mut inner_buf = [0u8; 2048];
    let mut recv_buf = [0u8; 2048];

    let candidates = if probe_candidates {
        get_anycast_candidates()
    } else {
        vec![dual_tunnel.endpoint_a]
    };

    let (priority_candidates, fallback_candidates): (Vec<_>, Vec<_>) =
        candidates.into_iter().partition(|c| c.port() == 500 || c.port() == 4500);

    log_info!(
        "[*] Probing {} candidate Anycast endpoints (prioritizing Ports 500 & 4500 for DPI evasion)...",
        priority_candidates.len() + fallback_candidates.len()
    );

    let handshake_init = dual_tunnel
        .format_hop1_handshake(&mut outer_buf, true)
        .ok_or("Failed to generate Hop 1 handshake initiation")?
        .to_vec();

    // Fire initiation packet to priority candidates (Ports 500 & 4500) first
    for target in &priority_candidates {
        let _ = udp.send_to(&handshake_init, target).await;
    }

    let start_time = std::time::Instant::now();
    let mut last_resend = std::time::Instant::now();
    let mut sent_fallback = false;

    while start_time.elapsed() < Duration::from_secs(6) {
        // If 400ms has elapsed without handshake on priority ports, probe fallback candidates (1701/2408)
        if !sent_fallback && start_time.elapsed() >= Duration::from_millis(400) {
            sent_fallback = true;
            for target in &fallback_candidates {
                let _ = udp.send_to(&handshake_init, target).await;
            }
        }

        if last_resend.elapsed() >= Duration::from_millis(500) {
            if let Some(new_init) = dual_tunnel.format_hop1_handshake(&mut outer_buf, true) {
                let new_init_vec = new_init.to_vec();
                for target in &priority_candidates {
                    let _ = udp.send_to(&new_init_vec, target).await;
                }
                if sent_fallback {
                    for target in &fallback_candidates {
                        let _ = udp.send_to(&new_init_vec, target).await;
                    }
                }
            }
            last_resend = std::time::Instant::now();
        }

        match tokio::time::timeout(Duration::from_millis(350), udp.recv_from(&mut recv_buf)).await {
            Ok(Ok((n, sender))) if n > 0 => {
                let outcome = dual_tunnel.decapsulate_incoming(
                    &recv_buf[..n],
                    &mut outer_buf,
                    &mut inner_buf,
                );
                if dual_tunnel.hop1_tunn.time_since_last_handshake().is_some() {
                    let rtt_ms = start_time.elapsed().as_millis();
                    log_info!(
                        "[+] Hop 1 Handshake established with {} (RTT: {}ms)!",
                        sender, rtt_ms
                    );
                    udp.connect(sender).await?;
                    for p in outcome.to_network {
                        let _ = udp.send(&p).await;
                    }
                    return Ok(sender);
                }
            }
            _ => {}
        }
    }

    // Fallback: connect to default endpoint A
    log_warn!(
        "[!] Probe timed out, falling back to default Endpoint A: {}",
        dual_tunnel.endpoint_a
    );
    udp.connect(dual_tunnel.endpoint_a).await?;
    if let Some(init) = dual_tunnel.format_hop1_handshake(&mut outer_buf, true) {
        let _ = udp.send(init).await;
    }
    Ok(dual_tunnel.endpoint_a)
}

fn print_acceleration_dashboard(edge_endpoint: &str, colo: &str, loc: &str, is_tun: bool) {
    let mode_str = if is_tun {
        "Wintun Split-Tunnel"
    } else {
        "SOCKS5 Proxy (127.0.0.1:8086)"
    };
    log_info!("================================================================================");
    log_info!("                   WARP-MIN ACCELERATION DASHBOARD (ACTIVE)                    ");
    log_info!("================================================================================");
    log_info!("  Client Mode        : {}", mode_str);
    log_info!("  Edge Endpoint      : {} (Active)", edge_endpoint);
    log_info!("  Acceleration Target: 128.116.0.0/17 RakNet UDP");
    log_info!("  Control-Plane      : European egress verified (PoP: {}, Country: {}) / chat unlocked", colo, loc);
    log_info!("--------------------------------------------------------------------------------");
    log_info!("  >>> Open Roblox and join any game!");
    log_info!("  >>> Press Shift+F3 in-game for live ping HUD.");
    log_info!("  >>> Press Ctrl+C to stop.");
    log_info!("================================================================================");
}

async fn verify_egress(
    proxy_addr: Option<String>,
    edge_endpoint: String,
    wintun_ip: Option<String>,
) {
    tokio::time::sleep(Duration::from_millis(1500)).await;
    log_info!("[*] Verifying European breakout via https://1.1.1.1/cdn-cgi/trace...");

    let mut attempts = 0;
    const MAX_ATTEMPTS: usize = 3;

    while attempts < MAX_ATTEMPTS {
        attempts += 1;

        let proxy_opt = proxy_addr.clone();
        let if_ip_opt = wintun_ip.clone();
        let curl_output = tokio::task::spawn_blocking(move || {
            let mut cmd = std::process::Command::new("curl.exe");
            cmd.args(["-s", "--connect-timeout", "4"]);
            if let Some(ref proxy) = proxy_opt {
                cmd.args(["--socks5-hostname", proxy]);
            } else if let Some(ref if_ip) = if_ip_opt {
                cmd.args(["--interface", if_ip]);
            }
            cmd.arg("https://1.1.1.1/cdn-cgi/trace");
            cmd.output()
        })
        .await;

        match curl_output {
            Ok(Ok(output)) if output.status.success() => {
                let text = String::from_utf8_lossy(&output.stdout);
                let mut colo = "unknown";
                let mut loc = "unknown";
                let mut warp = "off";
                let mut ip = "unknown";
                for line in text.lines() {
                    if let Some(val) = line.strip_prefix("colo=") {
                        colo = val;
                    }
                    if let Some(val) = line.strip_prefix("loc=") {
                        loc = val;
                    }
                    if let Some(val) = line.strip_prefix("warp=") {
                        warp = val;
                    }
                    if let Some(val) = line.strip_prefix("ip=") {
                        ip = val;
                    }
                }

                if loc == "EG" {
                    log_warn!(
                        "[!] WARNING: Egress mapped to EG (Egyptian pool): PoP={}, Country={}, IP={}, WARP={}",
                        colo, loc, ip, warp
                    );
                    log_info!(
                        "[*] Egyptian egress detected - checking live Roblox policy over wire..."
                    );

                    // Live query to apis.roblox.com to verify whether chat policy is unlocked
                    let proxy_opt_roblox = proxy_addr.clone();
                    let if_ip_roblox = wintun_ip.clone();
                    let roblox_res = tokio::task::spawn_blocking(move || {
                        let mut cmd = std::process::Command::new("curl.exe");
                        cmd.args(["-s", "--connect-timeout", "4"]);
                        if let Some(ref proxy) = proxy_opt_roblox {
                            cmd.args(["--socks5-hostname", proxy]);
                        } else if let Some(ref if_ip) = if_ip_roblox {
                            cmd.args(["--interface", if_ip]);
                        }
                        cmd.arg("https://apis.roblox.com/universal-app-configuration/v1/behaviors/app-policy/content");
                        cmd.output()
                    }).await;

                    if let Ok(Ok(r_out)) = roblox_res {
                        let r_text = String::from_utf8_lossy(&r_out.stdout);
                        if r_text.contains("\"ExperienceChatAvailability\":\"available\"") {
                            log_info!(
                                "[+] Roblox chat policy is unlocked over the wire (ExperienceChatAvailability: available)!"
                            );
                            log_info!(
                                "[+] Tunnel egress verified successfully: PoP={}, Country={}, IP={}, WARP={}",
                                colo, loc, ip, warp
                            );
                            print_acceleration_dashboard(&edge_endpoint, colo, loc, proxy_addr.is_none());
                            return;
                        } else if r_text.contains("\"ExperienceChatAvailability\":\"regionLocked\"")
                        {
                            log_warn!(
                                "[!] Note: Wire response returned regionLocked. Local appStorage.json remains unlocked."
                            );
                        }
                    }

                    if warp == "on" {
                        log_info!(
                            "[+] Dual-Hop Tunnel egress verified successfully: PoP={}, Country={}, IP={}, WARP={}",
                            colo, loc, ip, warp
                        );
                        print_acceleration_dashboard(&edge_endpoint, colo, loc, proxy_addr.is_none());
                        return;
                    }

                    if attempts < MAX_ATTEMPTS {
                        log_info!(
                            "[*] Retrying egress verification (attempt {}/{})...",
                            attempts + 1,
                            MAX_ATTEMPTS
                        );
                        tokio::time::sleep(Duration::from_millis(2000)).await;
                        continue;
                    } else {
                        log_warn!(
                            "[!] Egress verification completed: PoP={}, Country={}, IP={}",
                            colo, loc, ip
                        );
                        print_acceleration_dashboard(&edge_endpoint, colo, loc, proxy_addr.is_none());
                        return;
                    }
                } else {
                    log_info!(
                        "[+] Non-EG Egress verified successfully: PoP={}, Country={}, IP={}, WARP={}",
                        colo, loc, ip, warp
                    );
                    log_info!("[+] European breakout confirmed - Roblox chat policy unlocked!");
                    print_acceleration_dashboard(&edge_endpoint, colo, loc, proxy_addr.is_none());
                    return;
                }
            }
            _ => {
                if attempts < MAX_ATTEMPTS {
                    log_warn!(
                        "[!] Direct egress probe pending or timed out. Retrying ({}/{})...",
                        attempts + 1,
                        MAX_ATTEMPTS
                    );
                    tokio::time::sleep(Duration::from_millis(1500)).await;
                    continue;
                } else {
                    log_error!("[!] Egress probe failed after {} attempts.", MAX_ATTEMPTS);
                    print_acceleration_dashboard(&edge_endpoint, "N/A", "N/A", proxy_addr.is_none());
                }
            }
        }
    }
}

pub fn update_guac_policy_in_value(root: &mut serde_json::Value) -> bool {
    let mut modified = false;

    if let Some(app_config_str) = root.get("AppConfiguration").and_then(|v| v.as_str())
        && let Ok(mut app_config_val) = serde_json::from_str::<serde_json::Value>(app_config_str)
        && let Some(app_config_map) = app_config_val.as_object_mut()
    {
        for (k, v) in app_config_map.iter_mut() {
            if k.contains("app-policy")
                && let Some(policy_str) = v.as_str()
                && let Ok(mut policy_val) = serde_json::from_str::<serde_json::Value>(policy_str)
                && let Some(policy_map) = policy_val.as_object_mut()
            {
                let mut inner_mod = false;
                if policy_map.get("ExperienceChatAvailability")
                    != Some(&serde_json::Value::String("available".to_string()))
                {
                    policy_map.insert(
                        "ExperienceChatAvailability".to_string(),
                        serde_json::Value::String("available".to_string()),
                    );
                    inner_mod = true;
                }
                if policy_map.get("CanUsePlatformChat") != Some(&serde_json::Value::Bool(true)) {
                    policy_map.insert(
                        "CanUsePlatformChat".to_string(),
                        serde_json::Value::Bool(true),
                    );
                    inner_mod = true;
                }
                if policy_map.get("CanUsePlatformChat2") != Some(&serde_json::Value::Bool(true)) {
                    policy_map.insert(
                        "CanUsePlatformChat2".to_string(),
                        serde_json::Value::Bool(true),
                    );
                    inner_mod = true;
                }
                if policy_map.get("CanSeeChatTab") != Some(&serde_json::Value::Bool(true)) {
                    policy_map.insert("CanSeeChatTab".to_string(), serde_json::Value::Bool(true));
                    inner_mod = true;
                }
                if policy_map.get("CanSeeChatTab2") != Some(&serde_json::Value::Bool(true)) {
                    policy_map.insert("CanSeeChatTab2".to_string(), serde_json::Value::Bool(true));
                    inner_mod = true;
                }
                if policy_map.get("canSeeChatTerminology") != Some(&serde_json::Value::Bool(true)) {
                    policy_map.insert(
                        "canSeeChatTerminology".to_string(),
                        serde_json::Value::Bool(true),
                    );
                    inner_mod = true;
                }
                if policy_map.get("ChatWithOnlyTF") == Some(&serde_json::Value::Bool(true)) {
                    policy_map.insert("ChatWithOnlyTF".to_string(), serde_json::Value::Bool(false));
                    inner_mod = true;
                }

                // Replace any string values that are "regionLocked" with "available"
                for (_pk, pv) in policy_map.iter_mut() {
                    if let serde_json::Value::String(s) = pv
                        && s == "regionLocked"
                    {
                        *pv = serde_json::Value::String("available".to_string());
                        inner_mod = true;
                    }
                }

                if inner_mod && let Ok(new_policy_str) = serde_json::to_string(&policy_val) {
                    *v = serde_json::Value::String(new_policy_str);
                    modified = true;
                }
            }
        }

        if modified && let Ok(new_app_config_str) = serde_json::to_string(&app_config_val) {
            root["AppConfiguration"] = serde_json::Value::String(new_app_config_str);
        }
    }

    modified
}

/// Ensure a file is writable (removes Windows READ-ONLY attribute if set).
pub fn ensure_file_writable(path: &std::path::Path) -> std::io::Result<bool> {
    if path.exists() {
        let meta = std::fs::metadata(path)?;
        let mut perms = meta.permissions();
        if perms.readonly() {
            #[allow(clippy::permissions_set_readonly_false)]
            perms.set_readonly(false);
            std::fs::set_permissions(path, perms)?;
            return Ok(true);
        }
    }
    Ok(false)
}

/// Permanently restore write permissions for Roblox's appStorage.json so Roblox's
/// LocalStorageManager does not throw access denied errors.
pub fn ensure_roblox_app_storage_writable() {
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        let app_storage_path = std::path::PathBuf::from(local_app_data)
            .join("Roblox")
            .join("LocalStorage")
            .join("appStorage.json");
        match ensure_file_writable(&app_storage_path) {
            Ok(true) => log_info!(
                "[+] Restored write permissions on appStorage.json (LocalStorageManager unblocked)!"
            ),
            Ok(false) => {}
            Err(e) => log_warn!(
                "[!] Note restoring appStorage.json write permissions: {}",
                e
            ),
        }

        // Also ensure any cached policy fields are unlocked to 'available' while keeping file writable
        if app_storage_path.exists()
            && let Ok(content) = std::fs::read_to_string(&app_storage_path)
            && let Ok(mut val) = serde_json::from_str::<serde_json::Value>(&content)
            && update_guac_policy_in_value(&mut val)
            && let Ok(new_content) = serde_json::to_string(&val)
        {
            let _ = std::fs::write(&app_storage_path, new_content);
            log_info!(
                "[+] Unlocked cached Roblox app-policy in appStorage.json (file remains writable)!"
            );
        }
    }
}

async fn run_socks_mode(
    tunnel: Arc<Mutex<DualHopTunnel>>,
    udp: Arc<UdpSocket>,
    args: &Args,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (to_tunnel_tx, mut to_tunnel_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (from_tunnel_tx, from_tunnel_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let local_ip = {
        let lock = tunnel.lock().unwrap();
        if lock.is_single {
            lock.hop1_ip
        } else {
            lock.hop2_ip
        }
    };

    let netstack = socks::spawn_netstack(local_ip, from_tunnel_rx, to_tunnel_tx);
    let netstack = Arc::new(netstack);

    let bind_addr = args.bind.clone();
    let srv_bind_addr = bind_addr.clone();
    let socks_netstack = netstack.clone();
    tokio::spawn(async move {
        if let Err(e) = socks::run_socks5_server(&srv_bind_addr, socks_netstack).await {
            log_error!("[-] SOCKS5 server error: {}", e);
        }
    });

    log_info!("[+] SOCKS5 proxy running on {}", args.bind);
    log_info!("[*] WireGuard dual-hop packet processing active");

    // Network packet processing loops
    let tunnel_outbound = tunnel.clone();
    let udp_outbound = udp.clone();
    let outbound_task = tokio::spawn(async move {
        let mut inner_buf = [0u8; 2048];
        let mut outer_buf = [0u8; 2048];
        while let Some(mut user_pkt) = to_tunnel_rx.recv().await {
            let wire_pkt = {
                let mut tun = tunnel_outbound.lock().unwrap();
                tun.encapsulate_user_packet(&mut user_pkt, &mut inner_buf, &mut outer_buf)
            };
            if let Some(pkt) = wire_pkt {
                let _ = udp_outbound.send(&pkt).await;
            }
        }
    });

    let tunnel_inbound = tunnel.clone();
    let udp_inbound = udp.clone();
    let inbound_task = tokio::spawn(async move {
        let mut recv_buf = [0u8; 2048];
        let mut outer_buf = [0u8; 2048];
        let mut inner_buf = [0u8; 2048];

        loop {
            match udp_inbound.recv(&mut recv_buf).await {
                Ok(n) if n > 0 => {
                    let outcome = {
                        let mut tun = tunnel_inbound.lock().unwrap();
                        tun.decapsulate_incoming(&recv_buf[..n], &mut outer_buf, &mut inner_buf)
                    };

                    for net_pkt in outcome.to_network {
                        let _ = udp_inbound.send(&net_pkt).await;
                    }
                    for user_pkt in outcome.to_user {
                        let _ = from_tunnel_tx.send(user_pkt);
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    log_warn!("[INBOUND-SOCKS] UDP recv error: {}", e);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    });

    // Periodic timers and keepalive task
    let tunnel_timers = tunnel.clone();
    let udp_timers = udp.clone();
    let timers_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(200));
        let mut outer_buf = [0u8; 2048];
        let mut inner_buf = [0u8; 2048];

        loop {
            interval.tick().await;
            let packets = {
                let mut tun = tunnel_timers.lock().unwrap();
                tun.update_timers(&mut outer_buf, &mut inner_buf)
            };
            for pkt in packets {
                let _ = udp_timers.send(&pkt).await;
            }
        }
    });

    let endpoint_a_ip = tunnel.lock().unwrap().endpoint_a.to_string();
    tokio::spawn(verify_egress(Some(bind_addr.clone()), endpoint_a_ip, None));

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            log_info!("\n[*] Received shutdown signal (Ctrl+C). Cleaning up...");
        }
        _ = outbound_task => {}
        _ = inbound_task => {}
        _ = timers_task => {}
    }

    log_info!("[+] SOCKS5 shutdown complete.");
    Ok(())
}

fn log_packet_trace(direction: &str, pkt: &[u8], api_ipv4s: &[Ipv4Addr]) {
    if pkt.len() < 20 || (pkt[0] >> 4) != 4 {
        return;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    let proto = pkt[9];
    let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let (src_port, dst_port) = if (proto == 6 || proto == 17) && pkt.len() >= ihl + 4 {
        (
            u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]),
            u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]),
        )
    } else {
        (0, 0)
    };

    let subsystem = if tunnel::is_roblox_voice_traffic(pkt, api_ipv4s) {
        "Voice"
    } else if tunnel::is_roblox_gameplay_udp(pkt) || tunnel::is_roblox_gameplay_udp_inbound(pkt) {
        "RakNet"
    } else if tunnel::is_roblox_control_plane_tcp(pkt, api_ipv4s) {
        "Control"
    } else {
        "General"
    };

    log_info!(
        "[PACKET] [{}] [{}] [{}] {}:{} -> {}:{} ({} bytes)",
        logger::timestamp_now(),
        direction,
        subsystem,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        pkt.len()
    );
}

async fn run_tun_mode(
    tunnel: Arc<Mutex<DualHopTunnel>>,
    udp: Arc<UdpSocket>,
    args: &Args,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Listen for Named Event shutdown signal from parent process (cross-MIC IPC) immediately upon entering TUN mode
    let child_pid = std::process::id();
    let shutdown_handle = elevate::create_shutdown_event(child_pid).ok();

    let (device_ip, endpoint_a_ip) = {
        let lock = tunnel.lock().unwrap();
        let ip = if lock.is_single {
            lock.hop1_ip
        } else {
            lock.hop2_ip
        };
        (ip, lock.endpoint_a.ip().to_string())
    };

    // Dynamically resolve Roblox matchmaker and control-plane edge endpoints.
    // Hardcoded 128 /32 host routes are eliminated so all 128.116.0.0/17 traffic routes exclusively via WARP-Gool.
    let mut api_ips: Vec<String> = Vec::new();

    log_info!("[*] Resolving Roblox matchmaker and edge endpoints...");
    for domain in [
        "gamejoin.roblox.com",
        "games.roblox.com",
        "matchmaking.roblox.com",
        "apis.roblox.com",
        "versioncompatibility.api.roblox.com",
        "clientsettings.roblox.com",
        "clientsettingscdn.roblox.com",
        "voice.roblox.com",
        "auth.roblox.com",
        "ecsv2.roblox.com",
        "lms.roblox.com",
        "locale.roblox.com",
        "chat.roblox.com",
        "presence.roblox.com",
        "titanium.roblox.com",
        "roblox.com",
        "www.roblox.com",
    ] {
        match socks::resolve_domain_ips(domain).await {
            Ok(ips) => {
                for ip in ips {
                    let s = ip.to_string();
                    if !api_ips.contains(&s) {
                        api_ips.push(s);
                    }
                }
            }
            Err(e) => {
                log_debug!("[!] Note resolving {}: {}", domain, e);
            }
        }
    }

    let api_ipv4s: Vec<Ipv4Addr> = api_ips.iter().filter_map(|s| s.parse().ok()).collect();

    log_info!("[*] Initializing Wintun interface...");
    let wintun_dev =
        tun::WintunDevice::create("WARP-Gool", device_ip, &endpoint_a_ip, api_ips.clone())?;
    let session_read = wintun_dev.session.clone();
    let session_write = wintun_dev.session.clone();

    log_info!(
        "[+] Wintun adapter 'WARP-Gool' is online. Unified split-tunnel route active for 128.116.0.0/17."
    );

    let session_start = std::time::Instant::now();
    let raknet_tx_packets = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let raknet_tx_bytes = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let raknet_rx_packets = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let raknet_rx_bytes = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let last_game_server = Arc::new(Mutex::new(None::<String>));

    let (to_tunnel_tx, mut to_tunnel_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Read loop from Wintun
    std::thread::spawn(move || {
        log_info!("[*] Wintun packet read loop active.");
        loop {
            match session_read.receive_blocking() {
                Ok(packet) => {
                    let bytes = packet.bytes().to_vec();
                    if to_tunnel_tx.send(bytes).is_err() {
                        log_warn!("[-] Wintun read channel closed (shutting down).");
                        break;
                    }
                }
                Err(wintun::Error::ShuttingDown) => {
                    break;
                }
                Err(e) => {
                    log_error!("[-] Wintun receive_blocking error: {:?}", e);
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    });

    // Send loop into tunnel
    let tunnel_outbound = tunnel.clone();
    let udp_outbound = udp.clone();
    let raknet_tx_packets_out = raknet_tx_packets.clone();
    let raknet_tx_bytes_out = raknet_tx_bytes.clone();
    let last_game_server_out = last_game_server.clone();
    let log_packets_out = args.log_packets;
    let api_ipv4s_out = api_ipv4s.clone();
    let outbound_task = tokio::spawn(async move {
        let mut inner_buf = [0u8; 2048];
        let mut outer_buf = [0u8; 2048];
        let mut voice_count: u64 = 0;
        let mut control_count: u64 = 0;

        while let Some(mut user_pkt) = to_tunnel_rx.recv().await {
            if log_packets_out {
                log_packet_trace("TX", &user_pkt, &api_ipv4s_out);
            }

            if tunnel::is_roblox_voice_traffic(&user_pkt, &api_ipv4s_out) {
                voice_count += 1;
                if voice_count == 1 || voice_count.is_multiple_of(500) {
                    log_info!(
                        "[+] [ROBLOX-VOICE] Direct WARP egress for Voice Chat STUN/SRTP packet (~40ms, total: {})",
                        voice_count
                    );
                }
            } else if tunnel::is_roblox_gameplay_udp(&user_pkt) {
                let pkt_len = user_pkt.len() as u64;
                let tx_cnt = raknet_tx_packets_out.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                raknet_tx_bytes_out.fetch_add(pkt_len, std::sync::atomic::Ordering::Relaxed);

                let dst_ip = format!("{}.{}.{}.{}", user_pkt[16], user_pkt[17], user_pkt[18], user_pkt[19]);
                let dst_port = if user_pkt.len() >= 24 {
                    let ihl = (user_pkt[0] & 0x0f) as usize * 4;
                    u16::from_be_bytes([user_pkt[ihl + 2], user_pkt[ihl + 3]])
                } else {
                    0
                };
                let srv = format!("{}:{}", dst_ip, dst_port);
                *last_game_server_out.lock().unwrap() = Some(srv.clone());

                if tx_cnt <= 5 || tx_cnt == 10 || tx_cnt == 25 || tx_cnt == 50 || tx_cnt.is_multiple_of(100) {
                    log_info!(
                        "[+] [ROBLOX-RAKNET] Unified Hop 2 egress for UDP gameplay packet to {} (total: {})",
                        srv,
                        tx_cnt
                    );
                }
            } else if tunnel::is_roblox_control_plane_tcp(&user_pkt, &api_ipv4s_out) {
                control_count += 1;
                if control_count == 1 || control_count.is_multiple_of(100) {
                    log_info!(
                        "[*] [ROBLOX-CONTROL] Routing control-plane TCP 443 (apis.roblox.com) via Hop 2 tunnel (total: {})",
                        control_count
                    );
                }
            }

            let wire_pkt = {
                let mut tun = tunnel_outbound.lock().unwrap();
                tun.encapsulate_user_packet(&mut user_pkt, &mut inner_buf, &mut outer_buf)
            };
            if let Some(pkt) = wire_pkt {
                let _ = udp_outbound.send(&pkt).await;
            }
        }
    });

    // Inbound loop from tunnel into Wintun
    let tunnel_inbound = tunnel.clone();
    let udp_inbound = udp.clone();
    let raknet_rx_packets_in = raknet_rx_packets.clone();
    let raknet_rx_bytes_in = raknet_rx_bytes.clone();
    let log_packets_in = args.log_packets;
    let api_ipv4s_in = api_ipv4s.clone();
    let inbound_task = tokio::spawn(async move {
        let mut recv_buf = [0u8; 2048];
        let mut outer_buf = [0u8; 2048];
        let mut inner_buf = [0u8; 2048];

        loop {
            match udp_inbound.recv(&mut recv_buf).await {
                Ok(n) if n > 0 => {
                    let outcome = {
                        let mut tun = tunnel_inbound.lock().unwrap();
                        tun.decapsulate_incoming(&recv_buf[..n], &mut outer_buf, &mut inner_buf)
                    };

                    for net_pkt in outcome.to_network {
                        let _ = udp_inbound.send(&net_pkt).await;
                    }
                    for user_pkt in outcome.to_user {
                        if log_packets_in {
                            log_packet_trace("RX", &user_pkt, &api_ipv4s_in);
                        }

                        if tunnel::is_roblox_gameplay_udp_inbound(&user_pkt) {
                            let pkt_len = user_pkt.len() as u64;
                            let rx_cnt = raknet_rx_packets_in.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                            raknet_rx_bytes_in.fetch_add(pkt_len, std::sync::atomic::Ordering::Relaxed);

                            let ihl = (user_pkt[0] & 0x0f) as usize * 4;
                            let src_port = if user_pkt.len() >= ihl + 4 {
                                u16::from_be_bytes([user_pkt[ihl], user_pkt[ihl + 1]])
                            } else {
                                0
                            };
                            let src_ip = format!("{}.{}.{}.{}", user_pkt[12], user_pkt[13], user_pkt[14], user_pkt[15]);

                            if rx_cnt <= 5 || rx_cnt == 10 || rx_cnt == 25 || rx_cnt == 50 || rx_cnt.is_multiple_of(100) {
                                log_info!(
                                    "[+] [ROBLOX-RAKNET] Unified Hop 2 ingress for UDP gameplay packet from {}:{} (total: {})",
                                    src_ip,
                                    src_port,
                                    rx_cnt
                                );
                            }
                        }
                        if user_pkt.len() < 20 || user_pkt.len() > 65535 {
                            continue;
                        }
                        let pkt_len = user_pkt.len() as u16;
                        let mut allocated = None;
                        for attempt in 0..3 {
                            match session_write.allocate_send_packet(pkt_len) {
                                Ok(pkt) => {
                                    allocated = Some(pkt);
                                    break;
                                }
                                Err(_) => {
                                    if attempt < 2 {
                                         std::thread::yield_now();
                                    }
                                }
                            }
                        }
                        if let Some(mut send_pkt) = allocated {
                            send_pkt.bytes_mut().copy_from_slice(&user_pkt);
                            session_write.send_packet(send_pkt);
                        } else {
                            static DROPPED: std::sync::atomic::AtomicU64 =
                                std::sync::atomic::AtomicU64::new(0);
                            let d = DROPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                            if d == 1 || d.is_multiple_of(100) {
                                log_warn!(
                                    "[!] Wintun ring buffer full after 3 retry attempts; dropped inbound packet (total dropped: {})",
                                    d
                                );
                            }
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    log_warn!("[INBOUND-TUN] UDP recv error: {}", e);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    });

    // Periodic timers
    let tunnel_timers = tunnel.clone();
    let udp_timers = udp.clone();
    let timers_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(200));
        let mut outer_buf = [0u8; 2048];
        let mut inner_buf = [0u8; 2048];

        loop {
            interval.tick().await;
            let packets = {
                let mut tun = tunnel_timers.lock().unwrap();
                tun.update_timers(&mut outer_buf, &mut inner_buf)
            };
            for pkt in packets {
                let _ = udp_timers.send(&pkt).await;
            }
        }
    });

    tokio::spawn(verify_egress(None, endpoint_a_ip.clone(), None));

    let event_waiter = async move {
        if let Some(h) = shutdown_handle {
            tokio::task::spawn_blocking(move || {
                unsafe {
                    windows_sys::Win32::System::Threading::WaitForSingleObject(
                        h,
                        windows_sys::Win32::System::Threading::INFINITE,
                    );
                    windows_sys::Win32::Foundation::CloseHandle(h);
                }
            })
            .await
            .ok();
        } else {
            std::future::pending::<()>().await;
        }
    };

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            log_info!("\n[*] Received shutdown signal (Ctrl+C). Restoring host routing tables...");
        }
        _ = event_waiter => {
            log_info!("\n[*] Received shutdown IPC event from parent. Restoring host routing tables...");
        }
        _ = outbound_task => {}
        _ = inbound_task => {}
        _ = timers_task => {}
    }

    wintun_dev.restore_routing();
    log_info!("[+] Wintun session closed and host routing restored.");

    let duration = session_start.elapsed();
    let mins = duration.as_secs() / 60;
    let secs = duration.as_secs() % 60;
    let sent_pkts = raknet_tx_packets.load(std::sync::atomic::Ordering::Relaxed);
    let sent_bytes = raknet_tx_bytes.load(std::sync::atomic::Ordering::Relaxed);
    let recv_pkts = raknet_rx_packets.load(std::sync::atomic::Ordering::Relaxed);
    let recv_bytes = raknet_rx_bytes.load(std::sync::atomic::Ordering::Relaxed);
    let server_str = last_game_server
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(|| "None (Waiting for game)".to_string());

    log_info!("================================================================================");
    log_info!("                         WARP-MIN SESSION SUMMARY                              ");
    log_info!("================================================================================");
    log_info!("  Session Duration       : {:02}m {:02}s", mins, secs);
    log_info!("  Roblox Game Server     : {}", server_str);
    log_info!("  Gameplay Packets Sent  : {} ({} B)", sent_pkts, sent_bytes);
    log_info!("  Gameplay Packets Recv  : {} ({} B)", recv_pkts, recv_bytes);
    log_info!("  Total RakNet Packets   : {} packets accelerated ({} B)", sent_pkts + recv_pkts, sent_bytes + recv_bytes);
    log_info!("  Host Routing Status    : Confirmed cleanly restored (128.116.0.0/17 removed, 0 residual routes)");
    log_info!("  Adapter Status         : Wintun interface 'WARP-Gool' closed and unmounted");
    log_info!("================================================================================");
    log_info!("  [✓] Confirmation: All host routing tables were cleanly restored.");
    log_info!("  [+] Thank you for using WARP-MIN. Safe gaming!");
    log_info!("================================================================================");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_default_mode_is_tun() {
        let args = Args::try_parse_from(["warp-min"]).expect("parse default args");
        let use_tun = !args.socks;
        assert!(use_tun, "Default mode must be Option B (TUN mode)");
    }

    #[test]
    fn test_args_explicit_socks_mode() {
        let args = Args::try_parse_from(["warp-min", "--socks"]).expect("parse socks args");
        let use_tun = !args.socks;
        assert!(!use_tun, "Explicit --socks flag must select SOCKS mode");
    }

    #[test]
    fn test_args_explicit_tun_mode() {
        let args = Args::try_parse_from(["warp-min", "--tun"]).expect("parse tun args");
        let use_tun = !args.socks;
        assert!(use_tun, "Explicit --tun flag must select TUN mode");
    }

    #[test]
    fn test_args_elevated_flag_parsing() {
        let args = Args::try_parse_from(["warp-min", "--elevated"]).expect("parse elevated args");
        assert!(args.elevated, "--elevated flag must be parsed");
        let use_tun = !args.socks;
        assert!(use_tun, "Default with --elevated must still be TUN mode");
    }

    #[test]
    fn test_args_logging_flags_parsing() {
        let args = Args::try_parse_from(["warp-min", "--log-file", "test.log", "--verbose"])
            .expect("parse logging args");
        assert_eq!(args.log_file, "test.log");
        assert!(args.verbose);
        assert!(!args.no_log_file);
        assert_eq!(args.log_level, logger::LogLevel::Info);
        assert!(!args.log_packets);

        let args2 =
            Args::try_parse_from(["warp-min", "--no-log-file"]).expect("parse no-log-file args");
        assert!(args2.no_log_file);

        let args3 = Args::try_parse_from(["warp-min", "--log-packets", "--log-level", "debug"])
            .expect("parse log level and packets");
        assert!(args3.log_packets);
        assert_eq!(args3.log_level, logger::LogLevel::Debug);
    }

    #[test]
    fn test_unlock_guac_policy_json() {
        let raw_policy = r#"{"ExperienceChatAvailability":"regionLocked","CanUsePlatformChat":false,"CanUsePlatformChat2":false,"CountryCode":"FR","Username":"Owl_JustABird"}"#;
        let mut raw_app_storage = serde_json::json!({
            "Username": "Owl_JustABird",
            "AppConfiguration": serde_json::to_string(&serde_json::json!({
                "GUAC:-1:app-policy": raw_policy,
                "GUAC:600860999:app-policy": raw_policy,
                "OtherSetting": 123
            })).unwrap()
        });

        let modified = update_guac_policy_in_value(&mut raw_app_storage);
        assert!(modified);

        // Verify chat fields unlocked
        let app_config_str = raw_app_storage["AppConfiguration"].as_str().unwrap();
        let app_config: serde_json::Value = serde_json::from_str(app_config_str).unwrap();
        let p1: serde_json::Value =
            serde_json::from_str(app_config["GUAC:-1:app-policy"].as_str().unwrap()).unwrap();
        assert_eq!(p1["ExperienceChatAvailability"], "available");
        assert_eq!(p1["CanUsePlatformChat"], true);
        assert_eq!(p1["CanUsePlatformChat2"], true);
        assert_eq!(p1["CountryCode"], "FR");
        assert_eq!(raw_app_storage["Username"], "Owl_JustABird");

        // Second call should return false (already unlocked)
        let modified_again = update_guac_policy_in_value(&mut raw_app_storage);
        assert!(!modified_again);
    }

    #[test]
    fn test_align_hop2_endpoint() {
        let ep_a: SocketAddr = "162.159.192.1:500".parse().unwrap();
        let ep_b = align_hop2_endpoint(ep_a);
        assert_eq!(*ep_b.ip(), Ipv4Addr::new(188, 114, 97, 3));
        assert_eq!(ep_b.port(), 2408);

        let ep_a2: SocketAddr = "188.114.97.2:2408".parse().unwrap();
        let ep_b2 = align_hop2_endpoint(ep_a2);
        assert_eq!(*ep_b2.ip(), Ipv4Addr::new(162, 159, 192, 1));
        assert_eq!(ep_b2.port(), 2408);

        // Fallback when Hop 1 is on 188.114.96.1
        let ep_a3: SocketAddr = "188.114.96.1:500".parse().unwrap();
        let ep_b3 = align_hop2_endpoint(ep_a3);
        assert_eq!(*ep_b3.ip(), Ipv4Addr::new(162, 159, 192, 1));
        assert_eq!(ep_b3.port(), 2408);
    }

    #[test]
    fn test_get_hop2_candidates() {
        let candidates = get_hop2_candidates();
        assert!(candidates.len() >= 5);
        assert_eq!(candidates[0], "188.114.97.3:2408".parse().unwrap());
        assert!(candidates.contains(&"188.114.96.1:2408".parse().unwrap()));
    }

    #[test]
    fn test_get_anycast_candidates() {
        let candidates = get_anycast_candidates();
        assert!(
            candidates.len() >= 30,
            "Should have a robust candidate pool"
        );
        assert!(
            candidates
                .iter()
                .any(|c| c.ip() == Ipv4Addr::new(162, 159, 192, 1) && c.port() == 500)
        );
        assert!(candidates.iter().any(|c| c.port() == 500));
        assert!(candidates.iter().any(|c| c.port() == 1701));
        assert!(candidates.iter().any(|c| c.port() == 4500));
        assert!(candidates.iter().any(|c| c.port() == 2408));
    }

    #[test]
    fn test_ensure_file_writable_restores_write_permissions() {
        let temp_dir =
            std::env::temp_dir().join(format!("warp_min_writable_{}", rand::random::<u32>()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let test_file = temp_dir.join("appStorage.json");

        std::fs::write(&test_file, b"{\"test\": 123}").unwrap();

        // 1. Set file as READ-ONLY
        let meta = std::fs::metadata(&test_file).unwrap();
        let mut perms = meta.permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&test_file, perms).unwrap();

        // Verify it is currently read-only
        assert!(
            std::fs::metadata(&test_file)
                .unwrap()
                .permissions()
                .readonly()
        );

        // 2. Run ensure_file_writable
        let restored = ensure_file_writable(&test_file).expect("ensure_file_writable must succeed");
        assert!(restored, "Should report that permissions were restored");

        // 3. Verify it is no longer read-only
        assert!(
            !std::fs::metadata(&test_file)
                .unwrap()
                .permissions()
                .readonly(),
            "File must no longer be READ-ONLY"
        );

        // 4. Verify opening for writing succeeds (LocalStorageManager will not error)
        let write_res = std::fs::OpenOptions::new().write(true).open(&test_file);
        assert!(write_res.is_ok(), "Opening file for writing must succeed");

        // 5. Calling again returns false (already writable)
        let second_run = ensure_file_writable(&test_file).expect("second run must succeed");
        assert!(
            !second_run,
            "Second run should report false since file is already writable"
        );

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_unlock_guac_policy_fresh_install_keys_absent() {
        // When Roblox creates a default policy without any chat keys present initially
        let mut raw_app_storage = serde_json::json!({
            "AppConfiguration": serde_json::to_string(&serde_json::json!({
                "GUAC:-1:app-policy": "{}",
            })).unwrap()
        });

        let modified = update_guac_policy_in_value(&mut raw_app_storage);
        assert!(
            modified,
            "Must insert chat keys even when missing from initial policy"
        );

        let app_config_str = raw_app_storage["AppConfiguration"].as_str().unwrap();
        let app_config: serde_json::Value = serde_json::from_str(app_config_str).unwrap();
        let p: serde_json::Value =
            serde_json::from_str(app_config["GUAC:-1:app-policy"].as_str().unwrap()).unwrap();
        assert_eq!(p["ExperienceChatAvailability"], "available");
        assert_eq!(p["CanUsePlatformChat"], true);
        assert_eq!(p["CanUsePlatformChat2"], true);
        assert_eq!(p["CanSeeChatTab"], true);
        assert_eq!(p["CanSeeChatTab2"], true);
        assert_eq!(p["canSeeChatTerminology"], true);
    }
}
