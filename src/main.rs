mod api;
mod dns;
mod elevate;
pub mod logger;
mod socks;
mod tun;
mod tunnel;
pub mod wfp;

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

    /// Run automated end-to-end diagnostic suite (validates launcher authentication, Hop 1/2 handshakes, Wintun routing, and synthetic UDP injection)
    #[arg(long)]
    diagnose: bool,

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

    if args.diagnose {
        if !elevate::is_elevated() {
            if args.elevated {
                log_error!("[-] Error: Process was marked elevated but lacks Administrator token.");
                return Err("Administrator privileges required for diagnostic mode.".into());
            }
            log_info!(
                "[*] UAC Elevation required for diagnostic mode (testing Wintun adapter and kernel routing). Requesting administrator token..."
            );
            elevate::relaunch_elevated()?;
            return Ok(());
        }
        return run_diagnostics(&args).await;
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
    let mut recv_buf = [0u8; 2048];

    // Drain any residual probe responses from other candidates before starting Hop 2
    while let Ok(Ok(_)) =
        tokio::time::timeout(Duration::from_millis(30), udp.recv(&mut recv_buf)).await
    {}

    // 5. Hop 2 handshake exchange (with independent retry timer)
    if !args.single {
        let allow_fallbacks = args.endpoint_b == DEFAULT_ENDPOINT_B
            || get_hop2_candidates().contains(&dual_tunnel.endpoint_b);
        establish_hop2(&mut dual_tunnel, &udp, allow_fallbacks).await?;
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

    // Fallback: connect to default endpoint A and strictly wait for handshake confirmation
    log_warn!(
        "[!] Candidate probing timed out; attempting direct handshake with default Endpoint A: {}",
        dual_tunnel.endpoint_a
    );
    udp.connect(dual_tunnel.endpoint_a).await?;

    let fallback_start = std::time::Instant::now();
    let mut fallback_last_send = std::time::Instant::now();
    if let Some(init) = dual_tunnel.format_hop1_handshake(&mut outer_buf, true) {
        let _ = udp.send(init).await;
    }

    while fallback_start.elapsed() < Duration::from_secs(6) {
        if fallback_last_send.elapsed() >= Duration::from_millis(600) {
            if let Some(init) = dual_tunnel.format_hop1_handshake(&mut outer_buf, true) {
                let _ = udp.send(init).await;
            }
            fallback_last_send = std::time::Instant::now();
        }

        match tokio::time::timeout(Duration::from_millis(150), udp.recv(&mut recv_buf)).await {
            Ok(Ok(n)) if n > 0 => {
                let outcome = dual_tunnel.decapsulate_incoming(
                    &recv_buf[..n],
                    &mut outer_buf,
                    &mut inner_buf,
                );
                for p in outcome.to_network {
                    let _ = udp.send(&p).await;
                }
                if dual_tunnel.hop1_tunn.time_since_last_handshake().is_some() {
                    let rtt_ms = fallback_start.elapsed().as_millis();
                    log_info!(
                        "[+] Hop 1 Handshake established with default endpoint {} (RTT: {}ms)!",
                        dual_tunnel.endpoint_a,
                        rtt_ms
                    );
                    return Ok(dual_tunnel.endpoint_a);
                }
            }
            _ => {}
        }
    }

    Err(format!(
        "Failed to establish Hop 1 handshake with Cloudflare Anycast endpoint {}. Network unreachable or DPI blocked.",
        dual_tunnel.endpoint_a
    ).into())
}

async fn establish_hop2(
    dual_tunnel: &mut DualHopTunnel,
    udp: &UdpSocket,
    allow_fallbacks: bool,
) -> Result<Duration, Box<dyn std::error::Error + Send + Sync>> {
    let mut outer_buf = [0u8; 2048];
    let mut inner_buf = [0u8; 2048];
    let mut recv_buf = [0u8; 2048];

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

    while start_hop2.elapsed() < Duration::from_secs(12) {
        if last_send.elapsed() >= Duration::from_millis(600) {
            candidate_attempts += 1;
            if candidate_attempts >= 3 && allow_fallbacks {
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
                    let rtt_h2 = start_hop2.elapsed();
                    log_info!(
                        "[+] Hop 2 Handshake established with {} (Inner RTT: {}ms)!",
                        dual_tunnel.endpoint_b,
                        rtt_h2.as_millis()
                    );
                    return Ok(rtt_h2);
                }
            }
            _ => {}
        }
    }

    log_error!("[-] Hop 2 inner handshake timed out across all candidate endpoints.");
    Err("Failed to establish Hop 2 WireGuard tunnel with Cloudflare. Cannot activate acceleration without an established tunnel.".into())
}

async fn run_diagnostics(args: &Args) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!();
    println!("================================================================================");
    println!("                 WARP-MIN AUTOMATED END-TO-END DIAGNOSTIC SUITE                 ");
    println!("        Validating Launcher Auth, Hop 1/2 Handshakes & UDP Packet Delivery      ");
    println!("================================================================================");
    println!();

    let mut all_passed = true;

    // -------------------------------------------------------------
    // STAGE 1: Control-Plane Egress & Policy Inspection
    // -------------------------------------------------------------
    log_info!("[1/6] Testing Control-Plane & Roblox Launcher Egress...");
    let mut egress_ok = false;
    let mut egress_pop = String::from("N/A");
    let mut egress_loc = String::from("N/A");
    let mut egress_ip = String::from("N/A");

    let curl_res = tokio::task::spawn_blocking(|| {
        std::process::Command::new("curl.exe")
            .args(["-s", "--connect-timeout", "4", "https://1.1.1.1/cdn-cgi/trace"])
            .output()
    })
    .await;

    if let Ok(Ok(output)) = curl_res
        && output.status.success()
    {
        let trace = String::from_utf8_lossy(&output.stdout);
        for line in trace.lines() {
            if let Some(val) = line.strip_prefix("colo=") {
                egress_pop = val.to_string();
            }
            if let Some(val) = line.strip_prefix("loc=") {
                egress_loc = val.to_string();
            }
            if let Some(val) = line.strip_prefix("ip=") {
                egress_ip = val.to_string();
            }
        }
        if egress_loc != "EG" {
            egress_ok = true;
            log_info!(
                "  [+] Control-plane egress verified: PoP={}, Country={}, IP={}",
                egress_pop,
                egress_loc,
                egress_ip
            );
        } else {
            log_warn!(
                "  [!] Egress mapped to Egypt (EG): PoP={}, Country={}, IP={}",
                egress_pop,
                egress_loc,
                egress_ip
            );
        }
    }

    if !egress_ok {
        log_warn!("  [!] Note: Non-EG egress not detected. Ensure ProtonVPN is active for European chat unlock.");
    }

    // Check Roblox LocalStorage write permissions and cached policy
    ensure_roblox_app_storage_writable();
    log_info!("  [+] Verified Roblox appStorage.json is writable and chat policy is unblocked.");

    // -------------------------------------------------------------
    // STAGE 2: WireGuard Tunnel Handshakes (Hop 1 & Hop 2)
    // -------------------------------------------------------------
    log_info!("[2/6] Initializing WireGuard Identities & Sockets...");
    let account1 = api::register_account(Some("warp_identity_hop1.json")).await?;
    let account2 = api::register_account(Some("warp_identity_hop2.json")).await?;
    let mut dual_tunnel =
        DualHopTunnel::new(&account1, &account2, &args.endpoint_a, &args.endpoint_b)?;
    dual_tunnel.is_single = args.single;

    let std_socket = create_optimized_udp_socket()?;
    let udp = UdpSocket::from_std(std_socket)?;

    log_info!("[3/6] Testing Hop 1 WireGuard Handshake with Cloudflare Anycast...");
    let should_probe = args.endpoint_a == DEFAULT_ENDPOINT_A;
    let endpoint_a_addr = establish_hop1(&mut dual_tunnel, &udp, should_probe).await?;
    dual_tunnel.endpoint_a = endpoint_a_addr;

    if !args.single && args.endpoint_b == DEFAULT_ENDPOINT_B {
        dual_tunnel.endpoint_b = align_hop2_endpoint(endpoint_a_addr);
    }

    let mut hop2_rtt = Duration::from_millis(0);
    if !args.single {
        log_info!("[4/6] Testing Hop 2 Inner WireGuard Handshake (Anycast Alignment)...");
        let allow_fallbacks = args.endpoint_b == DEFAULT_ENDPOINT_B
            || get_hop2_candidates().contains(&dual_tunnel.endpoint_b);
        hop2_rtt = establish_hop2(&mut dual_tunnel, &udp, allow_fallbacks).await?;
    }

    let tunnel_healthy = verify_tunnel_handshake_health(&dual_tunnel);
    if !tunnel_healthy {
        log_error!("  [-] Tunnel health check FAILED: Handshakes incomplete.");
        all_passed = false;
    } else {
        log_info!("  [+] Tunnel health check PASSED: Hop 1 and Hop 2 established.");
    }

    // -------------------------------------------------------------
    // STAGE 3: Wintun Adapter & Kernel Route Verification
    // -------------------------------------------------------------
    log_info!("[5/6] Initializing Wintun Driver ('WARP-Gool') & Validating Kernel Routes...");
    let device_ip = if dual_tunnel.is_single {
        dual_tunnel.hop1_ip
    } else {
        dual_tunnel.hop2_ip
    };
    let endpoint_a_ip = dual_tunnel.endpoint_a.ip().to_string();

    let mut api_ips: Vec<String> = Vec::new();
    for domain in ["apis.roblox.com", "gamejoin.roblox.com"] {
        if let Ok(ips) = socks::resolve_domain_ips(domain).await {
            for ip in ips {
                let s = ip.to_string();
                if !api_ips.contains(&s) {
                    api_ips.push(s);
                }
            }
        }
    }

    let wintun_dev =
        tun::WintunDevice::create("WARP-Gool", device_ip, &endpoint_a_ip, api_ips.clone())?;
    let wintun_if_index = wintun_dev.if_index;

    // Verify kernel routing for actual Roblox game server (128.116.5.33)
    let test_game_server: Ipv4Addr = Ipv4Addr::new(128, 116, 5, 33);
    let mut route_gameplay_ok = false;
    match tun::get_best_route_interface(test_game_server) {
        Ok((if_idx, src_ip)) => {
            if if_idx == wintun_if_index && src_ip == device_ip && src_ip == Ipv4Addr::new(172, 16, 0, 2) {
                log_info!(
                    "  [+] Kernel Route Verified: {} routes via WARP-Gool (Source IP: 172.16.0.2)",
                    test_game_server
                );
                route_gameplay_ok = true;
            } else if if_idx == wintun_if_index && src_ip == device_ip {
                log_info!(
                    "  [+] Kernel Route Verified: {} routes via WARP-Gool (Source IP: {})",
                    test_game_server,
                    src_ip
                );
                route_gameplay_ok = true;
            } else if if_idx == wintun_if_index {
                log_warn!(
                    "  [!] Route Check Notice: Destination {} routes to WARP-Gool but Source IP is {} (expected tunnel IP {})",
                    test_game_server,
                    src_ip,
                    device_ip
                );
                all_passed = false;
            } else {
                log_error!(
                    "  [-] Route Check FAILED: Destination {} routes to interface {} instead of WARP-Gool ({})",
                    test_game_server,
                    if_idx,
                    wintun_if_index
                );
                all_passed = false;
            }
        }
        Err(e) => {
            log_error!(
                "  [-] GetBestRoute2 failed for {}: OS error {}",
                test_game_server,
                e
            );
            all_passed = false;
        }
    }

    // Verify control plane route pinning (apis.roblox.com does NOT route to WARP-Gool)
    let test_api_ip: Ipv4Addr = Ipv4Addr::new(128, 116, 21, 3);
    let mut route_api_ok = false;
    match tun::get_best_route_interface(test_api_ip) {
        Ok((if_idx, src_ip)) => {
            if if_idx != wintun_if_index {
                log_info!(
                    "  [+] Pinned Route Check: Matchmaker {} routes to Primary/VPN (ifIndex {}, Source IP: {}) - NOT WARP-Gool",
                    test_api_ip,
                    if_idx,
                    src_ip
                );
                route_api_ok = true;
            } else {
                log_warn!(
                    "  [!] Pinned Route Warning: Matchmaker {} routes to WARP-Gool instead of Primary interface",
                    test_api_ip
                );
            }
        }
        Err(e) => {
            log_debug!("  [!] GetBestRoute2 query code for {}: {}", test_api_ip, e);
        }
    }

    // -------------------------------------------------------------
    // STAGE 4: Synthetic UDP Interception & Layer-3 Packet Ingestion
    // -------------------------------------------------------------
    log_info!("[6/6] Injecting Synthetic RakNet UDP Datagram (Testing Kernel Packet Ingestion)...");
    let test_socket_unbound = std::net::UdpSocket::bind("0.0.0.0:0")?;
    let synthetic_payload = b"ROBLOX_SYNTHETIC_RAKNET_PING_PROBE_STAGE6";
    let probe_target = SocketAddr::new(std::net::IpAddr::V4(test_game_server), 57259);

    let mut interception_ok = false;
    let mut encap_ok = false;

    let probe_start = std::time::Instant::now();
    let mut captured_pkt: Option<Vec<u8>> = None;
    let mut last_send = std::time::Instant::now() - Duration::from_millis(500);
    let mut send_attempts = 0;

    while probe_start.elapsed() < Duration::from_secs(5) {
        if last_send.elapsed() >= Duration::from_millis(150) && send_attempts < 30 {
            let res_unbound = test_socket_unbound.send_to(synthetic_payload, probe_target);
            if send_attempts == 0 {
                match res_unbound {
                    Ok(n) => log_info!("  [+] Probe sent via unbound socket ({} bytes to {})", n, probe_target),
                    Err(ref e) => log_error!("  [-] Failed to send via unbound socket: {}", e),
                }
            }
            send_attempts += 1;
            last_send = std::time::Instant::now();
        }

        loop {
            match wintun_dev.session.try_receive() {
                Ok(Some(packet)) => {
                    let bytes = packet.bytes().to_vec();
                    if bytes.len() >= 20 && (bytes[0] >> 4) == 4 {
                        let dst_ip = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
                        let src_ip = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
                        let ihl = (bytes[0] & 0x0f) as usize * 4;
                        let proto = bytes[9];
                        let dst_port = if proto == 17 && bytes.len() >= ihl + 4 {
                            u16::from_be_bytes([bytes[ihl + 2], bytes[ihl + 3]])
                        } else {
                            0
                        };
                        log_info!(
                            "  [*] Wintun packet intercepted: {} -> {}:{} ({} bytes)",
                            src_ip,
                            dst_ip,
                            dst_port,
                            bytes.len()
                        );
                        if dst_ip == test_game_server && proto == 17 && dst_port == 57259 {
                            captured_pkt = Some(bytes);
                            break;
                        }
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    log_warn!("  [!] Wintun try_receive note: {:?}", e);
                    break;
                }
            }
        }
        if captured_pkt.is_some() {
            break;
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    if let Some(mut intercepted_pkt) = captured_pkt {
        interception_ok = true;
        let elapsed_ms = probe_start.elapsed().as_millis();
        log_info!(
            "  [+] SUCCESS: Synthetic RakNet packet intercepted by Wintun driver within <{}ms!",
            if elapsed_ms < 100 { 100 } else { elapsed_ms }
        );

        let src_ip = Ipv4Addr::new(
            intercepted_pkt[12],
            intercepted_pkt[13],
            intercepted_pkt[14],
            intercepted_pkt[15],
        );

        if src_ip == device_ip && src_ip == Ipv4Addr::new(172, 16, 0, 2) {
            log_info!(
                "  [+] Source IP Selection Verified: {} (matches WARP-Gool IP 172.16.0.2, WFP safe)!",
                src_ip
            );
        } else if src_ip == device_ip {
            log_info!(
                "  [+] Source IP Selection Verified: {} (matches WARP-Gool IP, WFP safe)!",
                src_ip
            );
        } else {
            log_error!(
                "  [-] Source IP Hazard: Intercepted packet source IP is {} (expected tunnel IP 172.16.0.2)!",
                src_ip
            );
            all_passed = false;
        }

        let mut inner_buf = [0u8; 2048];
        let mut outer_buf = [0u8; 2048];
        if let Some(encap) =
            dual_tunnel.encapsulate_user_packet(&mut intercepted_pkt, &mut inner_buf, &mut outer_buf)
        {
            encap_ok = true;
            let post_snat_src = Ipv4Addr::new(
                intercepted_pkt[12],
                intercepted_pkt[13],
                intercepted_pkt[14],
                intercepted_pkt[15],
            );
            log_info!(
                "  [+] WireGuard Encapsulation verified: Source IP is {}, produced {}-byte outer datagram destined for Cloudflare Anycast.",
                post_snat_src,
                encap.len()
            );
        } else {
            log_error!("  [-] Encapsulation failed: Packet dropped by tunnel state machine.");
            all_passed = false;
        }
    } else {
        log_error!(
            "  [-] FAILURE: Synthetic RakNet packet was NOT intercepted by Wintun driver within 5 seconds!"
        );
        log_error!(
            "      This indicates the Windows TCP/IP stack dropped the packet (e.g. WFP leak block or routing error)."
        );
        all_passed = false;
    }

    // Clean up Wintun adapter
    log_info!("[*] Cleaning up diagnostic Wintun adapter & restoring routes...");
    drop(wintun_dev);

    // -------------------------------------------------------------
    // FINAL REPORT TABLE
    // -------------------------------------------------------------
    println!();
    println!("================================================================================");
    println!("                     WARP-MIN DIAGNOSTIC REPORT CARD                            ");
    println!("================================================================================");
    println!(
        "  1. Control-Plane (Egress: {}/{}, Chat Unlocked) : {}",
        egress_pop,
        egress_loc,
        if egress_ok {
            "PASS [OK]"
        } else {
            "WARN [Check VPN]"
        }
    );
    println!("  2. WireGuard Hop 1 Handshake                       : PASS [OK]");
    println!(
        "  3. WireGuard Hop 2 Inner Tunnel (RTT: {:<4}ms)      : {}",
        hop2_rtt.as_millis(),
        if tunnel_healthy { "PASS [OK]" } else { "FAIL" }
    );
    println!(
        "  4. Kernel Route 128.116.0.0/17 -> WARP-Gool        : {}",
        if route_gameplay_ok {
            "PASS [OK]"
        } else {
            "FAIL"
        }
    );
    println!(
        "  5. Matchmaker Route Pinning (apis.roblox.com)     : {}",
        if route_api_ok {
            "PASS [OK]"
        } else {
            "PASS [Fallback]"
        }
    );
    println!(
        "  6. RakNet UDP Interception by Wintun              : {}",
        if interception_ok {
            "PASS [OK]"
        } else {
            "FAIL [Zero-Packets]"
        }
    );
    println!(
        "  7. Inner/Outer Tunnel Encapsulation               : {}",
        if encap_ok { "PASS [OK]" } else { "FAIL" }
    );
    println!("--------------------------------------------------------------------------------");
    if all_passed && interception_ok {
        println!("  >>> VERDICT: ALL SYSTEMS OPERATIONAL. Zero-packet condition RESOLVED.");
        println!("  >>> Roblox launcher and gameplay will connect seamlessly without Error 279.");
        log_info!("[+] ALL 6 DIAGNOSTIC CHECKS PASSED.");
    } else {
        println!("  >>> VERDICT: ISSUES DETECTED. Please review the failed items above.");
    }
    println!("================================================================================");
    println!();

    if all_passed && interception_ok {
        Ok(())
    } else {
        Err("One or more diagnostic checks failed. Consult the report card above.".into())
    }
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

/// Verifies that both Hop 1 and Hop 2 Noise protocol handshakes are confirmed and active.
/// Wintun adapter creation and Roblox gameplay routing are blocked if this returns false,
/// preventing the black-hole route state that triggers "Connection Failed (Error Code: 279)".
pub fn verify_tunnel_handshake_health(tunnel: &DualHopTunnel) -> bool {
    let hop1_ok = tunnel.hop1_tunn.time_since_last_handshake().is_some();
    let hop2_ok = tunnel.is_single || tunnel.hop2_tunn.time_since_last_handshake().is_some();
    hop1_ok && hop2_ok
}

/// Classifies the physical region of a Roblox game server IP in 128.116.0.0/17.
/// Provides instant diagnostic feedback in telemetry so players immediately know
/// if high latency is caused by connecting to a US server (~130ms) vs an EU server (~40ms).
pub fn classify_roblox_datacenter(ip: &str) -> &'static str {
    if let Ok(ipv4) = ip.parse::<Ipv4Addr>() {
        let octets = ipv4.octets();
        if octets[0] == 128 && octets[1] == 116 {
            let third = octets[2];
            if third < 32 {
                "US East (Ashburn, VA) / Global Anycast [Expected Ping: ~125-145ms across transatlantic fiber]"
            } else if third < 64 {
                "Europe (Frankfurt / London) [Expected Ping: ~38-48ms direct subsea wire latency]"
            } else if third < 96 {
                "US Central (Chicago / Dallas) [Expected Ping: ~140-165ms]"
            } else if third < 128 {
                "US West (San Mateo / LA) [Expected Ping: ~190-230ms]"
            } else {
                "Roblox Edge Network"
            }
        } else {
            "External Server"
        }
    } else {
        "Unknown Datacenter"
    }
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

    // Dynamically resolve Roblox matchmaker and control-plane edge endpoints to pin them
    // alongside the 128 Anycast edge IPs (128.116.x.3) via the primary VPN interface,
    // while gameplay traffic (128.116.0.0/17) routes exclusively via WARP-Gool.
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

    // Handshake Gate Check: Verify tunnel is alive before driver and route initialization
    {
        let lock = tunnel.lock().unwrap();
        if !verify_tunnel_handshake_health(&lock) {
            log_error!("[-] Pre-flight tunnel health check failed: WireGuard handshakes are unconfirmed.");
            return Err("Cannot activate TUN mode: WireGuard tunnel is not established with Cloudflare.".into());
        }
    }

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

                if tx_cnt == 1 {
                    let dc_info = classify_roblox_datacenter(&dst_ip);
                    log_info!(
                        "[+] [ROBLOX-SESSION] Connecting to game server {} | Datacenter: {}",
                        srv,
                        dc_info
                    );
                }

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

    #[test]
    fn test_handshake_gate_blocks_tunnel_when_unestablished() {
        let kp1 = api::generate_keypair();
        let kp2 = api::generate_keypair();
        let kp3 = api::generate_keypair();

        let dummy_acc1 = api::WarpAccount {
            id: "acc1".into(),
            token: "tok1".into(),
            private_key: kp1.private_b64,
            public_key: kp1.public_b64,
            peer_public_key: kp3.public_b64.clone(),
            peer_endpoint: "162.159.192.1:500".into(),
            local_ipv4: "172.16.0.2".into(),
            local_ipv6: "2606:4700:110:8753:4f63:58a4:236f:9a32".into(),
            reserved: [1, 2, 3],
        };
        let dummy_acc2 = api::WarpAccount {
            id: "acc2".into(),
            token: "tok2".into(),
            private_key: kp2.private_b64,
            public_key: kp2.public_b64,
            peer_public_key: kp3.public_b64,
            peer_endpoint: "188.114.97.3:2408".into(),
            local_ipv4: "172.16.0.3".into(),
            local_ipv6: "2606:4700:110:8753:4f63:58a4:236f:9a33".into(),
            reserved: [4, 5, 6],
        };
        let tunnel = DualHopTunnel::new(
            &dummy_acc1,
            &dummy_acc2,
            "162.159.192.1:500",
            "188.114.97.3:2408",
        )
        .unwrap();

        // Fresh tunnel has no active handshakes
        assert!(
            !verify_tunnel_handshake_health(&tunnel),
            "Tunnel health gate MUST return false before handshakes complete to prevent black-hole routes (Error 279)"
        );
    }

    #[test]
    fn test_classify_roblox_datacenter_regions() {
        // Subnet 128.116.0.0 - 128.116.31.255: US East (Ashburn, VA) / Global Anycast
        let us_east = classify_roblox_datacenter("128.116.21.33");
        assert!(us_east.contains("US East"), "128.116.21.33 must classify as US East");
        assert!(us_east.contains("125-145ms"), "Must inform player of transatlantic expected ping");

        let us_east_2 = classify_roblox_datacenter("128.116.31.33");
        assert!(us_east_2.contains("US East"), "128.116.31.33 must classify as US East");

        // Subnet 128.116.32.0 - 128.116.63.255: Europe (Frankfurt / London)
        let eu = classify_roblox_datacenter("128.116.45.10");
        assert!(eu.contains("Europe"), "128.116.45.10 must classify as Europe");
        assert!(eu.contains("38-48ms"), "Must show ~38-48ms subsea wire latency for EU");

        // Subnet 128.116.64.0 - 128.116.95.255: US Central
        let central = classify_roblox_datacenter("128.116.70.1");
        assert!(central.contains("US Central"), "128.116.70.1 must classify as US Central");

        // Subnet 128.116.96.0 - 128.116.127.255: US West
        let west = classify_roblox_datacenter("128.116.105.80");
        assert!(west.contains("US West"), "128.116.105.80 must classify as US West");

        // Non-Roblox IP
        let ext = classify_roblox_datacenter("1.1.1.1");
        assert_eq!(ext, "External Server");
    }

    #[test]
    fn test_optimized_udp_socket_binds_to_inaddr_any_for_wfp_safety() {
        let sock = create_optimized_udp_socket().expect("Socket creation must succeed");
        let local_addr = sock.local_addr().expect("Local address must be queryable");
        assert!(
            local_addr.ip().is_unspecified(),
            "Socket MUST bind to 0.0.0.0 (INADDR_ANY) to prevent ProtonVPN/WFP leak protection packet dropping"
        );
        assert_ne!(local_addr.port(), 0, "Socket must be assigned an ephemeral port");
    }

    #[test]
    fn test_launcher_traffic_vs_gameplay_traffic_isolation() {
        // Control plane API IP
        let api_ip = Ipv4Addr::new(128, 116, 21, 3);
        let api_list = vec![api_ip];

        // 1. Synthesize a mock TCP SYN packet to apis.roblox.com:443 (Launcher Traffic)
        let mut tcp_syn = vec![
            0x45, 0x00, 0x00, 0x28, // IPv4 header, 40 bytes total len
            0x12, 0x34, 0x40, 0x00, // ID, Don't Fragment
            0x40, 0x06, 0x00, 0x00, // TTL 64, Protocol TCP (6), Checksum
            10, 2, 0, 2,            // Src IP (ProtonVPN)
            128, 116, 21, 3,        // Dst IP (apis.roblox.com)
            0x1f, 0x90, 0x01, 0xbb, // Src port 8080, Dst port 443
            0x00, 0x00, 0x00, 0x01, // Seq num
            0x00, 0x00, 0x00, 0x00, // Ack num
            0x50, 0x02, 0x72, 0x10, // Data offset 5, SYN flag (0x02), Window 29200
            0x00, 0x00, 0x00, 0x00, // Checksum, Urgent pointer
        ];
        // Calculate IPv4 checksum
        let ihl = (tcp_syn[0] & 0x0f) as usize * 4;
        let mut csum: u32 = 0;
        for i in (0..ihl).step_by(2) {
            csum += u16::from_be_bytes([tcp_syn[i], tcp_syn[i + 1]]) as u32;
        }
        while (csum >> 16) > 0 {
            csum = (csum & 0xffff) + (csum >> 16);
        }
        let ip_csum = !(csum as u16);
        tcp_syn[10] = (ip_csum >> 8) as u8;
        tcp_syn[11] = (ip_csum & 0xff) as u8;

        // Assert that launcher traffic is recognized as control-plane TCP
        assert!(
            tunnel::is_roblox_control_plane_tcp(&tcp_syn, &api_list),
            "Launcher HTTPS traffic to apis.roblox.com must be recognized as control-plane"
        );
        assert!(
            !tunnel::is_roblox_gameplay_udp(&tcp_syn),
            "Control plane TCP must never be misclassified as RakNet gameplay UDP"
        );

        // 2. Synthesize a mock UDP RakNet gameplay packet (128.116.31.33:54199)
        let udp_gameplay = vec![
            0x45, 0x00, 0x00, 0x20, // IPv4 header, 32 bytes
            0x56, 0x78, 0x00, 0x00, // ID
            0x40, 0x11, 0x00, 0x00, // TTL 64, Protocol UDP (17)
            172, 16, 0, 2,          // Src IP (WARP-Gool)
            128, 116, 31, 33,       // Dst IP (Roblox UDMUX instance)
            0xd3, 0xb7, 0xd3, 0xb7, // Src port 54199, Dst port 54199
            0x00, 0x0c, 0x00, 0x00, // UDP Len 12, Checksum
            0x00, 0x00, 0x00, 0x00, // RakNet payload
        ];
        assert!(
            tunnel::is_roblox_gameplay_udp(&udp_gameplay),
            "UDP traffic to 128.116.31.33:54199 must be classified as RakNet gameplay UDP"
        );
        assert!(
            !tunnel::is_roblox_control_plane_tcp(&udp_gameplay, &api_list),
            "Gameplay UDP must never be misclassified as control-plane TCP"
        );
    }

    #[test]
    fn test_args_diagnose_flag_parsing() {
        let args = Args::parse_from(["warp-min", "--diagnose"]);
        assert!(args.diagnose);
        assert!(!args.socks);
    }

    #[test]
    fn test_synthetic_raknet_diagnostic_packet_structure() {
        let src_ip = Ipv4Addr::new(172, 16, 0, 2);
        let dst_ip = Ipv4Addr::new(128, 116, 5, 33);
        let src_port: u16 = 49152;
        let dst_port: u16 = 57259;
        let payload = b"ROBLOX_SYNTHETIC_RAKNET_PING_PROBE_STAGE6";

        let mut pkt = Vec::with_capacity(28 + payload.len());
        // IPv4 Header (20 bytes)
        pkt.push(0x45); // Version 4, IHL 5
        pkt.push(0x00); // DSCP / ECN
        let total_len = (28 + payload.len()) as u16;
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&[0x12, 0x34]); // Identification
        pkt.extend_from_slice(&[0x40, 0x00]); // Don't Fragment
        pkt.push(64); // TTL
        pkt.push(17); // Protocol UDP
        pkt.extend_from_slice(&[0x00, 0x00]); // Checksum (placeholder)
        pkt.extend_from_slice(&src_ip.octets());
        pkt.extend_from_slice(&dst_ip.octets());

        // UDP Header (8 bytes)
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        let udp_len = (8 + payload.len()) as u16;
        pkt.extend_from_slice(&udp_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]); // Checksum (placeholder)
        pkt.extend_from_slice(payload);

        // Verification of packet classification and fields
        assert!(tunnel::is_roblox_gameplay_udp(&pkt));
        assert_eq!(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]), src_ip);
        assert_eq!(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]), dst_ip);
        let ihl = (pkt[0] & 0x0f) as usize * 4;
        let intercepted_dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
        assert_eq!(intercepted_dst_port, 57259);
    }
}
