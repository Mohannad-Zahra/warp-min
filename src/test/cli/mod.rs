use crate::Args;
use crate::create_optimized_udp_socket;
use crate::logger;
use crate::tunnel;
use clap::Parser;
use std::net::Ipv4Addr;

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
fn test_args_patch_storage_flag_parsing() {
    let args = Args::try_parse_from(["warp-min"]).expect("parse default args");
    assert!(
        !args.patch_storage,
        "patch_storage must be false by default for safety"
    );

    let args2 = Args::try_parse_from(["warp-min", "--patch-storage"]).expect("parse opt-in flag");
    assert!(
        args2.patch_storage,
        "--patch-storage flag must enable storage patching"
    );
}

#[test]
fn test_args_diagnose_flag_parsing() {
    let args = Args::parse_from(["warp-min", "--diagnose"]);
    assert!(args.diagnose);
    assert!(!args.socks);
}

#[test]
fn test_optimized_udp_socket_binds_to_inaddr_any_for_wfp_safety() {
    let sock = create_optimized_udp_socket().expect("Socket creation must succeed");
    let local_addr = sock.local_addr().expect("Local address must be queryable");
    assert!(
        local_addr.ip().is_unspecified(),
        "Socket MUST bind to 0.0.0.0 (INADDR_ANY) to prevent ProtonVPN/WFP leak protection packet dropping"
    );
    assert_ne!(
        local_addr.port(),
        0,
        "Socket must be assigned an ephemeral port"
    );
}

#[test]
fn test_launcher_traffic_vs_gameplay_traffic_isolation() {
    let api_ip = Ipv4Addr::new(128, 116, 21, 3);
    let api_list = vec![api_ip];

    // 1. Synthesize a mock TCP SYN packet to apis.roblox.com:443 (Launcher Traffic)
    let mut tcp_syn = vec![
        0x45, 0x00, 0x00, 0x28, // IPv4 header, 40 bytes total len
        0x12, 0x34, 0x40, 0x00, // ID, Don't Fragment
        0x40, 0x06, 0x00, 0x00, // TTL 64, Protocol TCP (6), Checksum
        10, 2, 0, 2, // Src IP (ProtonVPN)
        128, 116, 21, 3, // Dst IP (apis.roblox.com)
        0x1f, 0x90, 0x01, 0xbb, // Src port 8080, Dst port 443
        0x00, 0x00, 0x00, 0x01, // Seq num
        0x00, 0x00, 0x00, 0x00, // Ack num
        0x50, 0x02, 0x72, 0x10, // Data offset 5, SYN flag (0x02), Window 29200
        0x00, 0x00, 0x00, 0x00, // Checksum, Urgent pointer
    ];
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
        172, 16, 0, 2, // Src IP (WARP-Gool)
        128, 116, 31, 33, // Dst IP (Roblox UDMUX instance)
        0xd3, 0xb7, 0xd3, 0xb7, // Src port 54199, Dst port 54199
        0x00, 0x0c, 0x00, 0x00, // UDP Len 12, Checksum
        0x00, 0x00, 0x00, 0x00, // RakNet payload
    ];
    assert!(
        tunnel::is_roblox_gameplay_udp(&udp_gameplay),
        "UDP gameplay traffic to 128.116.31.33 must be recognized as RakNet"
    );
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

    assert!(tunnel::is_roblox_gameplay_udp(&pkt));
    assert_eq!(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]), src_ip);
    assert_eq!(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]), dst_ip);
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    let intercepted_dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
    assert_eq!(intercepted_dst_port, 57259);
}
