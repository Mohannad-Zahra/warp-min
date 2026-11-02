use crate::api::WarpAccount;
use crate::tunnel::*;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use smoltcp::wire::{Ipv4Address, Ipv4Packet, TcpControl, TcpPacket, TcpRepr, UdpPacket};
use std::net::Ipv4Addr;

#[test]
fn test_build_ipv4_udp_packet_validity() {
    let src = Ipv4Addr::new(172, 16, 0, 2);
    let dst = Ipv4Addr::new(162, 159, 192, 1);
    let payload = b"hello wireguard handshake test payload";
    let pkt = build_ipv4_udp_packet(src, dst, 51820, 2408, payload);

    let ip_pkt = Ipv4Packet::new_checked(&pkt).expect("Valid IPv4 packet");
    assert_eq!(ip_pkt.src_addr(), Ipv4Address::new(172, 16, 0, 2));
    assert_eq!(ip_pkt.dst_addr(), Ipv4Address::new(162, 159, 192, 1));
    assert_eq!(ip_pkt.next_header(), smoltcp::wire::IpProtocol::Udp);

    let udp_pkt = UdpPacket::new_checked(ip_pkt.payload()).expect("Valid UDP packet");
    assert_eq!(udp_pkt.src_port(), 51820);
    assert_eq!(udp_pkt.dst_port(), 2408);
    assert_eq!(udp_pkt.payload(), payload);
    assert!(udp_pkt.verify_checksum(&ip_pkt.src_addr().into(), &ip_pkt.dst_addr().into()));
}

#[test]
fn test_update_checksum_rfc1624() {
    let identity = update_checksum_rfc1624(0x1234, 0xabcd, 0xabcd);
    assert_eq!(identity, 0x1234);
}

#[test]
fn test_clamp_tcp_mss_ipv4() {
    let src_ip = Ipv4Address::new(192, 168, 1, 100);
    let dst_ip = Ipv4Address::new(128, 116, 44, 3);

    let mut ip_buf = vec![0u8; 44];
    {
        let mut ip_pkt = smoltcp::wire::Ipv4Packet::new_unchecked(&mut ip_buf);
        ip_pkt.set_version(4);
        ip_pkt.set_header_len(20);
        ip_pkt.set_total_len(44);
        ip_pkt.set_next_header(smoltcp::wire::IpProtocol::Tcp);
        ip_pkt.set_hop_limit(64);
        ip_pkt.set_src_addr(src_ip);
        ip_pkt.set_dst_addr(dst_ip);
        ip_pkt.fill_checksum();

        let tcp_repr = TcpRepr {
            src_port: 49152,
            dst_port: 443,
            control: TcpControl::Syn,
            seq_number: smoltcp::wire::TcpSeqNumber(1000),
            ack_number: None,
            window_len: 65535,
            window_scale: None,
            max_seg_size: Some(1460),
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        };

        let mut tcp_pkt = TcpPacket::new_unchecked(ip_pkt.payload_mut());
        tcp_repr.emit(
            &mut tcp_pkt,
            &src_ip.into(),
            &dst_ip.into(),
            &smoltcp::phy::ChecksumCapabilities::default(),
        );
    }

    let check_tcp = TcpPacket::new_checked(&ip_buf[20..]).expect("Valid initial TCP packet");
    assert!(check_tcp.verify_checksum(&src_ip.into(), &dst_ip.into()));

    clamp_tcp_mss(&mut ip_buf, 1120);

    let clamped_tcp = TcpPacket::new_checked(&ip_buf[20..]).expect("Valid clamped TCP packet");
    let clamped_repr = TcpRepr::parse(
        &clamped_tcp,
        &src_ip.into(),
        &dst_ip.into(),
        &smoltcp::phy::ChecksumCapabilities::default(),
    )
    .expect("Valid parse");
    assert_eq!(clamped_repr.max_seg_size, Some(1120));
    assert!(
        clamped_tcp.verify_checksum(&src_ip.into(), &dst_ip.into()),
        "Incremental RFC 1624 checksum must verify"
    );
}

#[test]
fn test_clamp_tcp_mss_non_syn_ignored() {
    let src_ip = Ipv4Address::new(192, 168, 1, 100);
    let dst_ip = Ipv4Address::new(128, 116, 44, 3);

    let mut ip_buf = vec![0u8; 40];
    {
        let mut ip_pkt = smoltcp::wire::Ipv4Packet::new_unchecked(&mut ip_buf);
        ip_pkt.set_version(4);
        ip_pkt.set_header_len(20);
        ip_pkt.set_total_len(40);
        ip_pkt.set_next_header(smoltcp::wire::IpProtocol::Tcp);
        ip_pkt.set_hop_limit(64);
        ip_pkt.set_src_addr(src_ip);
        ip_pkt.set_dst_addr(dst_ip);
        ip_pkt.fill_checksum();

        let tcp_repr = TcpRepr {
            src_port: 49152,
            dst_port: 443,
            control: TcpControl::None,
            seq_number: smoltcp::wire::TcpSeqNumber(1001),
            ack_number: Some(smoltcp::wire::TcpSeqNumber(5000)),
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        };

        let mut tcp_pkt = TcpPacket::new_unchecked(ip_pkt.payload_mut());
        tcp_repr.emit(
            &mut tcp_pkt,
            &src_ip.into(),
            &dst_ip.into(),
            &smoltcp::phy::ChecksumCapabilities::default(),
        );
    }

    let orig = ip_buf.clone();
    clamp_tcp_mss(&mut ip_buf, 1120);
    assert_eq!(ip_buf, orig, "Non-SYN packet must remain untouched");
}

#[test]
fn test_is_roblox_gameplay_udp() {
    let src = Ipv4Addr::new(172, 16, 0, 2);
    let dst_game = Ipv4Addr::new(128, 116, 44, 3);
    let valid_gameplay = build_ipv4_udp_packet(src, dst_game, 51820, 58000, b"raknet_payload");
    assert!(
        is_roblox_gameplay_udp(&valid_gameplay),
        "UDP port 58000 on 128.116.44.3 must be recognized as Roblox gameplay"
    );

    let boundary_gameplay = build_ipv4_udp_packet(src, dst_game, 51820, 1024, b"raknet_payload");
    assert!(
        is_roblox_gameplay_udp(&boundary_gameplay),
        "UDP port 1024 must be recognized as Roblox gameplay"
    );

    let below_boundary = build_ipv4_udp_packet(src, dst_game, 51820, 1023, b"raknet_payload");
    assert!(
        !is_roblox_gameplay_udp(&below_boundary),
        "Privileged UDP port 1023 must NOT be recognized as Roblox gameplay"
    );
}

#[test]
fn test_is_roblox_control_plane_tcp() {
    let src = Ipv4Addr::new(172, 16, 0, 2);
    let dst_control = Ipv4Addr::new(128, 116, 5, 3);
    let control_ips = vec![dst_control];
    let mut ip_buf = vec![0u8; 40];
    ip_buf[0] = 0x45;
    ip_buf[2..4].copy_from_slice(&40u16.to_be_bytes());
    ip_buf[9] = 6;
    ip_buf[12..16].copy_from_slice(&src.octets());
    ip_buf[16..20].copy_from_slice(&dst_control.octets());
    ip_buf[22..24].copy_from_slice(&443u16.to_be_bytes());

    assert!(is_roblox_control_plane_tcp(&ip_buf, &control_ips));

    ip_buf[22..24].copy_from_slice(&80u16.to_be_bytes());
    assert!(!is_roblox_control_plane_tcp(&ip_buf, &control_ips));
}

#[test]
fn test_is_roblox_voice_traffic() {
    let src = Ipv4Addr::new(172, 16, 0, 2);
    let dst_voice = Ipv4Addr::new(128, 116, 10, 10);
    let voice_ips = vec![dst_voice];
    let pkt = build_ipv4_udp_packet(src, dst_voice, 51820, 3478, b"voice_payload");
    assert!(is_roblox_voice_traffic(&pkt, &voice_ips));

    let pkt5349 = build_ipv4_udp_packet(src, dst_voice, 51820, 5349, b"voice_payload");
    assert!(is_roblox_voice_traffic(&pkt5349, &voice_ips));

    let other_ip = Ipv4Addr::new(1, 1, 1, 1);
    let pkt_not_voice = build_ipv4_udp_packet(src, other_ip, 51820, 80, b"other");
    assert!(!is_roblox_voice_traffic(&pkt_not_voice, &[]));
}

#[test]
fn test_snat_outbound_and_inbound() {
    let acc1 = WarpAccount {
        id: "test1".into(),
        token: "tok1".into(),
        private_key: BASE64_STANDARD.encode([1u8; 32]),
        public_key: BASE64_STANDARD.encode([2u8; 32]),
        peer_public_key: BASE64_STANDARD.encode([3u8; 32]),
        peer_endpoint: "162.159.192.1:500".into(),
        local_ipv4: "172.16.0.2".into(),
        local_ipv6: "".into(),
        reserved: [0, 0, 0],
    };
    let acc2 = WarpAccount {
        id: "test2".into(),
        token: "tok2".into(),
        private_key: BASE64_STANDARD.encode([4u8; 32]),
        public_key: BASE64_STANDARD.encode([5u8; 32]),
        peer_public_key: BASE64_STANDARD.encode([6u8; 32]),
        peer_endpoint: "188.114.97.3:2408".into(),
        local_ipv4: "172.16.0.2".into(),
        local_ipv6: "".into(),
        reserved: [0, 0, 0],
    };
    let mut tunnel =
        DualHopTunnel::new(&acc1, &acc2, "162.159.192.1:500", "188.114.97.3:2408").unwrap();

    let orig_src = Ipv4Addr::new(10, 2, 0, 2);
    let dst_ip = Ipv4Addr::new(128, 116, 31, 33);
    let src_port = 55555u16;
    let dst_port = 57341u16;
    let payload = b"ROBLOX_UDP_TEST";
    let mut pkt = build_ipv4_udp_packet(orig_src, dst_ip, src_port, dst_port, payload);

    let target_ip = tunnel.hop2_ip;
    let mut outer_buf = [0u8; 2048];
    let mut inner_buf = [0u8; 2048];
    let _ = tunnel.encapsulate_user_packet(&mut pkt, &mut inner_buf, &mut outer_buf);

    let rewritten_s_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    assert_eq!(rewritten_s_ip, target_ip);
    assert_eq!(tunnel.snat_map.get(&src_port), Some(&orig_src));

    let reply_payload = b"ROBLOX_UDP_REPLY";
    let mut reply_pkt = build_ipv4_udp_packet(dst_ip, target_ip, dst_port, src_port, reply_payload);
    tunnel.apply_inbound_snat(&mut reply_pkt);

    let restored_dst = Ipv4Addr::new(reply_pkt[16], reply_pkt[17], reply_pkt[18], reply_pkt[19]);
    assert_eq!(restored_dst, orig_src);
}

#[test]
fn test_handshake_gate_blocks_tunnel_when_unestablished() {
    let kp1 = crate::api::generate_keypair();
    let kp2 = crate::api::generate_keypair();
    let kp3 = crate::api::generate_keypair();

    let dummy_acc1 = WarpAccount {
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
    let dummy_acc2 = WarpAccount {
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

    assert!(
        !crate::verify_tunnel_handshake_health(&tunnel),
        "Tunnel health gate MUST return false before handshakes complete"
    );
}
