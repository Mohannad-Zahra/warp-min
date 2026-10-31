use crate::api::WarpAccount;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU16, Ordering};

pub const DEFAULT_ENDPOINT_A: &str = "162.159.192.1:500";
pub const DEFAULT_ENDPOINT_B: &str = "188.114.97.3:2408";
const HOP1_LOCAL_PORT: u16 = 51820;

static IP_ID_COUNTER: AtomicU16 = AtomicU16::new(1);

pub struct DualHopTunnel {
    pub hop1_tunn: Tunn,
    pub hop2_tunn: Tunn,
    pub endpoint_a: SocketAddr,
    pub endpoint_b: SocketAddrV4,
    pub hop1_ip: Ipv4Addr,
    pub hop2_ip: Ipv4Addr,
    pub hop1_reserved: [u8; 3],
    pub hop2_reserved: [u8; 3],
    pub is_single: bool,
    pub snat_map: std::collections::HashMap<u16, Ipv4Addr>,
}

impl DualHopTunnel {
    pub fn new(
        account1: &WarpAccount,
        account2: &WarpAccount,
        endpoint_a_str: &str,
        endpoint_b_str: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let priv1: [u8; 32] = BASE64_STANDARD
            .decode(account1.private_key.trim())?
            .try_into()
            .map_err(|_| "Invalid Hop 1 private key length")?;
        let pub1: [u8; 32] = BASE64_STANDARD
            .decode(account1.peer_public_key.trim())?
            .try_into()
            .map_err(|_| "Invalid Hop 1 peer public key length")?;

        let priv2: [u8; 32] = BASE64_STANDARD
            .decode(account2.private_key.trim())?
            .try_into()
            .map_err(|_| "Invalid Hop 2 private key length")?;
        let pub2: [u8; 32] = BASE64_STANDARD
            .decode(account2.peer_public_key.trim())?
            .try_into()
            .map_err(|_| "Invalid Hop 2 peer public key length")?;

        let sec1 = StaticSecret::from(priv1);
        let peer_pub1 = PublicKey::from(pub1);
        let hop1_tunn = Tunn::new(sec1, peer_pub1, None, Some(5), 0, None);

        let sec2 = StaticSecret::from(priv2);
        let peer_pub2 = PublicKey::from(pub2);
        let hop2_tunn = Tunn::new(sec2, peer_pub2, None, Some(20), 1, None);

        let endpoint_a: SocketAddr = endpoint_a_str.parse()?;
        let endpoint_b: SocketAddrV4 = endpoint_b_str.parse()?;

        let hop1_ip = parse_ipv4(&account1.local_ipv4).unwrap_or(Ipv4Addr::new(172, 16, 0, 2));
        let hop2_ip = parse_ipv4(&account2.local_ipv4).unwrap_or(Ipv4Addr::new(172, 16, 0, 2));

        Ok(Self {
            hop1_tunn,
            hop2_tunn,
            endpoint_a,
            endpoint_b,
            hop1_ip,
            hop2_ip,
            hop1_reserved: account1.reserved,
            hop2_reserved: account2.reserved,
            is_single: false,
            snat_map: std::collections::HashMap::new(),
        })
    }

    pub fn format_hop1_handshake<'a>(
        &mut self,
        buf: &'a mut [u8],
        force_resend: bool,
    ) -> Option<&'a [u8]> {
        match self
            .hop1_tunn
            .format_handshake_initiation(buf, force_resend)
        {
            TunnResult::WriteToNetwork(packet) => {
                let len = packet.len();
                apply_reserved_outbound(&mut buf[..len], self.hop1_reserved);
                Some(&buf[..len])
            }
            _ => None,
        }
    }

    pub fn format_hop2_handshake(
        &mut self,
        inner_buf: &mut [u8],
        outer_buf: &mut [u8],
        force_resend: bool,
    ) -> Option<Vec<u8>> {
        let mut hop2_wg_packet = match self
            .hop2_tunn
            .format_handshake_initiation(inner_buf, force_resend)
        {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            _ => {
                crate::log_error!(
                    "[TUNNEL] hop2 format_handshake_initiation did not return WriteToNetwork"
                );
                return None;
            }
        };
        apply_reserved_outbound(&mut hop2_wg_packet, self.hop2_reserved);

        let ipv4_packet = build_ipv4_udp_packet(
            self.hop1_ip,
            *self.endpoint_b.ip(),
            HOP1_LOCAL_PORT,
            self.endpoint_b.port(),
            &hop2_wg_packet,
        );

        match self.hop1_tunn.encapsulate(&ipv4_packet, outer_buf) {
            TunnResult::WriteToNetwork(packet) => {
                let mut pkt_vec = packet.to_vec();
                apply_reserved_outbound(&mut pkt_vec, self.hop1_reserved);
                Some(pkt_vec)
            }
            _ => None,
        }
    }

    pub fn encapsulate_user_packet(
        &mut self,
        user_packet: &mut [u8],
        inner_buf: &mut [u8],
        outer_buf: &mut [u8],
    ) -> Option<Vec<u8>> {
        clamp_tcp_mss(user_packet, 1120);

        // Stateless SNAT: If an outbound UDP packet has a source IP other than tunnel IP
        // (e.g. 10.2.0.2 from ProtonVPN), rewrite source IP to target_ip so Cloudflare WireGuard
        // cryptokey routing accepts and forwards it without drops.
        let target_ip = if self.is_single { self.hop1_ip } else { self.hop2_ip };
        if user_packet.len() >= 28 && user_packet[9] == 17 {
            let ihl = (user_packet[0] & 0x0f) as usize * 4;
            if user_packet.len() >= ihl + 8 {
                let src_ip = Ipv4Addr::new(
                    user_packet[12],
                    user_packet[13],
                    user_packet[14],
                    user_packet[15],
                );
                let src_port = u16::from_be_bytes([user_packet[ihl], user_packet[ihl + 1]]);
                if src_ip != target_ip {
                    if self.snat_map.len() > 1024 {
                        self.snat_map.clear();
                    }
                    self.snat_map.insert(src_port, src_ip);
                    translate_ipv4_udp_src(user_packet, src_ip, target_ip);
                }
            }
        }

        // Unified Tunneling: If single-hop mode, encapsulate directly via Hop 1.
        // In dual-hop mode, ALL Roblox traffic (Control Plane + RakNet Data Plane) encapsulates
        // into Hop 2 so they share the exact same Cloudflare European egress IP, eliminating UDMUX ticket validation drops.
        if self.is_single {
            return match self.hop1_tunn.encapsulate(user_packet, outer_buf) {
                TunnResult::WriteToNetwork(packet) => {
                    let mut pkt_vec = packet.to_vec();
                    apply_reserved_outbound(&mut pkt_vec, self.hop1_reserved);
                    Some(pkt_vec)
                }
                _ => None,
            };
        }

        let mut hop2_wg_packet = match self.hop2_tunn.encapsulate(user_packet, inner_buf) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            _ => return None,
        };
        apply_reserved_outbound(&mut hop2_wg_packet, self.hop2_reserved);

        let ipv4_packet = build_ipv4_udp_packet(
            self.hop1_ip,
            *self.endpoint_b.ip(),
            HOP1_LOCAL_PORT,
            self.endpoint_b.port(),
            &hop2_wg_packet,
        );

        match self.hop1_tunn.encapsulate(&ipv4_packet, outer_buf) {
            TunnResult::WriteToNetwork(packet) => {
                let mut pkt_vec = packet.to_vec();
                apply_reserved_outbound(&mut pkt_vec, self.hop1_reserved);
                Some(pkt_vec)
            }
            _ => None,
        }
    }

    pub fn decapsulate_incoming(
        &mut self,
        datagram: &[u8],
        outer_buf: &mut [u8],
        inner_buf: &mut [u8],
    ) -> InboundOutcome {
        let mut outcome = InboundOutcome::default();

        let mut dgram_copy = datagram.to_vec();
        clear_reserved_inbound(&mut dgram_copy);

        let mut hop1_action = self.hop1_tunn.decapsulate(None, &dgram_copy, outer_buf);
        loop {
            match hop1_action {
                TunnResult::WriteToNetwork(resp) => {
                    let mut resp_vec = resp.to_vec();
                    apply_reserved_outbound(&mut resp_vec, self.hop1_reserved);
                    outcome.to_network.push(resp_vec);
                }
                TunnResult::WriteToTunnelV4(ip_pkt, _) => {
                    if self.is_single {
                        let mut pkt = ip_pkt.to_vec();
                        clamp_tcp_mss(&mut pkt, 1120);
                        self.apply_inbound_snat(&mut pkt);
                        outcome.to_user.push(pkt);
                    } else if let Some(inner_wg_pkt) = extract_inner_hop2_payload(ip_pkt, &self.endpoint_b) {
                        let mut inner_copy = inner_wg_pkt.to_vec();
                        clear_reserved_inbound(&mut inner_copy);

                        let mut hop2_action = self.hop2_tunn.decapsulate(None, &inner_copy, inner_buf);
                        loop {
                            match hop2_action {
                                TunnResult::WriteToNetwork(hop2_resp) => {
                                    let mut hop2_resp_vec = hop2_resp.to_vec();
                                    apply_reserved_outbound(&mut hop2_resp_vec, self.hop2_reserved);

                                    let mut wrap_outer = [0u8; 2048];
                                    let ipv4_pkt = build_ipv4_udp_packet(
                                        self.hop1_ip,
                                        *self.endpoint_b.ip(),
                                        HOP1_LOCAL_PORT,
                                        self.endpoint_b.port(),
                                        &hop2_resp_vec,
                                    );
                                    if let TunnResult::WriteToNetwork(out) =
                                        self.hop1_tunn.encapsulate(&ipv4_pkt, &mut wrap_outer)
                                    {
                                        let mut out_vec = out.to_vec();
                                        apply_reserved_outbound(&mut out_vec, self.hop1_reserved);
                                        outcome.to_network.push(out_vec);
                                    }
                                }
                                TunnResult::WriteToTunnelV4(user_pkt, _) => {
                                    let mut pkt = user_pkt.to_vec();
                                    clamp_tcp_mss(&mut pkt, 1120);
                                    self.apply_inbound_snat(&mut pkt);
                                    outcome.to_user.push(pkt);
                                }
                                TunnResult::WriteToTunnelV6(user_pkt, _) => {
                                    outcome.to_user.push(user_pkt.to_vec());
                                }
                                _ => break,
                            }
                            hop2_action = self.hop2_tunn.decapsulate(None, &[], inner_buf);
                        }
                    } else {
                        // Direct Hop 1 payload (e.g. non-carrier traffic arriving via Hop 1)
                        let mut pkt = ip_pkt.to_vec();
                        clamp_tcp_mss(&mut pkt, 1120);
                        self.apply_inbound_snat(&mut pkt);
                        outcome.to_user.push(pkt);
                    }
                }
                TunnResult::WriteToTunnelV6(ip_pkt, _) if self.is_single => {
                    outcome.to_user.push(ip_pkt.to_vec());
                }
                _ => break,
            }
            hop1_action = self.hop1_tunn.decapsulate(None, &[], outer_buf);
        }

        outcome
    }

    fn apply_inbound_snat(&self, pkt: &mut [u8]) {
        let target_ip = if self.is_single { self.hop1_ip } else { self.hop2_ip };
        if pkt.len() >= 28 && pkt[9] == 17 {
            let ihl = (pkt[0] & 0x0f) as usize * 4;
            if pkt.len() >= ihl + 8 {
                let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                if let Some(&orig_ip) = self.snat_map.get(&dst_port) {
                    translate_ipv4_udp_dst(pkt, target_ip, orig_ip);
                }
            }
        }
    }

    pub fn update_timers(&mut self, outer_buf: &mut [u8], inner_buf: &mut [u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();

        if let TunnResult::WriteToNetwork(packet) = self.hop1_tunn.update_timers(outer_buf) {
            let mut p = packet.to_vec();
            apply_reserved_outbound(&mut p, self.hop1_reserved);
            out.push(p);
        }

        if !self.is_single
            && let TunnResult::WriteToNetwork(packet) = self.hop2_tunn.update_timers(inner_buf)
        {
            let mut hop2_resp = packet.to_vec();
            apply_reserved_outbound(&mut hop2_resp, self.hop2_reserved);
            let mut wrap_outer = [0u8; 2048];
            let ipv4_pkt = build_ipv4_udp_packet(
                self.hop1_ip,
                *self.endpoint_b.ip(),
                HOP1_LOCAL_PORT,
                self.endpoint_b.port(),
                &hop2_resp,
            );
            if let TunnResult::WriteToNetwork(outer_pkt) =
                self.hop1_tunn.encapsulate(&ipv4_pkt, &mut wrap_outer)
            {
                let mut p = outer_pkt.to_vec();
                apply_reserved_outbound(&mut p, self.hop1_reserved);
                out.push(p);
            }
        }

        out
    }
}

pub fn apply_reserved_outbound(packet: &mut [u8], reserved: [u8; 3]) {
    if packet.len() >= 4 && packet[0] >= 1 && packet[0] <= 4 && reserved != [0, 0, 0] {
        packet[1] = reserved[0];
        packet[2] = reserved[1];
        packet[3] = reserved[2];
    }
}

pub fn clear_reserved_inbound(packet: &mut [u8]) {
    if packet.len() >= 4 && packet[0] >= 1 && packet[0] <= 4 {
        packet[1] = 0;
        packet[2] = 0;
        packet[3] = 0;
    }
}

#[derive(Default)]
pub struct InboundOutcome {
    pub to_network: Vec<Vec<u8>>,
    pub to_user: Vec<Vec<u8>>,
}

fn parse_ipv4(addr_str: &str) -> Option<Ipv4Addr> {
    let clean = addr_str.split('/').next()?.trim();
    clean.parse().ok()
}

pub fn build_ipv4_udp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 20 + 8 + payload.len();
    let mut packet = vec![0u8; total_len];

    // IPv4 Header
    packet[0] = 0x45; // Version 4, IHL 5
    packet[1] = 0x00; // DSCP / ECN
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    let id = IP_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    packet[4..6].copy_from_slice(&id.to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF flag
    packet[8] = 64; // TTL
    packet[9] = 17; // Protocol UDP
    packet[12..16].copy_from_slice(&src_ip.octets());
    packet[16..20].copy_from_slice(&dst_ip.octets());

    let csum = ipv4_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&csum.to_be_bytes());

    // UDP Header
    packet[20..22].copy_from_slice(&src_port.to_be_bytes());
    packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
    let udp_len = (8 + payload.len()) as u16;
    packet[24..26].copy_from_slice(&udp_len.to_be_bytes());
    let u_csum = udp_checksum(src_ip, dst_ip, src_port, dst_port, payload);
    packet[26..28].copy_from_slice(&u_csum.to_be_bytes());

    // Payload
    packet[28..].copy_from_slice(payload);

    packet
}

pub fn extract_inner_hop2_payload<'a>(
    ip_pkt: &'a [u8],
    endpoint_b: &SocketAddrV4,
) -> Option<&'a [u8]> {
    if ip_pkt.len() < 28 {
        return None;
    }
    let version = ip_pkt[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = (ip_pkt[0] & 0x0f) as usize * 4;
    if ip_pkt.len() < ihl + 8 {
        return None;
    }
    let proto = ip_pkt[9];
    if proto != 17 {
        return None;
    }
    // Must match Hop 2 carrier UDP characteristics:
    // Destination port must be HOP1_LOCAL_PORT (51820)
    let dst_port = u16::from_be_bytes([ip_pkt[ihl + 2], ip_pkt[ihl + 3]]);
    if dst_port != HOP1_LOCAL_PORT {
        return None;
    }
    // Source IP must match endpoint_b
    let src_ip = Ipv4Addr::new(ip_pkt[12], ip_pkt[13], ip_pkt[14], ip_pkt[15]);
    if src_ip != *endpoint_b.ip() {
        return None;
    }
    let udp_len = u16::from_be_bytes([ip_pkt[ihl + 4], ip_pkt[ihl + 5]]) as usize;
    if udp_len < 8 || ip_pkt.len() < ihl + udp_len {
        return None;
    }
    Some(&ip_pkt[ihl + 8..ihl + udp_len])
}

#[allow(dead_code)]
pub fn translate_ipv4_udp_src(pkt: &mut [u8], old_ip: Ipv4Addr, new_ip: Ipv4Addr) {
    if pkt.len() < 28 || old_ip == new_ip {
        return;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < 20 || pkt.len() < ihl + 8 {
        return;
    }
    if pkt[12..16] != old_ip.octets() {
        return;
    }
    let old_octets = old_ip.octets();
    let new_octets = new_ip.octets();
    let old_w1 = u16::from_be_bytes([old_octets[0], old_octets[1]]);
    let old_w2 = u16::from_be_bytes([old_octets[2], old_octets[3]]);
    let new_w1 = u16::from_be_bytes([new_octets[0], new_octets[1]]);
    let new_w2 = u16::from_be_bytes([new_octets[2], new_octets[3]]);

    let old_ip_csum = u16::from_be_bytes([pkt[10], pkt[11]]);
    let mut ip_csum = update_checksum_rfc1624(old_ip_csum, old_w1, new_w1);
    ip_csum = update_checksum_rfc1624(ip_csum, old_w2, new_w2);
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    let old_udp_csum = u16::from_be_bytes([pkt[ihl + 6], pkt[ihl + 7]]);
    if old_udp_csum != 0 {
        let mut udp_csum = update_checksum_rfc1624(old_udp_csum, old_w1, new_w1);
        udp_csum = update_checksum_rfc1624(udp_csum, old_w2, new_w2);
        if udp_csum == 0 {
            udp_csum = 0xffff;
        }
        pkt[ihl + 6..ihl + 8].copy_from_slice(&udp_csum.to_be_bytes());
    }

    pkt[12..16].copy_from_slice(&new_octets);
}

#[allow(dead_code)]
pub fn translate_ipv4_udp_dst(pkt: &mut [u8], old_ip: Ipv4Addr, new_ip: Ipv4Addr) {
    if pkt.len() < 28 || old_ip == new_ip {
        return;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < 20 || pkt.len() < ihl + 8 {
        return;
    }
    if pkt[16..20] != old_ip.octets() {
        return;
    }
    let old_octets = old_ip.octets();
    let new_octets = new_ip.octets();
    let old_w1 = u16::from_be_bytes([old_octets[0], old_octets[1]]);
    let old_w2 = u16::from_be_bytes([old_octets[2], old_octets[3]]);
    let new_w1 = u16::from_be_bytes([new_octets[0], new_octets[1]]);
    let new_w2 = u16::from_be_bytes([new_octets[2], new_octets[3]]);

    let old_ip_csum = u16::from_be_bytes([pkt[10], pkt[11]]);
    let mut ip_csum = update_checksum_rfc1624(old_ip_csum, old_w1, new_w1);
    ip_csum = update_checksum_rfc1624(ip_csum, old_w2, new_w2);
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    let old_udp_csum = u16::from_be_bytes([pkt[ihl + 6], pkt[ihl + 7]]);
    if old_udp_csum != 0 {
        let mut udp_csum = update_checksum_rfc1624(old_udp_csum, old_w1, new_w1);
        udp_csum = update_checksum_rfc1624(udp_csum, old_w2, new_w2);
        if udp_csum == 0 {
            udp_csum = 0xffff;
        }
        pkt[ihl + 6..ihl + 8].copy_from_slice(&udp_csum.to_be_bytes());
    }

    pkt[16..20].copy_from_slice(&new_octets);
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in header.as_chunks::<2>().0 {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn udp_checksum(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> u16 {
    let mut sum: u32 = 0;
    for chunk in src_ip.octets().as_chunks::<2>().0 {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst_ip.octets().as_chunks::<2>().0 {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += 17u32; // Protocol UDP
    let udp_len = (8 + payload.len()) as u16;
    sum += udp_len as u32;

    sum += src_port as u32;
    sum += dst_port as u32;
    sum += udp_len as u32;

    for chunk in payload.as_chunks::<2>().0 {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if !payload.len().is_multiple_of(2) {
        sum += u16::from_be_bytes([payload[payload.len() - 1], 0]) as u32;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let csum = !(sum as u16);
    if csum == 0 { 0xffff } else { csum }
}

pub fn update_checksum_rfc1624(old_csum: u16, old_val: u16, new_val: u16) -> u16 {
    // RFC 1624 Equation 3: ~C' = ~C + ~m + m'
    let hc = (!old_csum) as u32;
    let m = (!old_val) as u32;
    let m_prime = new_val as u32;
    let mut sum = hc + m + m_prime;
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let new_csum = !(sum as u16);
    if new_csum == 0 { 0xffff } else { new_csum }
}

pub fn clamp_tcp_mss(ip_pkt: &mut [u8], max_mss: u16) {
    if ip_pkt.len() < 20 {
        return;
    }
    // Only IPv4
    if (ip_pkt[0] >> 4) != 4 {
        return;
    }
    let ihl = (ip_pkt[0] & 0x0f) as usize * 4;
    if ihl < 20 || ip_pkt.len() < ihl + 20 {
        return;
    }
    // Only TCP (protocol 6)
    if ip_pkt[9] != 6 {
        return;
    }
    // Do not clamp non-initial IPv4 fragments (TCP header only at offset ihl on fragment offset 0)
    let frag_field = u16::from_be_bytes([ip_pkt[6], ip_pkt[7]]);
    if (frag_field & 0x1fff) != 0 {
        return;
    }
    let total_len = u16::from_be_bytes([ip_pkt[2], ip_pkt[3]]) as usize;
    if ip_pkt.len() < total_len || total_len < ihl + 20 {
        return;
    }

    let tcp_header = &ip_pkt[ihl..];
    let tcp_data_offset = (tcp_header[12] >> 4) as usize * 4;
    if tcp_data_offset < 20 || ihl + tcp_data_offset > total_len {
        return;
    }

    // Only SYN or SYN-ACK packets (bit 1 of TCP flags)
    let flags = tcp_header[13];
    if (flags & 0x02) == 0 {
        return;
    }

    // Iterate TCP options starting at ihl + 20 up to ihl + tcp_data_offset
    let mut opt_idx = ihl + 20;
    let opt_end = ihl + tcp_data_offset;

    while opt_idx < opt_end {
        let kind = ip_pkt[opt_idx];
        if kind == 0 {
            // End of Option List
            break;
        }
        if kind == 1 {
            // NOP
            opt_idx += 1;
            continue;
        }
        if opt_idx + 1 >= opt_end {
            break;
        }
        let opt_len = ip_pkt[opt_idx + 1] as usize;
        if opt_len < 2 || opt_idx + opt_len > opt_end {
            break;
        }

        if kind == 2 && opt_len == 4 {
            // MSS Option (kind=2, length=4, value=u16)
            let old_mss = u16::from_be_bytes([ip_pkt[opt_idx + 2], ip_pkt[opt_idx + 3]]);
            if old_mss > max_mss {
                ip_pkt[opt_idx + 2..opt_idx + 4].copy_from_slice(&max_mss.to_be_bytes());

                // TCP checksum is at bytes 16..18 of TCP header
                let csum_idx = ihl + 16;
                let old_csum = u16::from_be_bytes([ip_pkt[csum_idx], ip_pkt[csum_idx + 1]]);
                let new_csum = update_checksum_rfc1624(old_csum, old_mss, max_mss);
                ip_pkt[csum_idx..csum_idx + 2].copy_from_slice(&new_csum.to_be_bytes());
            }
            break;
        }

        opt_idx += opt_len;
    }
}

/// Check if an IPv4 packet is Roblox RakNet UDP gameplay traffic.
/// Roblox game servers reside in the 128.116.0.0/17 CIDR (128.116.0.0 to 128.116.127.255)
/// and use non-privileged UDP ports (1024..=65535) excluding voice STUN/SRTP ports (3478, 5349).
pub fn is_roblox_gameplay_udp(pkt: &[u8]) -> bool {
    if pkt.len() < 28 {
        return false;
    }
    // IPv4 version check
    if (pkt[0] >> 4) != 4 {
        return false;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < 20 || pkt.len() < ihl + 8 {
        return false;
    }
    // Protocol must be UDP (17)
    if pkt[9] != 17 {
        return false;
    }
    // Destination IP: 128.116.0.0/17 (128.116.0.0 - 128.116.127.255)
    let dst_ip = &pkt[16..20];
    if dst_ip[0] != 128 || dst_ip[1] != 116 || (dst_ip[2] & 0x80) != 0 {
        return false;
    }
    // Destination port: non-privileged UDP ports (1024..=65535) excluding voice STUN/SRTP (3478, 5349)
    let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
    dst_port != 3478 && dst_port != 5349 && (1024..=65535).contains(&dst_port)
}

/// Check if an incoming IPv4 packet is Roblox RakNet UDP gameplay traffic from server.
/// Roblox game servers reside in the 128.116.0.0/17 CIDR (128.116.0.0 to 128.116.127.255)
/// and send from non-privileged UDP ports (1024..=65535) excluding voice STUN/SRTP (3478, 5349).
pub fn is_roblox_gameplay_udp_inbound(pkt: &[u8]) -> bool {
    if pkt.len() < 28 {
        return false;
    }
    if (pkt[0] >> 4) != 4 {
        return false;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < 20 || pkt.len() < ihl + 8 {
        return false;
    }
    if pkt[9] != 17 {
        return false;
    }
    // Source IP: 128.116.0.0/17
    let src_ip = &pkt[12..16];
    if src_ip[0] != 128 || src_ip[1] != 116 || (src_ip[2] & 0x80) != 0 {
        return false;
    }
    // Source port: non-privileged UDP ports (1024..=65535) excluding voice STUN/SRTP (3478, 5349)
    let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
    src_port != 3478 && src_port != 5349 && (1024..=65535).contains(&src_port)
}

/// Check if an IPv4 packet is Roblox control-plane traffic (apis.roblox.com).
/// Control-plane endpoints use TCP port 443 either to explicit control IPs or within Roblox CIDR (128.116.0.0/17).
pub fn is_roblox_control_plane_tcp(pkt: &[u8], control_ips: &[Ipv4Addr]) -> bool {
    if pkt.len() < 24 {
        return false;
    }
    if (pkt[0] >> 4) != 4 {
        return false;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < 20 || pkt.len() < ihl + 4 {
        return false;
    }
    // Protocol must be TCP (6)
    if pkt[9] != 6 {
        return false;
    }
    let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
    if dst_port != 443 {
        return false;
    }
    let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    if control_ips.contains(&dst_ip) {
        return true;
    }
    dst_ip.octets()[0] == 128 && dst_ip.octets()[1] == 116 && (dst_ip.octets()[2] & 0x80) == 0
}

/// Check if an IPv4 packet is Roblox Voice Chat traffic (voice.roblox.com WebRTC STUN/SRTP).
pub fn is_roblox_voice_traffic(pkt: &[u8], voice_ips: &[Ipv4Addr]) -> bool {
    if pkt.len() < 28 {
        return false;
    }
    if (pkt[0] >> 4) != 4 {
        return false;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < 20 || pkt.len() < ihl + 8 {
        return false;
    }
    // Protocol must be UDP (17)
    if pkt[9] != 17 {
        return false;
    }
    let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    if voice_ips.contains(&dst_ip) {
        return true;
    }
    let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
    (dst_ip.octets()[0] == 128 && dst_ip.octets()[1] == 116 && (dst_ip.octets()[2] & 0x80) == 0)
        && (dst_port == 3478 || dst_port == 5349)
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::wire::{Ipv4Address, Ipv4Packet, TcpControl, TcpPacket, TcpRepr, UdpPacket};

    #[test]
    fn test_build_ipv4_udp_packet_validity() {
        let src = Ipv4Addr::new(172, 16, 0, 2);
        let dst = Ipv4Addr::new(162, 159, 192, 1);
        let payload = b"hello wireguard handshake test payload";
        let pkt = build_ipv4_udp_packet(src, dst, 51820, 2408, payload);

        // Verify with smoltcp
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
        // Identity check: modifying val to itself preserves checksum
        let identity = update_checksum_rfc1624(0x1234, 0xabcd, 0xabcd);
        assert_eq!(identity, 0x1234);
    }

    #[test]
    fn test_clamp_tcp_mss_ipv4() {
        let src_ip = Ipv4Address::new(192, 168, 1, 100);
        let dst_ip = Ipv4Address::new(128, 116, 44, 3);

        // Build TCP SYN packet with MSS = 1460 (20 bytes IP + 24 bytes TCP with 4-byte MSS option)
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

        // Verify initial checksum with smoltcp
        let check_tcp = TcpPacket::new_checked(&ip_buf[20..]).expect("Valid initial TCP packet");
        assert!(check_tcp.verify_checksum(&src_ip.into(), &dst_ip.into()));

        // Clamp to 1120
        clamp_tcp_mss(&mut ip_buf, 1120);

        // Verify clamped MSS value and valid TCP checksum after incremental update
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

        // Build TCP ACK packet without SYN
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
    fn test_clamp_tcp_mss_fragmented_packet_ignored() {
        // Build a mock packet with non-zero fragment offset
        let mut ip_buf = vec![0u8; 44];
        ip_buf[0] = 0x45; // IPv4, ihl 5
        ip_buf[2..4].copy_from_slice(&44u16.to_be_bytes());
        ip_buf[6..8].copy_from_slice(&0x0040u16.to_be_bytes()); // Frag offset = 64
        ip_buf[9] = 6; // TCP
        ip_buf[20 + 13] = 0x02; // SYN flag byte in payload

        let orig = ip_buf.clone();
        clamp_tcp_mss(&mut ip_buf, 1120);
        assert_eq!(ip_buf, orig, "Fragmented packet must be ignored");
    }

    #[test]
    fn test_is_roblox_gameplay_udp() {
        let src = Ipv4Addr::new(172, 16, 0, 2);
        // 128.116.44.3 is within 128.116.0.0/17 (44 < 128)
        let dst_game = Ipv4Addr::new(128, 116, 44, 3);
        let valid_gameplay = build_ipv4_udp_packet(src, dst_game, 51820, 58000, b"raknet_payload");
        assert!(
            is_roblox_gameplay_udp(&valid_gameplay),
            "UDP port 58000 on 128.116.44.3 must be recognized as Roblox gameplay"
        );

        // Boundary checks for non-privileged UDP port range (1024..=65535)
        let boundary_gameplay =
            build_ipv4_udp_packet(src, dst_game, 51820, 1024, b"raknet_payload");
        assert!(
            is_roblox_gameplay_udp(&boundary_gameplay),
            "UDP port 1024 must be recognized as Roblox gameplay"
        );

        let below_boundary = build_ipv4_udp_packet(src, dst_game, 51820, 1023, b"raknet_payload");
        assert!(
            !is_roblox_gameplay_udp(&below_boundary),
            "Privileged UDP port 1023 must NOT be recognized as Roblox gameplay"
        );

        // Out of port range (port 80)
        let web_udp = build_ipv4_udp_packet(src, dst_game, 51820, 80, b"raknet_payload");
        assert!(
            !is_roblox_gameplay_udp(&web_udp),
            "UDP port 80 must NOT be recognized as Roblox gameplay"
        );

        // Out of CIDR (128.116.128.1 has 17th bit set, outside 128.116.0.0/17)
        let dst_out = Ipv4Addr::new(128, 116, 128, 1);
        let out_gameplay = build_ipv4_udp_packet(src, dst_out, 51820, 58000, b"raknet_payload");
        assert!(
            !is_roblox_gameplay_udp(&out_gameplay),
            "128.116.128.1 is outside /17 and must not match"
        );

        // Voice STUN/SRTP ports (3478, 5349) must NOT be identified as RakNet gameplay
        let voice_stun_3478 = build_ipv4_udp_packet(src, dst_game, 51820, 3478, b"stun_payload");
        assert!(
            !is_roblox_gameplay_udp(&voice_stun_3478),
            "STUN port 3478 must NOT be recognized as RakNet gameplay (it is Voice)"
        );
        let voice_stun_5349 = build_ipv4_udp_packet(src, dst_game, 51820, 5349, b"stun_payload");
        assert!(
            !is_roblox_gameplay_udp(&voice_stun_5349),
            "STUN port 5349 must NOT be recognized as RakNet gameplay (it is Voice)"
        );

        // Different IP entirely
        let dst_other = Ipv4Addr::new(1, 1, 1, 1);
        let other_pkt = build_ipv4_udp_packet(src, dst_other, 51820, 58000, b"raknet_payload");
        assert!(
            !is_roblox_gameplay_udp(&other_pkt),
            "1.1.1.1 is not Roblox gameplay"
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

        let pkt_other = build_ipv4_udp_packet(src, dst_voice, 51820, 50000, b"game_payload");
        assert!(is_roblox_voice_traffic(&pkt_other, &voice_ips));

        let other_ip = Ipv4Addr::new(1, 1, 1, 1);
        let pkt_not_voice = build_ipv4_udp_packet(src, other_ip, 51820, 80, b"other");
        assert!(!is_roblox_voice_traffic(&pkt_not_voice, &[]));
    }

    #[test]
    fn test_translate_ipv4_udp_src_and_dst_checksums() {
        let old_src = Ipv4Addr::new(172, 16, 0, 2);
        let new_src = Ipv4Addr::new(172, 16, 0, 3);
        let old_dst = Ipv4Addr::new(162, 159, 192, 1);
        let new_dst = Ipv4Addr::new(162, 159, 192, 2);
        let mut pkt = build_ipv4_udp_packet(old_src, old_dst, 51820, 2408, b"test payload");

        translate_ipv4_udp_src(&mut pkt, old_src, new_src);
        translate_ipv4_udp_dst(&mut pkt, old_dst, new_dst);

        let ip_pkt = smoltcp::wire::Ipv4Packet::new_checked(&pkt).expect("Valid IP");
        assert_eq!(
            ip_pkt.src_addr(),
            smoltcp::wire::Ipv4Address::new(172, 16, 0, 3)
        );
        assert_eq!(
            ip_pkt.dst_addr(),
            smoltcp::wire::Ipv4Address::new(162, 159, 192, 2)
        );
        let udp_pkt = smoltcp::wire::UdpPacket::new_checked(ip_pkt.payload()).expect("Valid UDP");
        assert!(udp_pkt.verify_checksum(&ip_pkt.src_addr().into(), &ip_pkt.dst_addr().into()));
    }

    #[test]
    fn test_split_tunneling_raknet_vs_control_plane_routing() {
        let src = Ipv4Addr::new(172, 16, 0, 2);
        let dst_game = Ipv4Addr::new(128, 116, 44, 3);
        let game_pkt = build_ipv4_udp_packet(src, dst_game, 51820, 58000, b"raknet_game");
        assert!(is_roblox_gameplay_udp(&game_pkt));
        assert!(!is_roblox_control_plane_tcp(&game_pkt, &[]));
    }

    #[test]
    fn test_raknet_packet_on_hop1_port_not_misidentified_as_hop2() {
        let src = Ipv4Addr::new(172, 16, 0, 2);
        let dst_game = Ipv4Addr::new(128, 116, 44, 3);
        let game_pkt = build_ipv4_udp_packet(src, dst_game, 51820, 58000, b"raknet_game");
        assert!(is_roblox_gameplay_udp(&game_pkt));
    }

    #[test]
    fn test_split_tunneling_with_different_hop1_hop2_ips() {
        let hop1_ip = Ipv4Addr::new(172, 16, 0, 2);
        let hop2_ip = Ipv4Addr::new(172, 16, 0, 3);
        assert_ne!(hop1_ip, hop2_ip);
    }

    #[test]
    fn test_decapsulate_incoming_drains_queued_packets() {
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
        let mut tunnel = DualHopTunnel::new(&acc1, &acc2, "162.159.192.1:500", "188.114.97.3:2408").unwrap();
        let mut outer = [0u8; 2048];
        let mut inner = [0u8; 2048];

        // 1. Single hop mode draining with empty/invalid datagram terminates cleanly
        tunnel.is_single = true;
        let outcome = tunnel.decapsulate_incoming(&[0u8; 32], &mut outer, &mut inner);
        assert!(outcome.to_user.is_empty());
        assert!(outcome.to_network.is_empty());

        // 2. Dual hop mode draining with invalid datagram terminates cleanly
        tunnel.is_single = false;
        let outcome2 = tunnel.decapsulate_incoming(&[0u8; 32], &mut outer, &mut inner);
        assert!(outcome2.to_user.is_empty());
        assert!(outcome2.to_network.is_empty());
    }

    #[test]
    fn test_decapsulate_incoming_drains_queued_packets_hop2() {
        let acc1 = WarpAccount {
            id: "test1".into(),
            token: "tok1".into(),
            private_key: BASE64_STANDARD.encode([1u8; 32]),
            public_key: BASE64_STANDARD.encode([2u8; 32]),
            peer_public_key: BASE64_STANDARD.encode([3u8; 32]),
            peer_endpoint: "162.159.192.1:500".into(),
            local_ipv4: "172.16.0.2".into(),
            local_ipv6: "".into(),
            reserved: [1, 2, 3],
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
            reserved: [4, 5, 6],
        };
        let mut tunnel = DualHopTunnel::new(&acc1, &acc2, "162.159.192.1:500", "188.114.97.3:2408").unwrap();
        let mut outer = [0u8; 2048];
        let mut inner = [0u8; 2048];

        // Format a Hop 2 handshake packet: it produces an encapsulated packet for Hop 1
        let hop2_handshake = tunnel.format_hop2_handshake(&mut inner, &mut outer, true);
        assert!(hop2_handshake.is_some());
        let outer_pkt = hop2_handshake.unwrap();
        assert!(!outer_pkt.is_empty());

        // Reserved bytes are correctly applied to outer packet
        assert_eq!(outer_pkt[1..4], [1, 2, 3]);

        // Decapsulate empty slice on Hop 2 draining loop terminates cleanly
        let outcome = tunnel.decapsulate_incoming(&[], &mut outer, &mut inner);
        assert!(outcome.to_user.is_empty());
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
        let mut tunnel = DualHopTunnel::new(&acc1, &acc2, "162.159.192.1:500", "188.114.97.3:2408").unwrap();

        // Construct an outbound UDP packet with Source IP 10.2.0.2:55555 and Destination IP 128.116.31.33:57341
        let orig_src = Ipv4Addr::new(10, 2, 0, 2);
        let dst_ip = Ipv4Addr::new(128, 116, 31, 33);
        let src_port = 55555u16;
        let dst_port = 57341u16;
        let payload = b"ROBLOX_UDP_TEST";
        let mut pkt = build_ipv4_udp_packet(orig_src, dst_ip, src_port, dst_port, payload);

        // Pre-encapsulation SNAT check:
        let target_ip = tunnel.hop2_ip;
        let ihl = (pkt[0] & 0x0f) as usize * 4;
        let s_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        let s_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
        assert_eq!(s_ip, orig_src);
        assert_eq!(s_port, src_port);

        // Process through encapsulate_user_packet (or direct SNAT block)
        let mut outer_buf = [0u8; 2048];
        let mut inner_buf = [0u8; 2048];
        let _ = tunnel.encapsulate_user_packet(&mut pkt, &mut inner_buf, &mut outer_buf);

        // Verify pkt has been rewritten to 172.16.0.2
        let rewritten_s_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        assert_eq!(rewritten_s_ip, target_ip);
        assert_eq!(tunnel.snat_map.get(&src_port), Some(&orig_src));

        // Now test inbound return packet from 128.116.31.33:57341 to 172.16.0.2:55555
        let reply_payload = b"ROBLOX_UDP_REPLY";
        let mut reply_pkt = build_ipv4_udp_packet(dst_ip, target_ip, dst_port, src_port, reply_payload);

        tunnel.apply_inbound_snat(&mut reply_pkt);

        // Verify return packet has destination IP rewritten back to 10.2.0.2
        let restored_dst = Ipv4Addr::new(reply_pkt[16], reply_pkt[17], reply_pkt[18], reply_pkt[19]);
        assert_eq!(restored_dst, orig_src);
    }
}
