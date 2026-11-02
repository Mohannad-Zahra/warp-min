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
    pub snat_order: std::collections::VecDeque<u16>,
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
            snat_order: std::collections::VecDeque::new(),
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
        let target_ip = if self.is_single {
            self.hop1_ip
        } else {
            self.hop2_ip
        };
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
                    if !self.snat_map.contains_key(&src_port) {
                        if self.snat_map.len() >= 2048
                            && let Some(oldest_port) = self.snat_order.pop_front()
                        {
                            self.snat_map.remove(&oldest_port);
                        }
                        self.snat_order.push_back(src_port);
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
                    } else if let Some(inner_wg_pkt) =
                        extract_inner_hop2_payload(ip_pkt, &self.endpoint_b)
                    {
                        let mut inner_copy = inner_wg_pkt.to_vec();
                        clear_reserved_inbound(&mut inner_copy);

                        let mut hop2_action =
                            self.hop2_tunn.decapsulate(None, &inner_copy, inner_buf);
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

    pub(crate) fn apply_inbound_snat(&self, pkt: &mut [u8]) {
        let target_ip = if self.is_single {
            self.hop1_ip
        } else {
            self.hop2_ip
        };
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
