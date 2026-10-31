use std::net::Ipv4Addr;

pub fn build_dns_query(domain: &str, tx_id: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);
    // Header
    packet.extend_from_slice(&tx_id.to_be_bytes()); // ID
    packet.extend_from_slice(&[0x01, 0x00]); // Flags: recursion desired
    packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT: 1
    packet.extend_from_slice(&[0x00, 0x00]); // ANCOUNT: 0
    packet.extend_from_slice(&[0x00, 0x00]); // NSCOUNT: 0
    packet.extend_from_slice(&[0x00, 0x00]); // ARCOUNT: 0

    // Question
    for part in domain.split('.') {
        if part.is_empty() {
            continue;
        }
        packet.push(part.len() as u8);
        packet.extend_from_slice(part.as_bytes());
    }
    packet.push(0x00); // Terminating 0 length

    packet.extend_from_slice(&[0x00, 0x01]); // TYPE: A
    packet.extend_from_slice(&[0x00, 0x01]); // CLASS: IN

    packet
}

/// Skips an RFC 1035 domain name at the specified offset in a DNS packet buffer.
/// Correctly handles label sequences, zero-length root terminators, and 14-bit compression pointers (0xc0xx).
pub fn skip_dns_name(buf: &[u8], mut offset: usize) -> Option<usize> {
    while offset < buf.len() {
        let len = buf[offset] as usize;
        if len == 0 {
            return Some(offset + 1);
        }
        if (len & 0xc0) == 0xc0 {
            // RFC 1035 §4.1.4 14-bit pointer
            if offset + 1 >= buf.len() {
                return None;
            }
            return Some(offset + 2);
        }
        if (len & 0xc0) != 0 {
            // Reserved bits set; malformed DNS name
            return None;
        }
        if offset + 1 + len > buf.len() {
            return None;
        }
        offset += 1 + len;
    }
    None
}

/// Parses an IPv4 A-record response, properly traversing questions, CNAME alias chains,
/// and compression pointers conforming to RFC 1035 §4.1.4.
pub fn parse_dns_response(response: &[u8]) -> Option<Ipv4Addr> {
    if response.len() < 12 {
        return None;
    }
    // QR bit in byte 2 must be 1 (Response)
    if (response[2] & 0x80) == 0 {
        return None;
    }
    // RCODE in low 4 bits of byte 3 must be 0 (No Error)
    if (response[3] & 0x0f) != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([response[4], response[5]]) as usize;
    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
    if ancount == 0 {
        return None;
    }

    let mut offset = 12;

    // Skip question section(s)
    for _ in 0..qdcount {
        offset = skip_dns_name(response, offset)?;
        // Skip QTYPE (2) + QCLASS (2)
        offset += 4;
        if offset > response.len() {
            return None;
        }
    }

    // Parse answer records
    for _ in 0..ancount {
        offset = skip_dns_name(response, offset)?;
        if offset + 10 > response.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let rdlength = u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
        offset += 10;

        if rtype == 1 && rdlength == 4 && offset + 4 <= response.len() {
            return Some(Ipv4Addr::new(
                response[offset],
                response[offset + 1],
                response[offset + 2],
                response[offset + 3],
            ));
        }

        offset += rdlength;
        if offset > response.len() {
            return None;
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_skip_dns_name_root() {
        let buf = [0x00];
        assert_eq!(skip_dns_name(&buf, 0), Some(1));
    }

    #[test]
    fn test_skip_dns_name_labels() {
        // "com\0" -> 3 'c' 'o' 'm' 0
        let buf = [0x03, b'c', b'o', b'm', 0x00];
        assert_eq!(skip_dns_name(&buf, 0), Some(5));
    }

    #[test]
    fn test_skip_dns_name_pointer() {
        let buf = [0xc0, 0x0c];
        assert_eq!(skip_dns_name(&buf, 0), Some(2));
    }

    #[test]
    fn test_skip_dns_name_label_then_pointer() {
        // "sub" then pointer: 3 's' 'u' 'b' 0xc0 0x0c
        let buf = [0x03, b's', b'u', b'b', 0xc0, 0x0c];
        assert_eq!(skip_dns_name(&buf, 0), Some(6));
    }

    #[test]
    fn test_skip_dns_name_truncated() {
        let buf = [0x05, b'a', b'b'];
        assert_eq!(skip_dns_name(&buf, 0), None);
        let ptr_buf = [0xc0];
        assert_eq!(skip_dns_name(&ptr_buf, 0), None);
    }

    #[test]
    fn test_parse_dns_response_cname_pointer() {
        // Build mock DNS response for apis.roblox.com:
        // Question: apis.roblox.com (A, IN)
        // Answer 1: apis.roblox.com CNAME titanium.roblox.com (using pointer for suffix)
        // Answer 2: titanium.roblox.com A 128.116.44.3
        let mut resp = Vec::new();

        // 12-byte header: ID=0x1234, Flags=0x8180 (std response), QDCOUNT=1, ANCOUNT=2, NSCOUNT=0, ARCOUNT=0
        resp.extend_from_slice(&0x1234u16.to_be_bytes());
        resp.extend_from_slice(&[0x81, 0x80]);
        resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        resp.extend_from_slice(&2u16.to_be_bytes()); // ANCOUNT
        resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        // Question at offset 12: "apis.roblox.com"
        // 4 'a' 'p' 'i' 's' 6 'r' 'o' 'b' 'l' 'o' 'x' 3 'c' 'o' 'm' 0
        let q_name = [
            4, b'a', b'p', b'i', b's', 6, b'r', b'o', b'b', b'l', b'o', b'x', 3, b'c', b'o', b'm',
            0,
        ];
        resp.extend_from_slice(&q_name);
        resp.extend_from_slice(&1u16.to_be_bytes()); // QTYPE: A
        resp.extend_from_slice(&1u16.to_be_bytes()); // QCLASS: IN

        // Answer 1: Name = pointer to offset 12 (apis.roblox.com) -> 0xc0 0x0c
        resp.extend_from_slice(&[0xc0, 0x0c]);
        resp.extend_from_slice(&5u16.to_be_bytes()); // TYPE: CNAME (5)
        resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS: IN
        resp.extend_from_slice(&300u32.to_be_bytes()); // TTL: 300
        // CNAME target: "titanium" + pointer to "roblox.com" (offset 12 + 5 = 17)
        let cname_data = [8, b't', b'i', b't', b'a', b'n', b'i', b'u', b'm', 0xc0, 17];
        resp.extend_from_slice(&(cname_data.len() as u16).to_be_bytes()); // RDLENGTH
        resp.extend_from_slice(&cname_data);

        // Answer 2: Name = pointer to "titanium" (in answer 1, offset 12 + 17 + 4 + 2 + 10 = 45)
        // Or label then pointer
        resp.extend_from_slice(&[0xc0, 45]);
        resp.extend_from_slice(&1u16.to_be_bytes()); // TYPE: A (1)
        resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS: IN
        resp.extend_from_slice(&300u32.to_be_bytes()); // TTL
        resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH: 4
        resp.extend_from_slice(&[128, 116, 44, 3]); // RDATA: 128.116.44.3

        let parsed = parse_dns_response(&resp);
        assert_eq!(parsed, Some(Ipv4Addr::new(128, 116, 44, 3)));
    }

    #[test]
    fn test_parse_dns_response_nxdomain_and_query_rejected() {
        // Build NXDOMAIN response (RCODE=3)
        let mut resp = vec![0u8; 12];
        resp[2] = 0x81; // Response
        resp[3] = 0x83; // RCODE = 3 (NXDOMAIN)
        resp[7] = 1; // ANCOUNT = 1
        assert_eq!(parse_dns_response(&resp), None);

        // Build query packet (QR=0)
        let mut query = vec![0u8; 12];
        query[2] = 0x01; // QR = 0 (Query)
        query[7] = 1; // ANCOUNT = 1
        assert_eq!(parse_dns_response(&query), None);
    }
}
