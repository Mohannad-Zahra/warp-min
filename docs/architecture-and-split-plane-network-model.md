# Architecture & Split-Plane Network Model

## 1. Overview and Core Mission

**WARP-MIN** is a specialized, zero-bloat WireGuard networking client built in Rust. It was engineered to solve a multi-variable network challenge for gamers located in restricted Internet environments (specifically Egypt, connecting through AS8452 / Telecom Egypt):

1. **Submarine Latency Optimization:** Maintaining sub-45ms round-trip time (RTT) from North Africa to Central European servers by directly ingesting traffic into Cloudflare's Mediterranean submarine cable backbone (Milan `MXP` / Rome `FCO`).
2. **DPI Evasion:** Bypassing stateful middlebox Deep Packet Inspection (DPI) that throttles or injects TCP RST / UDP drops on traditional WireGuard ports (UDP 51820, 2408, 1701).
3. **GeoIP Egress Decoupling:** Overcoming Cloudflare WARP's default single-hop behavior (which retains the origin client country code `loc=EG`) by encapsulating a secondary WireGuard tunnel ("Gool" dual-hop) inside the outer session, obtaining European egress (`loc=IT`/`loc=DE`).
4. **Split-Plane Isolation:** Separating high-latency/authentication-critical HTTPS traffic (Control Plane) from latency-critical UDP gameplay streams (Data Plane), preventing launcher lockups, multi-homed DNS timeouts, and routing conflicts.

---

## 2. Dual-Hop WireGuard ("Gool") Encapsulation Pipeline

Standard Cloudflare WARP client connections terminate on edge worker proxies that assign egress IP addresses mapped to the client's physical country of origin (`loc=EG`). For services enforcing regional policy restrictions based on egress GeoIP, single-hop WARP is insufficient.

To obtain European egress without routing through high-latency third-party hops in Northern Europe, WARP-MIN implements a nested WireGuard tunnel architecture within Cloudflare's own Anycast infrastructure:

```
+========================================================================================+
|                                    LOCAL CLIENT                                        |
|                                                                                        |
|  [User Application / RakNet UDP / SOCKS5 TCP Client]                                   |
|                          |                                                             |
|                          v (Plain IPv4 Packet)                                         |
|  +----------------------------------------------------------------------------------+  |
|  | HOP 2 (Inner Tunnel Engine)                                                      |  |
|  | - BoringTun Noise Session (Local Index 1)                                        |  |
|  | - MTU: 1200 Bytes                                                                |  |
|  | - Curve25519 Ephemeral Keypair (Account 2)                                       |  |
|  | - Injects Hop 2 Reserved Client-ID Bytes (bytes 1..4)                            |  |
|  +---------------------------------------+------------------------------------------+  |
|                                          |                                             |
|                                          v (Encrypted WG Data Packet)                  |
|  +----------------------------------------------------------------------------------+  |
|  | Raw IPv4/UDP Packet Framing                                                       |  |
|  | - Source: 172.16.0.2:51820                                                       |  |
|  | - Destination: Endpoint B (188.114.97.3:2408)                                    |  |
|  | - Payload: Inner Encrypted WireGuard Packet                                      |  |
|  +---------------------------------------+------------------------------------------+  |
|                                          |                                             |
|                                          v (Framed IPv4 Packet)                        |
|  +----------------------------------------------------------------------------------+  |
|  | HOP 1 (Outer Tunnel Engine)                                                      |  |
|  | - BoringTun Noise Session (Local Index 0)                                        |  |
|  | - MTU: 1280 Bytes                                                                |  |
|  | - Curve25519 Ephemeral Keypair (Account 1)                                       |  |
|  | - Injects Hop 1 Reserved Client-ID Bytes (bytes 1..4)                            |  |
|  +---------------------------------------+------------------------------------------+  |
|                                          |                                             |
|                                          v (Encrypted Outer WG Packet)                 |
|  +----------------------------------------------------------------------------------+  |
|  | Physical Windows UDP Socket (Socket2: 4MB Buffer, SIO_UDP_CONNRESET Disabled)    |  |
|  | Destination: Endpoint A (162.159.192.1:500 via Physical Default Gateway)         |  |
|  +=======================================|==========================================+  |
                                           | (Submarine RTT: ~38-42ms)
                                           v
+----------------------------------------------------------------------------------------+
|                      CLOUDFLARE MEDITERRANEAN POP (MILAN MXP / ROME FCO)               |
|                                                                                        |
|  1. Hop 1 Terminates at Edge Ingress (Seen as Egyptian Origin: loc=EG)                 |
|  2. Outer WG Decapsulated -> Unveils UDP datagram targeting Endpoint B                 |
|  3. Hop 2 Ingress Packet routed intra-PoP (<1.5ms transit delay)                       |
|  4. Hop 2 Terminates -> Egress assigned from European Anycast Pool (loc=IT / loc=DE)   |
+------------------------------------------+---------------------------------------------+
                                           | (Peering Transit: ~2-4ms)
                                           v
+----------------------------------------------------------------------------------------+
|                                TARGET GAME/VOIP SERVERS                                |
|                                                                                        |
|  - Egress IP: Cloudflare European ASN (AS13335)                                        |
|  - GeoIP Location: Italy (IT) / Germany (DE)                                           |
|  - Total End-to-End Latency: 40-44ms                                                   |
+----------------------------------------------------------------------------------------+
```

### 2.1 Cloudflare WireGuard Reserved Bytes Protocol

Standard WireGuard implementations (RFC protocol specification) initialize bytes 1..3 of the 4-byte header in handshake and data packets with zeroes (`reserved: [0u8; 3]`).

Cloudflare's proprietary WireGuard implementation departs from this standard:
- During anonymous account registration via `POST https://api.cloudflareclient.com/v0a4005/reg`, the API returns a base64-encoded `client_id` string (e.g., `["client_id": "WDh5"]`).
- When decoded, this yields 3 bytes (e.g., `[88, 120, 121]`).
- Cloudflare edge routers require these 3 bytes to be present in packet bytes 1..4 of all outbound datagrams to identify the client session across Anycast worker clusters.
- However, standard BoringTun cryptographic decapsulators enforce strict zero checks on the reserved field. If an incoming datagram contains non-zero reserved bytes, BoringTun rejects it as malformed.

**WARP-MIN Solution (`src/tunnel.rs`):**
1. **Outbound Injection (`apply_reserved_outbound`):**
   ```rust
   pub fn apply_reserved_outbound(packet: &mut [u8], reserved: [u8; 3]) {
       if packet.len() >= 4 && (packet[0] == 1 || packet[0] == 4) {
           packet[1] = reserved[0];
           packet[2] = reserved[1];
           packet[3] = reserved[2];
       }
   }
   ```
2. **Inbound Sanitization (`clear_reserved_inbound`):**
   ```rust
   pub fn clear_reserved_inbound(packet: &mut [u8]) {
       if packet.len() >= 4 && (packet[0] == 1 || packet[0] == 2 || packet[0] == 4) {
           packet[1] = 0;
           packet[2] = 0;
           packet[3] = 0;
       }
   }
   ```
   Before passing received UDP datagrams to `boringtun::noise::Tunn::decapsulate`, bytes 1..4 are wiped to zeroes, allowing BoringTun's Noise state machine to validate authentication tags seamlessly.

---

## 3. TCP Maximum Segment Size (MSS) Clamping & RFC 1624

Nested encapsulation introduces significant protocol overhead:

| Layer | Header Type | Size (Bytes) |
|---|---|---|
| Outer Transport | Physical IPv4 Header | 20 |
| Outer Transport | Physical UDP Header | 8 |
| Outer Encryption | WireGuard Hop 1 Data Header | 32 |
| Inner Framing | Encapsulated IPv4 Header | 20 |
| Inner Framing | Encapsulated UDP Header | 8 |
| Inner Encryption | WireGuard Hop 2 Data Header | 32 |
| **Total Overhead** | **Tunnel Encapsulation Stack** | **120 Bytes** |

If an application on the client sends a standard Ethernet MTU frame (1500 bytes), double WireGuard encapsulation expands the packet to 1620 bytes. Because physical WAN paths enforce MTUs of 1492–1500 bytes, these packets either suffer IP fragmentation (which Egyptian ISP middleboxes frequently discard) or are dropped by intermediate routers without sending ICMP Fragmentation Needed messages (Path MTU Black Hole).

### 3.1 MSS Clamping Algorithm

WARP-MIN implements active TCP MSS clamping in `src/tunnel.rs`:
- Every outbound IPv4 TCP packet is inspected during encapsulation.
- If the packet is a TCP `SYN` or `SYN-ACK` packet (header flag `0x02`), the engine scans the TCP Options field for Option Kind 2 (Maximum Segment Size, 4 bytes).
- If the negotiated MSS exceeds **1120 bytes**, WARP-MIN overwrites the option with `0x0460` (1120 bytes).

### 3.2 RFC 1624 Incremental Checksum Recalculation

Recalculating the 16-bit one's complement TCP checksum across the entire segment on every packet is computationally expensive and cache-unfriendly. WARP-MIN implements incremental checksum updating using **RFC 1624 Eqn. 3**:

$$\sim C' = \sim C + \sim m + m'$$

```rust
pub fn update_checksum_rfc1624(old_csum: u16, old_val: u16, new_val: u16) -> u16 {
    let old_csum = old_csum as u32;
    let old_val = old_val as u32;
    let new_val = new_val as u32;

    let mut sum = (!old_csum & 0xffff) + (!old_val & 0xffff) + new_val;
    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
```
This guarantees 100% valid TCP checksums with sub-microsecond CPU cost and zero full-packet memory passes.

---

## 4. Split-Plane Network Model (Control vs Data)

A key architectural finding in WARP-MIN's engineering is that **full-system tunneling degrades performance and breaks game services**:

```
[Full System VPN (Wrong)]
All Traffic ---> Hop 1 ---> Hop 2 ---> Cloudflare Egress
   - Launcher HTTPS: High variance, rate limits, multi-homed DNS lookup lag.
   - Roblox WebSockets: Disconnects during server migrations.
   - General browsing: Captchas, latency penalties.

[WARP-MIN Split-Plane (Correct)]
Control Plane (HTTPS/APIs) ---> Primary Physical / VPN Egress ---> Roblox Edge (EU GeoIP)
Data Plane (RakNet UDP)    ---> WARP-Gool L3 Tun (Port 500)   ---> Milan Edge (38-42ms Submarine)
```

### 4.1 The Control Plane
- **Target Endpoints:** `apis.roblox.com`, `auth.roblox.com`, `versioncompatibility.api.roblox.com`, `clientsettings.roblox.com`.
- **Protocol:** HTTPS (TLS 1.3 over TCP 443) handled by embedded libcurl in `RobloxPlayerBeta.exe`.
- **Routing Strategy:** Pinned via `/32` Windows host routes through the primary network interface or a European VPN breakout (e.g., ProtonVPN Netherlands/Italy).
- **Function:** Authenticates the user, loads account inventory, and queries Universal App Configuration (GUAC) policies. Because this traffic exits through the European breakout, Roblox verifies legitimate account location without triggering geographic fraud alerts.

### 4.2 The Data Plane
- **Target Subnet:** `128.116.0.0/17` (`128.116.0.0` - `128.116.127.255`).
- **Target Ports:** UDP 50000–65535 (RakNet gameplay server instances).
- **Routing Strategy:** Bound strictly to the `WARP-Gool` Wintun adapter (`172.16.0.1` metric 1).
- **Function:** Delivers interactive game state updates across the direct Cairo-to-Milan subsea fiber. By isolating the Data Plane from the Control Plane:
  - Game ping is locked to wire speed (~40ms).
  - Background web traffic, Twitch streams, or Discord calls never saturate the game's tunnel buffers.
  - Launcher startup is instantaneous with zero DNS timeouts.

---

## 5. Subsystem Component Manifest

| Module | Source File | Responsibilities |
|---|---|---|
| **CLI & Lifecycle** | `src/main.rs` | Argument parsing (`clap`), Anycast latency probing, elevated privilege daemon management, graceful Ctrl+C shutdown. |
| **Dual-Hop Engine** | `src/tunnel.rs` | Noise handshake serialization, dual BoringTun session lifecycle, reserved byte handling, TCP MSS clamping, packet classifier. |
| **Kernel Adapter** | `src/tun.rs` | Wintun L3 interface creation (`WARP-Gool`), MTU 1200 configuration, kernel route table pinning, route teardown. |
| **SOCKS5 Netstack** | `src/socks.rs` | User-space TCP/IP stack (`smoltcp 0.14`), non-elevated fallback proxy on `127.0.0.1:8086`, DoH client. |
| **DNS Subsystem** | `src/dns.rs` | RFC 1035 wire query builder, CNAME alias chain traversal, 14-bit compression pointer decoder (`0xc0xx`). |
| **Cloudflare API** | `src/api.rs` | Curve25519 keypair generation, TLS 1.3 anonymous registration (`/v0a4005/reg`), JSON identity caching. |
| **UAC Elevation** | `src/elevate.rs` | Windows token inspection, `ShellExecuteExW` UAC prompt launcher, parent console hiding. |
