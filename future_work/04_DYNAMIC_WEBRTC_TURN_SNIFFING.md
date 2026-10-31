# Blueprint 04: Dynamic WebRTC / TURN Media Server Sniffing

## Deep Packet Inspection & Dynamic Route Injection for External Cloud Voice Relays

- **Initiative ID:** `BW-04`
- **Priority:** `P2` (Advanced Protocol Acceleration)
- **Status:** Architecture Approved / In Design
- **Target Release:** `v1.3.0`

---

## 1. Executive Summary & Problem Analysis

In WARP-MIN v1.0, Roblox data-plane traffic is routed using a static CIDR prefix:
```text
128.116.0.0/17  ->  Routed via WARP-Gool Wintun Adapter (Metric 1)
```
This CIDR encompasses the entire Roblox Autonomous System (`AS22697`), covering:
- RakNet UDP Gameplay physics and replication (`ports 50000-65535`).
- Internal Roblox voice signaling and Titanium edge media relays.

### The Emerging Challenge: Dynamic External WebRTC Infrastructure
Roblox is migrating large portions of its spatial voice audio infrastructure to distributed cloud providers, including **LiveKit Cloud**, **Agora**, and **AWS EC2 media clusters** (e.g., `us-east-1` / `eu-central-1` dynamic IP pools in `3.x.x.x`, `18.x.x.x`, `52.x.x.x`, and `54.x.x.x`).

When an Egyptian residential ISP (AS8452 / Telecom Egypt) encounters outbound UDP VoIP packets destined for arbitrary non-Roblox AWS IP ranges:
1. The static route `128.116.0.0/17` does **not** match the destination IP.
2. The packet falls through to the Default Gateway (`0.0.0.0/0` via physical ISP fiber/VDSL).
3. Stateful middlebox DPI inspects the UDP payload, detects SRTP/STUN headers, and applies **heuristic packet dropping or rate-limiting to 16 kbps**, causing complete voice chat muting or severe stutter.

### Why Full-Tunnel Routing (`0.0.0.0/0`) is Rejected:
Routing all PC traffic through WARP-MIN would force local web downloads, YouTube, Discord video streams, and Windows Updates through the dual-hop tunnel, increasing network congestion, consuming tunnel bandwidth, and raising gaming latency.

---

## 2. The Architectural Solution: Process-Correlated Dynamic Sniffing

Rather than statically guessing millions of AWS IP addresses or tunneling the entire computer, WARP-MIN implements an intelligent **Process-Correlated Dynamic Packet Classifier**:

```
+===================================================================================================+
|                                    LOCAL WINDOWS WORKSTATION                                      |
|                                                                                                   |
|  [RobloxPlayerBeta.exe] (PID: 14208)                                                              |
|        |                                                                                          |
|        +---> Outbound UDP packet to 3.120.45.19:3478                                              |
|                                                                                                   |
|  [Dynamic Packet Classifier & Sniffer Engine]                                                     |
|        |                                                                                          |
|        | 1. Intercept packet / query socket table (GetExtendedUdpTable)                           |
|        | 2. Confirm originating process == "RobloxPlayerBeta.exe"                                 |
|        | 3. Inspect packet payload for STUN RFC 5389 Magic Cookie: 0x2112A442                     |
|        |                                                                                          |
|        v                                                                                          |
|  [Dynamic Route Manager]                                                                          |
|        |                                                                                          |
|        +---> Matches external media server! Injects transient kernel route:                       |
|              "route add 3.120.45.19 mask 255.255.255.255 <WARP_GOOL_IP> metric 1"               |
|        +---> Adds IP to In-Memory Route Cache with 5-minute activity TTL                          |
|                                                                                                   |
|  [WARP-Gool Wintun Adapter]                                                                       |
|        |                                                                                          |
|        +---> Subsequent voice packets route at full kernel speed via Subsea Port 500 Tunnel       |
|        +---> Voice chat audio is crystal clear, unblocked, and DPI-immune                         |
+===================================================================================================+
```

---

## 3. Protocol Deep Inspection Mechanics

### 3.1 STUN / TURN Header Inspection (RFC 5389 / RFC 8489)
All WebRTC voice sessions initiate with a Session Traversal Utilities for NAT (STUN) handshake. STUN packets have a deterministic, lightweight 20-byte header:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0 0|     STUN Message Type     |         Message Length        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Magic Cookie                          |
|                          0x2112A442                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     Transaction ID (96 bits)                  |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 3.2 High-Speed Detection Algorithm (Zero Allocations):
```rust
/// Returns true if the UDP payload matches an active WebRTC STUN/TURN handshake.
#[inline(always)]
pub fn is_stun_turn_packet(payload: &[u8]) -> bool {
    // STUN header must be at least 20 bytes
    if payload.len() < 20 {
        return false;
    }

    // Top two bits must be 00 (RFC 5389 §6)
    if (payload[0] & 0xC0) != 0 {
        return false;
    }

    // Fixed Magic Cookie in network byte order: 0x21, 0x12, 0xA4, 0x42
    payload[4] == 0x21 && payload[5] == 0x12 && payload[6] == 0xA4 && payload[7] == 0x42
}
```

---

## 4. Socket Process Correlation Engine

To prevent inadvertently capturing STUN packets from background apps (such as Discord, WhatsApp, or Microsoft Teams), the sniffer correlates outbound sockets with `RobloxPlayerBeta.exe`:

1. Uses Windows IP Helper API: `GetExtendedUdpTable` with `UDP_TABLE_OWNER_PID`.
2. Matches the local port of the outgoing STUN packet against active sockets owned by the `RobloxPlayerBeta.exe` PID.
3. If confirmed, triggers dynamic route insertion for the destination IP address.

---

## 5. Dynamic Route Table Lifecycle & Cache Management

To maintain kernel route table hygiene and prevent performance degradation:

### 5.1 The Dynamic Route Cache
- **Data Structure:** `LruCache<Ipv4Addr, Instant>` protected by an `Arc<RwLock<_>>`.
- **Inactivity Timeout (TTL):** 300 seconds (5 minutes).
- **Eviction Worker:** A lightweight background Tokio task checks active media routes every 30 seconds.
- **Eviction Action:** If no packets have been routed to a specific `/32` address within the TTL, or if `RobloxPlayerBeta.exe` terminates:
  1. The route is deleted from the Windows IP forward table via `DeleteIpForwardEntry2`.
  2. The entry is removed from the cache.

### 5.2 Emergency Route Table Flush
Upon abnormal client exit, `tun::cleanup_routes()` automatically cleans up all dynamically added `/32` routes by recording their interface indices in an atomic registry.

---

## 6. Implementation Milestones

- **Phase 1 (v1.3.0-alpha):** Implement STUN/TURN header recognizer in `src/sniffer.rs` with unit test suite covering RFC 5389 and RFC 8489 test vectors.
- **Phase 2 (v1.3.0-beta):** Implement `GetExtendedUdpTable` polling and process name matching for `RobloxPlayerBeta.exe`.
- **Phase 3 (v1.3.0-rc):** Integrate dynamic `/32` route injection into `tun.rs` with automated LRU cache eviction and verify voice reliability across 20+ distinct Roblox experiences.
