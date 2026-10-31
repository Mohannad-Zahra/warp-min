# WARP-MIN Documentation

Welcome to the internal and technical documentation for **WARP-MIN**, a high-performance, low-latency Rust split-tunneling WireGuard / Cloudflare WARP client designed for gamers in restricted network environments (such as Egypt).

This documentation suite provides deep technical analyses, architectural specifications, network protocol dissections, kernel routing mechanics, and troubleshooting guides compiled from research and production debugging.

---

## Documentation Index

1. **[Architecture & Split-Plane Network Model](architecture-and-split-plane-network-model.md)**  
   *Covers the dual-hop WireGuard ("Gool") encapsulation pipeline, Cloudflare reserved client-ID byte injection/stripping, TCP MSS clamping with RFC 1624 incremental checksum updates, and the strict isolation between the Control Plane (HTTPS/REST) and the Data Plane (RakNet UDP).*

2. **[Deep Packet Inspection (DPI) & Anycast Port 500 Bypass](dpi-and-anycast-port-500-bypass.md)**  
   *Analyzes middlebox DPI heuristics deployed by Egyptian ISPs (AS8452 / Telecom Egypt), stateful dropping of WireGuard handshakes on UDP ports 51820/2408/1701, the structural immunity of IKEv2/IPsec port 500, dynamic Anycast latency probing, and intra-PoP complementary pool alignment.*

3. **[Roblox Protocol Analysis](roblox-protocol-analysis.md)**  
   *Examines Roblox client internals, including the RakNet UDP gameplay protocol (`128.116.0.0/17`), WebRTC/STUN voice chat streams, Titanium edge CNAME chains with RFC 1035 compression pointer resolution, embedded libcurl networking, and Universal App Configuration (GUAC) `appStorage.json` policy mechanics.*

4. **[Windows Kernel Routing & WLAN Optimization](windows-kernel-routing-and-wlan-optimization.md)**  
   *Details the Windows TCPIP routing table mechanics (Longest Prefix Match `/32` vs `/17` vs `/0`), loop avoidance algorithms, Wintun L3 ring buffer management, and WiFi 60-second background scan lag spike mitigation.*

5. **[Troubleshooting & Verification Guide](troubleshooting-and-verification-guide.md)**  
   *Provides the complete 6-Gate verification checklist, CLI diagnostic commands, Cloudflare trace analysis, rate limit management, and step-by-step remediation procedures for common failure modes.*

6. **[Future Work & Engineering Blueprints](../future_work/README.md)**  
   *Master roadmap, priority matrix, and technical blueprints for standalone European Hop 2 (eliminating Proton VPN), native Windows tray GUI, CI/CD automated installers, dynamic WebRTC TURN sniffing, and structured diagnostic logging.*

---

## Architectural Summary

```
                      +---------------------------------------+
                      |            Client System              |
                      |  [RobloxPlayerBeta.exe]               |
                      +-------------------+-------------------+
                                          |
        +---------------------------------+---------------------------------+
        | (Data Plane: RakNet UDP)                                          | (Control Plane: HTTPS / REST)
        v                                                                   v
+-------------------------------+                                 +-------------------------------+
| Wintun Adapter ("WARP-Gool")  |                                 | Primary Physical / VPN Egress |
| - 128.116.0.0/17 (RakNet)     |                                 | - apis.roblox.com /32         |
| - MTU 1200 / MSS Clamped 1120 |                                 | - auth.roblox.com /32         |
+---------------+---------------+                                 +---------------+---------------+
                |                                                                 |
                v                                                                 |
+-------------------------------+                                                 |
| Outer Tunnel (Hop 1)          |                                                 |
| - WireGuard Noise Protocol    |                                                 |
| - Port 500 (DPI Bypass)       |                                                 |
+---------------+---------------+                                                 |
                | (Submarine Fiber: Cairo -> Milan ~38-42ms)                      |
                v                                                                 |
+---------------------------------------------------------------+                 |
| Cloudflare Milan Edge PoP (MXP / AS13335)                     |                 |
| - Inner Tunnel (Hop 2) Decapsulation (<1.5ms intra-PoP)       |                 |
+---------------+-----------------------------------------------+                 |
                |                                                                 |
                v (Roblox Peering: ~2-4ms)                                        v
+---------------------------------------------------------------------------------+
|                         Roblox Edge Servers (AS22697)                           |
| - Gameplay Ping: ~40-44ms                                                       |
| - Account Location & Policy: Unblocked                                          |
+---------------------------------------------------------------------------------+
```
