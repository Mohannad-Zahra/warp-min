# Blueprint 01: Standalone European Hop 2 Architecture

## Eliminating External VPNs (Proton / Nord) for 100% Autonomous Operation

- **Initiative ID:** `BW-01`
- **Priority:** `P0` (Critical Path for v1.1.0)
- **Status:** Architecture Approved / In Design
- **Target Release:** `v1.1.0`

---

## 1. Executive Summary & Problem Analysis

In WARP-MIN v1.0, data plane gameplay packets (RakNet UDP `128.116.0.0/17`) exit directly through Cloudflare's Mediterranean subsea Anycast edge in Milan (`MXP`) via outer WireGuard over privileged UDP Port 500, achieving **sub-42ms wire latency**. 

However, Roblox enforces its regional restriction policy (**Universal App Configuration / GUAC**) over the **Control Plane (HTTPS/REST)**:
1. `RobloxPlayerBeta.exe` queries `https://apis.roblox.com/universal-app-configuration/v1/behaviors/app-policy/content`.
2. If the origin IP resolves to Egypt (`loc=EG`), GUAC responds with `"ExperienceChatAvailability": "regionLocked"`, disabling text and spatial voice chat.
3. In v1.0, the user must run a commercial European VPN (such as ProtonVPN set to Netherlands or Italy) concurrently to carry control-plane HTTPS traffic while WARP-MIN overrides the gameplay UDP route.

### Operational Pain Points of the Current Two-App Model:
1. **User Friction:** Users must launch ProtonVPN first, wait for connection, select a European server, launch WARP-MIN with admin rights, and then boot Roblox.
2. **Resource Overhead:** Commercial VPN clients run heavy Electron/WPF frontends, consuming 150MB+ RAM and 2–5% background CPU during gaming.
3. **Multi-Homed DNS Stalls:** Windows activates concurrent DNS resolution across both Proton's adapter and physical Wi-Fi/Ethernet, introducing intermittent 5-second delays on the Roblox launcher splash screen.
4. **Sudden Disconnects:** If Proton drops or renegotiates mid-game, HTTPS session invalidation can terminate the in-game session despite the gameplay UDP tunnel remaining healthy.

---

## 2. Technical Design & Solution Options

The goal of Blueprint 01 is to make WARP-MIN **100% standalone**: one single binary that achieves both sub-42ms gameplay latency AND an autonomous European control-plane egress without running Proton or any other external VPN software.

```
+===================================================================================================+
|                                  STANDALONE WARP-MIN v2.0 ENGINE                                  |
|                                                                                                   |
|  [Roblox Control Plane] (apis.roblox.com / auth.roblox.com)                                       |
|            |                                                                                      |
|            +---> Injected Route: Pin to WARP-Gool L3 TUN Adapter                                  |
|                                                                                                   |
|  [Roblox Data Plane] (RakNet UDP 128.116.0.0/17)                                                  |
|            |                                                                                      |
|            +---> Injected Route: Direct to WARP-Gool L3 TUN Adapter                               |
|                                                                                                   |
|  +---------------------------------------------------------------------------------------------+  |
|  | INNER WIREGUARD (Hop 2): Encapsulated inside Hop 1                                          |  |
|  | - Autonomous European Peer Egress (loc=IT / loc=DE / loc=NL)                                |  |
|  | - MTU: 1200 | MSS Clamped: 1120                                                             |  |
|  +----------------------------------------------+----------------------------------------------+  |
|                                                 |                                                 |
|  +----------------------------------------------v----------------------------------------------+  |
|  | OUTER WIREGUARD (Hop 1): Privileged Anycast Port 500 (DPI Bypass)                           |  |
|  | - Destination: Cloudflare Milan Edge (162.159.192.1:500)                                    |  |
|  | - Direct Submarine Cable across Mediterranean: Wire latency ~38-42ms                        |  |
|  +----------------------------------------------+----------------------------------------------+  |
+=================================================|=================================================+
                                                  v
                      [Cloudflare Milan MXP Edge Datacenter (AS13335)]
                                                  |
                                                  +---> Roblox RakNet (Peering SLA: ~2ms)
                                                  +---> European Egress (apis.roblox.com)
```

---

## 3. Comparative Evaluation of Implementation Paths

Three distinct options have been analyzed to deliver European egress natively inside Hop 2:

### Option A: Autonomous Dual-WARP In-Tunnel Registration (Recommended Default)
- **Concept:** WARP-MIN establishes Hop 1 over Port 500 to Cloudflare Milan (`MXP`). Hop 1 is immediately utilized as an internal SOCKS5/HTTP tunnel to invoke Cloudflare's client registration API (`https://api.cloudflareclient.com/v0a2158/reg`).
- **GeoIP Mechanism:** Because the registration request originates from Cloudflare's Milan datacenter internal network, Cloudflare provisions Account 2 with an internal European IPv4 address (`172.16.0.2/32`) and binds egress to the European pool (`loc=IT`).
- **Control Plane Handling:** Instead of pinning `apis.roblox.com` to the physical gateway, WARP-MIN routes `apis.roblox.com` directly through the `WARP-Gool` TUN adapter into Hop 2.
- **Pros:**
  - Zero recurring server cost for users (relies purely on Cloudflare Anycast infrastructure).
  - Fully automated with zero configuration files needed.
- **Cons:**
  - Requires maintaining TLS 1.3 client in Rust (`reqwest` + `rustls`) routed through the embryonic Hop 1 tunnel during startup.

### Option B: Automated Private European WireGuard Peer (Oracle / Hetzner VPS)
- **Concept:** Allow power users to specify a private WireGuard peer hosted on a low-cost European VPS (e.g., Oracle Cloud Always-Free ARM in Frankfurt/Amsterdam or Hetzner Cloud CX22 in Falkenstein for €3.50/mo).
- **Encapsulation:**
  - Outer: Local PC $\rightarrow$ Cloudflare Milan (`MXP`) over Port 500.
  - Inner: Local PC $\rightarrow$ Private European VPS WireGuard endpoint (tunneled through Hop 1).
- **Pros:**
  - 100% dedicated, static European IP address.
  - Zero risk of Cloudflare Anycast IP reputation flags or CAPTCHA triggers on Roblox web services.
- **Cons:**
  - Requires setting up a VPS (not zero-configuration for casual gamers).

### Option C: Cloudflare Zero Trust / Gateway Tunnel
- **Concept:** Use a Cloudflare Zero Trust team organization token with an automated egress rule pinning traffic through European gateway POPs.
- **Pros:** Enterprise-grade reliability and static egress IPs.
- **Cons:** Requires user authentication and management of Cloudflare Zero Trust credentials.

---

## 4. Architectural Specification for Option A (In-Tunnel Bootstrapping)

To maintain WARP-MIN's zero-friction philosophy, **Option A** is the primary target architecture.

### 4.1 Phase 1: Embryonic Hop 1 Bootstrapping
1. Client generates Curve25519 keypair $K_{priv1}, K_{pub1}$.
2. In Egypt, direct registration over HTTPS to `api.cloudflareclient.com` is completed via standard TLS (or via user-space domain-fronting if blocked).
3. Outer WireGuard tunnel handshakes with `162.159.192.1:500`.

### 4.2 Phase 2: Internal In-Tunnel Hop 2 Registration
1. Once Hop 1 handshake is confirmed, WARP-MIN creates a transient user-space TCP client through `DualHopTunnel`'s embryonic user-space netstack (`smoltcp`).
2. Generates Curve25519 keypair $K_{priv2}, K_{pub2}$.
3. Dispatches HTTP POST to `https://api.cloudflareclient.com/v0a2158/reg` through Hop 1.
4. Cloudflare's registration server sees the request originating from `162.159.192.1` (Milan datacenter) and returns a European identity (`account2`) with European Anycast pool tagging.
5. Saves the validated identity to `warp_identity_hop2.json`.

### 4.3 Phase 3: Split-Plane Kernel Route Expansion
In addition to the RakNet UDP subnet (`128.116.0.0/17`), WARP-MIN injects the following routes into `WARP-Gool`:
- `apis.roblox.com` (resolved dynamic /32 host routes)
- `auth.roblox.com` (resolved dynamic /32 host routes)
- `voice.roblox.com` (resolved dynamic /32 host routes)
- Optional: User-configurable whitelist of application domains (e.g. `discord.com`, `spotify.com`).

```rust
// Proposed Host Pinning Engine in src/tun.rs
pub fn pin_control_plane_to_tun(
    if_index: u32,
    domain_ips: &[Ipv4Addr],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for ip in domain_ips {
        add_host_route_to_adapter(if_index, *ip, 1)?;
    }
    Ok(())
}
```

---

## 5. Security & Verification Milestones

1. **Gate 1:** Validate that `curl --interface "WARP-Gool" https://www.cloudflare.com/cdn-cgi/trace` returns `loc=IT` or `loc=DE` without any other VPN running.
2. **Gate 2:** Validate that `GET https://apis.roblox.com/universal-app-configuration/v1/behaviors/app-policy/content` routed through `WARP-Gool` returns `"ExperienceChatAvailability": "available"`.
3. **Gate 3:** Verify that launching `RobloxPlayerBeta.exe` with zero external VPNs active results in full in-game text chat, spatial voice, and an in-game RakNet ping of **40–44ms**.
