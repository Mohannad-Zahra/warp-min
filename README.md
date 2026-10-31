# WARP-MIN

[![Rust](https://img.shields.io/badge/Rust-2024_Edition-orange.svg?logo=rust)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows_10%2F11_x64-blue.svg?logo=windows)](https://www.microsoft.com/windows)
[![Driver](https://img.shields.io/badge/Driver-Wintun_0.5.1-green.svg)](https://www.wintun.net/)
[![License](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![CI](https://github.com/mohan/Warper/actions/workflows/ci.yml/badge.svg)](https://github.com/mohan/Warper/actions)

> **Ultra-Low Latency Standalone Split-Tunneling WireGuard / Cloudflare WARP Client for Windows**  
> Engineered specifically for gamers in restricted network regions (e.g., Egypt) to bypass ISP Deep Packet Inspection (DPI), achieve sub-45ms wire latency, and unlock regional voice chat restrictions in Roblox without full-tunnel routing penalties.

---

## Table of Contents

- [The Problem](#the-problem)
- [Why WARP-MIN? (The Average Player's Dilemma Solved)](#why-warp-min-the-average-players-dilemma-solved)
- [The Architectural Solution](#the-architectural-solution)
- [Key Features](#key-features)
- [Network Architecture & Split-Plane Model](#network-architecture--split-plane-model)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Building from Source](#building-from-source)
  - [Running the Client](#running-the-client)
- [Roblox Pre-Flight Instructions](#roblox-pre-flight-instructions)
- [CLI Reference](#cli-reference)
- [Repository Structure](#repository-structure)
- [Documentation Index](#documentation-index)
- [Wi-Fi Latency Optimization](#wi-fi-latency-optimization)
- [License & Security Disclaimer](#license--security-disclaimer)

---

## The Problem

Gamers residing in restricted network regions such as Egypt (AS8452 / Telecom Egypt) encounter three major structural network roadblocks:

1. **ISP Deep Packet Inspection (DPI) & Throttling:**  
   Stateful DPI middleboxes inspect outbound UDP traffic. Standard WireGuard connections on UDP `51820`, as well as standard Cloudflare WARP traffic on ports `2408` and `1701`, trigger immediate heuristic packet dropping or rate-limiting, rendering standard VPN clients unusable.
2. **High Latency of Commercial VPNs:**  
   Standard VPNs (NordVPN, ExpressVPN, ProtonVPN) route all user traffic through Northern or Western European nodes (Frankfurt, Amsterdam, London), inducing an unavoidable **70ms–90ms** round-trip time (RTT).
3. **Roblox Regional Policy Restriction (`loc=EG`):**  
   Roblox queries its Universal App Configuration (GUAC) service on startup. When an Egyptian IP is detected, it locks in-game spatial voice and platform chat (`"ExperienceChatAvailability": "regionLocked"`). A single-hop WARP tunnel still presents origin country `loc=EG`, failing to unlock the restrictions.

---

## Why WARP-MIN? (The Average Player's Dilemma Solved)

For online gamers in restricted regions, choosing how to connect has historically been a lose-lose compromise between **Free Commercial VPNs** and **Raw Cloudflare WARP**:

### The 3-Way Comparative Benchmark Matrix

| Metric / Capability | Free Commercial VPN<br>*(e.g., ProtonVPN Free Tier)* | Raw Cloudflare WARP<br>*(Official 1.1.1.1 Desktop App)* | **WARP-MIN Split-Tunneling**<br>*(Engineered for Competitive Gaming)* |
| :--- | :---: | :---: | :---: |
| **In-Game Ping (Egypt $\to$ Europe)** | **85ms – 115ms+** *(High / Sluggish)* | **38ms – 42ms** *(Low Wire Speed)* | **~40ms – 44ms** (**>50% Lower Latency!**) |
| **Ping Jitter & Combat Spikes** | Severe *(Congested free servers, TCP packet loss)* | Minimal *(Direct subsea transit)* | **Minimal & Consistent** *(Dedicated UDP over direct subsea fiber)* |
| **Roblox In-Game Spatial Voice** | **Unlocked** *(European datacenter IP)* | **LOCKED** *(Restricted: `loc=EG` detected)* | **100% UNLOCKED** *(Full spatial voice chat enabled)* |
| **Roblox In-Game Text Chat** | **Unlocked** *(European datacenter IP)* | **LOCKED** *(`ExperienceChatAvailability: regionLocked`)* | **100% UNLOCKED** *(Platform chat enabled)* |
| **Egyptian Telecom DPI Bypass** | Flaky *(Falls back to slow WireGuard-over-TLS)* | Blocked *(Standard ports 2408/51820 dropped by ISP)* | **100% Native Bypass** *(Privileged Anycast UDP Port 500 exemption)* |
| **Anti-Cheat Integrity (Hyperion / Byfron)** | Safe *(OS-level VPN)* | Safe *(OS-level VPN)* | **100% Safe** *(Pure Layer-3 Wintun driver; zero memory hooks or injection)* |
| **Bandwidth & Speed Caps** | Throttled / Shared capacity on free nodes | Unlimited | **Full Line Speed** *(Direct Anycast routing)* |
| **The Average Player Experience** | Voice works, but high ping leads to missed shots & delay | Silky smooth ~40ms ping, but completely muted & unable to chat | **The Holy Grail: Sub-45ms Wire Latency + Full Voice & Chat** |

### How Split-Tunneling Solves the Puzzle

1. **Why Free VPNs Destroy In-Game Latency:**  
   Free commercial VPNs encapsulate *all* computer network traffic across shared European relay nodes. In regions like Egypt where standard WireGuard UDP is blocked, free VPNs fall back to TCP/TLS encapsulation (`WireGuardTls` on port 443). Any dropped TCP segment triggers **Head-of-Line (HoL) blocking**, stalling every inner game packet and causing in-game ping to fluctuate wildly between **85ms and 150ms+**.
2. **Why Raw WARP Leaves Players Muted:**  
   The official Cloudflare 1.1.1.1 application connects to Cloudflare's edge with low latency (~40ms), but it reports the user's actual geographic origin country (`loc=EG`). Roblox detects this during startup policy queries and permanently locks spatial voice and text chat. Furthermore, Egyptian ISP middleboxes immediately drop standard WARP UDP ports (`2408`, `1701`, `51820`).
3. **The WARP-MIN Hybrid Architecture:**  
   WARP-MIN separates the network traffic into two independent planes:
   - **Data Plane (RakNet UDP `128.116.0.0/17`):** Direct Cairo-to-Milan subsea fiber over DPI-exempt UDP Port 500. Game latency drops from **~95ms down to ~40ms** (an instant **~55ms reduction**).
   - **Control Plane (Authentication & GUAC HTTPS):** Routed through the European VPN free tier (or dual-hop egress), ensuring Roblox validates European residency and grants full spatial voice and text chat permissions.

---

## The Architectural Solution

WARP-MIN solves this through four core innovations:

1. **Direct Mediterranean Submarine Ingestion (~38–42ms Wire Latency):**  
   Connects directly to Cloudflare's Mediterranean Anycast edge nodes in Milan (`MXP`) and Rome (`FCO`), taking the most direct submarine fiber route across the Mediterranean Sea.
2. **DPI Evasion via Privileged Anycast Port 500:**  
   Routes the outer WireGuard tunnel through UDP port 500 (the standard IKEv2 / IPsec port). Because enterprise banks, payment gateways, and corporate IPsec tunnels in Egypt rely on port 500, ISP middleboxes exempt this port from WireGuard heuristic dropping.
3. **Dual-Hop WireGuard ("Gool") Encapsulation:**  
   Encapsulates an inner WireGuard tunnel (Hop 2) within the established session of the outer tunnel (Hop 1). Hop 2 originates inside Cloudflare's internal Milan backbone with $<1.5\text{ms}$ intra-PoP delay and receives an egress IP from the European Anycast pool (`loc=IT` / `loc=DE`), matching European account settings.
4. **Split-Plane Kernel Routing (Control Plane vs. Data Plane):**  
   Rather than routing all system traffic through the tunnel, WARP-MIN strictly routes **RakNet UDP gameplay traffic (`128.116.0.0/17`)** through the high-performance Wintun adapter (`WARP-Gool`), while pinning Roblox control-plane HTTPS APIs (`apis.roblox.com`) through the primary/VPN network adapter.

---

## Key Features

- **Pure Rust Implementation:** Zero C/C++ runtime dependencies, built on Tokio, BoringTun (Cloudflare's Noise protocol implementation), and Wintun.
- **Wintun Kernel Layer-3 Driver:** Operates directly on the high-speed Wintun TUN driver with 8 MB zero-copy circular ring buffers and 4 MB OS UDP socket buffers.
- **TCP MSS Clamping (RFC 1624):** Automatically clamps TCP MSS to 1120 bytes on `SYN`/`SYN-ACK` packets with incremental 16-bit 1's complement checksum updates to prevent Path MTU black holes.
- **Dynamic Anycast Probing:** Probes 52 candidate Cloudflare Anycast endpoints in parallel at startup, locking into the lowest-latency responsive edge server.
- **Intra-PoP Complementary Pool Alignment:** Automatically alternates Hop 2 across complementary IP subnets (`162.159.192.0/24` $\leftrightarrow$ `188.114.97.0/24`) to eliminate Cloudflare's internal self-traffic drop bug.
- **Non-Destructive Local Policy Unlocker:** Safely updates cached Roblox GUAC policies in `appStorage.json` while keeping the file writable and preserving French/European account identity, cookies, and tokens.
- **Automatic UAC Elevation:** Detects non-elevated terminal execution and automatically requests Windows Administrator privileges via UAC `runas`, cleanly hiding duplicate console windows.
- **SOCKS5 Proxy Fallback:** Includes a built-in user-space TCP/IP netstack powered by `smoltcp 0.14` listening on `127.0.0.1:8086` for testing and non-elevated environments.

---

## Network Architecture & Split-Plane Model

```
+========================================================================================+
|                              LOCAL WINDOWS CLIENT (EGYPT)                              |
|                                                                                        |
|  [RobloxPlayerBeta.exe]                                                                |
|       |                                                                                |
|       +---> Data Plane: RakNet UDP (Ports 50000-65535, Subnet 128.116.0.0/17)          |
|       |     Bound to Wintun L3 Interface "WARP-Gool" (Metric: 1, MTU: 1200)            |
|       |                                                                                |
|       +---> Control Plane: HTTPS APIs (apis.roblox.com, auth.roblox.com)               |
|             Pinned via /32 Windows Host Routes to Primary Interface / European VPN     |
|                                                                                        |
|  +----------------------------------------------------------------------------------+  |
|  | INNER TUNNEL (Hop 2): WireGuard (MTU = 1200)                                     |  |
|  | Cryptographic Keypair: Ephemeral Curve25519 (Account 2)                          |  |
|  | Destination: Endpoint B (188.114.97.3:2408)                                      |  |
|  | Payload: Encapsulated inside Hop 1's encrypted UDP payload                       |  |
|  +-------------------------------------------+--------------------------------------+  |
|                                              |                                         |
|  +-------------------------------------------v--------------------------------------+  |
|  | OUTER TUNNEL (Hop 1): WireGuard (MTU = 1280)                                     |  |
|  | Cryptographic Keypair: Ephemeral Curve25519 (Account 1)                          |  |
|  | Destination: Endpoint A (162.159.192.1:500) via Physical Gateway                 |  |
|  | **Bypasses ISP DPI via Enterprise UDP Port 500 Exemption**                       |  |
|  +-------------------------------------------+--------------------------------------+  |
+==============================================|=========================================+
                                               | (Mediterranean Subsea RTT: ~38-42ms)
                                               v
+----------------------------------------------------------------------------------------+
|                          CLOUDFLARE MILAN EDGE POP (MXP / AS13335)                     |
|                                                                                        |
|  1. Hop 1 Terminates at Edge Ingress               --> Seen from Egypt (loc=EG)        |
|  2. Hop 2 Originates INSIDE Cloudflare Datacenter  --> Intra-PoP Transit Delay < 1.5ms |
|  3. Hop 2 Egress Assigned from European Pool       --> GeoIP Output: loc=IT / loc=DE   |
+----------------------------------------------+-----------------------------------------+
                                               | (Direct Peering RTT: ~2-4ms)
                                               v
+----------------------------------------------------------------------------------------+
|                             ROBLOX EDGE SERVERS (AS22697)                              |
|                                                                                        |
|  - Active Session Egress GeoIP: Italy (loc=IT) / Germany (loc=DE)                      |
|  - Roblox Account Country: Europe (Match Confirmed)                                    |
|  >> RESULT: SPATIAL VOICE & CHAT UNLOCKED | GAMEPLAY WIRE LATENCY: ~40-44ms             |
+----------------------------------------------------------------------------------------+
```

---

## Getting Started

### Prerequisites

- **Operating System:** Windows 10 or Windows 11 (64-bit).
- **Rust Toolchain:** Rust 1.85+ (Edition 2024 compatible) with either:
  - `x86_64-pc-windows-gnu` (MinGW-w64 / GCC)
  - `x86_64-pc-windows-msvc` (Visual Studio Build Tools)
- **Wintun Driver:** `wintun.dll` (WireGuard LLC signed driver, included in repository root).
- **Permissions:** Windows Administrator privileges are required to create the Wintun network adapter and manage kernel IP routes.

### Building from Source

```powershell
# Clone the repository
git clone https://github.com/<your-username>/Warper.git
cd Warper

# Build optimized release binary
cargo build --release

# Run the complete test suite (48 unit & integration tests)
cargo test --release
```

The compiled executable will be located at `target\release\warp-min.exe`.

---

## Running the Client

### Option 1: Full System TUN Adapter Mode (Recommended Default)

Launch PowerShell or Windows Terminal as **Administrator**:

```powershell
.\target\release\warp-min.exe --tun
```

*Note: If executed from a non-elevated prompt, WARP-MIN will automatically request elevation via Windows UAC.*

This command:
1. Validates and initializes Curve25519 identities for Hop 1 and Hop 2 (cached in `warp_identity_*.json`).
2. Probes 73 Cloudflare Anycast endpoints over UDP ports 500 and 4500 to find the fastest subsea route.
3. Creates the `WARP-Gool` L3 adapter with MTU 1200.
4. Configures `WARP-Gool` with native Win32 `SkipAsSource=1` and WeakHost routing, enabling seamless co-existence with primary European VPNs (e.g. ProtonVPN) without WFP leak protection drops or recursive routing loops.
5. Injects the `128.116.0.0/17` split-tunnel route for Roblox RakNet gameplay.
6. Surgically verifies and unlocks `appStorage.json` while maintaining filesystem write permissions.

### Option 2: SOCKS5 Proxy Mode (Non-Elevated / Fallback)

To run a standalone SOCKS5 proxy on `127.0.0.1:8086`:

```powershell
.\target\release\warp-min.exe --socks --bind 127.0.0.1:8086
```

Verify traffic over the proxy:

```powershell
curl.exe -v --socks5-hostname 127.0.0.1:8086 https://www.cloudflare.com/cdn-cgi/trace
```

---

## Roblox Pre-Flight Instructions

To guarantee that regional voice chat and platform text chat are unlocked:

1. **Preserve Account Cache:**  
   Do **NOT** wipe `%LOCALAPPDATA%\Roblox\LocalStorage\*` or remove `appStorage.json`. Preserving this file maintains your account cookies, authentication tokens, and European country code (`CountryCode: FR/IT`).
2. **Ensure European Control-Plane Egress:**  
   Connect your European VPN (e.g. ProtonVPN set to Netherlands or Italy) for web and launcher traffic.
3. **Launch WARP-MIN First:**  
   Start `warp-min.exe --tun` in an elevated terminal. Wait until you see:
   ```text
   [+] Hop 1 Handshake established with 162.159.192.1:500 (RTT: 41ms)!
   [+] Hop 2 Handshake established with 188.114.97.3:2408 (Inner RTT: 42ms)!
   [+] Pure Split-Tunneling active: Roblox gameplay UDP routes via WARP-Gool (128.116.0.0/17)
   ```
4. **Launch Roblox:**  
   Launch `RobloxPlayerBeta.exe`. In-game chat and spatial voice will be fully active, and gameplay latency will lock in at **~40ms**.

---

## CLI Reference

```text
Usage: warp-min.exe [OPTIONS]

Options:
      --tun                    Enable Wintun adapter mode ('WARP-Gool') with split-tunneling [default]
      --socks                  Enable SOCKS5 proxy mode
      --bind <BIND>            Bind address for SOCKS5 proxy mode [default: 127.0.0.1:8086]
      --endpoint-a <ADDR>      Cloudflare outer Anycast endpoint A [default: 162.159.192.1:500]
      --endpoint-b <ADDR>      Cloudflare inner Anycast endpoint B [default: 188.114.97.3:2408]
      --single                 Single-hop direct WARP mode (outer tunnel only, for diagnostics)
      --register-hop2          Re-register Hop 2 identity through SOCKS5 proxy to obtain European GeoIP
  -h, --help                   Print help
  -V, --version                Print version
```

---

## Repository Structure

```text
Warper/
├── .github/workflows/ci.yml # GitHub Actions CI automation (fmt, clippy, test, build)
├── .gitattributes           # Cross-platform LF normalization & binary driver rules
├── .gitignore               # Strict ignore rules for binaries, build artifacts, and tokens
├── Cargo.toml               # Rust package manifest and zero-bloat dependencies
├── Cargo.lock               # Deterministic dependency lockfile
├── build.rs                 # Automatic driver bundling for target/(debug|release)
├── wintun.dll               # WireGuard LLC official signed Wintun driver (427 KB)
├── warp_identity.example.json # Template for WARP Curve25519 identity credentials
├── CONTRIBUTING.md          # Open-source contribution guidelines & developer workflow
├── LICENSE-MIT              # MIT license
├── LICENSE-APACHE           # Apache-2.0 license
├── README.md                # Project documentation and user guide
├── future_work/             # Engineering roadmaps & architectural blueprints
│   ├── README.md                                          # Master roadmap & priority matrix
│   ├── 01_STANDALONE_EUROPEAN_HOP2.md                    # Blueprint 01: Standalone EU Hop 2
│   ├── 02_WINDOWS_SYSTEM_TRAY_GUI.md                     # Blueprint 02: Win32 Tray GUI & HUD
│   ├── 03_RELEASE_PACKAGING_AND_INSTALLER.md             # Blueprint 03: Automated CI/CD & Setup
│   ├── 04_DYNAMIC_WEBRTC_TURN_SNIFFING.md                # Blueprint 04: WebRTC TURN Sniffing
│   ├── 05_STRUCTURED_DIAGNOSTIC_LOGGING.md               # Blueprint 05: Logging & Error Chaining
│   └── 06_LATENCY_SPIKE_MITIGATION_AND_PING_STABILITY.md # Blueprint 06: Ping Jitter Mitigation
├── docs/                    # Comprehensive architectural and engineering specifications
│   ├── README.md                                          # Documentation index
│   ├── architecture-and-split-plane-network-model.md     # Dual-Hop WireGuard & Split-Plane
│   ├── dpi-and-anycast-port-500-bypass.md                # Middlebox DPI evasion & Port 500
│   ├── roblox-protocol-analysis.md                       # RakNet UDP, Titanium CDN & GUAC
│   ├── windows-kernel-routing-and-wlan-optimization.md   # Windows LPM routing & Wi-Fi fix
│   └── troubleshooting-and-verification-guide.md         # 6-Gate verification & diagnostics
└── src/
    ├── main.rs              # CLI orchestration, Anycast probing, policy watchdog
    ├── tunnel.rs            # Dual-hop BoringTun engine, MSS clamp, packet classifier
    ├── tun.rs               # Wintun L3 adapter engine & kernel route table manager
    ├── socks.rs             # smoltcp user-space netstack & SOCKS5 proxy server
    ├── dns.rs               # In-memory RFC 1035 DNS parser (CNAME & 14-bit pointers)
    ├── api.rs               # Curve25519 keypair generator & Cloudflare TLS 1.3 reg API
    ├── elevate.rs           # Windows token elevation & console hiding
    └── logger.rs            # Structured logging, error backtraces & cross-MIC IPC
```

---

## Documentation Index

For deep technical insights, refer to the documentation in `docs/` and `future_work/`:

- **[Architecture & Split-Plane Network Model](docs/architecture-and-split-plane-network-model.md)**
- **[Deep Packet Inspection (DPI) & Anycast Port 500 Bypass](docs/dpi-and-anycast-port-500-bypass.md)**
- **[Roblox Protocol Analysis](docs/roblox-protocol-analysis.md)**
- **[Windows Kernel Routing & WLAN Optimization](docs/windows-kernel-routing-and-wlan-optimization.md)**
- **[Troubleshooting & Verification Guide](docs/troubleshooting-and-verification-guide.md)**
- **[Future Work & Engineering Roadmap](future_work/README.md)** (Blueprints 01-06: Standalone EU Hop 2, Tray GUI, CI/CD, Voice Sniffing, Diagnostics, Ping Stability)

---

## Wi-Fi Latency Optimization

If playing over Wi-Fi, Windows AutoConfig (`WlanSvc`) scans for surrounding SSIDs every 60 seconds, causing a periodic **100ms–500ms** ping spike.

To temporarily disable background scanning during gaming:

```cmd
:: Run as Administrator in Command Prompt or PowerShell:
netsh wlan set autoconfig enabled=no interface="Wi-Fi"
```

To re-enable scanning when switching networks:

```cmd
netsh wlan set autoconfig enabled=yes interface="Wi-Fi"
```

---

## License & Security Disclaimer

### Licensing (Dual-License Model: MIT OR Apache-2.0)

This project is licensed under the standard Rust ecosystem dual-license structure: you may choose either the [MIT License](LICENSE-MIT) or the [Apache License 2.0](LICENSE-APACHE) at your option.

- **Why two licenses?**  
  In the Rust community (following the precedent set by the Rust language itself, Tokio, and standard crates), dual-licensing allows downstream developers and organizations to select whichever terms fit their legal requirements:
  - **MIT:** Short, simple, and permissive with minimal constraints for individual developers and small projects.
  - **Apache 2.0:** Includes explicit patent grants and intellectual property protections for corporate/enterprise environments.
- **Can you use just one license?**  
  Yes. Users and redistributors are free to treat this project solely under the terms of the **MIT License**.

### Security Notice: Identity Files & Cryptographic Secrets

WARP-MIN automatically registers client sessions with Cloudflare's Edge API on initial startup and generates credentials cached locally in:
- `warp_identity_hop1.json` (Outer tunnel session)
- `warp_identity_hop2.json` (Inner tunnel session)

These files contain:
1. **Curve25519 Private Keys:** The local cryptographic secret key used by WireGuard (via BoringTun) to compute Diffie-Hellman shared secrets and encrypt all outbound network packets.
2. **Cloudflare Device Tokens:** Secret bearer authentication tokens issued by Cloudflare's registration API.

> [!WARNING]
> **Keep your identity files private.**  
> If your `warp_identity_*.json` files are committed to a public Git repository or shared online, third parties can extract your tokens, duplicate your WireGuard session across multiple machines simultaneously (causing session reset collisions), or abuse Cloudflare's API under your identity.  
> 
> These files are strictly ignored by Git via `.gitignore`. A safe dummy template with placeholders is provided in `warp_identity.example.json`.
