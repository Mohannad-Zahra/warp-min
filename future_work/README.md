# WARP-MIN Future Engineering Roadmap & Architecture Blueprints

Welcome to the **WARP-MIN Future Work & Engineering Blueprints** repository. This directory houses technical specifications, architectural roadmaps, and protocol designs for upcoming milestones in the WARP-MIN project.

---

## 1. Vision & Architectural Evolution

WARP-MIN v1.0 successfully proved that **nested dual-hop WireGuard over privileged UDP Port 500** bypasses stateful ISP Deep Packet Inspection (DPI) in Egypt (AS8452 / Telecom Egypt) while delivering unprecedented **~38–42ms subsea wire latency** and unlocking Roblox regional voice restrictions via split-tunneling.

The v2.0 roadmap transitions WARP-MIN from an advanced developer CLI utility into an **autonomous, 100% standalone, zero-friction network accelerator** with native Windows GUI controls and dynamic media traffic classification.

```
CURRENT ARCHITECTURE (v1.0):
+---------------------+      +----------------------+      +-----------------------+
|  Roblox / Discord   | ---> | WARP-MIN CLI (Rust)  | ---> | Cloudflare Milan PoP  |
+---------------------+      | [Wintun Data Plane]  |      | (Hop 1 via UDP 500)   |
           |                 +----------------------+      +-----------------------+
           v
+---------------------+
| External ProtonVPN  | ---> Required for Control Plane (GUAC / apis.roblox.com)
+---------------------+

FUTURE ARCHITECTURE (v2.0):
+----------------------------------------------------------------------------------+
|                            WARP-MIN v2.0 PLATFORM                                |
|                                                                                  |
|  [System Tray GUI] <-----> [Dynamic Packet Classifier] <-----> [Dual-Hop Engine] |
|   - Win32 HUD (41ms)        - Sniffs external WebRTC/TURN       - 100% Standalone|
|   - 1-Click Toggle          - Auto-injects /32 host routes      - Self-Egress EU |
|   - Zero Bloat (<12MB)      - LiveKit / AWS VoIP unblocked      - No Proton VPN  |
+----------------------------------------------------------------------------------+
                                        |
                 Subsea Mediterranean Wire Transit (Port 500)
                                        v
                    +---------------------------------------+
                    | Cloudflare Anycast & European Egress  |
                    | (Milan MXP / Frankfurt FRA / Hetzner) |
                    +---------------------------------------+
```

---

## 2. Priority Matrix

| ID | Initiative | Priority | Complexity | Target Milestone | Primary Impact | Dependencies |
|:---|:---|:---:|:---:|:---:|:---|:---|
| **[01](01_STANDALONE_EUROPEAN_HOP2.md)** | **Standalone European Hop 2** | **P0** | High | v1.1.0 | Eliminates external Proton VPN requirement; 100% standalone operation | BoringTun, Cloudflare Reg API |
| **[02](02_WINDOWS_SYSTEM_TRAY_GUI.md)** | **Windows System Tray GUI & HUD** | **P1** | Medium | v1.2.0 | Eliminates console window; real-time ping monitor & 1-click toggle | `tray-icon`, `muda`, Win32 |
| **[03](03_RELEASE_PACKAGING_AND_INSTALLER.md)** | **Automated CI/CD & Installer** | **P1** | Medium | v1.2.0 | Zero-setup distribution; embedded driver; signed portable bundle | GitHub Actions, NSIS/Inno |
| **[04](04_DYNAMIC_WEBRTC_TURN_SNIFFING.md)** | **Dynamic WebRTC / TURN Sniffer** | **P2** | High | v1.3.0 | Unblocks dynamic AWS/LiveKit voice relays outside `128.116.0.0/17` | WinDivert / IP Helper API |
| **[05](05_STRUCTURED_DIAGNOSTIC_LOGGING.md)** | **Structured Logging & Diagnostics** | **P0** | Low | Immediate | Eliminates silent failures, file logging, error cause chaining | `src/logger.rs`, Win32 Console |
| **[06](06_LATENCY_SPIKE_MITIGATION_AND_PING_STABILITY.md)** | **Latency Spike & Ping Jitter Mitigation** | **P0** | Medium | v1.0.1 | Eliminates transient ping spikes; pre-emptive rekeying, Wi-Fi scan pause, QoS | `src/tunnel.rs`, `wlanapi.dll` |

---

## 3. Engineering Blueprints Directory

### [Blueprint 01: Standalone European Hop 2 Architecture](01_STANDALONE_EUROPEAN_HOP2.md)
*Eliminating External Commercial VPNs (Proton/Nord) from the Split-Plane Model*
- **Problem:** Currently, Roblox control-plane HTTPS requests (`apis.roblox.com`, `auth.roblox.com`) require an external European VPN to bypass Egypt GeoIP detection (`loc=EG`) and fetch unlocked GUAC policies.
- **Solution:** Integrates an autonomous European egress pipeline directly into Hop 2 via Cloudflare Zero Trust, automated in-tunnel WARP registration, or private European WireGuard peers (Hetzner / Oracle Always-Free).
- **Deliverables:** In-tunnel identity bootstrapping, micro-DNS resolver, control-plane route pinning, standalone startup.

### [Blueprint 02: Windows System Tray GUI & Real-Time HUD](02_WINDOWS_SYSTEM_TRAY_GUI.md)
*Ultra-Lightweight Native Win32 Tray Application with Live In-Game Latency Monitor*
- **Problem:** Gamers must run WARP-MIN inside an elevated terminal window, without graphical status indicators, live ping graphs, or one-click toggles.
- **Solution:** A high-performance, native Windows system tray application built in pure Rust using `tray-icon` and `muda` (or direct Win32 message loop). Strict performance budget: **<12 MB RAM, 0% idle CPU**.
- **Deliverables:** State-colored tray icons, real-time RTT tooltip, native context menu, toast notifications, Roblox process watchdog.

### [Blueprint 03: Automated Release Packaging, Driver Bundling & Installer](03_RELEASE_PACKAGING_AND_INSTALLER.md)
*GitHub Actions CI/CD Pipeline, Embedded Wintun Driver, and One-Click Setup*
- **Problem:** Users currently build from source or manually manage `wintun.dll` placement, leading to driver path mismatches and UAC confusion.
- **Solution:** Automated GitHub Actions release pipeline building optimized portable binaries with embedded `wintun.dll` (via `include_bytes!`), checksum generation, and an optional one-click Windows installer (Inno Setup / NSIS).
- **Deliverables:** `.github/workflows/release.yml`, embedded driver extraction fallback, portable ZIP archive, automated code signing workflow.

### [Blueprint 04: Dynamic WebRTC / TURN Media Server Sniffing](04_DYNAMIC_WEBRTC_TURN_SNIFFING.md)
*Deep Packet Inspection Engine for Dynamic Voice Servers Outside Static CIDRs*
- **Problem:** While RakNet gameplay is bound to AS22697 (`128.116.0.0/17`), Roblox Spatial Voice uses external WebRTC relays (LiveKit / AWS EC2) on dynamic IP addresses that are throttled by ISP DPI if unrouted.
- **Solution:** A kernel-level or socket-level packet classifier (WinDivert / IP Helper API) that detects STUN/TURN binding requests from `RobloxPlayerBeta.exe` and dynamically injects transient `/32` host routes through the `WARP-Gool` adapter.
- **Deliverables:** STUN packet parser, dynamic route table manager with LRU eviction, process socket correlator.

### [Blueprint 05: Structured Diagnostic Logging & Telemetry Engine](05_STRUCTURED_DIAGNOSTIC_LOGGING.md)
*High-Precision Log Architecture, Error Cause Chaining, and Crash Diagnostics*
- **Problem:** When launched without a persistent terminal or when elevated, silent exits occur without logs, making network or driver troubleshooting impossible without deep investigation.
- **Solution:** Dual-sink logging engine (Console + `warp-min.log` on disk), ISO 8601 timestamps, log level filtering, error cause chaining, and pause-on-error for interactive windows.
- **Deliverables:** File logger, error backtrace formatters, CLI flags (`--log-file`, `--verbose`).

### [Blueprint 06: Latency Spike Mitigation, Ping Jitter Stabilization & Flow Resilience](06_LATENCY_SPIKE_MITIGATION_AND_PING_STABILITY.md)
*Eliminating Transient Elevated Ping Events, Rekeying Delays, and Wi-Fi Scanning Spikes*
- **Problem:** Live field testing in Cairo revealed periodic transient ping spikes lasting several seconds before returning to baseline ~42ms.
- **Solution:** Pre-emptive asynchronous WireGuard rekeying (at 90s before the 120s deadline), automated Windows `WlanSvc` background scan suppression via `wlanapi.dll`, DSCP 46 Expedited Forwarding QoS marking, and multi-candidate hot-standby Anycast failover.
- **Deliverables:** `wlanapi.dll` RAII scanner guard, pre-emptive rekeying timer loop in `src/tunnel.rs`, DSCP 46 socket configuration.

---

## 4. Development Principles & Non-Functional Requirements

All contributions to future milestones must uphold the core engineering tenets of WARP-MIN:

1. **Sub-45ms Latency SLA:** No added architectural layer (GUI, sniffer, or routing layer) may add more than **0.5ms** of processing latency to the RakNet data plane.
2. **Zero Bloat Policy:** No webview runtimes (Electron, Tauri, CEF) are permitted. All client components must be written in pure Rust or native Win32.
3. **Fail-Safe Route Recovery:** If the application terminates abnormally, all injected Windows kernel routes (`128.116.0.0/17`, `/32` pins) must be cleanly removed or fail back to the default gateway without disrupting user internet connectivity.
4. **Deterministic Security:** WireGuard private keys and authentication tokens must never be written to non-protected locations or transmitted in plaintext.

---

## 5. Getting Started on Future Items

To contribute to or implement any of the blueprints:
1. Review the detailed blueprint document in this directory.
2. Create a feature branch following the naming convention: `feature/<blueprint-id>-<short-description>` (e.g., `feature/01-standalone-hop2` or `feature/02-tray-gui`).
3. Maintain test coverage: any new protocol parser or route generator must include unit tests matching existing standards in `src/`.
