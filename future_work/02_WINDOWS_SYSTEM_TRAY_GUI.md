# Blueprint 02: Windows System Tray GUI & Real-Time In-Game HUD

## High-Performance, Zero-Bloat Win32 Tray Application for Gamers

- **Initiative ID:** `BW-02`
- **Priority:** `P1` (User Experience & Usability)
- **Status:** Architecture Approved / In Design
- **Target Release:** `v1.2.0`

---

## 1. Executive Summary & Design Philosophy

WARP-MIN is an esports-grade network utility designed for competitive gaming. Traditional consumer desktop tools often rely on heavy webview engines (Electron, Tauri, Chromium Embedded Framework) which consume **150MB–350MB of RAM** and create CPU micro-spikes that induce framerate stuttering during fast-paced gameplay.

### The Zero-Bloat Mandate:
- **Language & Runtime:** Pure Rust 2024 with direct Win32 API bindings (`windows-sys` / `muda` / `tray-icon`).
- **Memory Footprint:** $\le 12 \text{ MB}$ RSS working set.
- **CPU Overhead:** $0.0\%$ CPU at idle; $<0.2\%$ when polling real-time metrics.
- **Visuals:** Native Windows 11 Fluent / Win32 dark theme system tray icon, context menu, and minimal telemetry HUD.

---

## 2. User Experience & State Machine

```
              +-----------------------------------+
              |          DISCONNECTED             | (Gray Tray Icon)
              |  - All routes restored to default |
              |  - Tunnel sockets closed          |
              +-----------------+-----------------+
                                |
                   User clicks "Connect"
                                |
                                v
              +-----------------------------------+
              |         PROBING / SYNC            | (Yellow Pulsing Icon)
              |  - Anycast Port 500 probing (52x) |
              |  - Curve25519 handshake exchange  |
              |  - Wintun adapter initialization  |
              +-----------------+-----------------+
                                |
                     Handshake 2 Confirmed
                                |
                                v
              +-----------------------------------+
              |            CONNECTED              | (Bright Green Shield Icon)
              |  - Milan MXP (41ms wire latency)  |
              |  - Split-tunnel 128.116.0.0/17    |
              |  - Roblox chat & voice unlocked   |
              +-----------------+-----------------+
                                |
                   Packet loss > 5% detected
                                |
                                v
              +-----------------------------------+
              |       DEGRADED / RE-ROUTING       | (Orange Warning Icon)
              |  - Intra-PoP pool re-probing      |
              |  - Dynamic failover candidate     |
              +-----------------------------------+
```

---

## 3. Tray Interface & Context Menu Hierarchy

Right-clicking the WARP-MIN tray icon presents a native Win32 context menu:

```text
+-------------------------------------------------------+
|  [●] WARP-MIN: Connected (Milan MXP - 41ms)           | <- Status Header (bold)
|-------------------------------------------------------|
|  [■] Disconnect                                       | <- Primary Action Toggle
|-------------------------------------------------------|
|  Latency Mode                                       > | -> [✓] Dual-Hop Subsea (41ms - MXP)
|                                                       |    [ ] Single-Hop Direct (Diagnostic)
|-------------------------------------------------------|
|  [⚡] Show In-Game Ping HUD                           | <- Opens micro floating overlay
|  [🛡] Unlock Roblox Voice Chat Now                     | <- Runs GUAC surgery on demand
|  [↺] Reset Windows Network Routes                     | <- Emergency route table flush
|-------------------------------------------------------|
|  Settings                                           > | -> [✓] Start with Windows
|                                                       |    [✓] Auto-Connect on Game Boot
|                                                       |    [✓] Enable Low-Latency WLAN Fix
|-------------------------------------------------------|
|  [📄] Open Log File (warp-min.log)                    |
|  [✖] Exit WARP-MIN                                    |
+-------------------------------------------------------+
```

### Dynamic Tray Tooltip (Hover):
Hovering over the tray icon displays a real-time status summary without opening any windows:
```text
WARP-MIN v1.2.0 | Status: Active
• Edge PoP: Milan MXP (162.159.192.1:500)
• Wire Latency: 40.8 ms (Jitter: 0.6 ms)
• Active Game: Roblox (128.116.42.10:59124)
• Transferred: 42.1 MB In / 18.4 MB Out
```

---

## 4. Live In-Game Ping HUD (Micro-Overlay)

For gamers who want real-time visibility without alt-tabbing:
- An ultra-compact $180\times 48\text{px}$ transparent click-through window positioned in a screen corner.
- Rendered using Direct2D or native Win32 GDI with zero composition lag.
- Displays:
  - Wire RTT to Cloudflare Anycast Milan edge (ICMP / UDP echo).
  - Estimated RakNet gameplay RTT based on WireGuard sliding window sequence telemetry.
  - Active tunnel state indicator.

---

## 5. Architectural Implementation

### 5.1 Technology Stack Selection
- `tray-icon` (`0.14`) and `muda` (`0.13`): Modern, official Cross-platform Rust system-tray and native menu libraries maintained by the Tauri/Rust community, but compiled without webview runtimes.
- `windows-sys` (`0.52`): Native Win32 window messaging (`WM_USER`, `Shell_NotifyIconW`, `SetTimer`).
- `tokio::sync::watch`: Broadcasts connection state changes to the UI thread without locks or allocations.

### 5.2 Privilege Separation & Elevation Architecture

Because creating the `WARP-Gool` Wintun adapter and injecting routes into `MibIPInterfaceRow` requires Windows Administrator rights, two elevation architectures are evaluated:

#### Option 1: Monolithic Single-Process Elevation (Target for v1.2.0)
- The entire application runs as Administrator (prompted once via UAC on boot or shortcut launch).
- Advantages: Zero IPC overhead, straightforward distribution, no background service to register/unregister.

#### Option 2: Split Client-Service Architecture (Target for Enterprise / v2.0)
- **Windows Service (`warp-svc.exe`):** Runs as `NT AUTHORITY\SYSTEM` in Session 0. Manages `wintun.dll`, BoringTun encryption loops, and route tables.
- **Tray Client (`warp-tray.exe`):** Runs in the standard interactive user session without admin privileges. Communicates with the service via Windows Named Pipes (`\\.\pipe\warp-min-ipc`).
- Advantages: Gamers never see a UAC prompt on login.

---

## 6. Implementation Roadmap

1. **Step 1:** Implement Win32 message loop and system tray event listener in `src/tray.rs`.
2. **Step 2:** Integrate connection toggle with existing Tokio runtime (`tokio::sync::broadcast`).
3. **Step 3:** Add real-time RTT estimator querying `DualHopTunnel` statistics every 1,000ms.
4. **Step 4:** Add Windows Toast notification integration (`windows_sys::Win32::UI::Shell`) for match detection.
