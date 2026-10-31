# Windows Kernel Routing & WLAN Background Scan Optimization

## 1. Windows TCPIP Kernel Routing Mechanics

Windows manages network egress using its internal TCPIP routing table. When multiple interfaces (physical Ethernet/Wi-Fi, VPN virtual adapters, and Wintun interfaces) are active simultaneously, the kernel applies deterministic route selection rules.

```
Incoming Outbound Packet (e.g. Dest: 128.116.21.3)
                  |
                  v
+-------------------------------------------------------------+
| Step 1: Longest Prefix Match (LPM) Evaluation               |
+-------------------------------------------------------------+
| Candidates:                                                 |
|  - 0.0.0.0/0         (Prefix Length:  0)                    |
|  - 128.116.0.0/17    (Prefix Length: 17)                    |
|  - 128.116.21.3/32   (Prefix Length: 32)  <-- LONGEST MATCH |
+-------------------------------------------------------------+
                  |
                  v
[Selected Route: 128.116.21.3/32 via Primary/VPN Interface (ProtonVPN)]
Result: HTTPS Control Traffic routes to European Breakout.
```

If another packet is destined for `128.116.88.45:52140` (a RakNet gameplay server):
```
Candidates:
 - 0.0.0.0/0         (Prefix Length:  0)
 - 128.116.0.0/17    (Prefix Length: 17)  <-- LONGEST MATCH
Result: RakNet UDP Gameplay routes directly via WARP-Gool L3 Tun (<45ms).
```

---

## 2. Split-Plane Routing Implementation

WARP-MIN achieves zero-overhead split-tunneling by injecting specific routing entries into the Windows kernel:

### 2.1 Outer Anycast Endpoint Pinning (Anti-Loop Rule)
To prevent recursive encapsulation loops:
- If the outer WireGuard socket sends encrypted UDP packets to `162.159.192.1:500`, those packets must traverse the physical network adapter through the physical gateway.
- If a default route (`0.0.0.0/0`) pointed to the Wintun adapter without this exception, outer encrypted WireGuard packets would route back into the Wintun interface, causing an immediate kernel packet loop and freeze.
- **Enforcement (`src/tun.rs`):**
  ```cmd
  route add 162.159.192.1 mask 255.255.255.255 <PHYSICAL_GATEWAY> metric 1
  ```

### 2.2 RakNet Gameplay Route (`128.116.0.0/17`)
- The Roblox server subnet (`AS22697`) is bound to the `WARP-Gool` interface:
  ```cmd
  route add 128.116.0.0 mask 255.255.128.0 172.16.0.1 metric 1 if <WARP_GOOL_IF_INDEX>
  ```
- Because its metric is set to `1`, all gameplay UDP traffic to servers in the range `128.116.0.0`–`128.116.127.255` egresses exclusively through the low-latency dual-hop tunnel.

### 2.3 Roblox Control-Plane Host Routes (`/32`)
Roblox API edge servers (`apis.roblox.com`, `auth.roblox.com`, `voice.roblox.com`) often reside on IP addresses within the `128.116.x.x` prefix (e.g. `128.116.5.3`, `128.116.13.3`, `128.116.21.3`).
- Because `/32` prefix length takes absolute precedence over `/17` in the Windows kernel routing table, WARP-MIN pins these specific edge IPs to the primary/VPN network adapter:
  ```powershell
  New-NetRoute -DestinationPrefix "128.116.21.3/32" -InterfaceIndex <PRIMARY_IF> -NextHop <PRIMARY_GW> -RouteMetric 1
  ```
- This ensures HTTPS authentication and GUAC policy checks exit through the European VPN breakout, while RakNet gameplay packets exit through `WARP-Gool`.

---

## 3. Route Lifecycle & Teardown Architecture

Orphaned routes left behind by crashed or improperly terminated VPN software can break internet connectivity. WARP-MIN enforces atomic cleanup:

1. **Shutdown Signal Interception:** Tokio listens for `tokio::signal::ctrl_c()`. When triggered, graceful teardown is initiated.
2. **Deterministic Route Deletion:**
   - Shuts down the Wintun ring session (`session.shutdown()`).
   - Removes adapter IP bindings via `netsh`.
   - Deletes all injected `/32` API routes.
   - Deletes the `128.116.0.0/17` gameplay route.
   - Deletes the `/32` physical gateway host route for Endpoint A.
3. **Rust `Drop` Trait Guard:**
   `WintunDevice` implements `Drop`. If the application panics or exits prematurely, `restore_routing()` is executed automatically. An `AtomicBool` (`cleaned_up`) prevents double-free or redundant route deletions.

---

## 4. Windows WLAN Background Scan Optimization

A frequent cause of micro-stutter and lag spikes in online games on Windows is the **WLAN Background AutoConfig Scan**.

### 4.1 The 60-Second Lag Spike Problem
When connecting to a game over Wi-Fi on Windows 10/11:
- The Windows WLAN AutoConfig service (`WlanSvc`) periodically scans for surrounding Wi-Fi networks every 60 seconds to populate the taskbar network list.
- To execute this scan, the Wi-Fi card must tune its radio away from the active router's channel and cycle across all 2.4 GHz and 5 GHz channels.
- While the radio is on other channels, incoming and outgoing UDP packets cannot be transmitted or received.
- **Symptom:** Every 60 seconds, game ping spikes from ~40ms to **250ms–600ms**, accompanied by packet loss and teleportation.

```
Game Latency Timeline (WlanSvc Scanning Enabled):
Ping (ms)
 500 |                   *                                       *
 400 |                  ***                                     ***
 300 |                 *****                                   *****
 200 |                *******                                 *******
 100 |               *********                               *********
  40 |--------------------------------------------------------------------- (Normal RTT)
     +---------------+-----------------------+---------------+-------------+
    0s              60s                    120s            180s          240s
                     ^                                       ^
              [Scan Occurred]                         [Scan Occurred]
```

### 4.2 Remediation: Disabling Background Scanning
During gaming sessions, background scanning can be disabled via `netsh wlan`:

```cmd
:: Disable Wi-Fi background scanning (Run as Administrator)
netsh wlan set autoconfig enabled=no interface="Wi-Fi"
```
*Note: Replace `"Wi-Fi"` with your Wi-Fi interface name as shown in `netsh wlan show interfaces`.*

Once disabled:
- The Wi-Fi adapter stays locked to the active channel.
- Latency remains flat at **~40ms** with zero periodic spikes.

### 4.3 Restoring Wi-Fi Scanning
When roaming to a new location or switching networks, re-enable scanning:
```cmd
:: Re-enable Wi-Fi background scanning
netsh wlan set autoconfig enabled=yes interface="Wi-Fi"
```

---

## 5. Wintun Low-Level Driver Optimization

WARP-MIN embeds the high-performance **Wintun** driver developed by WireGuard LLC:

### 5.1 Ring Buffer Allocation
- WARP-MIN initializes the driver session with `wintun::MAX_RING_CAPACITY` (8 MB per ring buffer).
- Wintun uses zero-copy circular ring buffers in shared kernel-user memory, avoiding standard Windows NDIS filter driver latency.

### 5.2 Buffer Contention Handling
During heavy gameplay bursts, kernel ring buffers can temporarily fill:
- WARP-MIN implements a 3-attempt spin-yield retry algorithm:
  ```rust
  let mut allocated = None;
  for attempt in 0..3 {
      match session_write.allocate_send_packet(pkt_len) {
          Ok(pkt) => { allocated = Some(pkt); break; }
          Err(_) => {
              if attempt < 2 { std::thread::yield_now(); }
          }
      }
  }
  ```
- Yielding the OS thread allows the kernel driver to drain processed packets, avoiding packet drops.

### 5.3 Physical UDP Socket Tuning
The physical UDP socket communicating with Cloudflare Anycast endpoints is configured with:
- **4 MB Send / Receive OS Buffers:** Eliminates Windows socket buffer overflow during traffic spikes.
- **`SIO_UDP_CONNRESET` Suppression:** By default, Windows socket calls return `WSAECONNRESET` (10054) on UDP sockets if a previous outbound datagram generated an ICMP Port Unreachable. WARP-MIN uses `WSAIoctl` to disable this behavior, ensuring the socket never drops healthy WireGuard streams due to stray ICMP messages.
