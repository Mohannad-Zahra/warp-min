# Roblox Protocol Analysis

## 1. Roblox Multi-Tier Network Architecture

The Roblox client (`RobloxPlayerBeta.exe`) employs a hybrid multi-tier networking model combining embedded HTTP clients, CDN edge terminators, proprietary UDP game sync protocols, and WebRTC voice pipelines.

```
+========================================================================================+
|                                  RobloxPlayerBeta.exe                                  |
+========================================================================================+
         |                                           |                           |
         | (1) Control Plane: HTTPS/REST             | (2) Data Plane: RakNet    | (3) Voice: STUN/SRTP
         v                                           v                           v
+-------------------------------+       +-------------------------+     +----------------+
| Embedded libcurl Client       |       | Custom RakNet UDP Engine|     | WebRTC Audio   |
| - TLS 1.3 over TCP 443        |       | - Ports: 50000-65535    |     | - Signaling:   |
| - Titanium Edge CDN           |       | - Subnet: 128.116.0.0/17|     | voice.roblox   |
| - GUAC Policy Engine          |       | - State Sync & Physics  |     | - SRTP Voice   |
+---------------+---------------+       +------------+------------+     +-------+--------+
                |                                    |                          |
                v                                    v                          v
  [Primary / EU VPN Egress]                 [WARP-Gool L3 Tun]          [WARP-Gool L3 Tun]
  - European GeoIP (loc=IT/FR)              - Direct Subsea Fiber       - VoIP Unblocked
  - Instant Launcher Load                   - Ping: 40-44ms wire SLA    - Sub-45ms Voice
```

---

## 2. Control Plane Analysis: libcurl & Titanium Edge

### 2.1 The Embedded libcurl Engine
Roblox builds its Windows client with a customized build of `libcurl` statically linked into `RobloxPlayerBeta.exe`.
- **Target Endpoints:**
  - `apis.roblox.com`: Core configuration, telemetry, and feature flags.
  - `auth.roblox.com`: Account session validation and token refreshing.
  - `versioncompatibility.api.roblox.com`: Launcher boot check and channel selection.
  - `clientsettings.roblox.com` & `clientsettingscdn.roblox.com`: Engine flags (FFlags).
  - `voice.roblox.com`: Spatial voice token distribution and session initialization.

### 2.2 Titanium Edge & RFC 1035 Compression Pointer Resolution
Roblox terminates API traffic through its proprietary **Titanium Edge** load-balancing infrastructure.
- In DNS, `apis.roblox.com` resolves through a multi-tier CNAME alias hierarchy:
  `apis.roblox.com` $\rightarrow$ `titanium.roblox.com` $\rightarrow$ `edge-term4-ams2.roblox.com` $\rightarrow$ `128.116.53.3`
- According to **RFC 1035 §4.1.4**, DNS answer records utilize 14-bit compression pointers (`0xc0xx`) to reference previously encountered domain labels in the query buffer.
- Simplified DNS decoders that assume contiguous uncompressed strings fail when parsing Titanium edge answers. WARP-MIN's internal DNS parser (`src/dns.rs`) implements compliant pointer tracking:

```rust
pub fn skip_dns_name(buf: &[u8], mut offset: usize) -> Option<usize> {
    while offset < buf.len() {
        let len = buf[offset] as usize;
        if len == 0 {
            return Some(offset + 1); // Zero-length root label
        }
        if (len & 0xc0) == 0xc0 {
            // RFC 1035 §4.1.4 14-bit compression pointer (2 bytes)
            if offset + 1 >= buf.len() { return None; }
            return Some(offset + 2);
        }
        if (len & 0xc0) != 0 { return None; } // Invalid reserved bits
        if offset + 1 + len > buf.len() { return None; }
        offset += 1 + len;
    }
    None
}
```

### 2.3 Multi-Homed DNS Timeout Phenomenon
When a virtual VPN adapter registers DNS servers (e.g. `1.1.1.1`) while a physical adapter also has active DNS servers, Windows activates its **Multi-Homed DNS Resolution** behavior:
- Queries are sent concurrently across both interfaces.
- If one interface stalls or drops DNS datagrams, `libcurl` in the Roblox launcher waits for the internal timeout (up to 5000ms per attempt) before rendering the startup splash screen.
- **Architectural Mitigation:** WARP-MIN explicitly configures `WARP-Gool` **without** any DNS server bindings. All DNS requests are handled exclusively by the primary/VPN network adapter, eliminating multi-homed resolution delays and enabling immediate launcher startup.

---

## 3. Data Plane Analysis: RakNet UDP Protocol

### 3.1 Packet Framing and Network Properties
Once the client joins a server, gameplay traffic shifts to a proprietary protocol derived from **RakNet** running directly over raw UDP:
- **Server CIDR:** Roblox Autonomous System `AS22697` assigns game servers within `128.116.0.0/17` (spanning `128.116.0.0` through `128.116.127.255`).
- **Dynamic Port Range:** UDP ports **50000–65535**.
- **Sliding-Window Reliability:** RakNet operates a sequencing and ACK/NACK reliability layer on top of UDP. It is acutely sensitive to:
  1. **Packet Delay Variation (Jitter):** Jitter $> 15\text{ms}$ causes RakNet's internal RTT estimators to collapse, triggering unnecessary packet retransmissions and rubber-banding.
  2. **Out-of-Order Delivery:** Out-of-order packets cause frame buffer stalls in the Roblox rendering pipeline.
  3. **Path MTU Exhaustion:** If packets exceed Path MTU and get fragmented, packet loss rates spike above 20%.

### 3.2 Data Plane Routing Enforcement
WARP-MIN isolates RakNet traffic by injecting a kernel route directly into the Windows IP routing table:
```cmd
route add 128.116.0.0 mask 255.255.128.0 172.16.0.1 metric 1 if <WARP_GOOL_IF_INDEX>
```
Because the `WARP-Gool` adapter is connected directly to Cloudflare's Milan PoP (`MXP`) via subsea fiber, RakNet UDP packets exit Egypt with the lowest possible latency (~38–42ms wire time).

---

## 4. Voice Chat Protocol: STUN & SRTP

Roblox Spatial Voice relies on WebRTC standards:
- **Signaling:** Initial authentication and token exchange occur via HTTPS requests to `voice.roblox.com`.
- **NAT Traversal (STUN):** Client issues UDP STUN Binding Requests to discover public mapped IP/port tuples.
- **Media Transport (SRTP):** Audio frames are compressed using the Opus codec and transmitted inside Secure Real-time Transport Protocol (SRTP) packets over UDP.

In Egypt, ISP DPI appliances inspect UDP traffic and drop SRTP and STUN packets matching VoIP signatures. By tunneling all traffic destined for `voice.roblox.com` and its associated edge media relays through the WireGuard interface over Anycast Port 500, voice chat is fully unblocked and free of distortion or drops.

---

## 5. Universal App Configuration (GUAC) & `appStorage.json` Mechanics

Roblox enforces regional restrictions using its **Universal App Configuration (GUAC)** service.

### 5.1 The Regional Restriction Flow
1. On startup, Roblox queries:
   `GET https://apis.roblox.com/universal-app-configuration/v1/behaviors/app-policy/content`
2. If the request originates from an Egyptian IP address (`loc=EG`), the server responds with a JSON payload containing:
   ```json
   {
     "ExperienceChatAvailability": "regionLocked",
     "CanUsePlatformChat": false,
     "CanUsePlatformChat2": false,
     "CanSeeChatTab": false,
     "CanSeeChatTab2": false,
     "canSeeChatTerminology": false,
     "ChatWithOnlyTF": true
   }
   ```
3. The client writes this policy into its local cache located at:
   `%LOCALAPPDATA%\Roblox\LocalStorage\appStorage.json`
4. When entering an experience, the UI layer checks `ExperienceChatAvailability`. If set to `regionLocked`, the text chat widget and spatial voice icons are completely hidden from the user interface.

### 5.2 Safe In-Place Policy Unlocker (`update_guac_policy_in_value`)
WARP-MIN implements an automated policy surgery routine in `src/main.rs`:
- It inspects `%LOCALAPPDATA%\Roblox\LocalStorage\appStorage.json`.
- It deserializes `AppConfiguration` and locates all policy blocks (`GUAC:-1:app-policy` for guests and `GUAC:<user_id>:app-policy` for authenticated accounts).
- It surgically flips restriction flags:
  - `"ExperienceChatAvailability"` $\rightarrow$ `"available"`
  - `"CanUsePlatformChat"` $\rightarrow$ `true`
  - `"CanUsePlatformChat2"` $\rightarrow$ `true`
  - `"CanSeeChatTab"` $\rightarrow$ `true`
  - `"CanSeeChatTab2"` $\rightarrow$ `true`
  - `"canSeeChatTerminology"` $\rightarrow$ `true`
  - `"ChatWithOnlyTF"` $\rightarrow$ `false`
  - Replaces any remaining `"regionLocked"` string values with `"available"`.
- **Strict Identity Preservation:** It never touches or overwrites account tokens, usernames, cached cookies, or `CountryCode` fields (e.g. `CountryCode: FR`), ensuring no account re-authentication is required.

### 5.3 Write-Permission Preservation (`ensure_roblox_app_storage_writable`)
In early experiments, setting `appStorage.json` to Windows `READ-ONLY` was tested to prevent Roblox from rewriting the file. However, this caused Roblox's internal `LocalStorageManager` to crash with Windows Error `0x5` (`ERROR_ACCESS_DENIED`).

WARP-MIN adopts a safe approach:
1. It guarantees `appStorage.json` remains permanently writable (`ensure_file_writable`).
2. It pre-populates unlocked policy settings before Roblox boots.
3. It routes all Control Plane API calls (`apis.roblox.com`) through the European VPN breakout so that Roblox's live wire query natively returns `ExperienceChatAvailability: available`.
4. The file is never locked at the filesystem level, allowing `LocalStorageManager` to operate normally without crash or permission faults.
