# Troubleshooting & Verification Guide

## 1. Automated Verification Gates

To validate the security, integrity, and performance of WARP-MIN, every build should pass the 6 verification gates:

| Gate | Description | Command & Criteria | Expected Result |
|---|---|---|---|
| **Gate 1** | **Static Security & Dependency Audit** | `Select-String -Path .\Cargo.toml, .\src\*.rs -Pattern "psiphon\|oblivion\|telemetry"` | **0 matches found.** Clean dependency tree. |
| **Gate 2** | **Wintun Authenticode Signature** | `(Get-AuthenticodeSignature .\wintun.dll).Status` | **`Valid`** (Issued to `WireGuard LLC`). |
| **Gate 3** | **Trace Geo-Tag & Dual-Hop Verification** | `curl.exe -v --socks5-hostname 127.0.0.1:8086 https://www.cloudflare.com/cdn-cgi/trace` | `HTTP 200 OK`, `warp=on`, `colo=MXP` or `colo=FCO`. |
| **Gate 4** | **Latency & Local Handshake Benchmark** | `curl.exe -o NUL -s -w "%{time_connect}\n" --socks5-hostname 127.0.0.1:8086 http://1.1.1.1/cdn-cgi/trace` | **$< 0.002\text{s}$** ($< 2\text{ms}$ bridge delay, $\le 45\text{ms}$ wire SLA). |
| **Gate 5** | **External ASN & GeoIP Validation** | `(curl.exe -s --socks5-hostname 127.0.0.1:8086 https://api.country.is/).country` | Cloudflare AS13335 IP. |
| **Gate 6** | **Clean Teardown Verification** | Terminate process (Ctrl+C), check `Get-NetRoute -InterfaceAlias 'WARP-Gool'` | **0 orphan routes.** Port 8086 cleanly released. |

---

## 2. Troubleshooting Matrix & Common Failure Modes

### 2.1 Hop 1 Handshake Timeout
- **Symptom:** CLI outputs `Probing candidate Anycast endpoints...` and repeatedly logs `Retrying Hop 1 handshake...` until falling back or failing.
- **Root Cause:**
  1. Local Windows Firewall or third-party antivirus is blocking outbound UDP port 500.
  2. The ISP is experiencing deep submarine cable routing flapping.
- **Remediation:**
  - Verify outbound UDP rule:
    ```powershell
    Get-NetFirewallRule -DisplayName "*WARP*"
    ```
  - Allow outbound traffic for `warp-min.exe` or temporarily test with firewall disabled.
  - Ensure the client is using `--endpoint-a 162.159.192.1:500`.

---

### 2.2 Hop 2 Handshake Timeout (Intra-PoP Routing Drop)
- **Symptom:** Hop 1 connects immediately (`Hop 1 Handshake established`), but Hop 2 times out (`Retrying Hop 2 handshake with 188.114.97.3:2408...`).
- **Root Cause:** Intra-PoP self-traffic drop. When Hop 1 and Hop 2 reside in the same IP block (e.g. both in `162.159.192.x`), Cloudflare's internal edge firewall drops the encapsulated packet.
- **Remediation:**
  - WARP-MIN's dynamic complementary pool alignment automatically detects this and alternates pools (e.g., switches Hop 2 to `162.159.192.1:2408` if Hop 1 is on `188.114.x.x`, or vice versa).
  - If a manual endpoint is specified, pass the complementary pool explicitly:
    ```powershell
    .\target\release\warp-min.exe --endpoint-a 162.159.192.1:500 --endpoint-b 188.114.97.3:2408
    ```

---

### 2.3 Roblox Launcher Hangs on Splash Screen (Multi-Homed DNS Timeout)
- **Symptom:** `RobloxPlayerBeta.exe` starts, displays a white window or loading spinner for 10–30 seconds before erroring out or starting sluggishly.
- **Root Cause:** Multi-homed DNS lookup lag. If a virtual network interface configures DNS addresses (such as `1.1.1.1` or `8.8.8.8`) while the primary/VPN adapter also has active DNS servers, Windows sends parallel queries and waits for the slowest timeout.
- **Remediation:**
  - WARP-MIN intentionally does **not** configure DNS servers on the `WARP-Gool` adapter.
  - Verify that `WARP-Gool` has empty DNS entries:
    ```powershell
    Get-DnsClientServerAddress -InterfaceAlias 'WARP-Gool'
    ```
  - Ensure your primary adapter or European VPN (ProtonVPN) provides valid, fast DNS resolution.

---

### 2.4 Roblox In-Game Chat Displays "regionLocked"
- **Symptom:** Roblox loads, but the chat window is absent or settings report regional voice/chat restrictions.
- **Root Cause:**
  1. The Roblox client was launched *before* WARP-MIN was started, causing `apis.roblox.com` to return `regionLocked` to the cache.
  2. The Control Plane traffic exited through a local Egyptian IP instead of the European VPN breakout.
- **Remediation:**
  1. Stop Roblox:
     ```powershell
     Stop-Process -Name "RobloxPlayerBeta" -Force -ErrorAction SilentlyContinue
     ```
  2. Verify your European VPN connection (e.g. ProtonVPN set to Netherlands or Italy).
  3. Start WARP-MIN elevated:
     ```powershell
     .\target\release\warp-min.exe --tun
     ```
  4. Launch Roblox. WARP-MIN automatically updates `appStorage.json` to `"ExperienceChatAvailability": "available"`, and the European VPN ensures live wire queries confirm the policy.

---

### 2.5 Access Denied / Administrator Privileges Error
- **Symptom:** Terminal outputs `Failed to create Wintun adapter: Access is denied (os error 5)`.
- **Root Cause:** Wintun adapter creation and kernel route table manipulation require Windows `SeLoadDriverPrivilege` and administrative privileges.
- **Remediation:**
  - Run PowerShell or Windows Terminal as **Administrator**.
  - If executed from a non-elevated prompt, WARP-MIN automatically requests UAC elevation via Windows `runas`. Ensure you accept the UAC prompt.

---

### 2.6 MinGW Linker Error: `cannot find -lgcc_eh`
- **Symptom:** During `cargo build --release` on a MinGW toolchain (`x86_64-pc-windows-gnu`), proc-macro compilation fails with `ld.exe: cannot find -lgcc_eh`.
- **Root Cause:** Standalone MinGW distributions (e.g. `w64devkit`) sometimes do not place `libgcc_eh.a` in the default linker search directory.
- **Remediation:**
  - Copy `libgcc_eh.a` from Rust's internal toolchain:
    ```powershell
    Copy-Item "$env:USERPROFILE\.rustup\toolchains\stable-x86_64-pc-windows-gnu\lib\rustlib\x86_64-pc-windows-gnu\lib\self-contained\libgcc_eh.a" "C:\Users\mohan\w64devkit\lib\libgcc_eh.a"
    ```

---

### 2.7 Cloudflare Registration Rate Limiting (HTTP 429)
- **Symptom:** `register_account` returns error: `HTTP 429 Too Many Requests`.
- **Root Cause:** Deleting `warp_identity_hop1.json` or `warp_identity_hop2.json` repeatedly triggers Cloudflare's client registration rate limiter.
- **Remediation:**
  - Never delete identity files unnecessarily. WARP-MIN caches and reuses existing keys across sessions.
  - If rate limited, wait 15–30 minutes or generate identities through a proxy using:
    ```powershell
    .\target\release\warp-min.exe --register-hop2 --bind 127.0.0.1:8086
    ```

---

### 2.8 Roblox Error Code 279 (Failed to Connect to Server) & Proton VPN Co-Existence
- **Symptom:** Roblox client logs in, but joining any experience fails after 20 seconds with:
  > *"Connection Failed: Failed to connect to the experience. No response from server. (Error Code: 279)"*
  Telemetry in `warp-min.log` shows `Gameplay Packets Sent: 0 (0 B)`.
- **Root Cause:**
  1. **Proton VPN WFP Leak Isolation:** Proton VPN's WFP filter `BlockAllIpv4Network` at `FWPM_LAYER_ALE_AUTH_CONNECT_V4` drops non-RFC1918 outbound connections unless the socket's local interface matches the Proton VPN interface (`10.2.0.2`).
  2. Because Roblox binds to `inaddr_any:0` (`0.0.0.0:0`), Windows source address selection would pick `WARP-Gool`'s IP (`172.16.0.2`) unless `SkipAsSource` is enabled.
- **Remediation:**
  - WARP-MIN automatically assigns `172.16.0.2` with native Win32 `SkipAsSource = 1` and enables `WeakHostSend=1` on both adapters.
  - Windows TCP/IP assigns `10.2.0.2` to the socket, allowing packets to pass Proton VPN's WFP firewall into `WARP-Gool`.
  - WARP-MIN's stateless bidirectional SNAT rewrites `10.2.0.2` $\leftrightarrow$ `172.16.0.2` before WireGuard encapsulation, ensuring Cloudflare forwards the packets and Roblox connects seamlessly.

---

## 3. Diagnostic Commands Cheat Sheet

```powershell
# 1. Inspect Windows Routing Table for Roblox Subnet:
Get-NetRoute -DestinationPrefix '128.116.0.0/17'

# 2. Inspect Injected /32 API Host Routes:
Get-NetRoute | Where-Object { $_.DestinationPrefix -like "128.116.*" }

# 3. Test Direct Egress via SOCKS5 Proxy:
curl.exe -s --socks5-hostname 127.0.0.1:8086 https://1.1.1.1/cdn-cgi/trace

# 4. Measure SOCKS5 Proxy Connect Latency:
curl.exe -o NUL -s -w "Connect Time: %{time_connect}s | Total Time: %{time_total}s\n" --socks5-hostname 127.0.0.1:8086 http://1.1.1.1/cdn-cgi/trace

# 5. Check Wintun Adapter Status:
Get-NetAdapter -Name "WARP-Gool" | Format-List Status, LinkSpeed, InterfaceMetric

# 6. Check Active Wi-Fi Background Scanning State:
netsh wlan show interfaces
```
