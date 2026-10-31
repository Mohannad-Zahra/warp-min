# Blueprint 05: Structured Diagnostic Logging & Telemetry Engine

## High-Precision Log Architecture, Error Cause Chaining, and Crash Diagnostics

- **Initiative ID:** `BW-05`
- **Priority:** `P0` (Reliability & Developer Ergonomics)
- **Status:** Architecture Approved / In Implementation
- **Target Release:** Immediate (`v0.1.1` / `v1.0.0`)

---

## 1. Executive Summary & Problem Analysis

In network engineering tools operating at the Windows kernel level (Wintun L3 drivers, IP routing tables, raw UDP sockets, and Cryptographic Noise handshakes), failures can occur across multiple layers:
- Missing `wintun.dll` driver file in working directory or System32.
- UAC elevation token refusal or cancellation (`ERROR_CANCELLED 1223`).
- ISP UDP port 500 blockades or dynamic Anycast probe timeouts.
- Cloudflare API rate limits (`HTTP 429 Too Many Requests`).
- Windows route table collisions with existing VPN adapters (e.g. Proton, OpenVPN, TAP).
- Corrupted `appStorage.json` Roblox cache files or NTFS filesystem permission locks.

### The Immediate Blind Spot:
Currently, when WARP-MIN encounters a fatal error or is launched via Windows Explorer / UAC elevation, the elevated child process may exit immediately, causing the console window to vanish instantly without leaving any persistent trace or error details. Users and developers are left without logs, making troubleshooting impossible without deep investigation.

---

## 2. Core Architecture & Design Specifications

To ensure zero ambiguity during failures, WARP-MIN requires an autonomous, resilient logging subsystem:

```
+===================================================================================================+
|                                    WARP-MIN LOGGING SUBSYSTEM                                     |
|                                                                                                   |
|  [Application Events] ---> [Central Logger Dispatcher]                                            |
|                                   |                                                               |
|        +--------------------------+--------------------------+                                    |
|        |                                                     |                                    |
|        v                                                     v                                    |
|  [Console Output]                                     [Persistent Disk File]                      |
|  - Color-coded (ANSI/Win32)                           - "warp-min.log" in current app directory  |
|  - Real-time user feedback                            - Timestamped ISO 8601 UTC / Local           |
|  - Concise operational messages                       - Full Error Source & Backtrace Details     |
|                                                       - Auto-flushed on every write               |
+===================================================================================================+
```

---

## 3. Subsystem Requirements

### 3.1 Dual-Sink Output (Console + Persistent File)
1. **Console Stream:** Clean, human-readable terminal output for standard operation.
2. **Persistent Disk Sink (`warp-min.log`):** Every single startup step, network probe, handshake state change, Windows API call, and warning/error must be written with precise timestamps to `warp-min.log` in the application directory.
3. **Guaranteed Flush on Fatal Exit:** Before the process terminates with an exit code, the log buffer must be fully flushed to disk.

### 3.2 Error Cause Chaining
When a failure occurs (e.g., in Windows IP Helper API `CreateIpForwardEntry2` or `WintunCreateAdapter`), the logger must recursively inspect and log the entire chain of error sources:
```text
[2026-10-29 23:30:12.415] [ERROR] Fatal startup failure:
  --> Error: Failed to initialize Wintun Layer-3 adapter 'WARP-Gool'
  --> Caused by: Unable to load driver library 'wintun.dll'
  --> OS Error: The specified module could not be found. (os error 126)
  --> Suggested Fix: Ensure wintun.dll is located in the same directory as warp-min.exe
```

### 3.3 Interactive Window Hold on Error
If WARP-MIN is executed by double-clicking or through an elevated console window that would otherwise close upon process termination, the application must detect if it is running in an isolated console and pause with:
```text
[!] Press Enter to exit...
```
This guarantees the user can read the full error message directly before the window dismisses.

---

## 4. Implementation Specification

### 4.1 Log Level Hierarchy
- `DEBUG`: Raw WireGuard handshake packet sizes, internal state machine ticks, DNS label offsets.
- `INFO`: Normal operational milestones (Anycast probe completion, tunnel handshake success, route additions).
- `WARN`: Recoverable network events (candidate probe timeout, intra-PoP candidate switch, retry attempts).
- `ERROR`: Recoverable component errors (failed domain resolution for a single CDN node, Roblox file lock).
- `FATAL`: Unrecoverable errors that force application termination (driver missing, UAC refused, socket bind failure).

### 4.2 Configuration via CLI Flags & Environment
- `--log-file <PATH>`: Custom log file destination (default: `warp-min.log` in current working dir).
- `--verbose` / `-v`: Enables debug-level logging to console and disk.
- `--no-log-file`: Disables disk logging for ephemeral CI testing environments.
