# Contributing to WARP-MIN

Thank you for your interest in contributing to **WARP-MIN**! This document provides guidelines and best practices for setting up your environment, making changes, and submitting pull requests.

---

## 1. Development Prerequisites

- **Operating System:** Windows 10 or 11 (64-bit).
- **Rust Toolchain:** Stable Rust (1.85+ compatible with Edition 2024).
  - Supported targets:
    - `x86_64-pc-windows-msvc` (Visual Studio C++ Build Tools - recommended)
    - `x86_64-pc-windows-gnu` (MinGW-w64 / GCC)
- **Wintun Driver:** `wintun.dll` (WireGuard LLC signed driver, bundled in repository root and auto-copied by `build.rs`).
- **Terminal:** PowerShell or Windows Terminal (elevated Administrator privileges required for TUN adapter creation and route manipulation).

---

## 2. Setting Up the Repository

```powershell
# Clone the repository
git clone https://github.com/<your-username>/Warper.git
cd Warper

# Verify toolchain and build
cargo build --release

# Run unit and integration test suite
cargo test --release
```

---

## 3. Code Standards & Quality Gates

All pull requests must pass our automated quality gates:

### 3.1 Formatting (`rustfmt`)
All code must adhere to standard Rust formatting:
```powershell
cargo fmt --check
```
To format your code automatically:
```powershell
cargo fmt
```

### 3.2 Linter (`clippy`)
The codebase enforces zero clippy warnings across all targets:
```powershell
cargo clippy --all-targets -- -D warnings
```

### 3.3 Test Suite
Ensure all existing and new unit tests pass cleanly:
```powershell
cargo test --release
```

---

## 4. Architectural Rules & Best Practices

1. **Split-Plane Isolation:**  
   Never route control plane HTTPS traffic (`apis.roblox.com`) through the Wintun adapter. Keep control plane and data plane (RakNet UDP `128.116.0.0/17`) strictly decoupled.
2. **Deterministic Route Cleanup:**  
   Any route added to the kernel table must implement automated teardown via `WintunDevice`'s `Drop` implementation and `Ctrl+C` signal interception.
3. **Identity Token Protection:**  
   Never commit `warp_identity_hop1.json` or `warp_identity_hop2.json`. Use `warp_identity.example.json` for documenting configuration schemas.
4. **Driver Dependency:**  
   Do not modify `wintun.dll` without re-verifying its Authenticode signature from WireGuard LLC.

---

## 5. Submitting a Pull Request

1. Create a feature branch: `git checkout -b feat/my-improvement`.
2. Commit your changes with clear, descriptive commit messages.
3. Verify that `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --release` all pass with 0 errors.
4. Push to your branch and open a Pull Request against `master`.
