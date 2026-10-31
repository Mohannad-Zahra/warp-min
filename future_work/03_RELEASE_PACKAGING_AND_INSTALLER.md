# Blueprint 03: Automated Release Packaging, Driver Bundling & Installer

## Enterprise CI/CD Pipeline, Self-Contained Binaries, and One-Click Setup

- **Initiative ID:** `BW-03`
- **Priority:** `P1` (Distribution & Deployment)
- **Status:** Architecture Approved / In Design
- **Target Release:** `v1.2.0`

---

## 1. Executive Summary & Goals

WARP-MIN relies on the official WireGuard LLC signed `wintun.dll` kernel TUN driver to create the high-speed `WARP-Gool` Layer-3 virtual interface. 

Currently, users must build from source with Cargo or ensure `wintun.dll` is manually copied next to `warp-min.exe`. If `wintun.dll` is missing, the application fails at runtime with:
```text
[-] Fatal: Unable to load wintun.dll (The specified module could not be found. 0x7E)
```

### Strategic Objectives:
1. **Zero-Missing-DLL Architecture:** Embed `wintun.dll` directly inside `warp-min.exe` via compile-time binary inclusion (`include_bytes!`). At startup, if `wintun.dll` is missing from disk, WARP-MIN automatically unpacks and verifies the driver.
2. **Automated GitHub Actions CI/CD:** Every tagged release (`v*.*.*`) automatically compiles, tests, packages, signs, and publishes portable releases and installers to GitHub Releases.
3. **One-Click Windows Setup:** Provide an optional Inno Setup or NSIS Windows installer that creates desktop shortcuts, registers Windows Firewall rules, and provides a clean uninstaller.

---

## 2. Embedded Driver Self-Extraction Engine

To achieve a true "single-file portable executable" experience:

```rust
// Proposed self-extraction mechanism in src/tun.rs
pub fn ensure_wintun_driver_present() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let current_exe = std::env::current_exe()?;
    let exe_dir = current_exe.parent().ok_or("Cannot determine exe directory")?;
    let dll_path = exe_dir.join("wintun.dll");

    if !dll_path.exists() {
        println!("[*] wintun.dll not detected in executable path. Extracting embedded driver...");
        const EMBEDDED_WINTUN: &[u8] = include_bytes!("../wintun.dll");
        std::fs::write(&dll_path, EMBEDDED_WINTUN)?;
        println!("[+] Successfully extracted embedded wintun.dll (427 KB).");
    }

    Ok(())
}
```

### Safety & Integrity Checks:
- Calculate SHA-256 of any existing `wintun.dll` on disk.
- Match against official WireGuard LLC SHA-256 signature (`e5e8...`) to ensure it has not been corrupted or tampered with.

---

## 3. GitHub Actions Automated Release Pipeline

The automated release workflow is defined at `.github/workflows/release.yml`:

```yaml
name: Release Automation

on:
  push:
    tags:
      - 'v*.*.*'

permissions:
  contents: write

jobs:
  build-release:
    name: Build & Package Windows Release
    runs-on: windows-2022

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Install Rust Toolchain (Edition 2024)
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: x86_64-pc-windows-msvc

      - name: Rust Cache
        uses: Swatinem/rust-cache@v2

      - name: Run Test Suite
        run: cargo test --release

      - name: Build Optimized Release Binary
        run: cargo build --release
        env:
          RUSTFLAGS: "-C target-cpu=x86-64-v3 -C link-arg=/OPT:REF,ICF"

      - name: Create Portable Bundle Directory
        run: |
          mkdir staging
          copy target\release\warp-min.exe staging\
          copy wintun.dll staging\
          copy warp_identity.example.json staging\
          copy README.md staging\
          copy LICENSE-MIT staging\
          Compress-Archive -Path staging\* -DestinationPath staging\warp-min-${{ github.ref_name }}-windows-x64.zip

      - name: Generate SHA-256 Checksums
        run: |
          Get-FileHash -Algorithm SHA256 staging\*.zip | Out-File -FilePath staging\SHA256SUMS.txt
          Get-Content staging\SHA256SUMS.txt

      - name: Publish GitHub Release Assets
        uses: softprops/action-gh-release@v2
        with:
          files: |
            staging/*.zip
            staging/SHA256SUMS.txt
          draft: false
          prerelease: false
          generate_release_notes: true
```

---

## 4. One-Click Windows Setup (Inno Setup Script)

For users who prefer a standard installer over portable ZIP archives:

```iss
; Script: installer/warp-min-setup.iss
#define MyAppName "WARP-MIN"
#define MyAppVersion "1.2.0"
#define MyAppPublisher "WARP-MIN Core Team"
#define MyAppExeName "warp-min.exe"

[Setup]
AppId={{D37E6F22-5401-44B1-8C52-192B9E3F8701}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DisableProgramGroupPage=yes
OutputBaseFilename=warp-min-setup-{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64

[Files]
Source: "..\target\release\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\warp_identity.example.json"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
```

---

## 5. Clean Uninstall & Driver Cleanup

The uninstaller must guarantee zero residual network state:
1. Terminates any running `warp-min.exe` processes.
2. Removes the `WARP-Gool` virtual adapter via Wintun's API (`WintunDeleteAdapter`).
3. Deletes any orphaned `/17` or `/32` routes.
4. Removes Windows Firewall rules associated with the executable.
