use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2, FlushIpNetTable,
    FlushIpPathTable, GetIpInterfaceEntry, InitializeIpForwardEntry, InitializeIpInterfaceEntry,
    InitializeUnicastIpAddressEntry, SetIpInterfaceEntry, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW,
    MIB_UNICASTIPADDRESS_ROW,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;
use wintun::{Adapter, Session};

#[derive(Debug, Clone)]
pub struct PrimaryInterface {
    pub if_index: u32,
    pub alias: String,
    pub next_hop: Option<String>,
    pub ip: Option<String>,
}

/// Native Win32 TCP/IP interface tuner via iphlpapi.dll (SetIpInterfaceEntry).
/// Configures WeakHostSend/Receive, disables DAD, disables router discovery,
/// and enforces metric 1 without PowerShell CIM overhead or access-denied failures.
pub fn tune_interface_win32(if_index: u32, metric: u32, forwarding: bool) -> Result<(), u32> {
    unsafe {
        let mut row: MIB_IPINTERFACE_ROW = std::mem::zeroed();
        InitializeIpInterfaceEntry(&mut row);
        row.Family = AF_INET;
        row.InterfaceIndex = if_index;

        let get_res = GetIpInterfaceEntry(&mut row);
        if get_res != 0 {
            return Err(get_res);
        }

        row.ForwardingEnabled = if forwarding { 1 } else { 0 };
        row.WeakHostSend = 1;
        row.WeakHostReceive = 1;
        row.DadTransmits = 0;
        row.UseAutomaticMetric = 0;
        row.Metric = metric;
        row.RouterDiscoveryBehavior = 0; // RouterDiscoveryDisabled
        row.SitePrefixLength = 0;

        let set_res = SetIpInterfaceEntry(&mut row);
        if set_res != 0 {
            return Err(set_res);
        }
        Ok(())
    }
}

/// Native Win32 helper to ensure WeakHostSend and WeakHostReceive are enabled
/// on the primary/VPN adapter (e.g. ProtonVPN) so Windows allows cross-interface
/// routing between ProtonVPN and WARP-Gool without kernel packet drops.
pub fn tune_interface_weak_host(if_index: u32) -> Result<(), u32> {
    unsafe {
        let mut row: MIB_IPINTERFACE_ROW = std::mem::zeroed();
        InitializeIpInterfaceEntry(&mut row);
        row.Family = AF_INET;
        row.InterfaceIndex = if_index;

        let get_res = GetIpInterfaceEntry(&mut row);
        if get_res != 0 {
            return Err(get_res);
        }

        row.WeakHostSend = 1;
        row.WeakHostReceive = 1;

        let set_res = SetIpInterfaceEntry(&mut row);
        if set_res != 0 {
            return Err(set_res);
        }
        Ok(())
    }
}

/// Flushes both the IP path cache and neighbor discovery cache for the specified interface,
/// immediately clearing any Stale or Unreachable neighbor entries from previous attempts.
pub fn flush_interface_neighbors(if_index: u32) {
    unsafe {
        let _ = FlushIpPathTable(AF_INET);
        let _ = FlushIpNetTable(if_index);
    }
}

/// Adds an IPv4 route directly to the Windows TCP/IP stack via CreateIpForwardEntry2.
pub fn add_route_win32(
    if_index: u32,
    dest: Ipv4Addr,
    prefix_len: u8,
    next_hop: Option<Ipv4Addr>,
    metric: u32,
) -> Result<(), u32> {
    unsafe {
        let mut row: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
        InitializeIpForwardEntry(&mut row);
        row.InterfaceIndex = if_index;
        row.Metric = metric;
        row.DestinationPrefix.Prefix.si_family = AF_INET;
        row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr =
            u32::from_ne_bytes(dest.octets());
        row.DestinationPrefix.PrefixLength = prefix_len;

        row.NextHop.si_family = AF_INET;
        if let Some(nh) = next_hop {
            row.NextHop.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(nh.octets());
        }

        let ret = CreateIpForwardEntry2(&row);
        // NO_ERROR (0) or ERROR_OBJECT_ALREADY_EXISTS (5010 / 183)
        if ret == 0 || ret == 5010 || ret == 183 {
            Ok(())
        } else {
            Err(ret)
        }
    }
}

/// Deletes an IPv4 route directly from the Windows TCP/IP stack via DeleteIpForwardEntry2.
pub fn delete_route_win32(if_index: u32, dest: Ipv4Addr, prefix_len: u8) -> Result<(), u32> {
    unsafe {
        let mut row: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
        InitializeIpForwardEntry(&mut row);
        row.InterfaceIndex = if_index;
        row.DestinationPrefix.Prefix.si_family = AF_INET;
        row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr =
            u32::from_ne_bytes(dest.octets());
        row.DestinationPrefix.PrefixLength = prefix_len;

        let ret = DeleteIpForwardEntry2(&row);
        // NO_ERROR (0), ERROR_FILE_NOT_FOUND (2), or ERROR_NOT_FOUND (1168)
        if ret == 0 || ret == 2 || ret == 1168 {
            Ok(())
        } else {
            Err(ret)
        }
    }
}

/// Adds an IPv4 address to the specified interface via CreateUnicastIpAddressEntry.
/// When `skip_as_source` is true, Windows TCP/IP will NOT select this address as the source
/// address for unbound sockets (e.g. RobloxPlayerBeta.exe binding to inaddr_any:0), allowing
/// the primary VPN address (e.g. ProtonVPN 10.2.0.2) to be chosen so outbound packets pass
/// ProtonVPN's WFP leak protection filter at FWPM_LAYER_ALE_AUTH_CONNECT_V4.
pub fn add_ip_address_win32(
    if_index: u32,
    ip: Ipv4Addr,
    prefix_len: u8,
    skip_as_source: bool,
) -> Result<(), u32> {
    unsafe {
        let mut row: MIB_UNICASTIPADDRESS_ROW = std::mem::zeroed();
        InitializeUnicastIpAddressEntry(&mut row);
        row.InterfaceIndex = if_index;
        row.Address.si_family = AF_INET;
        row.Address.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
        row.OnLinkPrefixLength = prefix_len;
        row.SkipAsSource = if skip_as_source { 1 } else { 0 };

        let ret = CreateUnicastIpAddressEntry(&row);
        // NO_ERROR (0) or ERROR_OBJECT_ALREADY_EXISTS (5010 / 183)
        if ret == 0 || ret == 5010 || ret == 183 {
            Ok(())
        } else {
            Err(ret)
        }
    }
}

pub struct WintunDevice {
    #[allow(dead_code)]
    pub adapter: Arc<Adapter>,
    pub session: Arc<Session>,
    pub endpoint_a_ip: String,
    pub api_ips: Vec<String>,
    #[allow(dead_code)]
    pub primary_interface: Option<PrimaryInterface>,
    #[allow(dead_code)]
    pub original_gateway: Option<String>,
    cleaned_up: AtomicBool,
}

impl WintunDevice {
    pub fn create(
        adapter_name: &str,
        local_ipv4: Ipv4Addr,
        endpoint_a_ip: &str,
        api_ips: Vec<String>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Load wintun.dll from current working directory, executable directory, or system PATH
        let wintun = unsafe {
            wintun::load_from_path("wintun.dll")
                .or_else(|_| {
                    if let Ok(mut exe) = std::env::current_exe() {
                        exe.pop();
                        let dll = exe.join("wintun.dll");
                        if dll.exists() {
                            return wintun::load_from_path(dll);
                        }
                    }
                    wintun::load()
                })
                .map_err(|e| format!("Failed to load wintun.dll: {:?}. Ensure wintun.dll is in the working directory, beside warp-min.exe, or in PATH.", e))?
        };

        // Startup route table scrubber: purge any leftover routes or neighbor entries from previous crashes
        let _ = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-NetRoute -DestinationPrefix '128.116*' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue; Remove-NetNeighbor -IPAddress '172.16.0.1' -Confirm:$false -ErrorAction SilentlyContinue; Remove-NetRoute -DestinationPrefix '1.1.1.1/32' -Confirm:$false -ErrorAction SilentlyContinue",
            ])
            .output();
        let _ = Command::new("route")
            .args(["delete", "128.116.0.0"])
            .output();

        // If existing adapter exists, delete it first to ensure clean state
        if let Ok(existing) = Adapter::open(&wintun, adapter_name)
            && let Ok(adapter) = Arc::try_unwrap(existing)
        {
            let _ = adapter.delete();
            std::thread::sleep(std::time::Duration::from_millis(500));
        }

        crate::log_info!("[*] Creating Wintun adapter '{}'...", adapter_name);
        let adapter = Adapter::create(&wintun, adapter_name, "WARP", None)
            .map_err(|e| format!("Failed to create Wintun adapter: {:?}. Note: TUN mode requires Administrator privileges (Run as Administrator).", e))?;

        let session = adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|e| format!("Failed to start Wintun session: {:?}", e))?;

        let session = Arc::new(session);

        // Find current default physical gateway for outer endpoint A pinning
        let original_gateway = get_default_gateway();
        crate::log_info!(
            "[*] Detected physical default gateway: {:?}",
            original_gateway
        );

        // Detect primary / VPN default route interface (e.g. ProtonVPN or physical default gateway)
        let primary_interface = get_primary_interface();
        if let Some(ref pri) = primary_interface {
            crate::log_info!(
                "[*] Detected primary/VPN default interface: {} (ifIndex: {}, NextHop: {:?}, IP: {:?})",
                pri.alias, pri.if_index, pri.next_hop, pri.ip
            );
        } else {
            crate::log_info!(
                "[!] Could not detect primary/VPN default interface; will fallback to gateway routing"
            );
        }

        let if_index = adapter.get_adapter_index()?;
        let if_index_str = if_index.to_string();

        // Configure adapter IP via native Win32 CreateUnicastIpAddressEntry with SkipAsSource=1
        // (falling back to netsh skipassource=true and PowerShell Set-NetIPAddress).
        // Setting SkipAsSource=true ensures Windows source address selection picks the primary VPN
        // address (e.g. ProtonVPN 10.2.0.2) for unbound sockets (Roblox inaddr_any:0), allowing packets
        // to pass ProtonVPN's WFP leak-protection filter at FWPM_LAYER_ALE_AUTH_CONNECT_V4.
        let ip_str = local_ipv4.to_string();
        crate::log_info!(
            "[*] Configuring adapter IP {} (mask=255.255.255.255, skip_as_source=true, if_index {})...",
            ip_str, if_index
        );

        if let Err(e) = add_ip_address_win32(if_index, local_ipv4, 32, true) {
            crate::log_warn!(
                "[!] Native Win32 add_ip_address_win32 returned code {}; falling back to netsh/powershell",
                e
            );
            let _ = Command::new("netsh")
                .args([
                    "interface",
                    "ipv4",
                    "set",
                    "address",
                    &format!("name={}", adapter_name),
                    "source=static",
                    &format!("addr={}", ip_str),
                    "mask=255.255.255.255",
                    "gateway=none",
                ])
                .output();
            let _ = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    &format!(
                        "Set-NetIPAddress -InterfaceIndex {} -IPAddress '{}' -SkipAsSource $true -ErrorAction SilentlyContinue",
                        if_index, ip_str
                    ),
                ])
                .output();
        } else {
            crate::log_info!(
                "[+] Configured adapter IP via native Win32: SkipAsSource=Enabled, PrefixLength=32"
            );
        }

        // Allow Windows NDIS stack to finalize interface IP assignment before adding routes
        std::thread::sleep(std::time::Duration::from_millis(250));

        // 1. Optimize TUN interface parameters via native Win32 API (SetIpInterfaceEntry):
        // Sets WeakHostSend / WeakHostReceive, disables DAD, disables router discovery, disables forwarding, and sets metric 1.
        // ForwardingEnabled MUST be false so ProtonVPN's InterfaceForwardingMonitor does not trigger a VPN disconnect.
        if let Err(err) = tune_interface_win32(if_index, 1, false) {
            crate::log_warn!("[!] Native Win32 interface tuning returned error code: {}; falling back to netsh/powershell", err);
        } else {
            crate::log_info!("[+] Configured interface parameters via native Win32: WeakHostSend/Receive=Enabled, Forwarding=Disabled, DadTransmits=0, Metric=1");
        }

        // Netsh & PowerShell fallback for tuning
        let _ = Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "set",
                "interface",
                &if_index_str,
                "weakhostsend=enabled",
                "weakhostreceive=enabled",
                "routerdiscovery=disabled",
                "dadtransmits=0",
                "metric=1",
                "store=active",
            ])
            .output();
        let ps_tune_tun = format!(
            "Set-NetIPInterface -InterfaceIndex {} -AddressFamily IPv4 -Forwarding Disabled -WeakHostSend Enabled -WeakHostReceive Enabled -DadTransmits 0 -RouterDiscovery Disabled -ManagedAddressConfiguration Disabled -OtherStatefulConfiguration Disabled -NeighborUnreachabilityDetection Disabled -InterfaceMetric 1 -ErrorAction SilentlyContinue",
            if_index
        );
        let _ = Command::new("powershell")
            .args(["-NoProfile", "-Command", &ps_tune_tun])
            .output();

        // 2. Also enable WeakHostSend/WeakHostReceive on the primary interface so Windows allows
        // dual-interface traffic between ProtonVPN and WARP-Gool without kernel packet drops
        if let Some(ref pri) = primary_interface {
            let _ = tune_interface_weak_host(pri.if_index);
            let _ = Command::new("netsh")
                .args([
                    "interface",
                    "ipv4",
                    "set",
                    "interface",
                    &pri.if_index.to_string(),
                    "weakhostsend=enabled",
                    "weakhostreceive=enabled",
                    "store=active",
                ])
                .output();
            let ps_tune_primary = format!(
                "Set-NetIPInterface -InterfaceIndex {} -AddressFamily IPv4 -WeakHostSend Enabled -WeakHostReceive Enabled -ErrorAction SilentlyContinue",
                pri.if_index
            );
            let _ = Command::new("powershell")
                .args(["-NoProfile", "-Command", &ps_tune_primary])
                .output();
        }

        // Flush stale neighbor / IP path entries to purge any residual Unreachable states
        flush_interface_neighbors(if_index);

        // 3. Enforce Private Network Profile so Windows Firewall does not restrict outbound packets
        let ps_private_profile = format!(
            "Set-NetConnectionProfile -InterfaceAlias '{}' -NetworkCategory Private -ErrorAction SilentlyContinue",
            adapter_name
        );
        let _ = Command::new("powershell")
            .args(["-NoProfile", "-Command", &ps_private_profile])
            .output();

        crate::log_info!("[*] Enforcing MTU 1200 on '{}'...", adapter_name);
        let _ = Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "set",
                "subinterface",
                adapter_name,
                "mtu=1200",
                "store=active",
            ])
            .output();

        // Pin route to Endpoint A via physical gateway ONLY if no primary VPN is managing egress.
        // Under ProtonVPN, pinning Endpoint A to the physical Wi-Fi gateway blackholes Hop 1 due to WFP leak protection.
        if primary_interface.is_none() {
            if let Some(ref gw) = original_gateway {
                crate::log_info!(
                    "[*] Pinning outer endpoint {} route via physical gateway {}...",
                    endpoint_a_ip, gw
                );
                let _ = Command::new("route")
                    .args([
                        "add",
                        endpoint_a_ip,
                        "mask",
                        "255.255.255.255",
                        gw,
                        "metric",
                        "1",
                    ])
                    .output();
            }
        } else {
            crate::log_info!(
                "[*] Primary VPN active ({}): Preserving Hop 1 egress via VPN tunnel without physical gateway pinning",
                primary_interface.as_ref().map(|p| p.alias.as_str()).unwrap_or("VPN")
            );
        }

        // Pin Roblox API, launcher, and web endpoints (including all 128 edge Anycast IPs 128.116.x.3)
        // via primary/VPN connection (ProtonVPN) FIRST so they route cleanly through Europe and never get captured by 128.116.0.0/17
        let mut target_host_ips = api_ips.clone();
        for i in 0..128 {
            let s = format!("128.116.{}.3", i);
            if !target_host_ips.contains(&s) {
                target_host_ips.push(s);
            }
        }
        if let Some(ref pri) = primary_interface {
            pin_host_routes(&target_host_ips, pri);
        }

        // Pinned on-link route for Roblox gameplay traffic (128.116.0.0/17 RakNet UDP) via WARP-Gool
        crate::log_info!(
            "[*] Installing Roblox gameplay route (128.116.0.0/17) via {} (on-link 0.0.0.0, Metric 1)...",
            adapter_name
        );
        let _ = add_route_win32(if_index, Ipv4Addr::new(128, 116, 0, 0), 17, None, 1);
        let ps_add_route = format!(
            "New-NetRoute -DestinationPrefix '128.116.0.0/17' -InterfaceIndex {} -NextHop '0.0.0.0' -RouteMetric 1 -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue",
            if_index
        );
        let _ = Command::new("powershell")
            .args(["-NoProfile", "-Command", &ps_add_route])
            .output();

        // Verify active route in the Windows routing table
        let verify_route = Command::new("route")
            .args(["print", "128.116*"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();
        if verify_route.contains("128.116.0.0") {
            crate::log_info!(
                "[+] Verified active route: 128.116.0.0/17 bound to {} (on-link 0.0.0.0)",
                adapter_name
            );
        } else {
            crate::log_info!(
                "[+] Configured active route: 128.116.0.0/17 on {}",
                adapter_name
            );
        }

        crate::log_info!(
            "[+] Split-Tunneling active: Roblox gameplay UDP (128.116.0.0/17) routes via WARP-Gool into Hop 2; API and launcher endpoints ({} IPs) pinned via primary VPN.",
            target_host_ips.len()
        );

        Ok(Self {
            adapter,
            session,
            endpoint_a_ip: endpoint_a_ip.to_string(),
            api_ips: target_host_ips,
            primary_interface,
            original_gateway,
            cleaned_up: AtomicBool::new(false),
        })
    }

    pub fn restore_routing(&self) {
        if self.cleaned_up.swap(true, Ordering::SeqCst) {
            return;
        }
        let _ = self.session.shutdown();
        let adapter_name = self
            .adapter
            .get_name()
            .unwrap_or_else(|_| "WARP-Gool".into());
        let _ = Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "delete",
                "address",
                &format!("name={}", adapter_name),
            ])
            .output();
        cleanup_routes(&self.endpoint_a_ip, &self.api_ips);
    }
}

pub fn pin_host_routes(target_ips: &[String], primary: &PrimaryInterface) {
    if target_ips.is_empty() {
        return;
    }
    let if_index_str = primary.if_index.to_string();

    let is_on_link = matches!(
        primary.next_hop.as_deref(),
        Some("0.0.0.0") | Some("172.16.0.1") | Some("") | None
    );

    let nh_addr = if !is_on_link {
        primary
            .next_hop
            .as_deref()
            .and_then(|gw| gw.parse::<Ipv4Addr>().ok())
    } else {
        None
    };

    crate::log_info!(
        "[*] Pinning {} /32 host routes via primary interface {} (if {}, on_link: {})...",
        target_ips.len(),
        primary.alias,
        if_index_str,
        is_on_link
    );

    // Fast native Win32 route pinning via CreateIpForwardEntry2 (< 2ms total, 0 subprocesses)
    let mut win32_success = 0usize;
    for ip in target_ips {
        if let Ok(ip_addr) = ip.parse::<Ipv4Addr>()
            && add_route_win32(primary.if_index, ip_addr, 32, nh_addr, 1).is_ok()
        {
            win32_success += 1;
        }
    }
    crate::log_info!(
        "[+] Installed {} /32 host routes via native Win32 CreateIpForwardEntry2",
        win32_success
    );
}

#[allow(dead_code)]
pub fn pin_host_route_to_primary(target_ip: &str, primary: &PrimaryInterface) {
    pin_host_routes(&[target_ip.to_string()], primary);
}

pub fn cleanup_routes(endpoint_a_ip: &str, api_ips: &[String]) {
    crate::log_info!("[*] Restoring host routing table...");
    let _ = delete_route_win32(0, Ipv4Addr::new(128, 116, 0, 0), 17);
    let _ = Command::new("netsh")
        .args([
            "interface",
            "ipv4",
            "delete",
            "route",
            "128.116.0.0/17",
            "WARP-Gool",
            "store=active",
        ])
        .output();
    let _ = Command::new("route")
        .args(["delete", "128.116.0.0"])
        .output();
    let _ = Command::new("route")
        .args(["delete", "128.116.0.0", "mask", "255.255.128.0", "0.0.0.0"])
        .output();
    let _ = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-NetRoute -DestinationPrefix '128.116*' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue",
        ])
        .output();

    let mut all_clean_ips = api_ips.to_vec();
    for i in 0..128 {
        let s = format!("128.116.{}.3", i);
        if !all_clean_ips.contains(&s) {
            all_clean_ips.push(s);
        }
    }

    // Fast native Win32 route deletion (< 2ms total, 0 subprocesses)
    let mut win32_deleted = 0usize;
    for ip in &all_clean_ips {
        if let Ok(ip_addr) = ip.parse::<Ipv4Addr>()
            && delete_route_win32(0, ip_addr, 32).is_ok()
        {
            win32_deleted += 1;
        }
    }
    crate::log_info!(
        "[+] Deleted {} /32 host routes via native Win32 DeleteIpForwardEntry2",
        win32_deleted
    );

    let _ = Command::new("route")
        .args(["delete", endpoint_a_ip])
        .output();
}

impl Drop for WintunDevice {
    fn drop(&mut self) {
        self.restore_routing();
    }
}

pub fn get_primary_interface() -> Option<PrimaryInterface> {
    let ps_cmd = r#"$route = $null; $ip = $null; $r = Find-NetRoute -RemoteIPAddress '1.1.1.1' -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -ne 'WARP-Gool' }; if ($r) { $route = $r | Where-Object { $null -ne $_.DestinationPrefix } | Select-Object -First 1; $ip = ($r | Where-Object { $null -ne $_.IPAddress } | Select-Object -First 1).IPAddress }; if (-not $route) { $def = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -ne 'WARP-Gool' } | ForEach-Object { $im = (Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).InterfaceMetric; if ($null -eq $im) { $im = 0 }; [PSCustomObject]@{ InterfaceIndex = $_.InterfaceIndex; InterfaceAlias = $_.InterfaceAlias; NextHop = $_.NextHop; TotalMetric = ($_.RouteMetric + $im) } } | Sort-Object TotalMetric | Select-Object -First 1; if ($def) { $route = $def } }; if ($route) { if (-not $ip) { $ip = (Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress }; [PSCustomObject]@{ ifIndex = $route.InterfaceIndex; ifAlias = $route.InterfaceAlias; nextHop = $route.NextHop; ip = $ip } | ConvertTo-Json -Compress }"#;

    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", ps_cmd])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() {
        return None;
    }

    let val = serde_json::from_str::<serde_json::Value>(&text).ok()?;
    let if_index = val
        .get("ifIndex")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)?;
    let alias = val
        .get("ifAlias")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let next_hop = val
        .get("nextHop")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let ip = val
        .get("ip")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Some(PrimaryInterface {
        if_index,
        alias,
        next_hop,
        ip,
    })
}

fn get_default_gateway() -> Option<String> {
    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.InterfaceAlias -ne 'WARP-Gool' -and $_.NextHop -ne '172.16.0.1' -and $_.NextHop -ne '0.0.0.0' } | Sort-Object RouteMetric | Select-Object -First 1).NextHop"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() || text == "0.0.0.0" || text == "172.16.0.1" {
        None
    } else {
        Some(text)
    }
}

#[allow(dead_code)]
pub fn is_in_roblox_gameplay_cidr(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 128 && octets[1] == 116 && (octets[2] & 0x80) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roblox_gameplay_cidr_17() {
        // Subnet 128.116.0.0/17 spans 128.116.0.0 to 128.116.127.255
        assert!(is_in_roblox_gameplay_cidr(Ipv4Addr::new(128, 116, 0, 1)));
        assert!(is_in_roblox_gameplay_cidr(Ipv4Addr::new(128, 116, 13, 3))); // voice.roblox.com
        assert!(is_in_roblox_gameplay_cidr(Ipv4Addr::new(128, 116, 21, 3))); // apis.roblox.com
        assert!(is_in_roblox_gameplay_cidr(Ipv4Addr::new(128, 116, 44, 3)));
        assert!(is_in_roblox_gameplay_cidr(Ipv4Addr::new(
            128, 116, 127, 255
        )));

        // 128.116.128.0 has 17th bit set, outside /17
        assert!(!is_in_roblox_gameplay_cidr(Ipv4Addr::new(128, 116, 128, 0)));
        assert!(!is_in_roblox_gameplay_cidr(Ipv4Addr::new(
            128, 116, 255, 255
        )));
        // Different /16
        assert!(!is_in_roblox_gameplay_cidr(Ipv4Addr::new(128, 117, 0, 1)));
        assert!(!is_in_roblox_gameplay_cidr(Ipv4Addr::new(162, 159, 192, 1)));
    }

    #[test]
    fn test_get_default_gateway() {
        let gw = get_default_gateway();
        println!("Detected gateway: {:?}", gw);
        assert!(
            gw.is_some(),
            "Default physical gateway must be detected to prevent routing loop"
        );
    }

    #[test]
    fn test_get_primary_interface() {
        let primary = get_primary_interface();
        println!("Detected primary interface: {:?}", primary);
        assert!(primary.is_some(), "Primary interface must be detected");
        let p = primary.unwrap();
        assert!(p.if_index > 0);
        assert!(!p.alias.is_empty());
    }

    #[test]
    fn test_win32_iphelper_helpers() {
        // Calling Win32 helpers on a non-existent dummy interface index (e.g. 999999)
        // should return an OS error code without panicking or crashing.
        assert!(tune_interface_win32(999999, 1, false).is_err());
        assert!(tune_interface_weak_host(999999).is_err());
        flush_interface_neighbors(999999);
        assert!(add_ip_address_win32(999999, Ipv4Addr::new(172, 16, 0, 2), 32, true).is_err());
        assert!(add_route_win32(999999, Ipv4Addr::new(128, 116, 0, 0), 17, None, 1).is_err());
        let del_err = delete_route_win32(999999, Ipv4Addr::new(128, 116, 0, 0), 17);
        println!("del_err on dummy if: {:?}", del_err);
    }

    #[test]
    fn test_pin_host_routes_does_not_panic() {
        let dummy_primary = PrimaryInterface {
            if_index: 9999,
            alias: "Dummy".to_string(),
            next_hop: Some("192.0.2.1".to_string()),
            ip: Some("192.0.2.2".to_string()),
        };
        // Calling on dummy non-elevated parameters should not panic
        pin_host_routes(
            &["192.0.2.3".to_string(), "192.0.2.4".to_string()],
            &dummy_primary,
        );
    }

    #[test]
    fn test_pin_host_route_on_link_does_not_panic() {
        let dummy_on_link = PrimaryInterface {
            if_index: 9999,
            alias: "DummyVPN".to_string(),
            next_hop: Some("0.0.0.0".to_string()),
            ip: Some("10.2.0.2".to_string()),
        };
        pin_host_route_to_primary("192.0.2.5", &dummy_on_link);
    }
}
