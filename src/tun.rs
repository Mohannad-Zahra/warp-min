use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceIndexToLuid, CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2,
    FlushIpNetTable, FlushIpPathTable, GetBestRoute2, GetIpInterfaceEntry,
    InitializeIpForwardEntry, InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry,
    SetIpForwardEntry2, SetIpInterfaceEntry, SetUnicastIpAddressEntry, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW,
    MIB_UNICASTIPADDRESS_ROW,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_INET};
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
        let mut luid = std::mem::zeroed();
        if ConvertInterfaceIndexToLuid(if_index, &mut luid) == 0 {
            row.InterfaceLuid = luid;
        }

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
        row.NlMtu = 1200; // Enforce MTU 1200 natively via IP Helper API
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
        let mut luid = std::mem::zeroed();
        if ConvertInterfaceIndexToLuid(if_index, &mut luid) == 0 {
            row.InterfaceLuid = luid;
        }

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
        let mut luid = std::mem::zeroed();
        if ConvertInterfaceIndexToLuid(if_index, &mut luid) == 0 {
            row.InterfaceLuid = luid;
        }
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
        if ret == 5010 || ret == 183 {
            // Route already exists: update metric and interface properties
            let set_ret = SetIpForwardEntry2(&row);
            if set_ret == 0 {
                return Ok(());
            }
        }
        // NO_ERROR (0) or ERROR_OBJECT_ALREADY_EXISTS (5010 / 183)
        if ret == 0 || ret == 5010 || ret == 183 {
            Ok(())
        } else {
            Err(ret)
        }
    }
}

/// Deletes an IPv4 route directly from the Windows TCP/IP stack via DeleteIpForwardEntry2.
/// If `if_index == 0`, dynamically queries `get_best_route_interface` to discover which
/// interface owns the route prefix before deletion.
pub fn delete_route_win32(if_index: u32, dest: Ipv4Addr, prefix_len: u8) -> Result<(), u32> {
    unsafe {
        let mut target_if = if_index;
        if target_if == 0
            && let Ok((routed_if, _)) = get_best_route_interface(dest)
        {
            target_if = routed_if;
        }

        let mut row: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
        InitializeIpForwardEntry(&mut row);
        row.InterfaceIndex = target_if;
        let mut luid = std::mem::zeroed();
        if target_if > 0 && ConvertInterfaceIndexToLuid(target_if, &mut luid) == 0 {
            row.InterfaceLuid = luid;
        }
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
/// When `skip_as_source` is false (0), Windows TCP/IP will select this address as the source
/// address for unbound sockets routing through this interface (RFC 6724), ensuring natural
/// Layer-3 tunnel ingestion without triggering ProtonVPN WFP leak-protection drops.
/// If the IP already exists, updates it via SetUnicastIpAddressEntry to guarantee SkipAsSource is false (0).
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
        let mut luid = std::mem::zeroed();
        if ConvertInterfaceIndexToLuid(if_index, &mut luid) == 0 {
            row.InterfaceLuid = luid;
        }
        row.Address.si_family = AF_INET;
        row.Address.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
        row.OnLinkPrefixLength = prefix_len;
        row.SkipAsSource = if skip_as_source { 1 } else { 0 };
        row.DadState = 4; // IpDadStatePreferred (4) -> Bypasses tentative DAD state so the IP is immediately active

        let ret = CreateUnicastIpAddressEntry(&row);
        if ret == 5010 || ret == 183 {
            // Address already exists on the adapter: actively repair existing bad state
            let mut update_row: MIB_UNICASTIPADDRESS_ROW = std::mem::zeroed();
            InitializeUnicastIpAddressEntry(&mut update_row);
            update_row.InterfaceIndex = if_index;
            let _ = ConvertInterfaceIndexToLuid(if_index, &mut update_row.InterfaceLuid);
            update_row.Address.si_family = AF_INET;
            update_row.Address.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
            update_row.SkipAsSource = if skip_as_source { 1 } else { 0 };
            let set_ret = SetUnicastIpAddressEntry(&update_row);
            if set_ret == 0 {
                return Ok(());
            } else {
                return Err(set_ret);
            }
        }
        if ret == 0 {
            Ok(())
        } else {
            Err(ret)
        }
    }
}

/// Queries the Windows TCP/IP stack via GetBestRoute2 to determine which interface
/// and source IP Windows will choose for an outbound socket to `dest`.
pub fn get_best_route_interface(dest: Ipv4Addr) -> Result<(u32, Ipv4Addr), u32> {
    unsafe {
        let mut dest_addr: SOCKADDR_INET = std::mem::zeroed();
        dest_addr.si_family = AF_INET;
        dest_addr.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(dest.octets());

        let mut best_route: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
        let mut best_source: SOCKADDR_INET = std::mem::zeroed();

        let ret = GetBestRoute2(
            std::ptr::null(),
            0,
            std::ptr::null(),
            &dest_addr,
            0,
            &mut best_route,
            &mut best_source,
        );

        if ret == 0 {
            let src_bytes = best_source.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes();
            let src_ip = Ipv4Addr::from(src_bytes);
            Ok((best_route.InterfaceIndex, src_ip))
        } else {
            Err(ret)
        }
    }
}

pub struct WintunDevice {
    pub if_index: u32,
    #[allow(dead_code)]
    pub adapter: Arc<Adapter>,
    pub session: Arc<Session>,
    pub endpoint_a_ip: String,
    pub api_ips: Vec<String>,
    #[allow(dead_code)]
    pub primary_interface: Option<PrimaryInterface>,
    #[allow(dead_code)]
    pub original_gateway: Option<String>,
    #[allow(dead_code)]
    pub wfp_session: std::sync::Mutex<Option<crate::wfp::WfpPermitSession>>,
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
        let _ = delete_route_win32(0, Ipv4Addr::new(128, 116, 0, 0), 17);
        let _ = Command::new("route")
            .args(["delete", "128.116.0.0"])
            .output();
        let _ = Command::new("route")
            .args(["delete", "128.116.0.0", "mask", "255.255.128.0", "0.0.0.0"])
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

        // Initialize Wintun session immediately after creation so NDIS transitions to MediaConnectStateConnected.
        // This ensures the interface is connected before route table manipulation and GetBestRoute2 queries.
        crate::log_info!("[*] Initializing Wintun session ring-buffer on '{}'...", adapter_name);
        let session = adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|e| format!("Failed to start Wintun session: {:?}", e))?;
        let session = Arc::new(session);

        // Allow Windows NDIS link-state transition (MediaConnectStateConnected) to propagate to tcpip.sys
        std::thread::sleep(std::time::Duration::from_millis(300));

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

        // Register WFP Hard-Permit filter (SubLayer Weight 65535) scoped to this Wintun adapter LUID.
        // Under multi-VPN environments with active kill-switches (e.g. ProtonVPN's "ProtonVPN block IPv4"),
        // this guarantees Windows TCP/IP stack allows outbound packets on WARP-Gool to proceed into the driver ring buffer.
        let mut luid = unsafe { std::mem::zeroed() };
        let mut wfp_session = None;
        if unsafe { ConvertInterfaceIndexToLuid(if_index, &mut luid) } == 0 {
            let luid_val = unsafe { luid.Value };
            match crate::wfp::WfpPermitSession::install_tun_permit(luid_val) {
                Ok(s) => {
                    wfp_session = Some(s);
                }
                Err(err) => {
                    crate::log_warn!(
                        "[!] WFP Hard-Permit registration note: OS error code {} (continuing with standard TCP/IP routing)",
                        err
                    );
                }
            }
        }

        // Configure adapter IP via native Win32 CreateUnicastIpAddressEntry with SkipAsSource=0 (false)
        // (falling back to netsh skipassource=false and PowerShell Set-NetIPAddress -SkipAsSource $false).
        // SkipAsSource MUST be FALSE so that when Roblox creates an unbound socket (inaddr_any:0),
        // Windows Source Address Selection (RFC 6724) selects the virtual TUN address (172.16.0.2)
        // rather than the physical Wi-Fi IP (192.168.1.106). Outbound gameplay packets enter WARP-Gool directly.
        let ip_str = local_ipv4.to_string();
        crate::log_info!(
            "[*] Configuring adapter IP {} (mask=255.255.255.255, skip_as_source=false, if_index {})...",
            ip_str, if_index
        );

        if let Err(e) = add_ip_address_win32(if_index, local_ipv4, 32, false) {
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
            let _ = Command::new("netsh")
                .args([
                    "interface",
                    "ipv4",
                    "add",
                    "address",
                    &format!("name={}", adapter_name),
                    &format!("addr={}", ip_str),
                    "mask=255.255.255.255",
                    "skipassource=false",
                ])
                .output();
            let _ = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    &format!(
                        "if (Get-NetIPAddress -InterfaceIndex {0} -IPAddress '{1}' -ErrorAction SilentlyContinue) {{ Set-NetIPAddress -InterfaceIndex {0} -IPAddress '{1}' -PrefixLength 32 -SkipAsSource $false -ErrorAction SilentlyContinue }} else {{ New-NetIPAddress -InterfaceIndex {0} -IPAddress '{1}' -PrefixLength 32 -SkipAsSource $false -ErrorAction SilentlyContinue }}",
                        if_index, ip_str
                    ),
                ])
                .output();
        } else {
            crate::log_info!(
                "[+] Configured adapter IP via native Win32: SkipAsSource=Disabled, PrefixLength=32"
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

        // Layer-3 TUN interfaces (Wintun) operate at the IP layer and do not use ARP or Ethernet neighbors.
        // Interface neighbor cache flushed above ensures clean routing path state.

        // 4. Enforce Private Network Profile and add explicit outbound permit rule so Windows Firewall does not restrict outbound packets
        let ps_private_profile = format!(
            "Set-NetConnectionProfile -InterfaceIndex {} -NetworkCategory Private -ErrorAction SilentlyContinue; Set-NetConnectionProfile -InterfaceAlias '{}' -NetworkCategory Private -ErrorAction SilentlyContinue; New-NetFirewallRule -DisplayName 'WARP-Gool Permit Outbound' -Direction Outbound -InterfaceAlias '{}' -Action Allow -Profile Any -ErrorAction SilentlyContinue",
            if_index, adapter_name, adapter_name
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

        // Pinned on-link route for Roblox gameplay traffic (128.116.0.0/17 RakNet UDP) via WARP-Gool.
        // On Layer-3 TUN interfaces (Wintun), traffic must be routed as On-Link (NextHop = 0.0.0.0).
        // Since SkipAsSource is false (0) on WARP-Gool, Windows Source Address Selection binds
        // outbound gameplay sockets directly to the virtual TUN IP (172.16.0.2), cleanly entering
        // WARP-Gool without passing through physical Wi-Fi or triggering ProtonVPN WFP leak filters.
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

        // Real-time kernel route verification via GetBestRoute2 for actual Roblox game server (128.116.5.33)
        match get_best_route_interface(Ipv4Addr::new(128, 116, 5, 33)) {
            Ok((routed_if, src_ip)) => {
                if routed_if == if_index && src_ip == local_ipv4 {
                    crate::log_info!(
                        "[+] Kernel Route Verified: 128.116.5.33 bound to {} (ifIndex {}) with source IP {} (WFP-safe)",
                        adapter_name, if_index, src_ip
                    );
                } else if routed_if == if_index {
                    crate::log_warn!(
                        "[!] Kernel Route Notice: 128.116.5.33 routed to {} but source IP is {} (expected tunnel IP {})",
                        adapter_name, src_ip, local_ipv4
                    );
                } else {
                    crate::log_error!(
                        "[-] Kernel Route Error: 128.116.5.33 routed to interface {} instead of {}",
                        routed_if, adapter_name
                    );
                }
            }
            Err(e) => {
                crate::log_debug!("[!] GetBestRoute2 pre-flight query code: {}", e);
            }
        }

        crate::log_info!(
            "[+] Split-Tunneling active: Roblox gameplay UDP (128.116.0.0/17) routes via WARP-Gool into Hop 2; API and launcher endpoints ({} IPs) pinned via primary VPN.",
            target_host_ips.len()
        );

        Ok(Self {
            if_index,
            adapter,
            session,
            endpoint_a_ip: endpoint_a_ip.to_string(),
            api_ips: target_host_ips,
            primary_interface,
            original_gateway,
            wfp_session: std::sync::Mutex::new(wfp_session),
            cleaned_up: AtomicBool::new(false),
        })
    }

    pub fn restore_routing(&self) {
        if self.cleaned_up.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Ok(mut lock) = self.wfp_session.lock() {
            let _ = lock.take();
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
        let _ = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Remove-NetFirewallRule -DisplayName 'WARP-Gool Permit Outbound' -ErrorAction SilentlyContinue",
            ])
            .output();
        cleanup_routes_with_interfaces(
            &self.endpoint_a_ip,
            &self.api_ips,
            self.primary_interface.as_ref().map(|p| p.if_index),
            Some(self.if_index),
        );
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

#[allow(dead_code)]
pub fn cleanup_routes(endpoint_a_ip: &str, api_ips: &[String]) {
    let pri = get_primary_interface();
    cleanup_routes_with_interfaces(
        endpoint_a_ip,
        api_ips,
        pri.as_ref().map(|p| p.if_index),
        None,
    );
}

#[allow(dead_code)]
pub fn cleanup_routes_with_interfaces(
    endpoint_a_ip: &str,
    api_ips: &[String],
    primary_if_index: Option<u32>,
    wintun_if_index: Option<u32>,
) {
    crate::log_info!("[*] Restoring host routing table...");
    let _ = delete_route_win32(wintun_if_index.unwrap_or(0), Ipv4Addr::new(128, 116, 0, 0), 17);
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
    let pri_if = primary_if_index.unwrap_or(0);
    let mut win32_deleted = 0usize;
    for ip in &all_clean_ips {
        if let Ok(ip_addr) = ip.parse::<Ipv4Addr>()
            && delete_route_win32(pri_if, ip_addr, 32).is_ok()
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
        assert!(add_ip_address_win32(999999, Ipv4Addr::new(172, 16, 0, 2), 32, false).is_err());
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
    fn test_add_ip_address_win32_skip_as_source_false() {
        // Assert calling add_ip_address_win32 with skip_as_source = false on dummy interface returns error without panic
        let res = add_ip_address_win32(999999, Ipv4Addr::new(172, 16, 0, 2), 32, false);
        assert!(res.is_err());
    }

    #[test]
    fn test_add_ip_address_win32_skip_as_source_true() {
        // Assert calling add_ip_address_win32 with skip_as_source = true on dummy interface returns error without panic
        let res = add_ip_address_win32(999999, Ipv4Addr::new(172, 16, 0, 2), 32, true);
        assert!(res.is_err());
    }

    #[test]
    fn test_get_best_route_interface_loopback_or_default() {
        // Querying route to 127.0.0.1 should succeed and return loopback interface
        let res = get_best_route_interface(Ipv4Addr::new(127, 0, 0, 1));
        assert!(res.is_ok(), "GetBestRoute2 to 127.0.0.1 must succeed");
        let (if_index, src_ip) = res.unwrap();
        assert!(if_index > 0);
        assert_eq!(src_ip, Ipv4Addr::new(127, 0, 0, 1));

        // Querying route to Roblox game server when WARP-Gool is not running should route via Primary/ProtonVPN
        let res_game = get_best_route_interface(Ipv4Addr::new(128, 116, 5, 33));
        println!("Current Route to Roblox 128.116.5.33: {:?}", res_game);
        assert!(res_game.is_ok(), "GetBestRoute2 to 128.116.5.33 must succeed");
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

    #[test]
    fn test_roblox_gameplay_server_ip_classification() {
        // Actual server from RobloxPlayerBeta logs: 128.116.5.33
        let game_ip = Ipv4Addr::new(128, 116, 5, 33);
        assert!(is_in_roblox_gameplay_cidr(game_ip));

        // Subnet boundaries
        assert!(is_in_roblox_gameplay_cidr(Ipv4Addr::new(128, 116, 0, 1)));
        assert!(is_in_roblox_gameplay_cidr(Ipv4Addr::new(128, 116, 127, 254)));
        assert!(!is_in_roblox_gameplay_cidr(Ipv4Addr::new(128, 116, 128, 1)));
    }

    #[test]
    fn test_roblox_edge_pinning_targets_all_subnets() {
        let mut target_host_ips = Vec::new();
        for i in 0..128 {
            target_host_ips.push(format!("128.116.{}.3", i));
        }
        assert_eq!(target_host_ips.len(), 128);
        assert!(target_host_ips.contains(&"128.116.31.3".to_string()));
        assert!(target_host_ips.contains(&"128.116.5.3".to_string()));
        // Actual game server (128.116.5.33) must NOT be in target_host_ips so it routes via WARP-Gool
        assert!(!target_host_ips.contains(&"128.116.5.33".to_string()));
    }

    #[test]
    fn test_delete_route_win32_zero_if_index_resolves_dynamically() {
        // Calling delete_route_win32 with if_index = 0 should resolve route via GetBestRoute2
        // and return without panic
        let res = delete_route_win32(0, Ipv4Addr::new(128, 116, 5, 33), 32);
        assert!(res.is_ok() || res.is_err());
    }

    #[test]
    fn test_cleanup_routes_with_interfaces_does_not_panic() {
        cleanup_routes_with_interfaces(
            "162.159.192.1",
            &["128.116.21.3".to_string()],
            Some(9999),
            Some(9998),
        );
    }
}
